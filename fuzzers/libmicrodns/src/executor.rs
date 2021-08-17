use core::marker::PhantomData;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Not;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    observers::{ObserversTuple, StdMapObserver, MapObserver},
    inputs::Input,
    Error
};
use tartiflette_vm::{Vm, VmExit, Register};

/// Error during executor actions
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorError {
    /// Error during interaction with the vm
    VmError(&'static str)
}

/// Mode of execution after a hook was fired
pub enum HookResult {
    /// Continue executing the code following the hook
    Continue,
    /// Hook modified the execution state, do not continue where it fired
    Redirect,
    /// Hook induced crash
    Crash,
    /// Hook induced stop
    Exit
}

pub type TartifletteHook = dyn FnMut(&mut Vm) -> HookResult;

pub struct TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>
{
    /// Function to prepare the vm state before execution
    harness_fn: &'a mut H,
    /// Execution observers
    observers: OT,
    /// List of hooks installed by the user
    hooks: BTreeMap<u64, &'a mut TartifletteHook>,
    /// Syscall hooking function
    syscall_hook: Option<&'a mut TartifletteHook>,
    /// Map of coverage addresses to the corresponding original instruction byte
    coverage: BTreeSet<u64>,
    /// Original bytes before hooks or coverage
    orig_bytes: BTreeMap<u64, u8>,
    /// Vm used for the execution
    exec_vm: Vm,
    /// Vm used for reseting
    reset_vm: Vm,
    /// Execution hooks
    phantom: PhantomData<(I, S)>
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, I, S, Z> for TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> std::result::Result<ExitKind, Error> {
        // Load the map we will modify with coverage
        let map_observer = self.observers
            .match_name_mut::<StdMapObserver<u8>>("coverage")
            .expect("TartifletteExecutor expects a StdMapObserver<u8> named 'coverage'");

        // Place the input in memory
        (self.harness_fn)(&mut self.exec_vm, &input);

        // If the processor was put into singlestep mode, this object will
        // contain the address where we removed the breakpoint.
        let mut singlestep: Option<u64> = None;

        // Execution loop
        let exit_kind = loop {
            let vmexit = self.exec_vm.run()
                .expect("Unexpected vm error");
            let rip = self.exec_vm.get_reg(Register::Rip);

            match vmexit {
                VmExit::Interrupted => break ExitKind::Timeout,
                VmExit::Syscall => {
                    if let Some(hook) = &mut self.syscall_hook {
                        match hook(&mut self.exec_vm) {
                            HookResult::Crash => break ExitKind::Crash,
                            HookResult::Exit => break ExitKind::Ok,
                            _ => {}
                        }
                    } else {
                        panic!("Guest used a syscall but not handler was defined");
                    }
                },
                VmExit::Breakpoint => {
                    // Handling the singlestep after a continue
                    if let Some(starting_rip) = singlestep {
                        // Restore the breakpoint
                        // Should be safe as well as we came from starting rip
                        self.exec_vm.write_value::<u8>(starting_rip, 0xcc)
                            .expect("Error while restoring exec_vm hook (after continue)");

                        // Disable the trap bit
                        let rflags = self.exec_vm.get_reg(Register::Rflags);
                        self.exec_vm.set_reg(Register::Rflags, rflags & !(1 << 8));

                        // Empty the singlestep slot
                        singlestep = None;
                    }

                    // Handle coverage
                    if self.coverage.contains(&rip) {
                        // Restore the original instruction byte
                        // The unwrap should be safe as these two structures should
                        // be in sync.
                        let orig_byte = self.orig_bytes.get(&rip).unwrap();

                        // Normally it is impossible for the memory access to fail
                        // as we breakpointed on the instruction at rip.
                        self.exec_vm.write_value::<u8>(rip, *orig_byte)
                            .expect("Error while removing exec_vm coverage");
                        self.reset_vm.write_value::<u8>(rip, *orig_byte)
                            .expect("Error while removing reset_vm coverage");

                        // Remove the breakpoint from the coverage
                        self.coverage.remove(&rip);
                        self.orig_bytes.remove(&rip);

                        // Add the coverage to the map
                        let map = map_observer.map_mut();
                        map[(rip as usize) % map.len()] += 1;

                        println!("cov 0x{:x}", rip);
                    }

                    // Handle hooks
                    if let Some(hook) = self.hooks.get_mut(&rip) {
                        match hook(&mut self.exec_vm) {
                            HookResult::Exit => break ExitKind::Ok,
                            HookResult::Crash => break ExitKind::Crash,
                            HookResult::Continue => {
                                // The user wants to continue execution right
                                // after its hook. First restore the original
                                // code byte.
                                let orig_byte = self.orig_bytes.get(&rip).unwrap();

                                // This write should never fail as we breakpointed
                                // on this address.
                                self.exec_vm.write_value::<u8>(rip, *orig_byte)
                                    .expect("Error while restoring hook byte");

                                // Activate trap flag and fill the singlestep slot
                                let rflags = self.exec_vm.get_reg(Register::Rflags);
                                self.exec_vm.set_reg(Register::Rflags, rflags | (1 << 8));
                                singlestep = Some(rip);
                            }
                            HookResult::Redirect => {}
                        }
                    }
                },
                // TODO: See how to properly handle hlt (crash ? normal exit ? forward to user ?)
                VmExit::Hlt => {
                    panic!("guest abort (hlt)");
                },
                _ => break ExitKind::Crash
            }
        };

        // Reset the vm to its original state
        self.exec_vm.reset(&self.reset_vm);

        Ok(exit_kind)
    }
}

impl<'a, H, I, OT, S> TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>
{
    /// Adds a coverage point to the executor
    pub fn add_coverage(&mut self, address: u64) -> Result<(), ExecutorError> {
        // Check that the spot is not already instrumented
        if self.hooks.contains_key(&address) {
            return Err(ExecutorError::VmError("Hook already installed at this address"));
        }

        if self.coverage.contains(&address).not() {
            // Read original byte from memory
            let mut orig_byte: [u8; 1] = [0; 1];
            self.exec_vm.read(address, &mut orig_byte)
                .map_err(|_| ExecutorError::VmError("Could not read original byte (invalid address ?)"))?;

            // Write breakpoint to memory
            self.exec_vm.write_value::<u8>(address, 0xcc).unwrap();
            self.reset_vm.write_value::<u8>(address, 0xcc).unwrap();

            self.coverage.insert(address);
            self.orig_bytes.insert(address, orig_byte[0]);

        }

        Ok(())
    }

    /// Adds an address callback to the executor
    pub fn add_hook(&mut self, address: u64, hook: &'a mut TartifletteHook) -> Result<(), ExecutorError> {
        // Check that the spot is not already instrumented
        if self.coverage.contains(&address) {
            return Err(ExecutorError::VmError("Coverage already installed at this address"));
        }

        let mut orig_byte: [u8; 1] = [0; 1];

        // Read original byte
        self.exec_vm.read(address, &mut orig_byte)
            .map_err(|_| ExecutorError::VmError("Could not read original byte (invalid address ?)"))?;

        if self.hooks.insert(address, hook).is_none() {
            // Write breakpoint to memory. Should not fail as orig byte was read from same address
            self.exec_vm.write_value::<u8>(address, 0xcc).unwrap();
            self.reset_vm.write_value::<u8>(address, 0xcc).unwrap();

            // New hook, add the original byte
            self.orig_bytes.insert(address, orig_byte[0]);
        }

        Ok(())
    }

    /// Adds a syscall handling callback to the executor
    pub fn add_syscall_hook(&mut self, hook: &'a mut TartifletteHook) {
        self.syscall_hook = Some(hook);
    }
}

impl<'a, H, I, OT, S> HasObservers<I, OT, S> for TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}

impl<'a, H, I, OT, S> TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>
{
    pub fn new(vm: &Vm, observers: OT, harness: &'a mut H) -> Result<Self, ExecutorError> {
        Ok(TartifletteExecutor {
            harness_fn: harness,
            observers,
            exec_vm: vm.clone(),
            reset_vm: vm.clone(),
            hooks: Default::default(),
            syscall_hook: None,
            coverage: Default::default(),
            orig_bytes: Default::default(),
            phantom: PhantomData::<(I, S)>
        })
    }
}
