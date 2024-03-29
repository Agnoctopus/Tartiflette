use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;
use libafl::bolts::AsMutSlice;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::Input,
    observers::{ObserversTuple, StdMapObserver},
    Error,
};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::unistd::alarm;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Not;
use std::time::{Duration, Instant};

use tartiflette_vm::{Register, Vm, VmExit};

const INT3: u8 = 0xCC;

// XXX: Big hack to handle timeouts. We simply catch SIGALARM and do nothing,
//      which will make kvm_run(...) fail with EINTR so we can return a timeout.
extern "C" fn alarm_handler(_: i32) {
    // Do nothing
}

pub fn install_alarm_handler() {
    let action = SigAction::new(
        SigHandler::Handler(alarm_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );

    unsafe {
        sigaction(Signal::SIGALRM, &action).expect("Failed to setup SIGALRM handler");
    }
}

/// Error during executor actions
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorError {
    /// Error during interaction with the vm
    VmError(&'static str),
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
    Exit,
}

pub type TartifletteHook = dyn FnMut(&mut Vm) -> HookResult;
pub type CoverageHook = dyn FnMut(u64);

pub struct TartifletteExecutor<'a, H, I, OT: Debug, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
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
    /// Coverage hook
    coverage_hook: Option<&'a mut CoverageHook>,
    /// Original bytes before hooks or coverage
    orig_bytes: BTreeMap<u64, u8>,
    /// Vm used for the execution
    exec_vm: Vm,
    /// Vm used for reseting
    reset_vm: Vm,
    /// Timeout duration
    timeout_duration: Duration,
    /// Execution hooks
    phantom: PhantomData<(I, S)>,
}

impl<'a, EM, H, I, OT: Debug, S, Z> Executor<EM, I, S, Z> for TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> std::result::Result<ExitKind, Error> {
        // Load the map we will modify with coverage
        let map_observer = self
            .observers
            .match_name_mut::<StdMapObserver<u8>>("coverage")
            .expect("TartifletteExecutor expects a StdMapObserver<u8> named 'coverage'");

        // Place the input in memory
        (self.harness_fn)(&mut self.exec_vm, &input);

        // If the processor was put into singlestep mode, this object will
        // contain the address where we removed the breakpoint.
        let mut singlestep: Option<u64> = None;

        // Install the alarm
        alarm::set(self.timeout_duration.as_secs() as u32);

        // Usually the SIGALRM should land when we are in the kvm_run ioctl.
        // In the rare case where it would land outside the kvm_run, we have
        // to manually track the time to exit early on the next kvm_run.
        let starting_time = Instant::now();

        // Execution loop
        let exit_kind = loop {
            if starting_time.elapsed() > self.timeout_duration {
                break ExitKind::Timeout;
            }

            let vmexit = self.exec_vm.run().expect("Unexpected vm error");
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
                }
                VmExit::Exception(code) => {
                    match code {
                        // Exception debug, raise after trap flasg set for a singlestep
                        1 => {
                            // Get the starting point before the singlestep
                            let starting_rip = singlestep
                                .take()
                                .expect("Debug exception triggered not in singlestep");

                            // Restore the breakpoint
                            // Should be safe as well as we came from starting rip
                            self.exec_vm
                                .write_value::<u8>(starting_rip, INT3)
                                .expect("Error while restoring exec_vm hook (after continue)");

                            // Disable the trap bit
                            let mut rflags = self.exec_vm.get_reg(Register::Rflags);
                            rflags &= !(1 << 8);
                            self.exec_vm.set_reg(Register::Rflags, rflags);
                        }
                        _ => break ExitKind::Crash,
                    }
                }
                VmExit::Breakpoint => {
                    // Handling the singlestep after a continue
                    if let Some(starting_rip) = singlestep.take() {
                        // Restore the breakpoint
                        // Should be safe as well as we came from starting rip
                        self.exec_vm
                            .write_value::<u8>(starting_rip, INT3)
                            .expect("Error while restoring exec_vm hook (after continue)");

                        // Disable the trap bit
                        let mut rflags = self.exec_vm.get_reg(Register::Rflags);
                        rflags &= !(1 << 8);
                        self.exec_vm.set_reg(Register::Rflags, rflags);
                    }

                    // Handle coverage
                    if self.coverage.contains(&rip) {
                        // Restore the original instruction byte
                        // The unwrap should be safe as these two structures should
                        // be in sync.
                        let orig_byte = self.orig_bytes.get(&rip).unwrap();

                        // Normally it is impossible for the memory access to fail
                        // as we breakpointed on the instruction at rip.
                        self.exec_vm
                            .write_value::<u8>(rip, *orig_byte)
                            .expect("Error while removing exec_vm coverage");
                        self.reset_vm
                            .write_value::<u8>(rip, *orig_byte)
                            .expect("Error while removing reset_vm coverage");

                        // Remove the breakpoint from the coverage
                        self.coverage.remove(&rip);
                        self.orig_bytes.remove(&rip);

                        // Add the coverage to the map
                        let map = map_observer.as_mut_slice();
                        let bb_index = (rip as usize) % map.len();
                        map[bb_index] += 1;

                        // Call coverage hook if any
                        if let Some(hook) = &mut self.coverage_hook {
                            hook(rip)
                        }
                    }

                    // Handle hooks
                    if let Some(hook) = self.hooks.get_mut(&rip) {
                        match hook(&mut self.exec_vm) {
                            HookResult::Exit => break ExitKind::Ok,
                            HookResult::Crash => break ExitKind::Crash,
                            HookResult::Continue => {
                                println!("Continue Hook: {:x}", rip);
                                // The user wants to continue execution right
                                // after its hook. First restore the original
                                // code byte.
                                let orig_byte = self.orig_bytes.get(&rip).unwrap();

                                // This write should never fail as we breakpointed
                                // on this address.
                                self.exec_vm
                                    .write_value::<u8>(rip, *orig_byte)
                                    .expect("Error while restoring hook byte");

                                // Activate trap flag and fill the singlestep slot
                                let rflags = self.exec_vm.get_reg(Register::Rflags);
                                self.exec_vm.set_reg(Register::Rflags, rflags | (1 << 8));

                                singlestep = Some(rip);
                            }
                            HookResult::Redirect => {}
                        }
                    }
                }
                // TODO: See how to properly handle hlt (crash ? normal exit ? forward to user ?)
                VmExit::Hlt => {
                    panic!("guest abort (hlt)");
                }
                _ => break ExitKind::Crash,
            }
        };

        // Remove the alarm
        alarm::cancel();

        // Reset the vm to its original state
        self.exec_vm.reset(&self.reset_vm);

        Ok(exit_kind)
    }
}

impl<'a, H, I, OT: Debug, S> TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    pub fn new(
        vm: &Vm,
        timeout: Duration,
        observers: OT,
        harness: &'a mut H,
    ) -> Result<Self, ExecutorError> {
        assert!(
            timeout >= Duration::from_secs(1),
            "Timeout must at least be 1 second"
        );

        Ok(TartifletteExecutor {
            harness_fn: harness,
            observers,
            exec_vm: vm.clone(),
            reset_vm: vm.clone(),
            hooks: Default::default(),
            syscall_hook: None,
            coverage: Default::default(),
            coverage_hook: None,
            orig_bytes: Default::default(),
            timeout_duration: timeout,
            phantom: PhantomData::<(I, S)>,
        })
    }

    /// Adds a coverage point to the executor
    pub fn add_coverage(&mut self, address: u64) -> Result<(), ExecutorError> {
        // Check that the spot is not already instrumented
        if self.hooks.contains_key(&address) {
            return Err(ExecutorError::VmError(
                "Hook already installed at this address",
            ));
        }

        if self.coverage.contains(&address).not() {
            // Read original byte from memory
            let mut orig_byte: [u8; 1] = [0; 1];
            self.exec_vm.read(address, &mut orig_byte).map_err(|_| {
                ExecutorError::VmError("Could not read original byte (invalid address ?)")
            })?;

            // Write breakpoint to memory
            self.exec_vm.write_value::<u8>(address, INT3).unwrap();
            self.reset_vm.write_value::<u8>(address, INT3).unwrap();

            self.coverage.insert(address);
            self.orig_bytes.insert(address, orig_byte[0]);
        }

        Ok(())
    }

    /// Adds an address callback to the executor
    pub fn add_hook(
        &mut self,
        address: u64,
        hook: &'a mut TartifletteHook,
    ) -> Result<(), ExecutorError> {
        // Check that the spot is not already instrumented
        if self.coverage.contains(&address) {
            return Err(ExecutorError::VmError(
                "Coverage already installed at this address",
            ));
        }

        // Read original byte
        let mut orig_byte: [u8; 1] = [0; 1];
        self.exec_vm.read(address, &mut orig_byte).map_err(|_| {
            ExecutorError::VmError("Could not read original byte (invalid address ?)")
        })?;

        if self.hooks.insert(address, hook).is_none() {
            // Write breakpoint to memory. Should not fail as orig byte was read from same address
            self.exec_vm.write_value::<u8>(address, INT3).unwrap();
            self.reset_vm.write_value::<u8>(address, INT3).unwrap();

            // New hook, add the original byte
            self.orig_bytes.insert(address, orig_byte[0]);
        }

        Ok(())
    }

    /// Adds a syscall handling callback to the executor
    #[inline]
    pub fn add_syscall_hook(&mut self, hook: &'a mut TartifletteHook) {
        self.syscall_hook = Some(hook);
    }

    /// Adds a hook to the executor that is called each time there is new coverage
    #[inline]
    pub fn add_coverage_hook(&mut self, hook: &'a mut CoverageHook) {
        self.coverage_hook = Some(hook);
    }
}

impl<'a, H, I, OT: Debug, S> HasObservers<I, OT, S> for TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
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

impl<'a, H, I, OT, S> Debug for TartifletteExecutor<'a, H, I, OT, S>
where
    H: FnMut(&mut Vm, &I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TartifletteExecutor")
            .field("harness_fn", &"<fn>")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}
