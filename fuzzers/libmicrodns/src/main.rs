mod executor;

use tartiflette_vm::{Vm, Register};
use crate::executor::TartifletteExecutor;

fn main() {
    let mut vm = Vm::from_snapshot("./snapshot_info.json", "snapshot_data.bin", 10*0x1000*0x1000).unwrap();
    let copy = vm.clone();
    vm.reset(&copy);

    vm.set_reg(Register::Rip, 0x1337);
}
