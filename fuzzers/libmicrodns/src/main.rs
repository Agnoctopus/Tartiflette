mod executor;

use tartiflette_vm::{Vm, Register};
use crate::executor::TartifletteExecutor;

fn main() {
    let vm = Vm::from_snapshot("./snapshot_info.json", "snapshot_data.bin", 10*0x1000*0x1000).unwrap();
}
