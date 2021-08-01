mod executor;

use tartiflette_vm::{Vm, Register, SnapshotInfo};
use crate::executor::TartifletteExecutor;

fn main() {
    // let mut vm = Vm::from_snapshot("./snapshot_info.json", "snapshot_data.bin", 10*0x1000*0x1000).unwrap();
    let snapshot = SnapshotInfo::from_file("./snapshot_info.json").expect("crash");

    for module in snapshot.modules.iter() {
        println!("{:#x?}", module);
    }
}
