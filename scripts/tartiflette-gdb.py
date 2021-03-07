import gdb
import json
import sys
import struct
from enum import Enum
from typing import Optional, Dict, List, Any


def p64(x: int) -> bytes:
    return struct.pack("<Q", x)


def gdb_int_value(exp: str) -> int:
    value = int(gdb.parse_and_eval(exp))

    # Two's complement because we only want positive values
    if value < 0:
        value = (value * -1 ^ 0xffffffffffffffff) + 1

    return value


class Architecture(Enum):
    x86_64 = "x86-64"


x86_64_user_regs_struct = [
    "r15", "r14", "r13", "r12",
    "rbp", "rbx", "r11", "r10",
    "r9", "r8", "rax", "rcx",
    "rdx", "rsi", "rdi", "orig_rax",
    "rip", "cs", "eflags", "rsp",
    "ss", "fs_base", "gs_base", "ds",
    "es", "fs", "gs"
]

arch_registers = {
    Architecture.x86_64.value: x86_64_user_regs_struct,
}


class DumpSnapshot(gdb.Command):
    def __init__(self) -> None:
        super().__init__("tartiflette-snapshot", gdb.COMMAND_USER)

    def get_architecture(self) -> Optional[str]:
        arch_str = gdb.execute("show architecture", False, True)

        if Architecture.x86_64.value in arch_str:
            return Architecture.x86_64.value

        return None

    def get_pid(self, from_tty: bool) -> int:
        proc_info = gdb.execute("info proc", from_tty, True).split("\n")
        proc_info = list(filter(lambda a: a.startswith("process"), map(str.strip, proc_info)))
        if len(proc_info) != 1:
            raise Exception("Could not find process id")

        return int(proc_info[0].split(" ")[-1])

    def dump_mappings(self, pid: int, filename: str) -> List[Dict[str, str]]:
        mappings = []
        offset = 0

        data_out = open(filename, "wb")
        proc_maps = open(f"/proc/{pid}/maps", "r").readlines()
        proc_mem = open(f"/proc/{pid}/mem", "rb")

        for line in proc_maps:
            line = line.strip()
            info = list(filter(lambda a: len(a) > 1 and not a.isspace(), line.split(" ")))

            mapping_range = info[0].split("-")
            start = int(mapping_range[0], 16)
            end = int(mapping_range[1], 16)

            if start > sys.maxsize or end > sys.maxsize:
                print(f"Mapping too high in memory, cannot dump: {line}")
                continue

            perm_str = info[1]
            proc_mem.seek(start)

            mapping = {
                "start": f"{start:x}",
                "end": f"{end:x}",
                "physical_offset": f"{offset:x}",
                "permissions": perm_str
            }

            # XXX: Veeeeery bad heuristic to detect file mappings
            if "/" in info[-1]:
                mapping["image"] = info[-1]

            try:
                data = proc_mem.read(end - start)
                print(f"Dumping range 0x{start:x} -> 0x{end:x} {perm_str}")
                data_out.write(data)

                mappings.append(mapping)
                offset += end - start
            except OSError:
                print(f"Could not dump range 0x{start:x} -> 0x{end:x}")
                continue

        # Close opened files
        data_out.close()
        proc_mem.close()

        return mappings

    def dump_registers(self, arch: str) -> Dict[str, str]:
        register_data = {}

        for reg in arch_registers[arch]:
            reg_value = gdb_int_value(f"${reg}")
            register_data[reg] = f"{reg_value:x}"
        return register_data

    def dump_symbols(self, from_tty: bool) -> Dict[str, str]:
        symbols = gdb.execute("info functions", from_tty, True)
        symbols = filter(lambda s: len(s) > 0 and s.startswith("0x"), map(str.strip, symbols.split("\n")))
        symbol_map = {}

        for symbol in symbols:
            chunks = symbol.split(" ")
            address, name = int(chunks[0], 16), chunks[-1]

            if name not in symbol_map:
                symbol_map[name] = [address]
            else:
                symbol_map[name].append(address)

        symbol_info = {}

        # As some functions appear multiple times we need to suffix them with
        # an identifier. Otherwise all tools won't be happy
        for name, addresses in symbol_map.items():
            if len(addresses) == 1:
                symbol_info[name] = f"{addresses[0]:x}"
            else:
                for i, e in enumerate(addresses):
                    symbol_info[f"{name}_{i}"] = f"{e:x}"
        return symbol_info

    def invoke(self, arg: str, from_tty: bool) -> None:
        info_file_name = "snapshot_info.json"
        data_file_name = "snapshot_data.bin"

        # Command line
        args = gdb.string_to_argv(arg)
        if len(args) > 2:
            print("usage: tartiflette-snapshot [output info file] [output memory file]]")
            return
        if len(args) >= 1:
            info_file_name = args[0]
        if len(args) == 2:
            data_file_name = args[1]

        # Architecture check
        arch = self.get_architecture()
        if arch is None:
            print("Unsupported architecture")
            return

        snapshot_info: Dict[str, Any] = {
            "memory_file": data_file_name,
        }

        # Get pid
        pid = self.get_pid(from_tty)
        print(f"Process id: {pid}")

        # Dump mappings
        snapshot_info["mappings"] = self.dump_mappings(pid, data_file_name)

        # Dump registers
        snapshot_info["registers"] = self.dump_registers(arch)

        # Dump symbols
        snapshot_info["symbols"] = self.dump_symbols(from_tty)

        # Write out the json information
        with open(info_file_name, "w") as info_file:
            info_file.write(json.dumps(snapshot_info))


def main() -> None:
    DumpSnapshot()

if __name__ == '__main__':
    main()
