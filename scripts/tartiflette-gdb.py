import gdb
import json
import sys
import struct


def p64(x):
    return struct.pack("<Q", x)


def gdb_int_value(exp):
    value = int(gdb.parse_and_eval(exp))

    # Two's complement because we only want positive values
    if value < 0:
        value = (value * -1 ^ 0xffffffffffffffff) + 1

    return value


class Architecture:
    x86_64 = "x86_64"


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
        Architecture.x86_64: x86_64_user_regs_struct,
}


class DumpSnapshot(gdb.Command):
    def __init__(self):
        super().__init__("tartiflette-snapshot", gdb.COMMAND_USER)

    def get_architecture(self):
        arch_str = gdb.execute("show architecture", False, True)

        if "x86-64" in arch_str:
            return Architecture.x86_64

        return None

    def invoke(self, arg, from_tty):
        info_file_name = "snapshot_info.json"
        data_file_name = "snapshot_data.bin"
        args = gdb.string_to_argv(arg)

        if len(args) > 2:
            print("usage: tartiflette-snapshot [optional output info file] [optional output memory file]]")
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

        snapshot_info = {
            "memory_file": data_file_name,
        }

        # Get pid and mappings
        proc_info = gdb.execute("info proc", from_tty, True).split("\n")
        proc_info = list(filter(lambda a: a.startswith("process"), map(str.strip, proc_info)))

        if len(proc_info) != 1:
            print("Could not find process id")
            return

        pid = proc_info[0].split(" ")[-1]
        print(f"Process id: {pid}")

        proc_maps = open(f"/proc/{pid}/maps", "r").readlines()
        proc_mem = open(f"/proc/{pid}/mem", "rb")
        data_out = open(data_file_name, "wb")

        # Dump mappings
        mappings = []
        offset = 0

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
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "physical_offset": offset,
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

        snapshot_info["mappings"] = mappings

        # Dump registers
        register_data = {}

        for reg in arch_registers[arch]:
            reg_value = gdb_int_value(f"${reg}")
            register_data[reg] = f"0x{reg_value:x}"

        snapshot_info["registers"] = register_data

        # Dump symbols
        symbols = gdb.execute("info functions", from_tty, True)
        symbols = filter(lambda s: len(s) > 0 and s.startswith("0x"), map(str.strip, symbols.split("\n")))
        symbol_map = {}

        for s in symbols:
            chunks = s.split(" ")
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
                symbol_info[name] = f"0x{addresses[0]:x}"
            else:
                for i, e in enumerate(addresses):
                    symbol_info[f"{name}_{i}"] = f"0x{e:x}"

        snapshot_info["symbols"] = symbol_info

        # Write out the json information
        open(info_file_name, "w").write(json.dumps(snapshot_info))


DumpSnapshot()
