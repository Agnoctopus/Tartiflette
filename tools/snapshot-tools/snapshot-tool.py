import argparse
import cmd
import json
from pathlib import Path


class Mapping:
    """ Memory mapping """

    def __init__(self, start, end, physical_offset, permissions, image=None):
        self.start = start
        self.end = end
        self.physical_offset = physical_offset
        self.permissions = permissions
        self.image = image


class Snapshot:
    def __init__(self, json_path):
        # First check for the snapshot info file
        json_p = Path(json_path)

        if not json_p.exists():
            raise FileNotFoundError(f"Could not find snapshot info file: {json_path}")

        snapshot_info = json.loads(open(json_path, "r").read())

        # Process the different fields
        self.registers = {}

        for k, v in snapshot_info.get("registers", {}).items():
            self.registers[k] = int(v, 16)

        self.symbols = {}

        for k, v in snapshot_info.get("symbols", {}).items():
            self.symbols[k] = int(v, 16)

        self.coverage = map(lambda a: int(a, 16), snapshot_info.get("coverage", []))

        self.mappings = []

        for entry in snapshot_info.get("mappings", []):
            start = int(entry["start"], 16)
            end = int(entry["end"], 16)
            physical_offset = int(entry["physical_offset"], 16)
            perms = entry["permissions"]
            image = entry.get("image")

            self.mappings.append(Mapping(start, end, physical_offset, perms, image))

        sorted(self.mappings, key=lambda m: m.start)

        # Now check for the memory dump
        folder = json_p.parent
        dump_p = folder / Path(snapshot_info["memory_file"])

        if not dump_p.exists():
            raise FileNotFoundError(f"Could not find snapshot memory dump: {dump_p}")

        # Store the resulting paths
        self.info_path = json_p
        self.memory_path = dump_p


class SnapshotCLI(cmd.Cmd):
    prompt = "snapshot> "

    def __init__(self, snapshot):
        super().__init__()
        self.snapshot = snapshot

    def __register_state(self):
        """ Displays the register state """
        print("--- Register state ---")

        for reg, val in self.snapshot.registers.items():
            print(f"{reg:10}: 0x{val:016x}")

    def __memory_mappings(self):
        """ Displays all memory mappings """
        print("--- Memory Mappings ---")

        for i, mapping in enumerate(self.snapshot.mappings):
            print(
                f"[{i:5}] start: 0x{mapping.start:016x} end: 0x{mapping.end:016x} perms: {mapping.permissions} phys: 0x{mapping.physical_offset:016x}",
                end="",
            )

            if mapping.image:
                print(f" {mapping.image}")
            else:
                print("")

    def do_info(self, arg):
        """ Prints all information about the snapshot """
        print(f"Snapshot info   : {self.snapshot.info_path}")
        print(f"Snapshot memory : {self.snapshot.memory_path}")
        print("")

        self.__register_state()
        self.__memory_mappings()

    def do_exit(self, arg):
        """ Closes the shell """
        return True

    def do_quit(self, arg):
        """ Closes the shell """
        return True

    def do_EOF(self, arg):
        return True


def main():
    parser = argparse.ArgumentParser(description="Manipulate Tartiflette snapshots")
    parser.add_argument("snapshot", help="Snapshot json file")

    args = parser.parse_args()

    snapshot = Snapshot(args.snapshot)
    SnapshotCLI(snapshot).cmdloop()


if __name__ == "__main__":
    main()