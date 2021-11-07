Tartiflette
===========

An attempt at snapshot fuzzing using KVM and libAFL.

# Architecture

- **vm**: Unicorn like api over KVM
- **fuzzers/giflib**: Sample harness for fuzzing giflib using tartiflette-vm
- **fuzzers/quickjs**: Attempt at token based fuzzing of js code using tartiflette-vm
- **scripts**: debugger scripts for capturing snapshots

# Authors

- César Belley <cesar.belley@lse.epita.fr>
- Tanguy Dubroca <tanguy.dubroca@lse.epita.fr>
