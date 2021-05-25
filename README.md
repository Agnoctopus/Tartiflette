Tartiflette
===========

A complete fuzzing environement based on KVM virtualization.

# Architecture

Three crates:
- vm: Library of fuzzing tools in virtualization
- fuzzer: LibAFL fuzzer using vm
- fuzzer_maison: Hand made fuzzer using vm
