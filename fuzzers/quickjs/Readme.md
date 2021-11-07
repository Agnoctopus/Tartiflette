# QuickJS

Fuzzing quickjs using token based fuzzing.

## Note

This whole endeavour is highly experimental and was made for demonstration
purposes.

## How to

For demonstration purposes, a snapshot, an encoded javascript corpus, as well
as the token mappings (`data/tokens.json`) are already provided. The fuzzer can
be executed out of the box as follows:

```sh
$ cargo run --release # Runs the fuzzer on core 1
$ cargo run --release -- -c 1-4 # Runs the fuzzer on cores 1 to 4
$ cargo run --release -- -c all # Runs the fuzzer on all cores
```

## Generating encoded javascript files

The first step is to generate the binary javascript files for the corpus and
the associated token mapping file (`tokens.json`). This can be done using the
`generator.js` in `data/corpus_generator`.

```sh
//fuzzers/quickjs/data/corpus_generator $ node generator.js -j tokens.json
```

The generated files in `data/corpus_generator/corpus_bin` can then be copied
to `data/corpus`. The `tokens.json` file should as well be copied to `/data`.

## Decoding

Decoding encoded files back to javascript can be done by using the `-d`
option of the generator and providing the token mappings:

```sh
$ node generator.js -d <encoded file> -j <token mapping file>
```
