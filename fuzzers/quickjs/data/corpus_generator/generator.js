const obfuscator = require('javascript-obfuscator');
const esprima = require('esprima');
const fs = require("fs");
const program = require("commander");

// Returns obfuscated code and a list of tokens
function normalizeCode(code) {
    // Compute predefined names of variables
    var var_names = [];
    for (let i = 0; i < 10; i++) {
        var_names.push("var" + i);
    }

    // Create obfuscator
    var obf_result = obfuscator.obfuscate(code,
        {
            compact: false,
            controlFlowFlattening: false,
            controlFlowFlatteningThreshold: 0.75,
            deadCodeInjection: false,
            deadCodeInjectionThreshold: 0.4,
            debugProtection: false,
            debugProtectionInterval: false,
            disableConsoleOutput: false,
            domainLock: [],
            domainLockRedirectUrl: 'about:blank',
            forceTransformStrings: [],
            identifierNamesCache: null,
            identifierNamesGenerator: 'dictionary',
            identifiersDictionary: var_names,
            identifiersPrefix: '',
            ignoreRequireImports: false,
            inputFileName: '',
            log: false,
            numbersToExpressions: false,
            renameGlobals: false,
            renameProperties: false,
            renamePropertiesMode: 'safe',
            reservedNames: [],
            reservedStrings: [],
            seed: 42,
            selfDefending: false,
            simplify: false,
            sourceMap: false,
            sourceMapBaseUrl: '',
            sourceMapFileName: '',
            sourceMapMode: 'separate',
            sourceMapSourcesMode: 'sources-content',
            splitStrings: false,
            splitStringsChunkLength: 10,
            stringArray: false,
            stringArrayIndexesType: [
                'hexadecimal-number'
            ],
            stringArrayEncoding: [],
            stringArrayIndexShift: false,
            stringArrayRotate: false,
            stringArrayShuffle: false,
            stringArrayWrappersCount: 1,
            stringArrayWrappersChainedCalls: false,
            stringArrayWrappersParametersMaxCount: 2,
            stringArrayWrappersType: 'variable',
            stringArrayThreshold: 0.75,
            target: 'browser',
            transformObjectKeys: false,
            unicodeEscapeSequence: false
        }
    );

    // Build the normalized code result
    const obf_code = obf_result.getObfuscatedCode();
    var result = {
        code: obf_code,
        tokens: esprima.tokenize(obf_code)
    };

    return result;
}

function main_decode(options) {
    if (!options.json) {
        throw "Token cache file was not specified with '-j'";
    }

    // Get token cache and binary file contents to decode
    var token_cache = JSON.parse(fs.readFileSync(options.json));
    var binfile = fs.readFileSync(options.decode);

    // Decode the file list of tokens index
    var tokens_index = new Uint16Array(binfile.length / 2);
    for (var i = 0; i < binfile.length; i += 2) {
        tokens_index[i / 2] = (binfile[i + 1] << 8) | binfile[i];
    }

    // Decode the file code
    var code = "";
    tokens_index.forEach((token_index) => {
        code += token_cache.tokens[token_index % token_cache.tokens.length];
    });

    console.log(code);
}

function main_encode(options) {
    // First process all the files
    var token_cache = new Set();
    var files = fs.readdirSync("./corpus_js/").map(file => {
        console.log(`Analyzing file ${file}`);

        // Get the normalized file contents
        var contents = fs.readFileSync(`./corpus_js/${file}`, { encoding: "UTF-8" });
        var result = normalizeCode(contents);

        // Add tokens to the cache
        result.tokens.forEach(tok => token_cache.add(tok.value));

        // Map normalized file contents to a file object
        var file_obj = {
            name: file,
            code: result.code,
            tokens: result.tokens
        };
        return file_obj;
    });

    // Get token list
    var token_list = Array.from(token_cache);
    console.log(`Collected ${token_list.length} different tokens`);
    if (token_list.length > 0xffff) {
        throw `Too many tokens to fit in 16bits (${token_list.length})`
    }

    // Ensure the existence of output directories
    const corpus_bin_dir = './corpus_bin';
    const corpus_obf_dir = './corpus_obf';
    if (!fs.existsSync(corpus_bin_dir)) {
        fs.mkdirSync(corpus_bin_dir, { recursive: true });
    }
    if (!fs.existsSync(corpus_obf_dir)) {
        fs.mkdirSync(corpus_obf_dir, { recursive: true });
    }

    // Output the encoded files and the obfuscated source for debugging
    files.forEach(file => {
        console.log(`Compiling ${file.name} ...`);

        // Encode file contents
        var encoded_contents = new Uint16Array(file.tokens.length);
        for (var i = 0; i < file.tokens.length; i++) {
            encoded_contents[i] = token_list.indexOf(file.tokens[i].value);
        }

        // Write encoded contents and obfuscated source
        fs.writeFileSync(`${corpus_bin_dir}/${file.name}`, encoded_contents);
        fs.writeFileSync(`${corpus_obf_dir}/${file.name}`, file.code);
    });

    // Postprocess some specific tokens
    const spaced_tokens = new Set([
        "new", "var", "let", "const", "function"
    ]);
    token_list = token_list.map((x) => {
        return spaced_tokens.has(x) ? x + " " : x;
    });

    // If set, output the token list as a json file to be consumed by other tools
    if (options.json) {
        console.log(`Writing token list to ${options.json}`);
        const obj = { tokens: token_list };
        fs.writeFileSync(options.json, JSON.stringify(obj));
    }
}

function main(options) {
    if (options.decode) {
        main_decode(options)
    } else {
        main_encode(options);
    }
}

program
    .description("Quickjs encoded corpus generator")
    .option("-j, --json <path>", "Output token list a json file")
    .option("-d, --decode <path>", "Binary file to decode");

program.parse();
var options = program.opts();

main(options);
