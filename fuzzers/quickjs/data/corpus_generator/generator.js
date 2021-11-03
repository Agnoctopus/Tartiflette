const obfuscator = require('javascript-obfuscator');
const esprima = require('esprima');
const fs = require("fs");
const program = require("commander");

// Returns obfuscated code and a list of tokens
function normalizeCode(code) {
    var var_names = [];

    for (let i = 0; i < 10; i++) {
        var_names.push("var" + i);
    }

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

    const obf_code = obf_result.getObfuscatedCode();

    var result = {
        code: obf_code,
        tokens: esprima.tokenize(obf_code)
    };

    return result;
}

function main(options) {
    // First process all the files
    var token_cache = new Set();
    var files = fs.readdirSync("./corpus_js/").map(file => {
        console.log(`Analyzing file ${file}`);

        var contents = fs.readFileSync(`./corpus_js/${file}`, { encoding: "UTF-8" });
        var result = normalizeCode(contents);

        // Add tokens to the cache
        result.tokens.forEach(tok => token_cache.add(tok.value));
        var file_obj = {
            name: file,
            code: result.code,
            tokens: result.tokens
        };

        return file_obj;
    });

    var token_list = Array.from(token_cache);
    console.log(`Collected ${token_list.length} different tokens`);

    // Now output the encoded files + the obfuscated source for debugging
    files.forEach(file => {
        if (token_list.length > 0xffff) {
            throw `Too many tokens to fit in 16bits (${token_list.length})`
        }

        console.log(`Compiling ${file.name} ...`);
        var encoded_contents = new Uint16Array(file.tokens.length);

        for (var i = 0; i < file.tokens.length; i++) {
            encoded_contents[i] = token_list.indexOf(file.tokens[i].value);
        }

        fs.writeFileSync(`./corpus_bin/${file.name}`, encoded_contents);
        fs.writeFileSync(`./corpus_obf/${file.name}`, file.code);
    });

    // If set, output the token list as a json file to be consumed by other tools
    if (options.json) {
        console.log(`Writing token list to ${options.json}`);
        const obj = { tokens: token_list };
        fs.writeFileSync(options.json, JSON.stringify(obj));
    }
}

program
    .description("Quickjs encoded corpus generator")
    .option("-j, --json <path>", "Output token list a json file")

program.parse();
var options = program.opts();

main(options);
