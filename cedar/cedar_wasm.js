/* @ts-self-types="./cedar_wasm.d.ts" */

/**
 * Check whether a context successfully parses.
 * @param {ContextParsingCall} call
 * @returns {CheckParseAnswer}
 */
export function checkParseContext(call) {
    const ret = wasm.checkParseContext(call);
    return ret;
}

/**
 * Check whether a set of entities successfully parses.
 * @param {EntitiesParsingCall} call
 * @returns {CheckParseAnswer}
 */
export function checkParseEntities(call) {
    const ret = wasm.checkParseEntities(call);
    return ret;
}

/**
 * Check whether a policy set successfully parses.
 * @param {PolicySet} policies
 * @returns {CheckParseAnswer}
 */
export function checkParsePolicySet(policies) {
    const ret = wasm.checkParsePolicySet(policies);
    return ret;
}

/**
 * Check whether a schema successfully parses.
 * @param {Schema} schema
 * @returns {CheckParseAnswer}
 */
export function checkParseSchema(schema) {
    const ret = wasm.checkParseSchema(schema);
    return ret;
}

/**
 * Apply the Cedar policy formatter to a policy set in the Cedar policy format
 * @param {FormattingCall} call
 * @returns {FormattingAnswer}
 */
export function formatPolicies(call) {
    const ret = wasm.formatPolicies(call);
    return ret;
}

/**
 * Get language version of Cedar
 * @returns {string}
 */
export function getCedarLangVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getCedarLangVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @returns {string}
 */
export function getCedarSDKVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getCedarSDKVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @returns {string}
 */
export function getCedarVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getCedarVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Get valid request environment
 * @param {Policy} t
 * @param {Schema} s
 * @returns {GetValidRequestEnvsResult}
 */
export function getValidRequestEnvsPolicy(t, s) {
    const ret = wasm.getValidRequestEnvsPolicy(t, s);
    return ret;
}

/**
 * Get valid request environment
 * @param {Template} t
 * @param {Schema} s
 * @returns {GetValidRequestEnvsResult}
 */
export function getValidRequestEnvsTemplate(t, s) {
    const ret = wasm.getValidRequestEnvsTemplate(t, s);
    return ret;
}

/**
 * Basic interface, using [`AuthorizationCall`] and [`AuthorizationAnswer`] types
 * @param {AuthorizationCall} call
 * @returns {AuthorizationAnswer}
 */
export function isAuthorized(call) {
    const ret = wasm.isAuthorized(call);
    return ret;
}

/**
 * Basic interface for partial evaluation, using [`AuthorizationCall`] and
 * [`PartialAuthorizationAnswer`] types
 * @param {PartialAuthorizationCall} call
 * @returns {PartialAuthorizationAnswer}
 */
export function isAuthorizedPartial(call) {
    const ret = wasm.isAuthorizedPartial(call);
    return ret;
}

/**
 * Takes a `PolicySet` represented as string and return the policies
 * and templates split into vecs and sorted by id.
 * @param {string} policyset_str
 * @returns {PolicySetTextToPartsAnswer}
 */
export function policySetTextToParts(policyset_str) {
    const ptr0 = passStringToWasm0(policyset_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.policySetTextToParts(ptr0, len0);
    return ret;
}

/**
 * Return the JSON representation of a policy.
 * @param {Policy} policy
 * @returns {PolicyToJsonAnswer}
 */
export function policyToJson(policy) {
    const ret = wasm.policyToJson(policy);
    return ret;
}

/**
 * Return the Cedar (textual) representation of a policy.
 * @param {Policy} policy
 * @returns {PolicyToTextAnswer}
 */
export function policyToText(policy) {
    const ret = wasm.policyToText(policy);
    return ret;
}

/**
 * Preparse and cache a policy set in thread-local storage
 *
 * # Errors
 *
 * Will return `Err` if the input cannot be parsed. Side-effect free on error.
 * @param {string} pset_id
 * @param {PolicySet} policies
 * @returns {CheckParseAnswer}
 */
export function preparsePolicySet(pset_id, policies) {
    const ptr0 = passStringToWasm0(pset_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.preparsePolicySet(ptr0, len0, policies);
    return ret;
}

/**
 * Preparse and cache a schema in thread-local storage
 *
 * # Errors
 *
 * Will return `Err` if the input cannot be parsed. Side-effect free on error.
 * @param {string} schema_name
 * @param {Schema} schema
 * @returns {CheckParseAnswer}
 */
export function preparseSchema(schema_name, schema) {
    const ptr0 = passStringToWasm0(schema_name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.preparseSchema(ptr0, len0, schema);
    return ret;
}

/**
 * Return the JSON representation of a schema.
 * @param {Schema} schema
 * @returns {SchemaToJsonAnswer}
 */
export function schemaToJson(schema) {
    const ret = wasm.schemaToJson(schema);
    return ret;
}

/**
 * Convert a Cedar schema string to JSON format with resolved types.
 *
 * This function resolves ambiguous "`EntityOrCommon`" types to their specific
 * Entity or `CommonType` classifications using the schema's type definitions.
 * This is primarily meant to be used when working with schemas programmatically,
 * for example when creating a schema building UI.
 * @param {string} schema_str
 * @returns {SchemaToJsonWithResolvedTypesAnswer}
 */
export function schemaToJsonWithResolvedTypes(schema_str) {
    const ptr0 = passStringToWasm0(schema_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.schemaToJsonWithResolvedTypes(ptr0, len0);
    return ret;
}

/**
 * Return the Cedar (textual) representation of a schema.
 * @param {Schema} schema
 * @returns {SchemaToTextAnswer}
 */
export function schemaToText(schema) {
    const ret = wasm.schemaToText(schema);
    return ret;
}

/**
 * Stateful authorization using preparsed schemas and policy sets.
 *
 * This function works like [`is_authorized`] but retrieves schemas and policy sets
 * from thread-local cache instead of parsing them on each call.
 * @param {StatefulAuthorizationCall} call
 * @returns {AuthorizationAnswer}
 */
export function statefulIsAuthorized(call) {
    const ret = wasm.statefulIsAuthorized(call);
    return ret;
}

/**
 * Return the JSON representation of a template.
 * @param {Template} template
 * @returns {PolicyToJsonAnswer}
 */
export function templateToJson(template) {
    const ret = wasm.templateToJson(template);
    return ret;
}

/**
 * Return the Cedar (textual) representation of a template.
 * @param {Template} template
 * @returns {PolicyToTextAnswer}
 */
export function templateToText(template) {
    const ret = wasm.templateToText(template);
    return ret;
}

/**
 * Parse a policy set and optionally validate it against a provided schema
 *
 * This is the basic validator interface, using [`ValidationCall`] and
 * [`ValidationAnswer`] types
 * @param {ValidationCall} call
 * @returns {ValidationAnswer}
 */
export function validate(call) {
    const ret = wasm.validate(call);
    return ret;
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_undefined_c0cca72b82b86f4d: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_string_get_914df97fcfa788f2: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_81fc77679af83bc6: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_parse_545d11396395fbbd: function() { return handleError(function (arg0, arg1) {
            const ret = JSON.parse(getStringFromWasm0(arg0, arg1));
            return ret;
        }, arguments); },
        __wbg_stringify_a2c39d991e1bf91d: function() { return handleError(function (arg0) {
            const ret = JSON.stringify(arg0);
            return ret;
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./cedar_wasm_bg.js": import0,
    };
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('cedar_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
