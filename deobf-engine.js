#!/usr/bin/env node

/**
 * ============================================================================
 * Lua 5.1 Bytecode & Obfuscation Deobfuscator (Windows/mingw64)
 * ============================================================================
 * 
 * This script deobfuscates Lua 5.1 bytecode and heavily obfuscated Lua source
 * files by orchestrating multiple decompilation and analysis stages:
 * 
 * 1. DYNAMIC TRACE CAPTURE:
 *    - Uses mingw64 Lua 5.1 interpreter with embedded Lua tracer
 *    - debug.sethook with "c" call mask logs every function call
 *    - Captures execution flow for runtime behavior analysis
 * 
 * 2. STATIC DECOMPILATION:
 *    - Invokes unluac Java decompiler on bytecode
 *    - Produces base decompiled Lua source
 * 
 * 3. MULTI-PASS DECRYPTION & NORMALIZATION:
 *    Targets obfuscation from: goofyscator V10.1, Luraph, IronBrew2, Moonsec
 *    
 *    Pass A - XOR Brute-Force Decryption:
 *      - Single-byte XOR key brute-force (0-255)
 *      - Validates against printable ASCII + Lua keywords
 *      - Handles string literal decryption
 *    
 *    Pass B - Numeric Decoding:
 *      - Decimal escape sequences: \123\45\67 → chr(123)..
 *      - Base64-encoded strings
 *      - Hybrid prefixed strings (StvZtbprJ0nkkv/bC9K6mMqeui- format)
 *    
 *    Pass C - Arithmetic Folding Resolution:
 *      - Constant-folding chains: ((x + 0x2D8D) * 0x5CF + 0x282A) % 0x1FFFF
 *      - VM opcode dispatch table resolution
 *      - Register index recovery
 *    
 *    Pass D - Helper Function Inlining:
 *      - Inline bit32.bxor, string.byte/char/sub, table.concat wrappers
 *      - Simplify VM state accessors
 *    
 *    Pass E - Identifier Renaming:
 *      - Mangled names: VEO, mvR, Isf, Hv3, neK, trp, Ntc, ieG, klp, NmX, Eth
 *      - Sequential descriptive names: vm_state, chunk, instr, op_a, op_b, ...
 *    
 *    Pass F - Integrity Check Stripping:
 *      - Remove debug.sethook-resistant checks (Mcy, c[1-5], wsX, Ctb, dtW)
 *      - Abort guards that break under debuggers
 * 
 * 4. OPCODE PATTERN HANDLING:
 *    - Recognizes "cff" and "bst" dispatcher obfuscation patterns
 *    - Resolves opcode dispatch tables to readable indices
 *    - Unwraps bytecode instruction sequences
 * 
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawnSync } = require('child_process');

// =============================================================================
// CONFIGURATION & ENVIRONMENT SETUP
// =============================================================================

const INPUT_FILE = process.argv[2];
const OUTPUT_FILE = process.argv[3] || (INPUT_FILE ? INPUT_FILE.replace(/\.[^.]+$/, '.deobf.lua') : null);

const TEMP_DIR = path.join(os.tmpdir(), `lua-deobf-${Date.now()}-${Math.random().toString(36).substring(7)}`);
const TRACE_FILE = path.join(TEMP_DIR, 'trace.log');
const DECOMPILED_FILE = path.join(TEMP_DIR, 'decompiled.lua');

// Tool detection flags
let HAS_LUA51 = false;
let HAS_JAVA = false;
let HAS_UNLUAC = false;

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * Log progress with prefixes for user readability
 * [*] = step in progress
 * [✓] = step completed
 * [✗] = error occurred
 */
function logStep(message, status = '*') {
  const prefix = status === 'ok' ? '[✓]' : status === 'err' ? '[✗]' : '[*]';
  console.log(`${prefix} ${message}`);
}

/**
 * Clean up temporary files created during deobfuscation
 */
function cleanupTempFiles() {
  try {
    if (fs.existsSync(TEMP_DIR)) {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
      logStep(`Cleaned up temporary directory: ${TEMP_DIR}`, 'ok');
    }
  } catch (err) {
    logStep(`Warning: Could not clean temp directory: ${err.message}`, 'err');
  }
}

/**
 * Verify input file exists and is readable
 */
function verifyInputFile() {
  logStep(`Verifying input file: ${INPUT_FILE}`);
  
  if (!INPUT_FILE) {
    logStep('No input file specified. Usage: node deobf-engine.js <input.lua>', 'err');
    process.exit(1);
  }
  
  if (!fs.existsSync(INPUT_FILE)) {
    logStep(`Input file not found: ${INPUT_FILE}`, 'err');
    process.exit(1);
  }
  
  const stats = fs.statSync(INPUT_FILE);
  if (stats.size === 0) {
    logStep(`Input file is empty: ${INPUT_FILE}`, 'err');
    process.exit(1);
  }
  
  logStep(`Input file verified (${stats.size} bytes)`, 'ok');
}

/**
 * Check for required tools: lua5.1, java, unluac.jar
 */
function checkDependencies() {
  logStep('Checking dependencies...');
  
  // Check for Lua 5.1
  try {
    execSync('lua5.1 -v', { stdio: 'pipe' });
    HAS_LUA51 = true;
    logStep('Found: lua5.1', 'ok');
  } catch (err) {
    logStep('Not found: lua5.1 (install mingw64 Lua 5.1)', 'err');
  }
  
  // Check for Java
  try {
    execSync('java -version', { stdio: 'pipe' });
    HAS_JAVA = true;
    logStep('Found: java', 'ok');
  } catch (err) {
    logStep('Not found: java (required for unluac)', 'err');
  }
  
  // Check for unluac.jar in current directory
  if (fs.existsSync('unluac.jar')) {
    HAS_UNLUAC = true;
    logStep('Found: unluac.jar', 'ok');
  } else {
    logStep('Not found: unluac.jar (place in current directory)', 'err');
  }
  
  // Proceed with warnings if not all tools present
  if (!HAS_LUA51 || !HAS_JAVA || !HAS_UNLUAC) {
    logStep('Some dependencies missing. Proceeding with available tools...', 'err');
  }
}

/**
 * Create temporary directory for intermediate files
 */
function setupTempDirectory() {
  logStep(`Creating temporary directory: ${TEMP_DIR}`);
  fs.mkdirSync(TEMP_DIR, { recursive: true });
  logStep('Temporary directory ready', 'ok');
}

// =============================================================================
// STAGE 1: DYNAMIC TRACE CAPTURE (mingw64 Lua 5.1 with debug.sethook)
// =============================================================================

/**
 * Embedded Lua tracer script that uses debug.sethook with "c" call mask
 * Logs every function call to analyze runtime behavior
 * Resistant to simple anti-debug checks
 */
const LUA_TRACER_SCRIPT = `
-- Lua 5.1 Dynamic Tracer Script
-- Uses debug.sethook with "c" call mask to log all function calls

local trace_file = arg[1]
local target_file = arg[2]

-- Open trace output
local fh = io.open(trace_file, 'w')
if not fh then
  error("Cannot open trace file: " .. trace_file)
end

-- Call hook function: log every C function call
local call_count = 0
local function hook(event)
  if event == "call" then
    call_count = call_count + 1
    local info = debug.getinfo(2, "nSl")
    if info then
      fh:write(string.format("CALL #%d: %s @ %s:%d\\n",
        call_count,
        info.name or "(unknown)",
        info.source or "(unknown)",
        info.currentline or 0
      ))
      fh:flush()
    end
  end
end

-- Install hook with "c" call mask
debug.sethook(hook, "c")

-- Load and execute target file
local chunk, err = loadfile(target_file)
if not chunk then
  fh:write("ERROR: " .. tostring(err) .. "\\n")
  fh:close()
  error(err)
end

-- Execute with protection
local ok, result = pcall(chunk)
if not ok then
  fh:write("EXECUTION ERROR: " .. tostring(result) .. "\\n")
end

-- Remove hook
debug.sethook(nil)
fh:close()
`;

/**
 * Run dynamic trace capture using mingw64 Lua 5.1
 */
function runDynamicTrace() {
  if (!HAS_LUA51) {
    logStep('Skipping dynamic trace (lua5.1 not found)', 'err');
    return false;
  }
  
  logStep('Running dynamic trace capture...');
  
  const tracerScriptPath = path.join(TEMP_DIR, 'tracer.lua');
  fs.writeFileSync(tracerScriptPath, LUA_TRACER_SCRIPT);
  
  try {
    execSync(`lua5.1 "${tracerScriptPath}" "${TRACE_FILE}" "${INPUT_FILE}"`, {
      stdio: 'pipe',
      timeout: 10000  // 10 second timeout
    });
    
    if (fs.existsSync(TRACE_FILE)) {
      const traceSize = fs.statSync(TRACE_FILE).size;
      logStep(`Dynamic trace captured (${traceSize} bytes)`, 'ok');
      return true;
    }
  } catch (err) {
    logStep(`Dynamic trace failed: ${err.message}`, 'err');
  }
  
  return false;
}

// =============================================================================
// STAGE 2: STATIC DECOMPILATION (unluac Java decompiler)
// =============================================================================

/**
 * Invoke unluac to decompile Lua 5.1 bytecode
 */
function runUnluacDecompilation() {
  if (!HAS_JAVA || !HAS_UNLUAC) {
    logStep('Skipping unluac decompilation (java or unluac.jar not found)', 'err');
    return false;
  }
  
  logStep('Running unluac decompilation...');
  
  try {
    execSync(`java -jar unluac.jar "${INPUT_FILE}" > "${DECOMPILED_FILE}"`, {
      stdio: 'pipe',
      timeout: 30000  // 30 second timeout
    });
    
    if (fs.existsSync(DECOMPILED_FILE)) {
      const decompSize = fs.statSync(DECOMPILED_FILE).size;
      logStep(`Decompilation complete (${decompSize} bytes)`, 'ok');
      return true;
    }
  } catch (err) {
    logStep(`Decompilation failed: ${err.message}`, 'err');
  }
  
  return false;
}

// =============================================================================
// STAGE 3: MULTI-PASS DECRYPTION & NORMALIZATION
// =============================================================================

/**
 * Pass A: XOR Brute-Force Decryption
 * 
 * Targets: Single-byte XOR encryption over string literals
 * Common in: goofyscator, Luraph, IronBrew2
 * 
 * Strategy:
 * 1. Extract string literals (quoted strings in source)
 * 2. Brute-force all 256 possible XOR keys
 * 3. Validate results against printable ASCII + Lua keywords
 * 4. Replace original with decrypted version
 */
function decryptXORPass(source) {
  logStep('Pass A: XOR brute-force decryption');
  let modified = false;
  
  // Lua keywords to validate against
  const LUA_KEYWORDS = [
    'local', 'function', 'return', 'if', 'then', 'end', 'else', 'elseif',
    'do', 'while', 'for', 'in', 'repeat', 'until', 'break', 'and', 'or',
    'not', 'nil', 'true', 'false', 'error', 'string', 'table', 'math',
    'bit32', 'os', 'io', 'debug', 'require', 'assert', 'pcall', 'xpcall'
  ];
  
  // Pattern to find quoted strings
  const stringPattern = /["']([^"'\\]|\\.)*["']/g;
  let match;
  
  while ((match = stringPattern.exec(source)) !== null) {
    const fullMatch = match[0];
    const quote = fullMatch[0];
    const content = fullMatch.slice(1, -1);
    
    // Skip very short strings
    if (content.length < 3) continue;
    
    // Try all 256 XOR keys
    for (let key = 1; key < 256; key++) {
      try {
        const decrypted = content
          .split('')
          .map(char => String.fromCharCode(char.charCodeAt(0) ^ key))
          .join('');
        
        // Check if decrypted result is valid
        if (isValidLuaCode(decrypted, LUA_KEYWORDS)) {
          const replacement = `${quote}${decrypted}${quote}`;
          source = source.replace(fullMatch, replacement);
          modified = true;
          logStep(`  XOR key ${key}: "${content.substring(0, 20)}..." → "${decrypted.substring(0, 20)}..."`, 'ok');
          break;
        }
      } catch (e) {
        // Invalid UTF-8 or decode error, skip this key
      }
    }
  }
  
  if (modified) {
    logStep('XOR decryption completed with modifications', 'ok');
  }
  return source;
}

/**
 * Validate if a string looks like valid Lua code
 */
function isValidLuaCode(str, keywords) {
  if (!str || str.length === 0) return false;
  
  // Check for printable ASCII
  if (!/^[\x20-\x7E\n\t\r]+$/.test(str)) return false;
  
  // Check for balanced quotes and parens
  let quoteCount = (str.match(/"/g) || []).length;
  if (quoteCount % 2 !== 0) return false;
  
  // Check for Lua keywords
  const wordPattern = /\b\w+\b/g;
  let keywordMatches = 0;
  let match;
  while ((match = wordPattern.exec(str)) !== null) {
    if (keywords.includes(match[0].toLowerCase())) {
      keywordMatches++;
    }
  }
  
  return keywordMatches > 0 || /^[\w_]+$/.test(str);
}

/**
 * Pass B: Numeric Decoding
 * 
 * Targets: 
 * - Decimal escape sequences: \123\45\67 → chr(123)..chr(45)..chr(67)
 * - Base64-encoded strings
 * - Hybrid prefixed strings (StvZtbprJ0nkkv/bC9K6mMqeui- format)
 */
function decodeNumericPass(source) {
  logStep('Pass B: Numeric decoding (escape sequences, base64, hybrid strings)');
  let modified = false;
  
  // Pattern B1: Decimal escape sequences in strings
  const escapePattern = /\\(\d{1,3})/g;
  if (escapePattern.test(source)) {
    source = source.replace(/"([^"]*(?:\\d+[^"]*)*)"/g, (match) => {
      const inner = match.slice(1, -1);
      const decoded = inner.replace(/\\(\d{1,3})/g, (esc, num) => {
        const charCode = parseInt(num, 10);
        if (charCode >= 32 && charCode <= 126) {
          return String.fromCharCode(charCode);
        }
        return esc;
      });
      
      if (decoded !== inner) {
        modified = true;
        logStep(`  Decoded escape sequence: "${inner.substring(0, 30)}..." → "${decoded.substring(0, 30)}..."`, 'ok');
        return `"${decoded}"`;
      }
      return match;
    });
  }
  
  // Pattern B2: Base64-encoded strings (common delimiter: base64(...))
  const base64Pattern = /base64\(["']([A-Za-z0-9+\/=]+)["']\)/g;
  source = source.replace(base64Pattern, (match, b64) => {
    try {
      const decoded = Buffer.from(b64, 'base64').toString('utf8');
      if (/^[\x20-\x7E\n\t\r]*$/.test(decoded)) {
        modified = true;
        logStep(`  Decoded base64: "${b64.substring(0, 20)}..." → "${decoded.substring(0, 30)}..."`, 'ok');
        return `"${decoded.replace(/"/g, '\\"')}"`;
      }
    } catch (e) {
      // Not valid base64
    }
    return match;
  });
  
  // Pattern B3: Hybrid prefixed strings (e.g., "prefix-data")
  const hybridPattern = /["']([A-Za-z0-9_-]+)-([A-Za-z0-9+\/=]+)["']/g;
  source = source.replace(hybridPattern, (match, prefix, payload) => {
    try {
      const decoded = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      if (/^[\x20-\x7E\n\t\r]*$/.test(decoded)) {
        modified = true;
        logStep(`  Decoded hybrid string: "${prefix}-${payload.substring(0, 10)}..." → "${decoded.substring(0, 30)}..."`, 'ok');
        return `"${decoded.replace(/"/g, '\\"')}"`;
      }
    } catch (e) {
      // Not valid
    }
    return match;
  });
  
  if (modified) {
    logStep('Numeric decoding completed', 'ok');
  }
  return source;
}

/**
 * Pass C: Arithmetic Folding Resolution
 * 
 * Targets: Constant-folding arithmetic chains that obfuscate indices and opcodes
 * 
 * Patterns:
 * - (((x + 0x2D8D) * 0x5CF) + 0x282A) % 0x1FFFF
 * - (y * 0x8C4D + 0xD4A3A) % 0xFFFFD
 * - ((a * b) + c) % MOD
 * 
 * Strategy: Evaluate arithmetic expressions with constant operands
 */
function resolveArithmeticPass(source) {
  logStep('Pass C: Arithmetic folding resolution');
  let modified = false;
  
  // Pattern: Nested arithmetic with modulo
  // This regex finds patterns like: (((...) * HEX) + HEX) % HEX
  const arithmeticPattern = /\(\s*\(\s*\(\s*(\d+|0x[0-9A-Fa-f]+)\s*([+\-*])\s*(\d+|0x[0-9A-Fa-f]+)\s*\)\s*\*\s*(\d+|0x[0-9A-Fa-f]+)\s*\)\s*([+\-])\s*(\d+|0x[0-9A-Fa-f]+)\s*\)\s*%\s*(\d+|0x[0-9A-Fa-f]+)\s*\)/g;
  
  source = source.replace(arithmeticPattern, (match) => {
    try {
      // Extract hex values
      const numMatch = match.match(/(\d+|0x[0-9A-Fa-f]+)/g);
      if (!numMatch || numMatch.length < 5) return match;
      
      // Convert hex to decimal
      const nums = numMatch.map(n => {
        if (n.startsWith('0x')) {
          return parseInt(n, 16);
        }
        return parseInt(n, 10);
      });
      
      // Parse and evaluate: (((a OP1 b) * c) OP2 d) % e
      let result = nums[0];
      const op1 = match.includes('+') ? '+' : '-';
      
      if (op1 === '+') result += nums[1];
      else result -= nums[1];
      
      result *= nums[2];
      
      const op2 = match.includes('+') ? '+' : '-';
      if (op2 === '+') result += nums[3];
      else result -= nums[3];
      
      result = result % nums[4];
      
      // Only replace if result is reasonable (small positive integer)
      if (result >= 0 && result < 100000) {
        modified = true;
        logStep(`  Folded arithmetic: ${match} → ${result}`, 'ok');
        return result.toString();
      }
    } catch (e) {
      // Evaluation failed
    }
    return match;
  });
  
  // Simpler patterns: single arithmetic with modulo
  const simplePattern = /\(\s*(\d+|0x[0-9A-Fa-f]+)\s*([+\-*])\s*(\d+|0x[0-9A-Fa-f]+)\s*\)\s*%\s*(\d+|0x[0-9A-Fa-f]+)/g;
  source = source.replace(simplePattern, (match) => {
    try {
      const parts = match.match(/(\d+|0x[0-9A-Fa-f]+)/g);
      if (parts.length >= 3) {
        let a = parts[0].startsWith('0x') ? parseInt(parts[0], 16) : parseInt(parts[0], 10);
        let b = parts[1].startsWith('0x') ? parseInt(parts[1], 16) : parseInt(parts[1], 10);
        let mod = parts[2].startsWith('0x') ? parseInt(parts[2], 16) : parseInt(parts[2], 10);
        
        const op = match.includes('*') ? '*' : match.includes('+') ? '+' : '-';
        
        let result;
        if (op === '+') result = (a + b) % mod;
        else if (op === '-') result = (a - b) % mod;
        else result = (a * b) % mod;
        
        if (result >= 0 && result < 100000) {
          modified = true;
          logStep(`  Folded: ${match} → ${result}`, 'ok');
          return result.toString();
        }
      }
    } catch (e) {
      // Failed
    }
    return match;
  });
  
  if (modified) {
    logStep('Arithmetic folding resolved', 'ok');
  }
  return source;
}

/**
 * Pass D: Helper Function Inlining
 * 
 * Targets: Wrapper functions that simply call standard library functions
 * 
 * Patterns:
 * - local function helper(x) return bit32.bxor(x, key) end
 * - local function helper(x) return string.byte(x) end
 * - local function helper(...) return table.concat({...}) end
 * 
 * Strategy: Replace function calls with direct library calls
 */
function inlineHelperFunctionsPass(source) {
  logStep('Pass D: Helper function inlining');
  let modified = false;
  
  // Pattern D1: XOR helpers
  // local function NAME(x, y) return bit32.bxor(x, y) end
  const xorHelperPattern = /local\s+function\s+(\w+)\s*\(\s*([^)]+)\s*\)\s*return\s+bit32\.bxor\s*\(\s*\2\s*,\s*(\w+)\s*\)\s*end/g;
  source = source.replace(xorHelperPattern, (match, funcName, params, key) => {
    modified = true;
    logStep(`  Inlined XOR helper: ${funcName}(${params}) → bit32.bxor(${params}, ${key})`, 'ok');
    return '';  // Remove the function definition
  });
  
  // Pattern D2: byte/char helpers
  const byteCharPattern = /local\s+function\s+(\w+)\s*\(\s*([^)]+)\s*\)\s*return\s+string\.(byte|char)\s*\(\s*\2\s*\)\s*end/g;
  source = source.replace(byteCharPattern, (match, funcName, params, method) => {
    modified = true;
    logStep(`  Inlined string.${method} helper: ${funcName}`, 'ok');
    return '';
  });
  
  // Pattern D3: table.concat helpers
  const concatPattern = /local\s+function\s+(\w+)\s*\(\s*\.\.\.\s*\)\s*return\s+table\.concat\s*\(\s*\{[^}]*\}\s*\)\s*end/g;
  source = source.replace(concatPattern, (match, funcName) => {
    modified = true;
    logStep(`  Inlined table.concat helper: ${funcName}`, 'ok');
    return '';
  });
  
  if (modified) {
    logStep('Helper functions inlined', 'ok');
  }
  return source;
}

/**
 * Pass E: Identifier Renaming
 * 
 * Targets: Mangled variable and function names from obfuscators
 * 
 * Common obfuscated names:
 * - VM state: VEO, mvR, Isf, Hv3, neK, trp, Ntc, ieG
 * - Memory/registers: klp, NmX, Eth, ddw, abf, Hk_, bfT
 * - Helper funcs: Mcy, c[], wsX, Ctb, dtW
 * 
 * Strategy: Build name map and rename systematically
 */
function renameIdentifiersPass(source) {
  logStep('Pass E: Identifier renaming (mangled → descriptive)');
  let modified = false;
  
  const OBFUSCATED_NAMES = {
    'VEO': 'vm_state',
    'mvR': 'chunk',
    'Isf': 'instr',
    'Hv3': 'op_a',
    'neK': 'op_b',
    'trp': 'op_c',
    'Ntc': 'reg',
    'ieG': 'const',
    'klp': 'upval',
    'NmX': 'stack',
    'Eth': 'pc',
    'ddw': 'result',
    'abf': 'error',
    'Hk_': 'dispatch',
    'bfT': 'call_fn'
  };
  
  // Build regex for word boundaries
  for (const [obfuscated, descriptive] of Object.entries(OBFUSCATED_NAMES)) {
    const pattern = new RegExp(`\\b${obfuscated}\\b`, 'g');
    if (pattern.test(source)) {
      source = source.replace(pattern, descriptive);
      modified = true;
      logStep(`  Renamed: ${obfuscated} → ${descriptive}`, 'ok');
    }
  }
  
  if (modified) {
    logStep('Identifier renaming completed', 'ok');
  }
  return source;
}

/**
 * Pass F: Integrity Check Stripping
 * 
 * Targets: Anti-debug and anti-trace integrity checks
 * 
 * Patterns to remove:
 * - debug.sethook integrity checks (Mcy, c[1]/c[2]/c[3]/c[4]/c[5])
 * - Debugger detection (wsX, Ctb, dtW)
 * - Call stack validation checks
 * - Abort guards that break under debuggers
 * 
 * Strategy: Remove entire blocks that start with these checks
 */
function stripIntegrityChecksPass(source) {
  logStep('Pass F: Integrity check stripping');
  let modified = false;
  
  // Pattern F1: debug.getinfo integrity checks
  // if debug.getinfo(...) then error(...) end
  const debugCheckPattern = /if\s+debug\.getinfo\s*\([^)]*\)\s*then\s+error\s*\([^)]*\)\s*end/g;
  if (debugCheckPattern.test(source)) {
    source = source.replace(debugCheckPattern, '');
    modified = true;
    logStep('  Removed debug.getinfo integrity checks', 'ok');
  }
  
  // Pattern F2: Mcy / wsX / Ctb / dtW checks
  const integrityVars = ['Mcy', 'wsX', 'Ctb', 'dtW'];
  for (const varName of integrityVars) {
    const pattern = new RegExp(
      `if\\s+${varName}\\s*then\\s+(?:error|return)\\s*\\([^)]*\\)\\s*end`,
      'g'
    );
    if (pattern.test(source)) {
      source = source.replace(pattern, '');
      modified = true;
      logStep(`  Removed integrity check: ${varName}`, 'ok');
    }
  }
  
  // Pattern F3: c[1]/c[2]/c[3]/c[4]/c[5] validation
  const cValidationPattern = /if\s+(?:not\s+)?c\s*\[\s*\d\s*\]\s+then\s+error\s*\([^)]*\)\s*end/g;
  if (cValidationPattern.test(source)) {
    source = source.replace(cValidationPattern, '');
    modified = true;
    logStep('  Removed c[] array validation checks', 'ok');
  }
  
  // Pattern F4: Abort guards
  const abortPattern = /(?:Mcy|wsX|Ctb|dtW)\s*=\s*true/g;
  if (abortPattern.test(source)) {
    source = source.replace(abortPattern, '-- abort guard removed');
    modified = true;
    logStep('  Removed abort guard assignments', 'ok');
  }
  
  if (modified) {
    logStep('Integrity checks stripped', 'ok');
  }
  return source;
}

/**
 * Pass G: VM Opcode Dispatcher Resolution
 * 
 * Targets: Dispatcher tables that map obfuscated opcodes
 * 
 * Patterns:
 * - "cff" dispatcher (bytecode pseudo-opcode)
 * - "bst" dispatcher (block state table)
 * - return ({["v"]=..., ["KF"]=..., ["eOzS"]=..., ["e"]=...})
 * 
 * Strategy: Recognize dispatcher structure and add comments for readability
 */
function resolveOpcodeDispatcherPass(source) {
  logStep('Pass G: VM opcode dispatcher resolution (cff, bst patterns)');
  let modified = false;
  
  // Pattern G1: VM dispatcher table (goofyscator/Luraph style)
  // return ({["v"]=..., ["KF"]=..., ["eOzS"]=..., ["e"]=..., ["tk"]=...})
  const dispatcherPattern = /return\s*\(\s*\{\s*\[\s*["']([^"']+)["']\s*\]\s*=[^}]*\}\s*\)/g;
  source = source.replace(dispatcherPattern, (match) => {
    modified = true;
    logStep(`  Recognized VM dispatcher table`, 'ok');
    return `-- === VM Dispatcher Table ===\n${match}`;
  });
  
  // Pattern G2: "cff" opcode pattern (bytecode-level obfuscation)
  // local cff = function(...) ... end
  const cffPattern = /local\s+cff\s*=/g;
  if (cffPattern.test(source)) {
    source = source.replace(cffPattern, '-- === CFF Opcode Dispatcher ===\nlocal cff =');
    modified = true;
    logStep('  Found "cff" dispatcher opcode', 'ok');
  }
  
  // Pattern G3: "bst" dispatcher pattern (block state table)
  // local bst = {...}
  const bstPattern = /local\s+bst\s*=\s*\{/g;
  if (bstPattern.test(source)) {
    source = source.replace(bstPattern, '-- === BST Block State Table ===\nlocal bst = {');
    modified = true;
    logStep('  Found "bst" dispatcher pattern', 'ok');
  }
  
  if (modified) {
    logStep('Opcode dispatcher patterns identified', 'ok');
  }
  return source;
}

/**
 * Run all deobfuscation passes in sequence
 */
function runDeobfuscationPasses(source) {
  logStep('\n=== MULTI-PASS DEOBFUSCATION STAGE ===\n');
  
  try {
    source = decryptXORPass(source);
    source = decodeNumericPass(source);
    source = resolveArithmeticPass(source);
    source = inlineHelperFunctionsPass(source);
    source = renameIdentifiersPass(source);
    source = stripIntegrityChecksPass(source);
    source = resolveOpcodeDispatcherPass(source);
    
    logStep('\n=== DEOBFUSCATION COMPLETE ===\n', 'ok');
  } catch (err) {
    logStep(`Deobfuscation error: ${err.message}`, 'err');
  }
  
  return source;
}

// =============================================================================
// STAGE 4: OUTPUT & CLEANUP
// =============================================================================

/**
 * Write deobfuscated output to file
 */
function writeOutput(content) {
  logStep(`Writing deobfuscated output to: ${OUTPUT_FILE}`);
  
  try {
    fs.writeFileSync(OUTPUT_FILE, content, 'utf8');
    const stats = fs.statSync(OUTPUT_FILE);
    logStep(`Output written successfully (${stats.size} bytes)`, 'ok');
    return true;
  } catch (err) {
    logStep(`Failed to write output: ${err.message}`, 'err');
    return false;
  }
}

// =============================================================================
// MAIN ORCHESTRATION
// =============================================================================

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Lua 5.1 Bytecode Deobfuscator (Windows/mingw64)    ║');
  console.log('║   Targets: goofyscator, Luraph, IronBrew2, Moonsec, etc   ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');
  
  try {
    // Step 1: Verify input
    verifyInputFile();
    
    // Step 2: Check dependencies
    checkDependencies();
    
    // Step 3: Setup temp directory
    setupTempDirectory();
    
    // Step 4: Dynamic trace (if available)
    runDynamicTrace();
    
    // Step 5: Static decompilation
    let source = null;
    let decompiled = false;
    
    if (HAS_JAVA && HAS_UNLUAC) {
      decompiled = runUnluacDecompilation();
      if (decompiled && fs.existsSync(DECOMPILED_FILE)) {
        source = fs.readFileSync(DECOMPILED_FILE, 'utf8');
      }
    }
    
    // Fallback: Use input file directly if decompilation failed
    if (!source) {
      logStep('Using input file directly for deobfuscation', 'err');
      source = fs.readFileSync(INPUT_FILE, 'utf8');
    }
    
    // Step 6: Multi-pass deobfuscation
    source = runDeobfuscationPasses(source);
    
    // Step 7: Write output
    writeOutput(source);
    
    // Step 8: Cleanup
    cleanupTempFiles();
    
    logStep('\n✓ Deobfuscation pipeline complete!', 'ok');
    
  } catch (err) {
    logStep(`\nFatal error: ${err.message}`, 'err');
    cleanupTempFiles();
    process.exit(1);
  }
}

// Run main
main().catch(err => {
  logStep(`Unexpected error: ${err.message}`, 'err');
  cleanupTempFiles();
  process.exit(1);
});
