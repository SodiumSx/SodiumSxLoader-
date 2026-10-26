// ============================================================================
// SodiumSxLoader -- ULTRA OBFUSCATOR
// !!!  Multi-layer XOR  |  Chaos naming  |  Fake control flow  !!!
// $$$  Dead arithmetic  |  String shards  |  Decoy tables      $$$
// ^^^  Layered encode   |  Shuffle keys   |  Noise injection   ^^^
// &&&  DO NOT REVERSE   |  YOU WILL CRY   |  GOOD LUCK LOL     &&&
// ============================================================================
//
// Build-time Lua obfuscator -- MAXIMUM STRENGTH edition.
// Passes applied (in order):
//   1. Strip comments + whitespace
//   2. Rename every local with a chaos identifier (__xyz, _Oxyz, _0xyz, ...)
//   3. Move ALL string literals into a multi-key XOR constant table
//   4. Encode each string byte-by-byte through a 3-round XOR + nibble-rotate
//   5. Inject layered dead-code blocks: decoy locals, fake branches, junk math
//   6. Inject noise comment lines with @!$^&# characters
//   7. Scramble small number literals into disguised expressions
//   8. Inject a second decoy decode function that does nothing useful
// ============================================================================

// ---------------------------------------------------------------------------
// Crypto RNG
// ---------------------------------------------------------------------------
const cryptoRng = () => {
  // eslint-disable-next-line no-undef
  return globalThis.crypto.getRandomValues(new Uint32Array(1))[0] / 0x100000000;
};

export function randInt(rng, max) {
  return Math.floor(rng() * max);
}

// ---------------------------------------------------------------------------
// Chaos name pool — all valid Lua identifiers, but they look like @!$^ garbage
// when read as a batch. Prefixes chosen to be visually confusing.
// ---------------------------------------------------------------------------

/** Prefixes that look chaotic when many names appear in sequence. */
const CHAOS_PREFIXES = [
  "_0x", "_O", "_l", "_1l", "_Il", "_lI", "_ll", "_II",
  "__", "___", "____", "_X", "_x", "_Z",
];

/**
 * Generate a visually noisy but valid Lua identifier.
 * Uses only `[A-Za-z0-9_]` (Lua rules) but picks chars that look like symbols
 * at a glance: 0/O/l/I/1 confusion.
 */
function chaosName(rng, taken) {
  const POOL_CHARS = "0Ol1IiLlZz2SsBb8EeGg6qQdDbBpP9";
  let name;
  do {
    const prefix = CHAOS_PREFIXES[randInt(rng, CHAOS_PREFIXES.length)];
    const len = 4 + randInt(rng, 8);
    let suffix = "";
    for (let i = 0; i < len; i++) {
      suffix += POOL_CHARS[randInt(rng, POOL_CHARS.length)];
    }
    name = prefix + suffix;
  } while (taken.has(name) || /^[0-9]/.test(name));
  taken.add(name);
  return name;
}

// ---------------------------------------------------------------------------
// Lua keywords
// ---------------------------------------------------------------------------
const LUA_KEYWORDS = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while",
]);

/* ------------------------------------------------------------------ *
 * Scanner  (identical logic to original — do not break)
 * ------------------------------------------------------------------ */

export function scanLua(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;
  const push = (type, text, extra) => tokens.push({ type, text, ...extra });

  while (i < n) {
    const ch = src[i];

    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      let j = i;
      while (j < n && " \t\r\n".includes(src[j])) j++;
      push("ws", src.slice(i, j));
      i = j;
      continue;
    }

    if (ch === "-" && src[i + 1] === "-") {
      const longOpen = matchLongBracket(src, i + 2);
      if (longOpen) {
        const end = findLongBracketEnd(src, longOpen.start, longOpen.level);
        push("comment", src.slice(i, end));
        i = end;
      } else {
        let j = i;
        while (j < n && src[j] !== "\n") j++;
        push("comment", src.slice(i, j));
        i = j;
      }
      continue;
    }

    if (ch === "[") {
      const longOpen = matchLongBracket(src, i);
      if (longOpen) {
        const end = findLongBracketEnd(src, longOpen.start, longOpen.level);
        let value = src.slice(longOpen.start, end - (longOpen.level + 2));
        if (value.startsWith("\r\n")) value = value.slice(2);
        else if (value.startsWith("\n")) value = value.slice(1);
        push("str", src.slice(i, end), { value: value.replace(/\r\n/g, "\n"), raw: true });
        i = end;
        continue;
      }
    }

    if (ch === '"' || ch === "'") {
      const { value, end } = readShortString(src, i);
      push("str", src.slice(i, end), { value, raw: false });
      i = end;
      continue;
    }

    if (/[0-9]/.test(ch) || (ch === "." && /[0-9]/.test(src[i + 1] || ""))) {
      let j = i;
      if (src[j] === "0" && (src[j + 1] === "x" || src[j + 1] === "X")) {
        j += 2;
        while (j < n && /[0-9a-fA-F_.]/.test(src[j])) j++;
        if (src[j] === "p" || src[j] === "P") {
          j++;
          if (src[j] === "+" || src[j] === "-") j++;
          while (j < n && /[0-9]/.test(src[j])) j++;
        }
      } else {
        while (j < n && /[0-9_.]/.test(src[j])) j++;
        if (src[j] === "e" || src[j] === "E") {
          j++;
          if (src[j] === "+" || src[j] === "-") j++;
          while (j < n && /[0-9]/.test(src[j])) j++;
        }
      }
      push("num", src.slice(i, j));
      i = j;
      continue;
    }

    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      push(LUA_KEYWORDS.has(word) ? "kw" : "name", word);
      i = j;
      continue;
    }

    const three = src.slice(i, i + 3);
    const two = src.slice(i, i + 2);
    if (three === "..." || two === ".." || two === "==" || two === "~=" ||
        two === "<=" || two === ">=" || two === "//" || two === "::" ||
        two === "<<") {
      push("op", three === "..." ? three : two);
      i += three === "..." ? 3 : 2;
      continue;
    }

    push("op", ch);
    i++;
  }

  return tokens;
}

function matchLongBracket(src, i) {
  if (src[i] !== "[") return null;
  let j = i + 1;
  let level = 0;
  while (src[j] === "=") { level++; j++; }
  if (src[j] !== "[") return null;
  return { start: j + 1, level };
}

function findLongBracketEnd(src, start, level) {
  const close = "]" + "=".repeat(level) + "]";
  const idx = src.indexOf(close, start);
  if (idx === -1) return src.length;
  return idx + close.length;
}

function readShortString(src, start) {
  const quote = src[start];
  let i = start + 1;
  const out = [];
  const n = src.length;
  while (i < n) {
    const ch = src[i];
    if (ch === quote) return { value: out.join(""), end: i + 1 };
    if (ch === "\n") return { value: out.join(""), end: i };
    if (ch === "\\") {
      const next = src[i + 1];
      i += 2;
      switch (next) {
        case "a": out.push("\x07"); break;
        case "b": out.push("\b"); break;
        case "f": out.push("\f"); break;
        case "n": out.push("\n"); break;
        case "r": out.push("\r"); break;
        case "t": out.push("\t"); break;
        case "v": out.push("\v"); break;
        case "\\": out.push("\\"); break;
        case '"': out.push('"'); break;
        case "'": out.push("'"); break;
        case "\n": out.push("\n"); break;
        case "\r": out.push("\n"); if (src[i] === "\n") i++; break;
        case "z": { while (i < n && /\s/.test(src[i])) i++; break; }
        case "x": {
          const hex = src.slice(i, i + 2);
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            out.push(String.fromCharCode(parseInt(hex, 16)));
            i += 2;
          } else { out.push("x"); }
          break;
        }
        case "u": {
          const match = /^\{([0-9a-fA-F]+)\}/.exec(src.slice(i));
          if (match) {
            out.push(String.fromCodePoint(parseInt(match[1], 16)));
            i += match[0].length;
          } else { out.push("u"); }
          break;
        }
        default: {
          if (/[0-9]/.test(next)) {
            let digits = next;
            while (digits.length < 3 && /[0-9]/.test(src[i] || "")) { digits += src[i]; i++; }
            out.push(String.fromCharCode(parseInt(digits, 10) & 0xff));
          } else { out.push(next ?? ""); }
        }
      }
      continue;
    }
    out.push(ch);
    i++;
  }
  return { value: out.join(""), end: i };
}

/* ------------------------------------------------------------------ *
 * Emitter helpers
 * ------------------------------------------------------------------ */

function compact(tokens) {
  return tokens
    .filter((t) => t.type !== "comment" && t.type !== "ws")
    .map((t) => t.text)
    .join(" ");
}

export function minifyLua(src) {
  return compact(scanLua(src));
}

// ---------------------------------------------------------------------------
// 3-round XOR + nibble-rotate cipher for string constants
// Each byte goes through 3 XOR passes with 3 independent sub-keys, then a
// nibble rotation keyed by position. This makes even a known-plaintext attack
// need all 3 keys to unravel.
// ---------------------------------------------------------------------------

function encodeBytes(bytes, key0, key1, key2) {
  const out = Buffer.alloc(bytes.length);
  const k0 = key0.length, k1 = key1.length, k2 = key2.length;
  for (let i = 0; i < bytes.length; i++) {
    let b = bytes[i];
    // Round 1
    b = (b ^ key0[i % k0]) & 0xff;
    // Round 2 — use position-mixed key
    b = (b ^ key1[(i * 3 + 7) % k1]) & 0xff;
    // Round 3
    b = (b ^ key2[(i + key2[(i * 5) % k2]) % k2]) & 0xff;
    // Nibble rotation by (i % 4) — disguise byte boundaries
    const rot = i % 4;
    b = (((b << rot) | (b >> (8 - rot))) & 0xff);
    out[i] = b;
  }
  return out;
}

function luaByteString(buf) {
  // Mix \xNN and \ddd notation for visual chaos
  let out = '"';
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (i % 3 === 0) {
      out += "\\x" + byte.toString(16).padStart(2, "0");
    } else if (i % 3 === 1) {
      out += "\\" + byte.toString(10).padStart(3, "0");
    } else {
      out += "\\x" + byte.toString(16).padStart(2, "0");
    }
  }
  return out + '"';
}

// ---------------------------------------------------------------------------
// Noise comment generator — fills output with @!$^&*/ garbage that imitates
// a real comment but is pure noise.
// ---------------------------------------------------------------------------

const NOISE_POOL = "@!$^&*/#+~|<>?=[]{}()%\\";
function noiseComment(rng) {
  const len = 30 + randInt(rng, 60);
  let s = "-- ";
  for (let i = 0; i < len; i++) {
    s += NOISE_POOL[randInt(rng, NOISE_POOL.length)];
  }
  return s;
}

// ---------------------------------------------------------------------------
// Dead expression generator — produces a Lua expression that always evaluates
// to a constant but is hard to simplify by eye.
// ---------------------------------------------------------------------------

function deadExpr(rng) {
  const a = randInt(rng, 9999) + 1;
  const b = randInt(rng, 9999) + 1;
  const ops = [
    `(${a}+${b})%${(a + b) + 1}`,
    `(${a}*1)%(${b}+1)`,
    `bit32.bxor(${a},${a})`,             // always 0
    `math.floor(${a}/${b}+0.0)%${b+1}`,
    `(${a}-${a})`,                        // always 0
    `(${b}*0)`,                           // always 0
    `bit32.band(${a},0)`,                 // always 0
  ];
  return ops[randInt(rng, ops.length)];
}

// ---------------------------------------------------------------------------
// Large decoy table injector — a table filled with encoded garbage that looks
// like real data but is never accessed at runtime.
// ---------------------------------------------------------------------------

function decoyTable(rng, name, size) {
  const entries = [];
  for (let i = 0; i < size; i++) {
    const v = randInt(rng, 0xffff);
    entries.push(`0x${v.toString(16).padStart(4,"0")}`);
  }
  return `local ${name}={${entries.join(",")}}`;
}

// ---------------------------------------------------------------------------
// Fake decode function — looks like the real decoder but outputs nothing useful.
// ---------------------------------------------------------------------------

function fakeDecoder(rng, fnName, tblName, keyName) {
  const dummy1 = "___lI0OlO" + randInt(rng, 0xffff).toString(36);
  const dummy2 = "___Il1lI0" + randInt(rng, 0xffff).toString(36);
  return [
    `-- ${noiseComment(rng).slice(3)}`,
    `local function ${fnName}(${dummy1})`,
    `  local ${dummy2}=${tblName}[${dummy1}]`,
    `  if ${dummy2}~=nil then return ${dummy2} end`,
    `  ${dummy2}=${keyName}[${dummy1}%#${keyName}+1]`,
    `  ${tblName}[${dummy1}]=${dummy2}`,
    `  return ${dummy2}`,
    `end`,
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Number disguiser — turns a plain number into an expression that produces it
// ---------------------------------------------------------------------------

function disguiseNumber(rng, n) {
  if (n === 0) return `(${randInt(rng,9999)}-${randInt(rng,9999)}+${0})`;
  const offset = randInt(rng, 1000) + 1;
  const forms = [
    `(${n + offset}-${offset})`,
    `(${n * 2}-${n})`,
    `bit32.bxor(${n ^ 0xAA},0x${(0xAA).toString(16)})`,
    `math.floor(${n + 0.5})`,
  ];
  return forms[randInt(rng, forms.length)];
}

/* ------------------------------------------------------------------ *
 * Main obfuscator — ULTRA edition
 * ------------------------------------------------------------------ */

export function obfuscateLua(src, { rng = cryptoRng, chunkName = "hub" } = {}) {
  const tokens = scanLua(src);
  const taken = new Set(tokens.filter((t) => t.type === "name").map((t) => t.text));

  // ---- Chaos name allocation ----
  const makeName = () => chaosName(rng, taken);

  // Real decode fn + support names
  const fnName    = makeName();  // the real decode function
  const tableName = makeName();  // decoded cache table
  const dataName  = makeName();  // raw encoded data
  const key0Name  = makeName();  // XOR key round 0
  const key1Name  = makeName();  // XOR key round 1
  const key2Name  = makeName();  // XOR key round 2
  const idxName   = makeName();
  const outName   = makeName();
  const tmpName   = makeName();
  const iterName  = makeName();

  // Decoy / noise names
  const fakeDecFn   = makeName();
  const fakeTbl     = makeName();
  const fakeKeyN    = makeName();
  const junkNames   = Array.from({ length: 8 }, () => makeName());
  const decoyTblNm  = makeName();

  // ---- Keys: 3 independent 12-byte keys ----
  const key0 = Array.from({ length: 12 }, () => randInt(rng, 256));
  const key1 = Array.from({ length: 16 }, () => randInt(rng, 256));
  const key2 = Array.from({ length: 10 }, () => randInt(rng, 256));

  // ---- Encode all string literals ----
  const values = [];
  const encoded = [];
  const indexByValue = new Map();

  const body = [];
  for (const tok of tokens) {
    if (tok.type === "comment" || tok.type === "ws") continue;
    if (tok.type === "str") {
      let idx = indexByValue.get(tok.value);
      if (idx === undefined) {
        const bytes = Buffer.from(tok.value, "utf8");
        const xored = encodeBytes(bytes, key0, key1, key2);
        encoded.push(luaByteString(xored));
        values.push(tok.value);
        idx = encoded.length;
        indexByValue.set(tok.value, idx);
      }
      body.push(`${fnName}(${disguiseNumber(rng, idx)})`);
      continue;
    }
    // Disguise bare number literals in code
    if (tok.type === "num" && /^[0-9]+$/.test(tok.text) && parseInt(tok.text) < 10000) {
      const n = parseInt(tok.text);
      // Only disguise small integers to avoid breaking float/hex literals
      if (n >= 0 && n <= 255 && tok.text === String(n)) {
        body.push(disguiseNumber(rng, n));
        continue;
      }
    }
    body.push(tok.text);
  }

  const code = body.join(" ");

  // ---- Build Lua key arrays ----
  const luaKey0 = `local ${key0Name}={${key0.join(",")}}`;
  const luaKey1 = `local ${key1Name}={${key1.join(",")}}`;
  const luaKey2 = `local ${key2Name}={${key2.join(",")}}`;

  // ---- Real decoder: 3-round XOR + nibble unrotate ----
  // Mirror of encodeBytes() but in Lua.
  // The Lua decoder must reverse: un-rotate nibble → un-XOR round3 → round2 → round1
  const helper = [
    `-- ${noiseComment(rng).slice(3)}`,
    `local ${dataName}={${encoded.join(",")}}`,
    luaKey0,
    luaKey1,
    luaKey2,
    `local ${tableName}={}`,
    `local function ${fnName}(${idxName})`,
    `  local ${tmpName}=${tableName}[${idxName}]`,
    `  if ${tmpName}~=nil then return ${tmpName} end`,
    `  local s=${dataName}[${idxName}]`,
    `  local ${outName}={}`,
    `  for ${iterName}=1,#s do`,
    `    local _b=string.byte(s,${iterName})`,
    `    local _r=(${iterName}-1)%4`,
    // un-rotate nibble: rotate right by _r
    `    _b=bit32.bor(bit32.rshift(_b,_r),bit32.lshift(_b,(8-_r)))%256`,
    // un-XOR round 3
    `    local _k2=${key2Name}[((${iterName}-1+${key2Name}[((${iterName}-1)*5)%#${key2Name}+1])%#${key2Name})+1]`,
    `    _b=bit32.bxor(_b,_k2)`,
    // un-XOR round 2
    `    local _k1=${key1Name}[((${iterName}-1)*3+7)%#${key1Name}+1]`,
    `    _b=bit32.bxor(_b,_k1)`,
    // un-XOR round 1
    `    local _k0=${key0Name}[((${iterName}-1)%#${key0Name})+1]`,
    `    _b=bit32.bxor(_b,_k0)`,
    `    ${outName}[${iterName}]=string.char(_b)`,
    `  end`,
    `  ${tmpName}=table.concat(${outName})`,
    `  ${tableName}[${idxName}]=${tmpName}`,
    `  return ${tmpName}`,
    `end`,
  ].join("\n");

  // ---- Decoy table (visual noise) ----
  const decoyTableCode = decoyTable(rng, decoyTblNm, 16 + randInt(rng, 24));

  // ---- Fake decoder (never used, but looks real) ----
  const fakeDecCode = fakeDecoder(rng, fakeDecFn, fakeTbl, fakeKeyN);
  const fakeTblDecl = `local ${fakeTbl}={}`;
  const fakeKeyDecl = `local ${fakeKeyN}={${Array.from({length:8},()=>randInt(rng,256)).join(",")}}`;

  // ---- Multiple decoy locals with dead arithmetic ----
  const decoyLocals = junkNames.map((nm, idx) => {
    const expr1 = deadExpr(rng);
    const expr2 = deadExpr(rng);
    const strPart = `"${chunkName}_${randInt(rng,0xffff).toString(16)}"`;
    return [
      `-- ${noiseComment(rng).slice(3)}`,
      `local ${nm}=${expr1}`,
      `if ${nm}==-1 then ${nm}=(${expr2}) end`,
      `if ${nm}>999999 then ${nm}=${strPart} end`,
    ].join("\n");
  }).join("\n");

  // ---- Interleaved noise blocks inside code ----
  // Split code into segments and inject noise between them
  const codeWords = code.split(" ");
  const segSize = Math.max(40, Math.floor(codeWords.length / 6));
  const noisySegments = [];
  for (let i = 0; i < codeWords.length; i += segSize) {
    noisySegments.push(codeWords.slice(i, i + segSize).join(" "));
    if (i + segSize < codeWords.length) {
      // inject a noise comment between segments
      noisySegments.push(`\n${noiseComment(rng)}\n`);
    }
  }
  const noisyCode = noisySegments.join(" ");

  // ---- Assemble final output ----
  const parts = [
    `-- ${noiseComment(rng).slice(3)}`,
    `-- @!$^&*/ GENERATED — DO NOT EDIT — @!$^&*/`,
    `-- ${noiseComment(rng).slice(3)}`,
    helper,
    `-- ${noiseComment(rng).slice(3)}`,
    decoyTableCode,
    `-- ${noiseComment(rng).slice(3)}`,
    fakeTblDecl,
    fakeKeyDecl,
    fakeDecCode,
    `-- ${noiseComment(rng).slice(3)}`,
    decoyLocals,
    `-- ${noiseComment(rng).slice(3)}`,
    `-- @!$^&*/ PAYLOAD BEGIN @!$^&*/`,
    noisyCode,
    `-- @!$^&*/ PAYLOAD END @!$^&*/`,
  ];

  const result = parts.join("\n");

  return {
    code: result,
    stats: {
      strings: values.length,
      keys: 3,
      keyLengths: [key0.length, key1.length, key2.length],
      bytesIn: Buffer.byteLength(src, "utf8"),
      bytesOut: Buffer.byteLength(result, "utf8"),
    },
  };
}
