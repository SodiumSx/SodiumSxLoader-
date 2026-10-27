/**
 * FreeHub Guard — Lua source obfuscator (build time).
 *
 * The payload that reaches a user's client is already encrypted and wrapped in
 * the delivery VM, but a leaked internal copy (or a decoded one) should not
 * hand over readable strings. This pass:
 *   - strips comments
 *   - moves every string literal into a shuffled constant table with decoy
 *     slots, per-slot key rotation, and a randomly chosen XOR/add cipher
 *   - mixes `\xNN` and `\ddd` escapes so encoded bytes do not look uniform
 *   - rewrites integer literals and booleans into equivalent expressions
 *   - injects dead branches / decoy locals into the header
 *
 * Identifiers are never renamed, and every rewrite is semantics-preserving, so
 * valid input Lua stays valid. The layout is regenerated on every build and on
 * every raw-link render (the VM runtime goes through this same pass).
 */

const cryptoRng = () => {
  // eslint-disable-next-line no-undef
  const buf = globalThis.crypto.getRandomValues(new Uint32Array(1))[0];
  return buf / 0x100000000;
};

export function randInt(rng, max) {
  return Math.floor(rng() * max);
}

const LUA_KEYWORDS = new Set([
  "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
  "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
  "true", "until", "while",
]);

/* ------------------------------------------------------------------ *
 * Scanner
 * ------------------------------------------------------------------ */

/**
 * Split Lua source into typed tokens. `str` tokens carry the decoded runtime
 * value so the emitter can rebuild them exactly.
 */
export function scanLua(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  const push = (type, text, extra) => tokens.push({ type, text, ...extra });

  while (i < n) {
    const ch = src[i];

    // whitespace
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      let j = i;
      while (j < n && " \t\r\n".includes(src[j])) j++;
      push("ws", src.slice(i, j));
      i = j;
      continue;
    }

    // comments
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

    // long strings
    if (ch === "[") {
      const longOpen = matchLongBracket(src, i);
      if (longOpen) {
        const end = findLongBracketEnd(src, longOpen.start, longOpen.level);
        let value = src.slice(longOpen.start, end - (longOpen.level + 2));
        // Lua drops a leading newline immediately after the opening bracket.
        if (value.startsWith("\r\n")) value = value.slice(2);
        else if (value.startsWith("\n")) value = value.slice(1);
        push("str", src.slice(i, end), { value: value.replace(/\r\n/g, "\n"), raw: true });
        i = end;
        continue;
      }
    }

    // short strings
    if (ch === '"' || ch === "'") {
      const { value, end } = readShortString(src, i);
      push("str", src.slice(i, end), { value, raw: false });
      i = end;
      continue;
    }

    // numbers
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

    // names / keywords
    if (/[A-Za-z_]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      push(LUA_KEYWORDS.has(word) ? "kw" : "name", word);
      i = j;
      continue;
    }

    // multi-char operators, longest match first; the Luau additions (`-=`,
    // `..=`, ...) must stay glued together, otherwise whitespace splitting
    // turns them into two unrelated tokens.
    const three = src.slice(i, i + 3);
    const two = src.slice(i, i + 2);
    if (three === "..." || three === "..=" || three === "//=") {
      push("op", three);
      i += 3;
      continue;
    }
    if (two === ".." || two === "==" || two === "~=" || two === ">=" ||
        two === "<=" || two === "//" || two === "::" || two === "<<" ||
        two === ">>" || two === "+=" || two === "-=" || two === "*=" ||
        two === "/=" || two === "%=" || two === "^=" || two === "->") {
      push("op", two);
      i += 2;
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
  while (src[j] === "=") {
    level++;
    j++;
  }
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
    if (ch === "\n") return { value: out.join(""), end: i }; // malformed; keep going
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
        case "z": {
          while (i < n && /\s/.test(src[i])) i++;
          break;
        }
        case "x": {
          const hex = src.slice(i, i + 2);
          if (/^[0-9a-fA-F]{2}$/.test(hex)) {
            out.push(String.fromCharCode(parseInt(hex, 16)));
            i += 2;
          } else {
            out.push("x");
          }
          break;
        }
        case "u": {
          const match = /^\{([0-9a-fA-F]+)\}/.exec(src.slice(i));
          if (match) {
            out.push(String.fromCodePoint(parseInt(match[1], 16)));
            i += match[0].length;
          } else {
            out.push("u");
          }
          break;
        }
        default: {
          if (/[0-9]/.test(next)) {
            let digits = next;
            while (digits.length < 3 && /[0-9]/.test(src[i] || "")) {
              digits += src[i];
              i++;
            }
            out.push(String.fromCharCode(parseInt(digits, 10) & 0xff));
          } else {
            out.push(next ?? "");
          }
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
 * Emitter
 * ------------------------------------------------------------------ */

/** Random integer in [min, max] inclusive. */
function irand(rng, min, max) {
  return min + Math.floor(rng() * (max - min + 1));
}

function shuffleArr(rng, arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/**
 * Byte string with mixed escape styles. Both `\xNN` and `\ddd` are plain Lua
 * escapes, so the value is identical; only the shape of the literal changes.
 */
function luaByteString(buf, rng) {
  let out = '"';
  for (const byte of buf) {
    if (rng() < 0.5) {
      const hex = byte.toString(16).padStart(2, "0");
      out += "\\x" + (rng() < 0.5 ? hex.toUpperCase() : hex);
    } else {
      out += "\\" + String(byte).padStart(3, "0");
    }
  }
  return out + '"';
}

/**
 * Rewrite a standalone integer literal into an equivalent expression. Only
 * plain decimal / hex integers are touched (no floats or exponents), and the
 * result is always parenthesized, so precedence and value are unchanged.
 */
function obfuscateNumber(text, rng) {
  let value;
  if (/^0[xX][0-9a-fA-F]+$/.test(text)) value = parseInt(text.slice(2), 16);
  else if (/^[0-9]+$/.test(text)) value = Number(text);
  else return text;
  if (!Number.isSafeInteger(value) || value <= 0 || value > 2 ** 40) return text;

  const chance = value < 5 ? 0.12 : value <= 1e6 ? 0.34 : 0.22;
  if (rng() >= chance) return text;

  const pick = irand(rng, 0, 9);
  if (pick < 4) {
    const isHex = text[1] === "x" || text[1] === "X";
    return isHex ? `(${value})` : `(0x${value.toString(16)})`;
  }
  if (pick < 8) {
    const k = irand(rng, 2, 9);
    const q = Math.floor(value / k);
    const r = value - q * k;
    return r ? `(${q}*${k}+${r})` : `(${q}*${k})`;
  }
  if (value > 1) {
    const a = irand(rng, 1, value - 1);
    return `(${a}+${value - a})`;
  }
  return `(0x${value.toString(16)})`;
}

/**
 * Join tokens with single spaces. Lua ignores whitespace between tokens, so this
 * preserves semantics exactly, while comment removal and the single space make
 * `--` injection impossible. Never touches string contents.
 */
function compact(tokens) {
  return tokens
    .filter((t) => t.type !== "comment" && t.type !== "ws")
    .map((t) => t.text)
    .join(" ");
}

/** Strip comments and excess whitespace, keep every token and string intact. */
export function minifyLua(src) {
  return compact(scanLua(src));
}

function uniqueName(taken, prefix) {
  let name;
  do {
    name = prefix + Math.floor(Math.random() * 0xfffffff).toString(36);
  } while (taken.has(name));
  taken.add(name);
  return name;
}

export function obfuscateLua(src, { rng = cryptoRng, chunkName = "hub" } = {}) {
  const tokens = scanLua(src);
  const taken = new Set(tokens.filter((t) => t.type === "name").map((t) => t.text));

  // Deduplicate string literals: one slot per distinct value.
  const values = [];
  const slotFor = new Map();
  for (const tok of tokens) {
    if (tok.type === "str" && !slotFor.has(tok.value)) {
      slotFor.set(tok.value, 0);
      values.push(tok.value);
    }
  }

  const hasStrings = values.length > 0;
  const cipher = rng() < 0.5 ? "xor" : "add";
  const keyLen = irand(rng, 6, 24);
  const key = Array.from({ length: keyLen }, () => irand(rng, 1, 255));
  const step = irand(rng, 1, 97);
  const salt = irand(rng, 0, 255);
  const totalSlots = values.length + (hasStrings ? irand(rng, 2, 7) : 0);

  // Real strings land on random slots; the holes hold random bytes, so the
  // table has no visible structure and call sites look arbitrary.
  const order = shuffleArr(rng, Array.from({ length: totalSlots }, (_, i) => i + 1));
  values.forEach((value, i) => slotFor.set(value, order[i]));

  // Key rotation is per-slot as well as per-byte: a repeated plaintext byte is
  // not a repeated ciphertext byte across the table.
  const seal = (slot, bytes) => {
    const offset = (slot * step + salt) % keyLen;
    const out = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      const k = key[(offset + i) % keyLen];
      out[i] = cipher === "xor" ? bytes[i] ^ k : (bytes[i] + k) % 256;
    }
    return luaByteString(out, rng);
  };

  const slots = new Array(totalSlots);
  if (hasStrings) {
    values.forEach((value) => {
      const slot = slotFor.get(value);
      slots[slot - 1] = seal(slot, Buffer.from(value, "utf8"));
    });
    for (let i = 0; i < totalSlots; i++) {
      if (slots[i] !== undefined) continue;
      const decoy = Buffer.alloc(irand(rng, 1, 12));
      for (let b = 0; b < decoy.length; b++) decoy[b] = irand(rng, 0, 255);
      slots[i] = seal(i + 1, decoy);
    }
  }

  const nm = {
    str: uniqueName(taken, "_s"),
    data: uniqueName(taken, "_d"),
    key: uniqueName(taken, "_k"),
    cache: uniqueName(taken, "_t"),
    idx: uniqueName(taken, "_i"),
    out: uniqueName(taken, "_o"),
    tmp: uniqueName(taken, "_c"),
    j: uniqueName(taken, "_j"),
    off: uniqueName(taken, "_f"),
    char: uniqueName(taken, "_h"),
    byte: uniqueName(taken, "_y"),
    cat: uniqueName(taken, "_n"),
    bxor: uniqueName(taken, "_x"),
  };

  const decls = [];
  const decoder = [];
  if (hasStrings) {
    decls.push(`local ${nm.data}={${slots.join(",")}}`);
    decls.push(`local ${nm.key}={${key.join(",")}}`);
    decls.push(`local ${nm.cache}={}`);
    const aliasNames = [nm.char, nm.byte, nm.cat];
    const aliasValues = ["string.char", "string.byte", "table.concat"];
    if (cipher === "xor") {
      aliasNames.push(nm.bxor);
      aliasValues.push("bit32.bxor");
    }
    decls.push(`local ${aliasNames.join(",")}=${aliasValues.join(",")}`);
    shuffleArr(rng, decls); // aliases may land before the tables; all resolve up front

    const keyAt = `((${nm.off}+${nm.j}-1)%#${nm.key})+1`;
    const plain =
      cipher === "xor"
        ? `${nm.bxor}(${nm.byte}(s,${nm.j}),${nm.key}[${keyAt}])`
        : `(${nm.byte}(s,${nm.j})-${nm.key}[${keyAt}])%256`;
    decoder.push(
      `local function ${nm.str}(${nm.idx})`,
      `local ${nm.tmp}=${nm.cache}[${nm.idx}]`,
      `if ${nm.tmp}~=nil then return ${nm.tmp} end`,
      `local s=${nm.data}[${nm.idx}]`,
      `local ${nm.out}={}`,
      `local ${nm.off}=(${nm.idx}*${step}+${salt})%#${nm.key}`,
      `for ${nm.j}=1,#s do ${nm.out}[${nm.j}]=${nm.char}(${plain}) end`,
      `${nm.tmp}=${nm.cat}(${nm.out})`,
      `${nm.cache}[${nm.idx}]=${nm.tmp}`,
      `return ${nm.tmp}`,
      `end`,
    );
  }

  // Decoy calculus. The branch condition is always false (a modulo result is
  // never negative), so the body is compiled but never runs; it only exists to
  // make the header look like machinery instead of a plain string table.
  const junk = [];
  {
    const qt = uniqueName(taken, "_q");
    const sum = uniqueName(taken, "_z");
    const wi = uniqueName(taken, "_w");
    const fn = uniqueName(taken, "_f");
    const aa = uniqueName(taken, "_a");
    const bb = uniqueName(taken, "_b");
    const cc = uniqueName(taken, "_c");
    const pp = uniqueName(taken, "_p");
    const jj = uniqueName(taken, "_j");
    const seed = Array.from({ length: irand(rng, 3, 7) }, () => irand(rng, 1, 999));
    junk.push(`local ${qt}={${seed.join(",")}}`);
    junk.push(`local ${sum}=0`);
    junk.push(`for ${wi}=1,#${qt} do ${sum}=${sum}+${qt}[${wi}] end`);
    junk.push(`local function ${fn}(${aa},${bb}) return (${aa}*${bb}+${sum})%${irand(rng, 3, 97)} end`);
    junk.push(`local ${cc}=${fn}(${sum},${irand(rng, 2, 9)})`);
    if (hasStrings) {
      const keyAt = `(${jj}%#${nm.key})+1`;
      const plain =
        cipher === "xor"
          ? `${nm.bxor}(${nm.byte}(${nm.data}[1],${jj}),${nm.key}[${keyAt}])`
          : `(${nm.byte}(${nm.data}[1],${jj})+${nm.key}[${keyAt}])%256`;
      junk.push(
        `if ${cc}<0 then local ${pp}={} for ${jj}=1,#${nm.key} do ${pp}[${jj}]=${nm.char}(${plain}) end ${nm.cache}[0]=${nm.cat}(${pp}) if #${nm.cache}[0]==-1 then ${nm.cache}[0]=nil end end`,
      );
    } else {
      junk.push(
        `if ${cc}<0 then local ${pp}=0 for ${jj}=1,3 do ${pp}=${pp}+${jj} end if ${pp}<0 then ${pp}=nil end end`,
      );
    }
  }

  const body = [];
  for (const tok of tokens) {
    if (tok.type === "comment" || tok.type === "ws") continue;
    if (tok.type === "str") {
      // Parenthesised so `f "x"` (literal-call sugar) stays valid as `f (_s(n))`.
      body.push(`(${nm.str}(${slotFor.get(tok.value)}))`);
      continue;
    }
    if (tok.type === "num") {
      body.push(obfuscateNumber(tok.text, rng));
      continue;
    }
    if (tok.type === "kw" && (tok.text === "true" || tok.text === "false") && rng() < 0.22) {
      body.push(tok.text === "true" ? "(0==0)" : "(0~=0)");
      continue;
    }
    body.push(tok.text);
  }

  // Random whitespace only ever sits between tokens, so Lua sees the same
  // program while the text stops breaking at logical statement boundaries.
  // Luau (Roblox and every executor) rejects a call whose `(` lands on a later
  // line than the callee, so `(` always gets a same-line separator.
  const seps = [" ", " ", " ", "  ", "\n", "\n\t", " \n"];
  const flat = [" ", " ", " ", "  ", "\t", " \t"];
  let code = "";
  for (let i = 0; i < body.length; i++) {
    if (i) {
      const pool = body[i].startsWith("(") ? flat : seps;
      code += pool[Math.floor(rng() * pool.length)];
    }
    code += body[i];
  }

  const head = [...decls, ...decoder, ...junk].join("\n");
  const out = head ? `${head}\n${code}` : code;

  return {
    code: out,
    stats: {
      strings: values.length,
      bytesIn: Buffer.byteLength(src, "utf8"),
      bytesOut: Buffer.byteLength(out, "utf8"),
    },
  };
}
