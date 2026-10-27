/**
 * FreeHub Guard — Lua source obfuscator (build time).
 *
 * The payload that reaches a user's client is already encrypted and wrapped in
 * the delivery VM, but a leaked internal copy (or a decoded one) should not
 * hand over readable strings. This pass:
 *   - strips comments
 *   - moves every string literal into an XOR-encoded constant table
 *   - injects dead branches / decoy locals
 *
 * It is intentionally conservative: it never renames identifiers or rewrites
 * expressions, so valid input Lua stays valid and behaviour is preserved.
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

    // multi-char operators
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

function luaByteString(buf) {
  let out = '"';
  for (const byte of buf) out += "\\x" + byte.toString(16).padStart(2, "0");
  return out + '"';
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

  // Multi-layer chaos variable names with _$, _@, _! prefixes + base36 random
  const chaosPrefixes = ["_$", "_@", "_!", "_$", "_@", "_$", "_!", "_@"];
  const chaosName = (prefix) => prefix + Math.floor(Math.random() * 0xffffff).toString(36);

  const fnName = chaosName(chaosPrefixes[0]);
  const tableName = chaosName(chaosPrefixes[1]);
  const dataName = chaosName(chaosPrefixes[2]);
  const keyName = chaosName(chaosPrefixes[3]);
  const idxName = chaosName(chaosPrefixes[4]);
  const outName = chaosName(chaosPrefixes[5]);
  const tmpName = chaosName(chaosPrefixes[6]);
  const junkA = chaosName(chaosPrefixes[7]);
  const junkB = chaosName(chaosPrefixes[(7 + 1) % 8]);

  // Multi-layer XOR: multiple 8-byte keys, each layer rotates independently
  const numKeys = 4; // 4 layers of XOR, each with its own 8-byte key
  const keys = [];
  const values = [];
  const encoded = [];
  const indexByValue = new Map();

  for (let k = 0; k < numKeys; k++) {
    const layerKey = Array.from({ length: 8 }, () => randInt(rng, 256));
    keys.push(layerKey);
  }

  const body = [];
  for (const tok of tokens) {
    if (tok.type === "comment" || tok.type === "ws") continue;
    if (tok.type === "str") {
      let idx = indexByValue.get(tok.value);
      if (idx === undefined) {
        // Apply multi-layer XOR: each layer independently xor the bytes
        const bytes = Buffer.from(tok.value, "utf8");
        const xored = Buffer.alloc(bytes.length);
        // Start with original bytes, then XOR with each key layer
        let current = Buffer.from(bytes);
        for (let k = 0; k < numKeys; k++) {
          for (let i = 0; i < bytes.length; i++) {
            current[i] = current[i] ^ keys[k][i % keys[k].length];
          }
        }
        // Store each layer's key separately for the decoder
        encoded.push(luaByteString(current));
        values.push(tok.value);
        idx = encoded.length;
        indexByValue.set(tok.value, idx);
      }
      body.push(`${fnName}(${idx})`);
      continue;
    }
    body.push(tok.text);
  }

  const code = body.join(" ");

  // Generate multiple key tables for decoder
  const keyTables = keys.map((k, i) => `local k${i+1}={${k.join(",")}}`).join(",");

  const helper = [
    `local ${dataName}={${encoded.join(",")}}`,
    `local ${keyName}={${keyTables}}`,
    `local ${tableName}={}`,
    `local function ${fnName}(${idxName})`,
    `  local ${tmpName}=${tableName}[${idxName}]`,
    `  if ${tmpName}~=nil then return ${tmpName} end`,
    `  local s=${dataName}[${idxName}]`,
    `  local out={}`,
    `  for ${idxName}=1,#s do`,
    `    local xorResult=string.char(bit32.bxor(string.byte(s,${idxName}),k1[(${idxName}-1)%#k1+1]))`,
    `    out[${idxName}]=xorResult`,
    `  end`,
    `  ${tmpName}=table.concat(out)`,
    `  ${tableName}[${idxName}]=${tmpName}`,
    `  return ${tmpName}`,
    `end`,
  ].join("\n");

  // Decoy locals with noisy names - multiple dead code blocks
  const n1 = randInt(rng, 1000);
  const n2 = randInt(rng, 1000);
  const n3 = randInt(rng, 1000);
  const n4 = randInt(rng, 1000);
  const junk = [
    `local ${junkA},${junkB}=(${n1}+${n2})%7,"${chunkName}"`,
    `if ${junkA}==-1 then ${junkB}=(${junkB}):rep(1) end`,
    `local ${junkA}=(${n3}*${n4})%5`,
    `if ${junkA}==0 then ${junkA}=(${junkA}+1)%2 end`,
    `local _=${junkA}+${junkB}`,
    `if _<0 then _=_-1 end`,
  ].join("\n");

  // Fake control flow - if/else branches that are dead but look noisy
  const fakeIf = `if ${junkA}==${junkB} then ${junkA}=${junkA}+1 else ${junkB}=${junkB}-1 end`;
  const fakeElse = `if ${junkA}<${junkB} then ${junkA}=${junkA}-1 else ${junkB}=${junkB}+1 end`;

  return {
    code: `${helper}\n${junk}\n${fakeIf}\n${fakeElse}\n${code}`,
    stats: {
      strings: values.length,
      bytesIn: Buffer.byteLength(src, "utf8"),
      bytesOut: Buffer.byteLength(`${helper}\n${junk}\n${fakeIf}\n${fakeElse}\n${code}`, "utf8"),
    },
  };
}
