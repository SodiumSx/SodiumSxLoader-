/**
 * FreeHub Guard — delivery VM compiler.
 *
 * A Lua script is split into random-size chunks and compiled into a program for
 * a small stack machine. Chunk bytes are XOR-encrypted with a per-session
 * keystream, and every program gets a fresh chunk layout, fresh register
 * numbering, a random concat tree and a permuted opcode table. A program
 * captured from one load therefore does not decode the next one.
 *
 * Program text format (no newlines inside any field):
 *   line 1: <perm csv>|<register count>
 *   line 2: <base64url consts csv>
 *   line 3: <instructions joined by ;>, fields joined by ,
 *
 * The Lua side of this format lives in lua/vm.lua.
 */
import { randomBytes } from "node:crypto";
import { b64u, ksSeg } from "./crypto.mjs";

export const OPS = [
  "PUSHX", // rd, constIndex  -> b64decode(const) XOR keystream
  "SETL", // rd, constIndex  -> b64decode(const)
  "MOV", // rd, ra
  "CAT", // rd, ra, rb
  "XOR", // rd, ra, rb       -> byte-wise xor
  "SLICE", // rd, ra, start, len
  "REV", // rd, ra
  "PUSHN", // rd, number
  "JMP", // target
  "JNZ", // ra, target
  "END", // ra
  "EXEC", // ra              -> loadstring + run, returns only a status
  "NEST", // ra, rkey        -> run embedded program with key = mac(key, parent)
];

const OP_INDEX = Object.fromEntries(OPS.map((op, i) => [op, i]));

export function makeRng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const randInt = (rng, min, max) => min + Math.floor(rng() * (max - min + 1));

export function shuffle(rng, arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function randomPermutation(rng, size) {
  const values = Array.from({ length: size }, (_, i) => i);
  return shuffle(rng, values);
}

/**
 * Compile plaintext Lua into VM program text.
 *
 * @param {string} source
 * @param {{keyWords:number[], rng?:()=>number, chunkMin?:number, chunkMax?:number, tail?:"END"|"EXEC"}} opts
 */
export function compileVm(source, opts) {
  const { keyWords, chunkMin = 64, chunkMax = 192 } = opts;
  const tail = opts.tail || "END";
  const rng = opts.rng || makeRng(randomBytes(4).readUInt32LE(0));
  const bytes = Buffer.from(source, "utf8");
  if (bytes.length === 0) throw new Error("compileVm: empty source");

  const chunks = [];
  let offset = 0;
  while (offset < bytes.length) {
    const size = Math.min(randInt(rng, chunkMin, chunkMax), bytes.length - offset);
    chunks.push(bytes.subarray(offset, offset + size));
    offset += size;
  }

  const consts = chunks.map((chunk, i) => {
    const stream = ksSeg(keyWords, i, chunk.length);
    const xored = Buffer.alloc(chunk.length);
    for (let b = 0; b < chunk.length; b++) xored[b] = chunk[b] ^ stream[b];
    return b64u(xored);
  });

  const totalRegs = chunks.length * 2 + 12;
  const pool = shuffle(
    rng,
    Array.from({ length: totalRegs }, (_, i) => i),
  );
  let cursor = 0;
  const alloc = () => {
    if (cursor >= pool.length) throw new Error("compileVm: out of registers");
    return pool[cursor++];
  };

  const instrs = [];
  const labels = new Map();
  let labelSeq = 0;
  const newLabel = () => ({ label: ++labelSeq });

  const emit = (op, ...args) => {
    instrs.push({ op, args });
  };
  const mark = (label) => instrs.push({ op: "LABEL", args: [label.label] });

  const scratch = [alloc(), alloc(), alloc()];
  emit("PUSHN", scratch[0], randInt(rng, 1, 999));
  emit("PUSHN", scratch[1], randInt(rng, 1, 999));

  const leaves = chunks.map((_, i) => {
    const reg = alloc();
    emit("PUSHX", reg, i + 1);
    if (rng() < 0.12) emit("MOV", scratch[2], reg);
    return reg;
  });

  // Randomly shaped but balanced concat tree. Only adjacent ranges are merged,
  // otherwise the reassembled source would be a permutation of itself.
  const build = (lo, hi) => {
    if (hi - lo === 1) return leaves[lo];
    const span = hi - lo;
    const jitter = Math.max(0, Math.floor(span / 4));
    const half = Math.floor(span / 2) + (jitter ? randInt(rng, -jitter, jitter) : 0);
    const cut = Math.max(1, Math.min(span - 1, half));
    const left = build(lo, lo + cut);
    const right = build(lo + cut, hi);
    const reg = alloc();
    emit("CAT", reg, left, right);

    if (rng() < 0.2) {
      const skip = newLabel();
      emit("JMP", skip);
      emit("PUSHN", scratch[0], randInt(rng, 1, 999));
      emit("MOV", scratch[1], scratch[0]);
      emit("JNZ", scratch[1], skip);
      mark(skip);
    }
    return reg;
  };

  emit("END", build(0, chunks.length));

  // Resolve labels to 1-based instruction indices, then drop markers.
  const labelIndex = new Map();
  let counter = 0;
  for (const ins of instrs) {
    if (ins.op === "LABEL") labelIndex.set(ins.args[0], counter + 1);
    else counter++;
  }
  const finalInstrs = [];
  for (const ins of instrs) {
    if (ins.op === "LABEL") continue;
    finalInstrs.push({
      op: ins.op,
      args: ins.args.map((arg) => (typeof arg === "object" && arg !== null ? labelIndex.get(arg.label) ?? 1 : arg)),
    });
  }
  if (finalInstrs.length > 512 * 1024) throw new Error("compileVm: program too large");

  // A tail of EXEC hands the decoded source straight to the native loader inside
  // the VM: the program text never leaves the VM as a return value.
  if (tail !== "END") {
    const last = finalInstrs[finalInstrs.length - 1];
    if (!last || last.op !== "END" || !OPS.includes(tail)) {
      throw new Error(`compileVm: cannot retarget tail to ${tail}`);
    }
    last.op = tail;
  }

  const perm = randomPermutation(rng, OPS.length);
  const lines = [
    `${perm.join(",")}|${totalRegs}`,
    consts.join(","),
    finalInstrs
      .map((ins) => [perm[OP_INDEX[ins.op]], ...ins.args].join(","))
      .join(";"),
  ];

  return {
    program: lines.join("\n"),
    chunks: chunks.length,
    instructions: finalInstrs.length,
    registers: totalRegs,
    bytes: bytes.length,
  };
}

/** Random 4-word key, serialised as 32 hex chars (the client-side format). */
export function randomKeyWords() {
  const buf = randomBytes(16);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const words = [view.getUint32(0, true), view.getUint32(4, true), view.getUint32(8, true), view.getUint32(12, true)];
  const hex = Buffer.from(buf).toString("hex");
  return { words, hex };
}
