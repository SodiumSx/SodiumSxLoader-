/**
 * FreeHub Guard — scope-aware local renamer (build time).
 *
 * The obfuscator never touches globals: a script that calls `game` or
 * `Instance` must keep working, and a renamed global turns into a nil call.
 * Locals are different — they are private to the file, so renaming them costs
 * nothing at runtime while it removes the author's vocabulary (`getTarget`,
 * `aimbotFov`, `bypassFilter`) from a leaked copy and breaks every signature
 * written against the old names.
 *
 * Safety comes first: one pass with a scope stack, and any construct whose
 * scoping cannot be proven is a bail-out that returns the source untouched:
 *   - `goto` / `::label::` (label scopes)
 *   - `repeat ... until` (the condition sees the body's locals)
 *   - Luau type annotations (type names inside annotations would be renamed)
 *   - Luau `if ... then ... else ...` expressions
 *   - string interpolation (expressions inside a backtick literal)
 *
 * Declaration timing matches Lua exactly: `local x = x` initialises from the
 * *outer* x, because a local only becomes visible after its statement ends.
 */

const CONTINUATIONS = new Set([
  ".", ":", "(", "[", "{", ",", "=", "+", "-", "*", "/", "//", "%", "^", "..",
  "..=", "+=", "-=", "*=", "/=", "%=", "^=", "//=", "<", ">", "<=", ">=", "==",
  "~=", "and", "or",
]);

const BOUNDARY_KEYWORDS = new Set([
  "local", "if", "while", "for", "repeat", "function", "return", "do", "break",
  "end", "elseif", "else", "until",
]);

// An `if` directly after one of these can only be a Luau if-expression: a
// statement can never start there. `then`/`else` are deliberately absent —
// `if a then if b then ... end end` is legal Lua and both are statements.
const EXPRESSION_START_OPS = new Set([
  "=", "(", "[", "{", ",", "+", "-", "*", "/", "//", "%", "^", "..",
  "<=", ">=", "==", "~=", "<", ">",
]);
const EXPRESSION_START_KEYWORDS = new Set(["return", "and", "or", "not", "in"]);

function isValueEnd(tok) {
  if (!tok) return false;
  if (tok.type === "name" || tok.type === "num" || tok.type === "str" || tok.type === "lit") return true;
  if (tok.type === "kw") return tok.text === "true" || tok.text === "false" || tok.text === "nil" || tok.text === "end";
  if (tok.type === "op") return tok.text === ")" || tok.text === "]" || tok.text === "}";
  return false;
}

function nextSignificant(tokens, from) {
  for (let i = from + 1; i < tokens.length; i++) {
    if (tokens[i].type !== "ws" && tokens[i].type !== "comment") return i;
  }
  return -1;
}

/** Reasons a file is too risky to rename. Returned as a short tag. */
function bailReason(tokens) {
  let prev = null;
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i];
    if (tok.type === "ws" || tok.type === "comment") continue;
    if (tok.type === "lit") return "interpolation";
    if (tok.type === "kw" && (tok.text === "goto" || tok.text === "repeat" || tok.text === "until")) {
      return tok.text;
    }
    if (tok.type === "op" && (tok.text === "::" || tok.text === "->")) return tok.text;
    if (tok.type === "op" && tok.text === ":") {
      // `name: Type` (annotation) vs `obj:method(...)` (method call/definition).
      const ni = nextSignificant(tokens, i);
      const ai = ni >= 0 ? nextSignificant(tokens, ni) : -1;
      const next = ni >= 0 ? tokens[ni] : null;
      const after = ai >= 0 ? tokens[ai] : null;
      if (next && next.type === "name" && after && !(after.type === "op" && after.text === "(")) {
        return "annotation";
      }
    }
    if (tok.type === "kw" && tok.text === "if" && prev) {
      const inExpression =
        (prev.type === "op" && EXPRESSION_START_OPS.has(prev.text)) ||
        (prev.type === "kw" && EXPRESSION_START_KEYWORDS.has(prev.text));
      if (inExpression) return "ifexpr";
    }
    prev = tok;
  }
  return null;
}

/**
 * Rename every local, parameter and loop variable in `tokens` in place.
 *
 * @param {Array} tokens output of scanLua()
 * @param {() => number} rng
 * @returns {{tokens: Array, renamed: number, skipped: string|null}}
 */
export function renameLocals(tokens, rng) {
  const skipped = bailReason(tokens);
  if (skipped) return { tokens, code: tokens.map((t) => t.text).join(""), names: new Map(), renamed: 0, skipped };

  const sig = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type !== "ws" && tokens[i].type !== "comment") sig.push(i);
  }
  const at = (k) => (k >= 0 && k < sig.length ? tokens[sig[k]] : null);

  const taken = new Set(["self", "_ENV", "..."]);
  for (const tok of tokens) if (tok.type === "name") taken.add(tok.text);
  // A monotonically growing suffix guarantees progress even if the caller
  // passes a degenerate rng (a fixed seed, or a crypto stub). Rejection alone
  // would spin forever on the second name.
  let seq = 0;
  const freshName = () => {
    let name;
    do {
      name = "_" + Math.floor(rng() * 0x7ffffff).toString(36) + (seq ? seq.toString(36) : "");
      seq++;
    } while (taken.has(name));
    taken.add(name);
    return name;
  };

  // Each scope keeps its own pending list, so a declaration inside a nested
  // function initialiser (`local a = function() local b = 1 ... end`) cannot
  // force `a` into view before its own statement is over.
  // `base` is the paren depth of the current statement context: a function body
  // is at depth 0 only at the top level, so `pcall(function() local x = 1 ...`
  // sits one level down and would never be seen as a statement boundary by a
  // plain `=== 0` check.
  const scopes = [{ vars: new Map(), pending: [], kind: "block", prevBase: 0 }];
  const top = () => scopes[scopes.length - 1];
  const names = new Map();
  let bracket = 0;
  let base = 0;
  let renamed = 0;

  // Snapshot so an unbalanced pass can be rolled back instead of shipping
  // half-renamed code.
  const snapshot = tokens.map((tok) => (tok.type === "name" ? tok.text : null));
  const rollback = () => {
    for (let i = 0; i < tokens.length; i++) {
      if (snapshot[i] !== null) tokens[i].text = snapshot[i];
    }
  };

  // `local a, b = <expr>` is only visible after the statement ends.
  const commitScope = (scope) => {
    if (!scope.pending.length) return;
    for (const entry of scope.pending) scope.vars.set(entry.orig, entry.mapped);
    scope.pending = [];
  };

  const declareNow = (tok) => {
    const orig = tok.text;
    const mapped = freshName();
    tok.text = mapped;
    top().vars.set(orig, mapped);
    names.set(orig, mapped);
    renamed++;
  };
  const declarePending = (tok) => {
    const orig = tok.text;
    const mapped = freshName();
    tok.text = mapped;
    top().pending.push({ orig, mapped });
    names.set(orig, mapped);
    renamed++;
  };

  const lookup = (orig) => {
    for (let s = scopes.length - 1; s >= 0; s--) {
      const hit = scopes[s].vars.get(orig);
      if (hit !== undefined) return hit;
    }
    return null;
  };

  // Function head tracking: `function a.b:c(x)` — `a` is a variable reference,
  // `b`/`c` are fields, and only what is inside the parens is a parameter. The
  // state clears when the parameter list closes, so a later call `f(x)` is not
  // mistaken for another parameter list.
  let fnState = null;
  let expectLoopBody = false;
  let loopVars = null;

  // Tracks the initialiser of a `local` declaration so the new names become
  // visible exactly when the expression is complete — including when the next
  // statement starts on the same line (`local i = 1 print(i)`).
  let inInitializer = false;
  let exprState = null;

  for (let k = 0; k < sig.length; k++) {
    const idx = sig[k];
    const tok = tokens[idx];

    if (exprState === "done" && bracket === base && !CONTINUATIONS.has(tok.text)) {
      commitScope(top());
      inInitializer = false;
      exprState = null;
    }

    if (top().pending.length) {
      const prev = at(k - 1);
      let hasNewline = false;
      for (let j = sig[k - 1] + 1; j < idx; j++) {
        const gap = tokens[j];
        if ((gap.type === "ws" || gap.type === "comment") && gap.text.includes("\n")) hasNewline = true;
      }
      const boundary =
        (tok.type === "op" && tok.text === ";") ||
        (tok.type === "kw" && BOUNDARY_KEYWORDS.has(tok.text)) ||
        (hasNewline && bracket === base && isValueEnd(prev) && !CONTINUATIONS.has(tok.text));
      if (boundary) {
        commitScope(top());
        inInitializer = false;
        exprState = null;
      }
    }

    if (tok.type === "op") {
      if (tok.text === "=" && bracket === base && top().pending.length && !inInitializer) {
        inInitializer = true;
        exprState = "want";
      }
      if (tok.text === "(") {
        bracket++;
        if (fnState === "name" || fnState === "path") fnState = "params";
      } else if (tok.text === ")") {
        bracket = Math.max(0, bracket - 1);
        if (fnState === "params") fnState = null;
      } else if (tok.text === "[" || tok.text === "{") {
        bracket++;
      } else if (tok.text === "]" || tok.text === "}") {
        bracket = Math.max(0, bracket - 1);
      }
      if (tok.text !== "." && tok.text !== ":" && tok.text !== "(" &&
          (fnState === "name" || fnState === "path")) {
        fnState = null;
      }
    }

    if (tok.type === "kw") {
      switch (tok.text) {
        case "local": {
          const next = at(k + 1);
          if (next && next.type === "kw" && next.text === "function") {
            const nameTok = at(k + 2);
            if (nameTok && nameTok.type === "name") declareNow(nameTok);
            break;
          }
          let cursor = k + 1;
          for (;;) {
            const nameTok = at(cursor);
            if (!nameTok || nameTok.type !== "name") break;
            declarePending(nameTok);
            const sep = at(cursor + 1);
            if (sep && sep.type === "op" && sep.text === ",") {
              cursor += 2;
              continue;
            }
            break;
          }
          break;
        }
        case "function":
          scopes.push({ vars: new Map(), pending: [], kind: "function", prevBase: base });
          base = bracket;
          fnState = "name";
          break;
        case "for": {
          expectLoopBody = true;
          loopVars = [];
          let cursor = k + 1;
          for (;;) {
            const nameTok = at(cursor);
            if (!nameTok || nameTok.type !== "name") break;
            loopVars.push(nameTok);
            const sep = at(cursor + 1);
            if (sep && sep.type === "op" && sep.text === ",") {
              cursor += 2;
              continue;
            }
            break;
          }
          break;
        }
        case "while":
          expectLoopBody = true;
          loopVars = null;
          break;
        case "do":
          scopes.push({ vars: new Map(), pending: [], kind: "block", prevBase: base });
          if (expectLoopBody) {
            expectLoopBody = false;
            if (loopVars) {
              for (const nameTok of loopVars) declareNow(nameTok);
              loopVars = null;
            }
          }
          break;
        case "then":
          scopes.push({ vars: new Map(), pending: [], kind: "block", prevBase: base });
          break;
        case "elseif":
          // Closes the previous branch; the `then` that follows opens the next.
          if (scopes.length > 1) scopes.pop();
          break;
        case "else":
          if (scopes.length > 1) scopes.pop();
          scopes.push({ vars: new Map(), pending: [], kind: "block", prevBase: base });
          break;
        case "end": {
          commitScope(top());
          const frame = scopes.length > 1 ? scopes.pop() : null;
          if (frame && frame.kind === "function") base = frame.prevBase;
          fnState = null;
          inInitializer = false;
          exprState = null;
          break;
        }
        default:
          break;
      }
      if (inInitializer) {
        if (tok.text === "true" || tok.text === "false" || tok.text === "nil") {
          exprState = "done";
        } else if (tok.text === "function") {
          // The body has its own statements; stop tracking the initialiser.
          inInitializer = false;
          exprState = null;
        } else {
          exprState = "want";
        }
      }
      continue;
    }

    if (inInitializer) {
      if (tok.type === "op" && (tok.text === ")" || tok.text === "]" || tok.text === "}")) {
        exprState = "done";
      } else if (tok.type === "op") {
        exprState = "want";
      } else {
        exprState = "done";
      }
    }

    if (tok.type !== "name") continue;

    if (fnState === "params") {
      if (tok.text === "self") continue; // implicit, only valid in `function t:m`
      declareNow(tok);
      continue;
    }

    const prev = at(k - 1);
    const next = at(k + 1);
    // Field, method or table-constructor key: part of the data model.
    if (prev && prev.type === "op" && (prev.text === "." || prev.text === ":")) {
      // `function a.b:m(x)` — the method name is data, but the parameter list
      // that follows it is not, so the head stays open one more step.
      fnState = prev.text === ":" && (fnState === "name" || fnState === "path") ? "name" : null;
      continue;
    }
    // `{ key = value }`: the key sits right after `{`, `,` or `;` at brace depth.
    if (next && next.type === "op" && next.text === "=" && bracket > base) {
      const isKey =
        !prev || (prev.type === "op" && (prev.text === "{" || prev.text === "," || prev.text === ";"));
      if (isKey) {
        if (fnState === "name" || fnState === "path") fnState = null;
        continue;
      }
    }
    const mapped = lookup(tok.text);
    if (mapped) tok.text = mapped;
    // `function name(...)`: a global assignment, or a reference to a local.
    if (fnState === "name") fnState = "path";
  }

  // A construct the scope machine does not understand would leave a scope open
  // and silently leak a mapping into the next function. Bail out instead.
  if (scopes.length !== 1) {
    rollback();
    return { tokens, code: tokens.map((t) => t.text).join(""), names: new Map(), renamed: 0, skipped: "unbalanced" };
  }

  return { tokens, code: tokens.map((t) => t.text).join(""), names, renamed, skipped: null };
}
