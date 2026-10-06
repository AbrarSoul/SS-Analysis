"""
Section 9 ground-truth test bundle: CASE-0269
(pugjs/pug, packages/pug-code-gen/index.js Compiler constructor,
CVE-2024-36361, CWE-94 code injection).

Core vulnerable mechanism: pug compiles a template into a JS function by
building up a STRING of source code and later executing it (via `new
Function(...)` in pug's loader). Three `Compiler` options are spliced
straight into that generated-source string with no validation that they
are safe to embed as code: `options.templateName` becomes the literal
function name (`'function ' + (this.options.templateName || 'template') +
'(locals) {...}'`), and `options.globals` (each entry) becomes a bare
identifier list used to build a `with(locals || {}) {...}` wrapper. An
application that lets a caller influence either option (a multi-tenant
templating/report-generation service exposing `templateName` or `globals`
as a configuration knob, for instance) lets that caller break out of the
intended `function <name>(locals) {...}` skeleton: a `templateName` of
`x(){};globalThis.__PWNED__=1337;function y` closes the generated
function early and splices in arbitrary JS that runs the moment the
compiled template is invoked -- confirmed for real against the actual
published `pug-code-gen`/`pug-lexer`/`pug-parser` packages (see
Verification). The upstream fix adds `isIdentifier()` validation: reject a
`templateName` or any `globals` entry that is not a valid bare JS
identifier (`/^[a-zA-Z_$][a-zA-Z0-9_$]*$/`).

Measured caveat, kept in the manifest notes: the SAME upstream commit also
adds a THIRD check, on `options.doctype` (also spliced into the generated
markup and, for `<script>`, executable if it can inject a `>` to close the
enclosing tag) -- but as actually written, it tests `this.doctype`, which
at that point in the constructor is still `undefined` (`this.doctype` is
only ever assigned later, inside `setDoctype()`, called a few lines further
down). Confirmed live against the real published patched package: a
`doctype` containing `>` and `<script>` markup is NOT rejected by the real
fix (`this.doctype && ...` short-circuits on the still-unset `this.doctype`
and the check never fires). This bundle's safe variant still adds a
doctype check -- but tests `options.doctype` directly, the value actually
available at that point, so it is not a faithful copy of upstream's own
ineffective check.

Sibling sites: `templateName` and `globals` are the only two compiler
options spliced into the generated code as bare (non-string-escaped)
identifiers; `doctype` is spliced into generated MARKUP (a different sink,
XSS/HTML-injection rather than JS-injection) and is out of scope for the
templateName/globals PoC below, though the safe variant still closes it.

Verification: each full file is swapped in for
`node_modules/pug-code-gen/index.js` inside a real npm install of
`pug-code-gen` (plus real `pug-lexer` and `pug-parser`, used together to
turn a trivial real template string into a real AST), so `Compiler` and the
exported `generateCode` function run as real, unmodified code. `generateCode`
is called with `{templateName: 'x(){};globalThis.__PWNED__=1337;function y'}`;
the returned JS source string is checked for the injection marker.

Every variant is the FULL real file. `Compiler`/`generateCode` are imported
by name elsewhere (`pug-load`, the main `pug` package) and by any code doing
`require('pug-code-gen')` directly, so their names and signatures are kept;
the renamed variant renames the constructor's own parameters and locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0269"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CTOR = """function Compiler(node, options) {
  this.options = options = options || {};
  this.node = node;
  this.bufferedConcatenationCount = 0;
  this.hasCompiledDoctype = false;
  this.hasCompiledTag = false;
  this.pp = options.pretty || false;
  if (this.pp && typeof this.pp !== 'string') {
    this.pp = '  ';
  }
  if (this.pp && !/^\\s+$/.test(this.pp)) {
    throw new Error(
      'The pretty parameter should either be a boolean or whitespace only string'
    );
  }
  this.debug = false !== options.compileDebug;
  this.indents = 0;
  this.parentIndents = 0;
  this.terse = false;
  this.mixins = {};
  this.dynamicMixins = false;
  this.eachCount = 0;
  if (options.doctype) this.setDoctype(options.doctype);
  this.runtimeFunctionsUsed = [];
  this.inlineRuntimeFunctions = options.inlineRuntimeFunctions || false;
  if (this.debug && this.inlineRuntimeFunctions) {
    this.runtimeFunctionsUsed.push('rethrow');
  }
}"""
assert original.count(CTOR) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CTOR, """function Compiler(astNode, opts) {
  this.options = opts = opts || {};
  this.node = astNode;
  this.bufferedConcatenationCount = 0;
  this.hasCompiledDoctype = false;
  this.hasCompiledTag = false;
  this.pp = opts.pretty || false;
  if (this.pp && typeof this.pp !== 'string') {
    this.pp = '  ';
  }
  if (this.pp && !/^\\s+$/.test(this.pp)) {
    throw new Error(
      'The pretty parameter should either be a boolean or whitespace only string'
    );
  }
  this.debug = false !== opts.compileDebug;
  this.indents = 0;
  this.parentIndents = 0;
  this.terse = false;
  this.mixins = {};
  this.dynamicMixins = false;
  this.eachCount = 0;
  if (opts.doctype) this.setDoctype(opts.doctype);
  this.runtimeFunctionsUsed = [];
  this.inlineRuntimeFunctions = opts.inlineRuntimeFunctions || false;
  if (this.debug && this.inlineRuntimeFunctions) {
    this.runtimeFunctionsUsed.push('rethrow');
  }
}""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CTOR, """function validatePrettyOption(pp) {
  if (pp && !/^\\s+$/.test(pp)) {
    throw new Error(
      'The pretty parameter should either be a boolean or whitespace only string'
    );
  }
}

function Compiler(node, options) {
  this.options = options = options || {};
  this.node = node;
  this.bufferedConcatenationCount = 0;
  this.hasCompiledDoctype = false;
  this.hasCompiledTag = false;
  this.pp = options.pretty || false;
  if (this.pp && typeof this.pp !== 'string') {
    this.pp = '  ';
  }
  validatePrettyOption(this.pp);
  this.debug = false !== options.compileDebug;
  this.indents = 0;
  this.parentIndents = 0;
  this.terse = false;
  this.mixins = {};
  this.dynamicMixins = false;
  this.eachCount = 0;
  if (options.doctype) this.setDoctype(options.doctype);
  this.runtimeFunctionsUsed = [];
  this.inlineRuntimeFunctions = options.inlineRuntimeFunctions || false;
  if (this.debug && this.inlineRuntimeFunctions) {
    this.runtimeFunctionsUsed.push('rethrow');
  }
}""")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream for templateName/globals (both must be valid
# JS identifiers) but expressed as one extracted assertSafeCompilerOptions()
# helper instead of upstream's three sequential inline ifs -- and the
# doctype leg is fixed to check options.doctype (the value actually in
# scope at this point), not upstream's own this.doctype (unset here, so
# upstream's doctype check is a no-op; confirmed live, see docstring).
v3 = swap(original, CTOR, """function assertSafeCompilerOptions(options) {
  if (options.templateName && !isIdentifier(options.templateName)) {
    throw new Error(
      'The templateName parameter must be a valid JavaScript identifier if specified.'
    );
  }
  if (options.doctype && (options.doctype.includes('<') || options.doctype.includes('>'))) {
    throw new Error('Doctype can not contain "<" or ">"');
  }
  if (options.globals && !options.globals.every(isIdentifier)) {
    throw new Error(
      'The globals option must be an array of valid JavaScript identifiers if specified.'
    );
  }
}

function Compiler(node, options) {
  this.options = options = options || {};
  this.node = node;
  this.bufferedConcatenationCount = 0;
  this.hasCompiledDoctype = false;
  this.hasCompiledTag = false;
  this.pp = options.pretty || false;
  if (this.pp && typeof this.pp !== 'string') {
    this.pp = '  ';
  }
  if (this.pp && !/^\\s+$/.test(this.pp)) {
    throw new Error(
      'The pretty parameter should either be a boolean or whitespace only string'
    );
  }
  assertSafeCompilerOptions(options);
  this.debug = false !== options.compileDebug;
  this.indents = 0;
  this.parentIndents = 0;
  this.terse = false;
  this.mixins = {};
  this.dynamicMixins = false;
  this.eachCount = 0;
  if (options.doctype) this.setDoctype(options.doctype);
  this.runtimeFunctionsUsed = [];
  this.inlineRuntimeFunctions = options.inlineRuntimeFunctions || false;
  if (this.debug && this.inlineRuntimeFunctions) {
    this.runtimeFunctionsUsed.push('rethrow');
  }
}""")
v3 = swap(v3, "function toConstant(src) {\n  return constantinople.toConstant(src, {pug: runtime, pug_interp: undefined});\n}\n",
          "function toConstant(src) {\n  return constantinople.toConstant(src, {pug: runtime, pug_interp: undefined});\n}\n\nfunction isIdentifier(name) {\n  return /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(name);\n}\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: validate that a locally-configured
// theme name matches a small allow-list before using it to pick a CSS
// class, purely so a typo in local config fails loudly instead of
// silently rendering unstyled -- theme names are never attacker input and
// are never spliced into executable code, so this is a config sanity
// check, not a security boundary.
var ALLOWED_THEMES = ['light', 'dark', 'high-contrast'];

function assertKnownTheme(themeName) {
  if (ALLOWED_THEMES.indexOf(themeName) === -1) {
    throw new Error('Unknown theme: ' + themeName);
  }
}

module.exports = { assertKnownTheme };
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
