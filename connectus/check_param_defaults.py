#!/usr/bin/env python3
"""ConnectUs param-default-removal analyzer.

Under ConnectUs, integration parameters no longer arrive with the
type-based defaults the XSOAR/XSIAM framework used to inject. Previously an
unchecked checkbox arrived as ``False`` and an empty numeric field as ``0``;
now an unset param arrives **absent / ``None`` / ``""``**. Integration code
that converts a *defaultless* param read with a strict converter
(``argToBoolean``, ``arg_to_number``, ``arg_to_bool_or_none``, ``int``,
``float``, ``bool``) will therefore raise at runtime — ``argToBoolean(None)``
and ``int(None)`` both throw.

This analyzer parses an integration's ``.py`` file with the stdlib ``ast``
module (no execution, no docker — runs in milliseconds) and classifies every
relevant param read into three buckets:

* **UNSAFE** — a provable break: a strict converter applied to a *literal*
  param read (``params.get("x")`` / ``params["x"]``) with **no** default
  (no second ``.get`` arg, not wrapped in ``... or <default>``), either
  inline or via a single-function local variable.
* **UNCERTAIN** — every static-analysis blind spot, surfaced **by name** as
  "params still to be checked by AI": cross-function value flow,
  dynamic/non-literal access, ``**params`` splats, custom read wrappers, and
  (Tier 2) previously-defaulted YML checkbox/number params read bare. These
  are NOT silently passed — they are the AI's review list.
* **SAFE** — provably fine: ``params.get("x", False)`` / ``... or <default>``.

Output: a single JSON envelope on stdout::

    {
      "integration": "<name>",
      "pass": <bool>,            # true only when unsafe AND uncertain empty
      "unsafe": [{"param","site","reason"}, ...],
      "uncertain": [{"param","site","reason"}, ...],
      "safe_count": <int>,
      "note": "<optional, e.g. non-Python short-circuit>"
    }

Exit code is ``0`` when ``pass`` is true, ``1`` otherwise — so the script
drops straight into an exit-code gate runner.

Non-Python integrations (``.js`` / ``.ps1``) are **short-circuited**: the
analyzer reports ``pass: true`` with a "not analyzed: non-Python" note,
mirroring how ``check_auth_parity`` treats non-Python with
``ERROR_NON_PYTHON``.

Usage::

    python3 connectus/check_param_defaults.py <integration_dir>
    python3 connectus/check_param_defaults.py --integration-id <id>
    python3 connectus/check_param_defaults.py <dir> --ignore-params a b
    python3 connectus/check_param_defaults.py <dir> --ignore-params-file PATH
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path
from typing import Iterable, Optional

try:  # PyYAML is available across the connectus tooling; degrade gracefully.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - exercised only when PyYAML is absent
    yaml = None  # type: ignore

# Make sibling connectus modules importable regardless of CWD.
sys.path.insert(0, str(Path(__file__).resolve().parent))

_REPO_ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Strict converters that raise (or silently flip) on ``None`` / ``""``.
STRICT_CONVERTERS = frozenset(
    {
        "argToBoolean",
        "arg_to_bool_or_none",
        "arg_to_number",
        "int",
        "float",
        "bool",
    }
)

#: Names that denote the params mapping in idiomatic integration code.
PARAMS_NAMES = frozenset({"params", "param"})

#: Names that denote the command-args mapping (out of scope for this check).
ARGS_NAMES = frozenset({"args", "arg"})

#: Inline suppression marker (mirrors ruff's ``# noqa`` convention).
NOQA_MARKER = "noqa: ucp-param-default"

#: YML param ``type`` codes that used to carry an injected default:
#: 8 = checkbox/boolean (was ``False``). Numeric free-text fields could
#: arrive as ``0`` historically; type 0 (short text) did not.
CHECKBOX_TYPES = frozenset({8})

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

# --------------------------------------------------------------------------
# Verdict bucket reasons (kept as constants so tests/users see stable text)
# --------------------------------------------------------------------------

REASON_INLINE_CONVERT = (
    "strict converter {conv}() applied to a defaultless param read; "
    "under ConnectUs this param can arrive absent/None and the conversion "
    "will raise. Add a default (e.g. .get(\"{param}\", <default>) or "
    "`... or <default>`)."
)
REASON_LOCAL_CONVERT = (
    "param read into a local variable with no default, then passed to "
    "strict converter {conv}(); will raise on an absent ConnectUs param. "
    "Add a default at the read site."
)
REASON_CROSS_FUNCTION = (
    "param read defaultless and handed across a call boundary; the strict "
    "conversion happens in another function so this needs manual review "
    "(cross-function value flow)."
)
REASON_DYNAMIC_ACCESS = (
    "param accessed via a non-literal / dynamic key (variable, loop, "
    "comprehension); the analyzer cannot bind the param name — needs manual "
    "review."
)
REASON_SPLAT = (
    "params passed via a **params splat; individual param defaults cannot be "
    "verified statically — needs manual review."
)
REASON_CUSTOM_WRAPPER = (
    "param read through a custom wrapper ({wrapper}()) then converted; the "
    "wrapper body is opaque to the analyzer — needs manual review."
)
REASON_YML_CHECKBOX_BARE = (
    "checkbox/boolean param (YML type 8) read without a default; it used to "
    "arrive as False and now arrives absent — verify the bare read still "
    "behaves correctly (silent behavior change)."
)


# --------------------------------------------------------------------------
# Small data carriers
# --------------------------------------------------------------------------


class Finding:
    """A single classified param read."""

    __slots__ = ("param", "line", "reason", "bucket")

    def __init__(self, param: str, line: int, reason: str, bucket: str):
        self.param = param
        self.line = line
        self.reason = reason
        self.bucket = bucket  # "unsafe" | "uncertain"

    def as_dict(self, filename: str) -> dict:
        return {
            "param": self.param,
            "site": f"{filename}:{self.line}",
            "reason": self.reason,
        }


# --------------------------------------------------------------------------
# AST helpers
# --------------------------------------------------------------------------


def _str_const(node: ast.AST) -> Optional[str]:
    """Return the string value of a constant node, else ``None``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_params_expr(node: ast.AST) -> bool:
    """True if ``node`` evaluates to the params mapping.

    Matches ``params`` / ``param`` (Name) and ``demisto.params()`` (Call).
    """
    if isinstance(node, ast.Name) and node.id in PARAMS_NAMES:
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "params"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "demisto"
    ):
        return True
    return False


def _is_args_expr(node: ast.AST) -> bool:
    """True if ``node`` evaluates to the command-args mapping.

    Matches ``args`` / ``arg`` (Name) and ``demisto.args()`` (Call). Command
    arguments are supplied at call time and are OUT OF SCOPE for the
    ConnectUs param-default-removal change — reads off them must not be
    flagged or treated as opaque wrappers.
    """
    if isinstance(node, ast.Name) and node.id in ARGS_NAMES:
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "args"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "demisto"
    ):
        return True
    return False


def _param_read(node: ast.AST) -> tuple[Optional[str], bool, bool]:
    """Classify an expression as a param read.

    Returns ``(param_name, has_default, is_dynamic)``:

    * ``param_name`` — literal param id if resolvable, else ``None``.
    * ``has_default`` — True if a ``.get(name, <default>)`` second arg is
      present (a built-in fallback).
    * ``is_dynamic`` — True when the access is a param read but the key is a
      non-literal (variable / expression), so the name cannot be bound.

    Non-param expressions return ``(None, False, False)``.
    """
    # params.get("x") / params.get("x", default) / params.get(var)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and _is_params_expr(node.func.value)
    ):
        if not node.args:
            return None, False, False
        key = node.args[0]
        name = _str_const(key)
        if name is None:
            return None, False, True  # dynamic key
        has_default = len(node.args) >= 2 or bool(node.keywords)
        return name, has_default, False
    # params["x"] / params[var]
    if isinstance(node, ast.Subscript) and _is_params_expr(node.value):
        key = node.slice
        # py3.9+: slice is the expression directly
        name = _str_const(key)
        if name is None:
            return None, False, True
        return name, False, False
    return None, False, False


def _strip_or_default(node: ast.AST) -> ast.AST:
    """If ``node`` is ``X or <default>``, return ``X``; else ``node``.

    A param read wrapped in ``... or <default>`` is given a fallback, so the
    underlying read should be treated as defaulted (safe).
    """
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        # The param read is the first operand of the `or` chain.
        return node.values[0]
    return node


def _converter_name(call: ast.Call) -> Optional[str]:
    """Return the converter callee name if ``call`` is a strict converter."""
    func = call.func
    if isinstance(func, ast.Name) and func.id in STRICT_CONVERTERS:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in STRICT_CONVERTERS:
        return func.attr
    return None


# --------------------------------------------------------------------------
# Core analyzer
# --------------------------------------------------------------------------


class _ParamDefaultVisitor(ast.NodeVisitor):
    """Walk a module, classifying param reads into unsafe / uncertain.

    Implements Tier 1 (inline converters), a single-function def-use pass
    (value stored in a local var then converted), and surfacing of every
    blind spot (dynamic access, splat, custom wrapper, cross-function flow)
    as uncertain.
    """

    def __init__(self, ignore_params: set[str], noqa_lines: set[int]):
        self.ignore_params = ignore_params
        self.noqa_lines = noqa_lines
        self.findings: list[Finding] = []
        self.safe_params: set[str] = set()
        self._seen: set[tuple[str, int, str]] = set()
        # Per-function def-use scratch: local var name -> (param, line, has_default)
        self._scope_stack: list[dict[str, tuple[str, int, bool]]] = [{}]

    # -- emission ------------------------------------------------------
    def _emit(self, param: Optional[str], line: int, reason: str, bucket: str):
        if line in self.noqa_lines:
            return
        if param is not None and param in self.ignore_params:
            return
        key = (param or "<dynamic>", line, bucket)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(param or "<dynamic>", line, reason, bucket))

    def _mark_safe(self, param: str):
        self.safe_params.add(param)

    @property
    def _scope(self) -> dict[str, tuple[str, int, bool]]:
        return self._scope_stack[-1]

    # -- scope management ----------------------------------------------
    def _enter_function(self, node: ast.AST):
        self._scope_stack.append({})
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef):  # noqa: N802
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):  # noqa: N802
        self._enter_function(node)

    # -- def-use: record `var = params.get("x")` -----------------------
    def visit_Assign(self, node: ast.Assign):  # noqa: N802
        value = _strip_or_default(node.value)
        name, has_default, is_dynamic = _param_read(value)
        if name is not None and len(node.targets) == 1 and isinstance(
            node.targets[0], ast.Name
        ):
            # Treat `or <default>` as defaulted.
            effective_default = has_default or (
                isinstance(node.value, ast.BoolOp)
                and isinstance(node.value.op, ast.Or)
            )
            self._scope[node.targets[0].id] = (name, node.lineno, effective_default)
        # Still descend (the value may itself contain a converter call).
        self.generic_visit(node)

    # -- the workhorse: converter calls + splats -----------------------
    def visit_Call(self, node: ast.Call):  # noqa: N802
        self._check_splat(node)
        conv = _converter_name(node)
        if conv is not None and node.args:
            self._classify_converter(node, conv)
        self.generic_visit(node)

    def _check_splat(self, node: ast.Call):
        for kw in node.keywords:
            if kw.arg is None and _is_params_expr(kw.value):  # **params
                self._emit(None, node.lineno, REASON_SPLAT, "uncertain")

    def _classify_converter(self, call: ast.Call, conv: str):
        raw_arg = call.args[0]
        # ``converter(X or <default>)`` gives the read a fallback -> safe.
        or_defaulted = isinstance(raw_arg, ast.BoolOp) and isinstance(
            raw_arg.op, ast.Or
        )
        arg = _strip_or_default(raw_arg)

        # Direct inline param read: converter(params.get("x")) etc.
        name, has_default, is_dynamic = _param_read(arg)
        if is_dynamic:
            if or_defaulted:
                return  # dynamic key but with an `or` fallback -> safe enough
            self._emit(None, call.lineno, REASON_DYNAMIC_ACCESS, "uncertain")
            return
        if name is not None:
            if has_default or or_defaulted:
                self._mark_safe(name)
                return
            self._emit(
                name,
                call.lineno,
                REASON_INLINE_CONVERT.format(conv=conv, param=name),
                "unsafe",
            )
            return

        # Converter on a local variable: resolve via def-use.
        if isinstance(arg, ast.Name):
            record = self._scope.get(arg.id)
            if record is not None:
                pname, pline, pdefault = record
                if pdefault:
                    self._mark_safe(pname)
                else:
                    self._emit(
                        pname,
                        call.lineno,
                        REASON_LOCAL_CONVERT.format(conv=conv, param=pname),
                        "unsafe",
                    )
                return
            # Unknown local — could be a cross-function param; can't bind.
            return

        # Converter on another call expression.
        if isinstance(arg, ast.Call):
            # ``args.get("x")`` / ``demisto.args().get("x")`` etc. are command
            # arguments — out of scope. Drop silently.
            if (
                isinstance(arg.func, ast.Attribute)
                and arg.func.attr == "get"
                and _is_args_expr(arg.func.value)
            ):
                return
            # Only a BARE-NAME call (``get_param("x")``) is treated as a custom
            # param-read wrapper worth surfacing. An attribute ``.get`` on some
            # unrelated object (a response dict, a sub-config) is not a param
            # read and must not be flagged.
            wrapper, wrap_name = self._wrapper_param(arg)
            if wrapper is not None:
                self._emit(
                    wrap_name,
                    call.lineno,
                    REASON_CUSTOM_WRAPPER.format(wrapper=wrapper),
                    "uncertain",
                )
            return

    @staticmethod
    def _wrapper_param(call: ast.Call) -> tuple[Optional[str], Optional[str]]:
        """If ``call`` is a bare-name custom read wrapper, return (name, param).

        Only ``get_param("x")``-style bare-name calls qualify. Attribute calls
        (``x.get(...)``, ``self.foo(...)``) are deliberately excluded: a
        ``.get`` on a non-params object is an unrelated dict read, and other
        method calls are too generic to attribute to a config param without
        producing noise.
        """
        func = call.func
        if not isinstance(func, ast.Name):
            return None, None
        wrapper_name = func.id
        # First string-literal arg, if any, is the likely param id.
        param = None
        if call.args:
            param = _str_const(call.args[0])
        return wrapper_name, param


# --------------------------------------------------------------------------
# Cross-function flow detection (lightweight, single pass over the tree)
# --------------------------------------------------------------------------


def _collect_cross_function(tree: ast.AST) -> set[str]:
    """Find params read defaultless and passed into another function call.

    Returns param names that are read with no default and then handed to a
    *user* call (not a strict converter, not ``.get``) as an argument — a
    cross-function value flow the single-function pass cannot follow.
    """
    flagged: set[str] = set()

    class _V(ast.NodeVisitor):
        def __init__(self):
            self.local_param: dict[str, str] = {}  # var -> param (defaultless)

        def _enter_function(self, node):
            saved = self.local_param
            self.local_param = {}
            self.generic_visit(node)
            self.local_param = saved

        def visit_FunctionDef(self, node):  # noqa: N802
            self._enter_function(node)

        def visit_AsyncFunctionDef(self, node):  # noqa: N802
            self._enter_function(node)

        def visit_Assign(self, node):  # noqa: N802
            value = _strip_or_default(node.value)
            name, has_default, is_dynamic = _param_read(value)
            if (
                name is not None
                and not has_default
                and not (
                    isinstance(node.value, ast.BoolOp)
                    and isinstance(node.value.op, ast.Or)
                )
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                self.local_param[node.targets[0].id] = name
            self.generic_visit(node)

        def visit_Call(self, node):  # noqa: N802
            # Skip strict converters and `.get` — those are handled elsewhere.
            if _converter_name(node) is None and not (
                isinstance(node.func, ast.Attribute) and node.func.attr == "get"
            ):
                for a in node.args:
                    if isinstance(a, ast.Name) and a.id in self.local_param:
                        flagged.add(self.local_param[a.id])
            self.generic_visit(node)

    _V().visit(tree)
    return flagged


# --------------------------------------------------------------------------
# noqa scanning
# --------------------------------------------------------------------------


def _noqa_lines(source: str) -> set[int]:
    lines: set[int] = set()
    for i, text in enumerate(source.splitlines(), start=1):
        if NOQA_MARKER in text:
            lines.add(i)
    return lines


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def analyze_source(
    source: str,
    filename: str = "<string>",
    *,
    ignore_params: Optional[Iterable[str]] = None,
    yml_params: Optional[dict[str, dict]] = None,
    integration: Optional[str] = None,
) -> dict:
    """Analyze Python ``source`` and return the three-bucket verdict dict.

    ``yml_params`` (Tier 2) maps param id -> ``{"type": int|None,
    "defaultvalue": str|None}`` so checkbox/number params read bare can be
    surfaced as uncertain.
    """
    ignore = set(ignore_params or ())
    noqa = _noqa_lines(source)
    tree = ast.parse(source, filename=filename)

    visitor = _ParamDefaultVisitor(ignore, noqa)
    visitor.visit(tree)

    # Cross-function flow -> uncertain (only if not already unsafe/safe).
    decided = {f.param for f in visitor.findings} | visitor.safe_params
    for pname in sorted(_collect_cross_function(tree)):
        if pname in decided or pname in ignore:
            continue
        visitor.findings.append(
            Finding(pname, 0, REASON_CROSS_FUNCTION, "uncertain")
        )
        decided.add(pname)

    # Tier 2: previously-defaulted checkbox params read bare. Only flag when
    # the read ESCAPES a pure-boolean context — a value used only for its
    # truthiness behaves the same whether it's the old False or the new None.
    if yml_params:
        bare = _bare_checkbox_reads(tree)
        for pname, (line, escapes) in sorted(bare.items()):
            if pname in decided or pname in ignore or line in noqa:
                continue
            if not escapes:
                continue
            meta = yml_params.get(pname)
            if meta and meta.get("type") in CHECKBOX_TYPES:
                visitor.findings.append(
                    Finding(pname, line, REASON_YML_CHECKBOX_BARE, "uncertain")
                )
                decided.add(pname)

    unsafe = [f.as_dict(filename) for f in visitor.findings if f.bucket == "unsafe"]
    uncertain = [
        f.as_dict(filename) for f in visitor.findings if f.bucket == "uncertain"
    ]
    safe_count = len(visitor.safe_params)

    return {
        "integration": integration or Path(filename).stem,
        "pass": not unsafe and not uncertain,
        "unsafe": unsafe,
        "uncertain": uncertain,
        "safe_count": safe_count,
    }


def _is_boolean_context(node: ast.AST, parent: Optional[ast.AST]) -> bool:
    """True if ``node`` (with the given ``parent``) sits in a pure-boolean use.

    A param value used ONLY for its truthiness behaves identically whether it
    is the old injected ``False``/``0`` or the new absent ``None`` — all are
    falsey. Such uses are safe and must not be flagged. Recognized contexts:

    * the test of an ``if`` / ``while`` / ``assert`` / ternary (``IfExp``);
    * a ``not`` operand (``UnaryOp(Not)``);
    * an operand of ``and`` / ``or`` (``BoolOp``);
    * a comprehension ``if`` filter.

    Comparisons (``== False``, ``is None``) and arithmetic are NOT boolean
    contexts — there the None-vs-False distinction can matter.
    """
    if parent is None:
        return False
    if isinstance(parent, (ast.If, ast.While)) and parent.test is node:
        return True
    if isinstance(parent, ast.Assert) and parent.test is node:
        return True
    if isinstance(parent, ast.IfExp) and parent.test is node:
        return True
    if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
        return True
    if isinstance(parent, ast.BoolOp):
        return True
    if isinstance(parent, ast.comprehension):
        return True
    return False


def _bare_checkbox_reads(tree: ast.AST) -> dict[str, tuple[int, bool]]:
    """Map param id -> ``(line, escapes_boolean_context)`` for bare reads.

    A "bare" read is ``params.get("x")`` / ``params["x"]`` not wrapped in a
    converter and not given a default. ``escapes_boolean_context`` is True if
    ANY read site of the param is used somewhere other than a pure-boolean
    context — meaning the old ``False``/``0`` could have mattered and the read
    deserves AI review. If every read is purely truthy/falsey, the param is
    safe under default removal.
    """
    out: dict[str, tuple[int, bool]] = {}

    # Attach parent pointers so each read knows its enclosing expression.
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent

    def _record(node: ast.AST, name: str):
        parent = parents.get(id(node))
        escapes = not _is_boolean_context(node, parent)
        node_line = getattr(node, "lineno", 0)
        line, prev_escapes = out.get(name, (node_line, False))
        out[name] = (line, prev_escapes or escapes)

    class _V(ast.NodeVisitor):
        def visit_Call(self, node):  # noqa: N802
            name, has_default, is_dynamic = _param_read(node)
            if name is not None and not has_default:
                _record(node, name)
            self.generic_visit(node)

        def visit_Subscript(self, node):  # noqa: N802
            name, has_default, is_dynamic = _param_read(node)
            if name is not None:
                _record(node, name)
            self.generic_visit(node)

    _V().visit(tree)
    return out


# --------------------------------------------------------------------------
# YML / integration-directory handling
# --------------------------------------------------------------------------


def _load_yml_params(yml_path: Path) -> tuple[Optional[str], dict[str, dict], str]:
    """Return ``(integration_name, {param: meta}, script_type)`` from a YML.

    ``script_type`` is the lowercased ``script.type`` (python/javascript/
    powershell) or ``""`` when unknown. Falls back to an empty mapping if
    PyYAML is unavailable or the file is unparseable.
    """
    if yaml is None:
        return None, {}, ""
    try:
        data = yaml.safe_load(yml_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return None, {}, ""
    name = data.get("name") if isinstance(data, dict) else None
    script_type = ""
    params: dict[str, dict] = {}
    if isinstance(data, dict):
        script = data.get("script")
        if isinstance(script, dict):
            script_type = str(script.get("type", "")).lower()
        for entry in data.get("configuration", []) or []:
            if not isinstance(entry, dict):
                continue
            pname = entry.get("name")
            if not pname:
                continue
            params[pname] = {
                "type": entry.get("type"),
                "defaultvalue": entry.get("defaultvalue"),
            }
    return name, params, script_type


def _detect_language(directory: Path, base: str) -> str:
    """Return python/javascript/powershell based on the code file present."""
    for ext, lang in (("py", "python"), ("js", "javascript"), ("ps1", "powershell")):
        if (directory / f"{base}.{ext}").is_file():
            return lang
    return ""


def _integration_base(directory: Path) -> str:
    """Best-effort integration base name from the directory contents."""
    yml = next(iter(sorted(directory.glob("*.yml"))), None)
    if yml is not None:
        return yml.stem
    return directory.name


def analyze_integration(
    directory: str | Path,
    *,
    ignore_params: Optional[Iterable[str]] = None,
) -> dict:
    """Analyze an integration directory; short-circuit non-Python.

    Resolves the integration's code + YML files from ``directory``, then:
    * for Python, runs :func:`analyze_source` with Tier 2 YML enrichment;
    * for JS / PS, returns a passing verdict with a non-Python note.
    """
    directory = Path(directory)
    base = _integration_base(directory)
    yml_path = directory / f"{base}.yml"
    name, yml_params, script_type = (
        _load_yml_params(yml_path) if yml_path.is_file() else (None, {}, "")
    )
    language = _detect_language(directory, base) or script_type

    integration_name = name or base

    if language and language != "python":
        return {
            "integration": integration_name,
            "pass": True,
            "unsafe": [],
            "uncertain": [],
            "safe_count": 0,
            "note": f"not analyzed: non-Python ({language})",
        }

    py_path = directory / f"{base}.py"
    if not py_path.is_file():
        return {
            "integration": integration_name,
            "pass": True,
            "unsafe": [],
            "uncertain": [],
            "safe_count": 0,
            "note": "not analyzed: no Python source found",
        }

    source = py_path.read_text(encoding="utf-8")
    return analyze_source(
        source,
        filename=py_path.name,
        ignore_params=ignore_params,
        yml_params=yml_params,
        integration=integration_name,
    )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _resolve_integration_path(integration_id: str) -> Path:
    """Resolve an integration directory from its workflow-CSV id."""
    try:
        from workflow_state import get_integration_files  # type: ignore

        files = get_integration_files(integration_id)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"could not resolve --integration-id {integration_id!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if "error" in files:
        raise ValueError(f"--integration-id {integration_id!r}: {files['error']}")
    yml_rel = files.get("yml")
    if not yml_rel:
        raise ValueError(
            f"--integration-id {integration_id!r}: workflow row has no YML path."
        )
    return (_REPO_ROOT / yml_rel).resolve().parent


def _load_ignore_file(path: Path) -> set[str]:
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def _render_human(verdict: dict) -> str:
    """Human-readable summary the AI presents to the user."""
    lines = [f"Integration: {verdict['integration']}"]
    if verdict.get("note"):
        lines.append(f"  {verdict['note']}")
    lines.append(f"  PASS: {verdict['pass']}")
    if verdict["unsafe"]:
        lines.append(f"  UNSAFE (provable breaks) [{len(verdict['unsafe'])}]:")
        for e in verdict["unsafe"]:
            lines.append(f"    - {e['param']} @ {e['site']}")
            lines.append(f"        {e['reason']}")
    if verdict["uncertain"]:
        lines.append(
            f"  UNCERTAIN (params still to be checked by AI) "
            f"[{len(verdict['uncertain'])}]:"
        )
        for e in verdict["uncertain"]:
            lines.append(f"    - {e['param']} @ {e['site']}")
            lines.append(f"        {e['reason']}")
    lines.append(f"  safe reads: {verdict['safe_count']}")
    return "\n".join(lines)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an integration for ConnectUs param-default-removal "
            "breakage (three buckets: unsafe / uncertain / safe)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "integration_path",
        nargs="?",
        help="Path to the integration directory (or pass --integration-id).",
    )
    parser.add_argument(
        "--integration-id",
        help="Resolve the integration directory from the workflow CSV id.",
    )
    parser.add_argument(
        "--ignore-params",
        nargs="*",
        default=[],
        help="Param names to treat as known-safe (recorded as resolved).",
    )
    parser.add_argument(
        "--ignore-params-file",
        help="File of param names to ignore (one per line; # comments ok).",
    )
    parser.add_argument(
        "--human",
        action="store_true",
        help="Also print a human-readable summary to stderr.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if not args.integration_path and not args.integration_id:
        print(
            "error: provide an integration_path or --integration-id",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        if args.integration_path:
            directory = Path(args.integration_path).resolve()
            if not directory.is_dir():
                alt = (_REPO_ROOT / args.integration_path).resolve()
                directory = alt if alt.is_dir() else directory
        else:
            directory = _resolve_integration_path(args.integration_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not directory.is_dir():
        print(f"error: not a directory: {directory}", file=sys.stderr)
        return EXIT_USAGE

    ignore: set[str] = set(args.ignore_params or ())
    if args.ignore_params_file:
        ignore |= _load_ignore_file(Path(args.ignore_params_file))

    verdict = analyze_integration(directory, ignore_params=ignore)

    print(json.dumps(verdict, indent=2, sort_keys=True))
    if args.human:
        print(_render_human(verdict), file=sys.stderr)

    return EXIT_PASS if verdict["pass"] else EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
