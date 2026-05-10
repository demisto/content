"""Determine which YML configuration parameters each command in an integration uses.

This tool combines two complementary analysis methods:

1. **Static analysis (Python AST)** - parses the integration's ``.py`` file
   without executing it, traces ``params`` from ``demisto.params()`` through
   ``main()`` and into the per-command handler (up to 3 nesting levels).
   Resolves Pydantic ``Field(alias=...)`` mappings back to YML names.

2. **Dynamic analysis (sentinel-based)** - prepares the integration with
   ``demisto-sdk prepare-content``, runs each command once in a child Python
   process with every YML param set to a unique ``SENTINEL_PARAM_<name>``
   string, captures all outgoing HTTP traffic with ``capture_proxy``, and
   greps each request for the sentinels.

Error policy: this analyzer **fails loudly** on every error. The only
graceful skip is "the analysis method does not apply to this language"
(e.g., AST analysis on a JavaScript or PowerShell integration logs a skip
and returns an empty static set). Any other failure — unreadable files,
real Python ``SyntaxError`` in the integration source, ``prepare-content``
errors, the dynamic child crashing before issuing any HTTP request,
dynamic timeouts, or ``demisto-sdk`` not on ``PATH`` when dynamic was
requested — propagates to the CLI and exits non-zero. ``--static-only``
skips dynamic analysis explicitly.

Usage::

    python3 connectus/check_command_params.py <integration_path> \\
        [--commands cmd1 cmd2 ...] \\
        [--static-only] \\
        [--ignore-params PARAM [PARAM ...]] \\
        [--ignore-params-file PATH] \\
        [--use-integration-docker]

``--use-integration-docker`` is opt-in. By default the per-command
child runs in the pinned ``demisto/py3-native`` image (one image, all
integrations, fully reproducible). With the flag set, the analyzer
honours ``script.dockerimage`` from the integration's YML so commands
run inside the integration's own production runtime. Use this when an
integration reports ``module_not_found`` under the default image.

Output schema (single JSON document on stdout)::

    {
      "integration": "<display name>",
      "commands": {
        "<cmd>": ["<param>", ...]   # case-sensitive sorted list
      },
      "diagnostics": {              # dynamic-only; omitted under --static-only
        "<cmd>": {
          "status": "ok" | "ok_no_capture" | "param_caused_failure"
                  | "no_data" | "timeout" | "docker_error"
                  | "module_not_found",
          "captured_requests": <int>,
          "failure_excerpt": "<str, optional, max 500 chars>",
          "failing_params": ["<param>", ...],  # only if param_caused_failure
          "missing_module": "<str>"            # only if module_not_found
        }
      }
    }

Status enum:

* ``ok`` — command completed (rc=0 OR rc=7 with captures>0), at least one
  HTTP request was captured by the proxy.
* ``ok_no_capture`` — command completed cleanly (rc=0) but the proxy saw
  zero HTTP requests. The command may be a pure local helper, or the
  seeded params didn't reach an HTTP path.
* ``param_caused_failure`` — command failed AND the failure message
  contains one or more ``SENTINEL_PARAM_<name>`` substrings; the matched
  names are listed in ``failing_params`` (and elevated to relevant for
  that command in ``commands``).
* ``no_data`` — command failed but no specific failing param could be
  identified. ``failure_excerpt`` is still informative.
* ``timeout`` — child process hit the per-command timeout.
* ``docker_error`` — Docker invocation itself failed (rc=125/126/127),
  not the wrapped integration child.
* ``module_not_found`` — Child process crashed with ``ModuleNotFoundError``.
  Integration needs a third-party package not present in the runtime image
  (``demisto/py3-native:8.9.0.114862``). The calling agent must inspect
  the integration source manually (analogous to JS / PowerShell handling).
  The missing package name is in ``missing_module``.

The ``diagnostics`` field is internal AI-consumed metadata: it is
emitted to stdout to aid the calling agent, but the calling agent MUST
NOT persist it into downstream pipeline data. Under ``--static-only``
the field is omitted entirely.

**Hybrid Scope-1 narrowing (Fix 7).** When a command's dynamic phase
actually captured ``>=1`` HTTP request **and** at least one sentinel
hit was detected, the analyzer assumes that captured-set is an
authoritative bound on which params reached the wire for that command.
It then **narrows** the static Scope-1 set (pre-dispatch params shared
across all commands — typically the ``Client(...)`` fan-out pattern in
``main()``) to the intersection with the captured params. Scope-2
(per-command handler-traced params) is preserved unchanged. This kills
the dominant false-positive class where every command appears to use
every Client-init param. The narrowed commands are flagged in
``diagnostics`` with ``scope_1_narrowed: true`` and a
``scope_1_dropped`` list. When dynamic did not capture (status
``ok_no_capture``, ``module_not_found``, etc.) or hit zero sentinels,
the analyzer falls back to the full ``scope_1 | scope_2`` static union
and adds no extra diagnostic field. Narrowing is silent in
``commands`` and visible in ``diagnostics`` only.

``commands`` lists, for each command, the params that are relevant to
it (case-sensitive, sorted). Params absent from the list (or excluded
via ``--ignore-params`` / ``--ignore-params-file``) are not relevant or
were explicitly excluded.

Example::

    {
      "integration": "QRadar v3",
      "commands": {
        "test-module": ["adv_params", "credentials", "url"],
        "fetch-incidents": ["credentials", "max_fetch", "url"]
      },
      "diagnostics": {
        "test-module": {
          "status": "param_caused_failure",
          "captured_requests": 0,
          "failure_excerpt": "DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params",
          "failing_params": ["adv_params"]
        },
        "fetch-incidents": {"status": "ok", "captured_requests": 3}
      }
    }

All informational messages go to stderr. See
``connectus/check_command_params_design.md`` for the full design.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Local import - this script lives next to capture_proxy.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from capture_proxy import CaptureProxy  # noqa: E402


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

PARAMS_VAR_ALIASES = {"params", "integration_params", "config", "PARAMS"}
URL_PARAM_NAMES = {"url", "server", "base_url", "host", "endpoint"}
SENTINEL_PREFIX = "SENTINEL_PARAM_"
DEFAULT_DYNAMIC_TIMEOUT_S = 30
COMMON_SERVER_SENTINEL = "class DemistoException"
COMMON_SERVER_PYTHON_REL = "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py"
DEMISTOMOCK_REL_CANDIDATES = (
    "Packs/Base/Scripts/CommonServerPython/demistomock.py",
    "Tests/demistomock/demistomock.py",
    "demistomock/demistomock.py",
)
# Pinned to a specific build of the demisto/py3-native image. The analyzer
# always runs the per-command child in this image (unless overridden via
# ``--docker-image`` for testing/debugging). If an integration needs a
# different runtime (e.g., a third-party Python package not present here),
# the child crashes with ``ModuleNotFoundError`` and the analyzer reports
# ``status: module_not_found`` so the calling agent can handle it manually.
DEFAULT_DOCKER_IMAGE = "demisto/py3-native:8.9.0.114862"
DOCKER_DAEMON_RC = 125  # `docker run` could not start the container
DOCKER_NOT_EXECUTABLE_RC = 126
DOCKER_CMD_NOT_FOUND_RC = 127


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------


def find_integration_files(integration_path: Path) -> tuple[Path, Path | None]:
    """Locate the integration YML and (optional) Python source.

    Returns ``(yml_path, py_path_or_None)``. Raises ``FileNotFoundError`` if
    no YML is found.
    """
    if not integration_path.is_dir():
        raise FileNotFoundError(f"Integration path is not a directory: {integration_path}")
    ymls = sorted(p for p in integration_path.glob("*.yml") if not p.name.endswith("_test.yml"))
    if not ymls:
        raise FileNotFoundError(f"No .yml file found in {integration_path}")
    yml_path = ymls[0]
    pys = [
        p for p in integration_path.glob("*.py")
        if not p.name.endswith("_test.py") and not p.name.startswith("test_")
    ]
    py_path = pys[0] if pys else None
    return yml_path, py_path


def load_yml(yml_path: Path) -> dict[str, Any]:
    """Load and return the integration YML as a dict."""
    with yml_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# --------------------------------------------------------------------------
# YML interrogation
# --------------------------------------------------------------------------


def get_yml_params(yml_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of param dicts from the YML configuration block."""
    config = yml_data.get("configuration") or []
    return [p for p in config if isinstance(p, dict) and p.get("name")]


def get_param_names(yml_data: dict[str, Any]) -> list[str]:
    return [p["name"] for p in get_yml_params(yml_data)]


def discover_commands(yml_data: dict[str, Any]) -> list[str]:
    """Discover all commands the integration supports from its YML."""
    script = yml_data.get("script") or {}
    commands: list[str] = ["test-module"]
    for entry in script.get("commands") or []:
        if isinstance(entry, dict) and entry.get("name"):
            commands.append(entry["name"])
    if script.get("isfetch"):
        commands.append("fetch-incidents")
    if script.get("isfetchevents"):
        commands.append("fetch-events")
    if script.get("isRemoteSyncIn"):
        commands.extend(["get-remote-data", "get-modified-remote-data"])
    if script.get("isRemoteSyncOut"):
        commands.append("update-remote-system")
    if script.get("longRunning"):
        commands.append("long-running-execution")
    # de-dup, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for c in commands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def display_name(yml_data: dict[str, Any], fallback: str) -> str:
    return yml_data.get("display") or yml_data.get("name") or fallback


# --------------------------------------------------------------------------
# Ignore-list plumbing
# --------------------------------------------------------------------------


def load_ignore_params(inline: list[str] | None, file_path: Path | None) -> set[str]:
    """Union the inline ``--ignore-params`` list with a file-supplied list."""
    out: set[str] = set(inline or [])
    if file_path is not None:
        if not file_path.is_file():
            raise FileNotFoundError(f"--ignore-params-file not found: {file_path}")
        for raw in file_path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                out.add(line)
    return out


# --------------------------------------------------------------------------
# Static analysis (AST)
# --------------------------------------------------------------------------


def _is_demisto_params_call(node: ast.AST) -> bool:
    """True if *node* is the AST shape ``demisto.params()`` (no args).

    Recognizes the chained inline pattern that many integrations use
    instead of binding ``params = demisto.params()`` once: e.g.

        if demisto.params().get("isFetch"):
            ...

    Without this check the visitor only matches the receiver-is-a-Name
    form (``params.get("isFetch")``) and silently misses every chained
    call.
    """
    if not isinstance(node, ast.Call):
        return False
    if node.args or node.keywords:
        return False
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "params"
        and isinstance(func.value, ast.Name)
        and func.value.id == "demisto"
    )


class _ParamAccessVisitor(ast.NodeVisitor):
    """Collects ``params.get('X')`` / ``params['X']`` / ``params.X`` accesses.

    Recognizes both forms of the receiver:

    * a bare ``Name`` whose id is in ``params_var_names`` (e.g. ``params``,
      ``PARAMS``, ``integration_params``) — the classic local-variable
      pattern.
    * a chained ``demisto.params()`` call expression — the inline pattern
      used by integrations that don't bind a local variable. Without this
      branch, code like ``demisto.params().get("isFetch")`` would be
      silently ignored even when the visitor walks the right function.
    """

    def __init__(self, params_var_names: set[str], pydantic_aliases: dict[str, str]):
        self._vars = params_var_names
        self._aliases = pydantic_aliases
        self.found: set[str] = set()

    def _receiver_is_params(self, node: ast.AST) -> bool:
        """True if *node* refers to a params object (Name in candidates OR demisto.params())."""
        if isinstance(node, ast.Name) and node.id in self._vars:
            return True
        return _is_demisto_params_call(node)

    def visit_Call(self, node: ast.Call) -> None:
        # <receiver>.get("X")  or  <receiver>.get("X", default)
        # where <receiver> is `params` (Name) or `demisto.params()` (Call).
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and self._receiver_is_params(func.value)
            and node.args
        ):
            arg0 = node.args[0]
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                self.found.add(arg0.value)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # <receiver>["X"]
        if self._receiver_is_params(node.value):
            sl = node.slice
            if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                self.found.add(sl.value)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # <receiver>.X  -> if Pydantic alias known, resolve to YML name; else raw attr.
        if self._receiver_is_params(node.value):
            attr = node.attr
            # Skip method-y attributes that are clearly not params.
            if attr not in {"get", "items", "keys", "values", "pop", "update", "setdefault", "copy"}:
                self.found.add(self._aliases.get(attr, attr))
        self.generic_visit(node)


def find_pydantic_aliases(tree: ast.AST) -> dict[str, str]:
    """Build {python_attr_name: yml_alias} from ``Field(alias="...")`` calls."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            target_name = _annassign_target(stmt)
            if target_name is None:
                continue
            value = getattr(stmt, "value", None)
            alias = _extract_field_alias(value)
            if alias:
                aliases[target_name] = alias
    return aliases


def _annassign_target(stmt: ast.stmt) -> str | None:
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return stmt.target.id
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id
    return None


def _extract_field_alias(value: ast.AST | None) -> str | None:
    if not isinstance(value, ast.Call):
        return None
    func = value.func
    func_name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    if func_name != "Field":
        return None
    for kw in value.keywords:
        if kw.arg == "alias" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def build_function_map(tree: ast.AST) -> dict[str, ast.FunctionDef]:
    """Map top-level + nested function names to their FunctionDef nodes."""
    out: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # First definition wins; ignore later overrides.
            out.setdefault(node.name, node)  # type: ignore[arg-type]
    return out


def find_main(func_map: dict[str, ast.FunctionDef]) -> ast.FunctionDef | None:
    return func_map.get("main")


def _is_demisto_params_assign(stmt: ast.stmt) -> str | None:
    """If *stmt* is ``<NAME> = demisto.params()``, return ``<NAME>``; else ``None``.

    Recognized forms:

    * ``foo = demisto.params()``                    (simple Assign, single target)
    * ``foo: dict = demisto.params()``              (AnnAssign with value)

    Tuple/list targets and chained assignments (``a = b = demisto.params()``)
    are intentionally ignored — the analyzer doesn't need them in practice
    and the ambiguity isn't worth modelling.
    """
    target: ast.AST | None
    value: ast.AST | None
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        target = stmt.targets[0]
        value = stmt.value
    elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
        target = stmt.target
        value = stmt.value
    else:
        return None
    if not _is_demisto_params_call(value):
        return None
    assert isinstance(target, ast.Name)  # narrowed above
    return target.id


def find_params_var(main_fn: ast.FunctionDef) -> str | None:
    """Find the variable in ``main()`` assigned from ``demisto.params()``."""
    for stmt in ast.walk(main_fn):
        name = _is_demisto_params_assign(stmt)
        if name is not None:
            return name
    return None


def find_module_level_params_vars(tree: ast.AST) -> set[str]:
    """Collect names assigned to ``demisto.params()`` at MODULE scope.

    Many integrations bind a global ``PARAMS = demisto.params()`` near the
    top of the file and then use it from helper functions and command
    handlers without ever passing ``params`` as a formal argument. Without
    this scan, the analyzer's per-handler tracer (which seeds candidate
    names from the function signature) never recognizes accesses to those
    globals and silently drops them.

    Walks only direct children of the ``Module`` node — module scope only.
    Handles both ``Assign`` and ``AnnAssign`` forms via
    :func:`_is_demisto_params_assign`.
    """
    if not isinstance(tree, ast.Module):
        return set()
    out: set[str] = set()
    for stmt in tree.body:
        name = _is_demisto_params_assign(stmt)
        if name is not None:
            out.add(name)
    return out


def find_command_dispatch_line(main_fn: ast.FunctionDef) -> int:
    """Return the line number of the first command-dispatch construct."""
    for node in ast.walk(main_fn):
        if _is_dispatch_node(node):
            return getattr(node, "lineno", 10**9)
    return 10**9  # no dispatch found -> entire function is "pre-dispatch"


def _is_dispatch_node(node: ast.AST) -> bool:
    if isinstance(node, ast.If):
        # if command == "...":  or  if "..." in commands:
        return _refs_command(node.test)
    if isinstance(node, ast.Match):
        return _refs_command(node.subject)
    if isinstance(node, ast.Assign):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "commands" and isinstance(node.value, ast.Dict):
                return True
    return False


def _refs_command(node: ast.AST | None) -> bool:
    if node is None:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id == "command":
            return True
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Attribute) and f.attr == "command":
                return True
    return False


def collect_pre_dispatch_params(
    main_fn: ast.FunctionDef,
    params_vars: set[str],
    aliases: dict[str, str],
    dispatch_line: int,
) -> set[str]:
    """Scope 1 (in-main): collect *unbound* param accesses in main() before dispatch.

    "Unbound" means the read does NOT happen inside an assignment of the
    form ``<Name> = RHS`` where the RHS contains the read. Reads that ARE
    bound to a local variable are tracked separately by
    :func:`build_binding_maps` and attributed only to the commands that
    actually consume that local variable at the dispatch site.

    Statements that are NOT bare ``Name = RHS`` assignments — e.g.
    ``Client(api_key=params.get("apikey"))`` as an expression statement,
    ``return params.get(...)``, ``if params.get(...): ...`` — are walked
    in full and their reads remain in Scope-1 (legitimate fan-out to
    every command).

    Special case: bindings whose target is declared ``global`` at the top
    of ``main()`` (``global BASE_URL; BASE_URL = params.get("url")``)
    are NOT bound locals — they re-bind a module-level name that any
    command handler may read. Those reads are kept in Scope-1 fan-out
    because the global is re-evaluated on every ``main()`` invocation.

    The visitor also catches the chained ``demisto.params().get(...)`` form
    automatically, so callers do NOT need to add that idiom to
    ``params_vars``. Module-level globals (e.g. ``PARAMS = demisto.params()``)
    must be passed in via ``params_vars``.
    """
    globals_in_main = _collect_global_decls(main_fn)
    visitor = _ParamAccessVisitor(params_vars, aliases)
    for stmt in main_fn.body:
        if stmt.lineno >= dispatch_line:
            break
        if _is_simple_name_assignment(stmt):
            pair = _assignment_target_and_value(stmt)
            assert pair is not None
            target_name, _ = pair
            if target_name not in globals_in_main:
                # Skip the entire binding statement — its reads are
                # handled by the binding-narrowing path, not blind
                # fan-out.
                continue
            # Else: ``global X; X = params.get("...")`` — re-binding a
            # module-level global. Walk it as Scope-1 fan-out.
        visitor.visit(stmt)
    return visitor.found


def _collect_global_decls(main_fn: ast.FunctionDef) -> set[str]:
    """Return the set of names declared ``global`` anywhere in ``main()``.

    Only direct ``ast.Global`` declarations are honored. Cases where
    ``main()`` calls a helper that itself uses ``global`` are not
    considered here — the helper is still walked by per-command Scope-2
    tracing, which doesn't depend on this set.
    """
    out: set[str] = set()
    for node in ast.walk(main_fn):
        if isinstance(node, ast.Global):
            out.update(node.names)
    return out


def _is_simple_name_assignment(stmt: ast.stmt) -> bool:
    """True if ``stmt`` is ``<NAME> = RHS`` or ``<NAME>: T = RHS``.

    Used by :func:`collect_pre_dispatch_params` and
    :func:`build_binding_maps` to decide whether the statement is a
    candidate for binding-narrowing (a single local var being bound) or
    a fan-out expression (everything else).
    """
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return True
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
        return True
    return False


def _assignment_target_and_value(stmt: ast.stmt) -> tuple[str, ast.AST] | None:
    """Return ``(target_name, rhs_expr)`` for a simple-Name assignment, else None."""
    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
        return stmt.targets[0].id, stmt.value
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
        return stmt.target.id, stmt.value
    return None


def _collect_param_reads_in_expr(
    expr: ast.AST, params_vars: set[str], aliases: dict[str, str]
) -> set[str]:
    """Run a one-shot ``_ParamAccessVisitor`` over a single expression node.

    Used to attribute params consumed inside a single RHS expression
    (binding RHS, handler-call argument, etc.) without polluting any
    accumulating Scope-1 / Scope-2 set.
    """
    visitor = _ParamAccessVisitor(params_vars, aliases)
    visitor.visit(expr)
    return set(visitor.found)


def build_binding_maps(
    main_fn: ast.FunctionDef,
    params_vars: set[str],
    aliases: dict[str, str],
    dispatch_line: int,
) -> dict[str, set[str]]:
    """Map every pre-dispatch local var to the set of YML param names it carries.

    Walks each ``<Name> = RHS`` (or ``<Name>: T = RHS``) statement in
    ``main()`` before the dispatch line and records:

    * **Direct reads**: param names accessed inside RHS via the
      ``_ParamAccessVisitor`` (catches ``params.get("X")``,
      ``params["X"]``, ``params.X``, and ``demisto.params().get("X")``).
    * **Transitive references**: ``Name`` nodes inside RHS whose id is
      already a key in the binding map. Their carried params are
      unioned in. This is what lets a subsequent
      ``client = Client(api_key=api_key)`` re-route the ``apikey``
      param onto ``client`` so it fans out to every command that
      receives ``client``.

    Bindings that carry zero params (``client = OktaClient()``,
    ``args = demisto.args()``) are still recorded with an empty set so
    that their appearance as a handler argument is recognized as
    "intermediary with no params" (no contribution) rather than an
    untracked Name (also no contribution, but indistinguishable from
    "we didn't see this binding at all").

    The ``demisto.params()`` binding itself — e.g.
    ``params = demisto.params()`` — is NOT entered into the map; it's a
    params-var, not a binding. The visitor naturally returns zero
    direct reads for that RHS, but we skip it explicitly for clarity.
    """
    globals_in_main = _collect_global_decls(main_fn)
    binding_map: dict[str, set[str]] = {}
    for stmt in main_fn.body:
        if stmt.lineno >= dispatch_line:
            break
        pair = _assignment_target_and_value(stmt)
        if pair is None:
            continue
        target_name, rhs = pair
        # Skip ``X = demisto.params()`` — it's a params-var, not a binding.
        if _is_demisto_params_call(rhs):
            continue
        # Skip targets declared ``global`` in main() — those are
        # re-bindings of module-level names that any command handler may
        # read; their reads are kept in Scope-1 fan-out by
        # :func:`collect_pre_dispatch_params`. Recording them here would
        # cause double counting (Scope-1 + per-command Scope-2).
        if target_name in globals_in_main:
            continue
        direct = _collect_param_reads_in_expr(rhs, params_vars, aliases)
        transitive: set[str] = set()
        for sub in ast.walk(rhs):
            if isinstance(sub, ast.Name) and sub.id in binding_map:
                transitive |= binding_map[sub.id]
        binding_map[target_name] = direct | transitive
    return binding_map


def collect_module_level_params(
    tree: ast.Module,
    main_fn: ast.FunctionDef | None,
    params_vars: set[str],
    aliases: dict[str, str],
) -> set[str]:
    """Scope-1 fan-out: param accesses at MODULE scope (outside any function).

    Many integrations evaluate config eagerly at import time::

        PARAMS = demisto.params()
        SERVER = PARAMS.get("url")
        USE_SSL = not PARAMS.get("insecure")

    These reads happen before any command dispatches and apply to every
    command, exactly like in-``main()`` Scope-1 reads. We feed the result
    into the same Scope-1 bucket so downstream behaviour (Hybrid
    narrowing in :func:`_merge_command_params`) treats them identically.

    Only **truly module-scope** statements are walked — function and
    class bodies are skipped because their contents only execute when
    the function/class is called, not at import. Walking into helper
    function bodies would falsely attribute params consumed by helpers
    (e.g., ``set_xsoar_entries()`` reading ``close_incident``) to
    EVERY command via fan-out, even commands that never reach those
    helpers. Per-command Scope-2 tracing handles handler-and-callees
    coverage; Scope-1 fan-out is strictly for "executed at import,
    therefore visible to every command".

    The walk also handles the common ``if __name__ in (...): main()``
    guard at the bottom of integration files: we don't descend into
    function bodies inside that ``if``, but we do walk the test
    expression and any non-function statements in its body for
    correctness. ``main()`` itself is identified by reference (``is
    main_fn``) so it's skipped even though its FunctionDef is a direct
    child of the Module.
    """
    visitor = _ParamAccessVisitor(params_vars, aliases)

    def _walk_module_scope(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if stmt is main_fn:
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Bodies only run on call; not part of module-level
                # eager evaluation. Decorators DO run at definition
                # time, but they don't typically read demisto.params().
                continue
            if isinstance(stmt, ast.If):
                # Walk the test expression (it runs at import) and
                # recursively walk both branches' bodies for nested
                # module-level statements; still skip nested funcdefs.
                visitor.visit(stmt.test)
                _walk_module_scope(stmt.body)
                _walk_module_scope(stmt.orelse)
                continue
            if isinstance(stmt, (ast.Try,)):
                _walk_module_scope(stmt.body)
                for handler in stmt.handlers:
                    _walk_module_scope(handler.body)
                _walk_module_scope(stmt.orelse)
                _walk_module_scope(stmt.finalbody)
                continue
            # Plain top-level statement (Assign, AnnAssign, Expr,
            # AugAssign, With, For, etc.). Walk it whole.
            visitor.visit(stmt)

    _walk_module_scope(list(tree.body))
    return visitor.found


def find_command_handler_calls(main_fn: ast.FunctionDef, command: str) -> list[ast.Call]:
    """Find all Call nodes that are reached when ``command`` matches.

    Supports ``if/elif`` chains, ``match/case``, and dict-dispatch
    ``commands = {"...": handler}``.
    """
    calls: list[ast.Call] = []
    calls.extend(_find_in_if_chain(main_fn, command))
    calls.extend(_find_in_match(main_fn, command))
    calls.extend(_find_in_dict_dispatch(main_fn, command))
    return calls


def find_command_dispatch_branches(
    main_fn: ast.FunctionDef, command: str
) -> list[list[ast.stmt]]:
    """Return the body stmt-lists of every dispatch branch matching ``command``.

    Used by :func:`attribute_dispatch_site_params` to scan, per command,
    only the code that actually runs when that command is dispatched —
    so binding-map names and inline ``params.get(...)`` reads get
    attributed to the right command.

    Dict-dispatch (``commands = {"X": handler_x}; commands[cmd](args)``)
    has no per-command branch body — the call site is shared across all
    commands. We return an empty list for that case; per-handler
    Scope-2 tracing already covers dict dispatch.
    """
    out: list[list[ast.stmt]] = []
    for node in ast.walk(main_fn):
        if isinstance(node, ast.If) and _if_test_matches_command(node.test, command):
            out.append(node.body)
        elif isinstance(node, ast.Match):
            for case in node.cases:
                pattern = case.pattern
                if isinstance(pattern, ast.MatchValue):
                    v = pattern.value
                    if isinstance(v, ast.Constant) and v.value == command:
                        out.append(case.body)
    return out


def find_dict_dispatch_call_sites(main_fn: ast.FunctionDef) -> list[ast.Call]:
    """Return any ``commands[<...>](...)`` invocation sites in ``main()``.

    The classic dict-dispatch idiom (used by MongoDB, Cherwell, GitLab,
    Slack IAM, etc.) is::

        commands = {"foo": foo_handler, "bar": bar_handler}
        commands[command](client, **args)

    The single call site is shared across **every** command listed in
    ``commands``. Its ``Name`` arguments — typically a ``client`` built
    via ``Client(api_key=params.get("apikey"), ...)`` — therefore fan
    out to every command in the dict. We expose those call sites so
    :func:`analyze_static` can replay binding-map attribution for each
    dispatched command.
    """
    out: list[ast.Call] = []
    for node in ast.walk(main_fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Subscript):
            continue
        receiver = func.value
        if isinstance(receiver, ast.Name) and receiver.id == "commands":
            out.append(node)
    return out


def _attribute_call_args(
    call: ast.Call,
    binding_map: dict[str, set[str]],
    params_vars: set[str],
    aliases: dict[str, str],
) -> set[str]:
    """Walk one ``Call`` node's positional + keyword args.

    For each arg that is a ``Name`` already in ``binding_map``, take
    its carried params. Otherwise walk the arg expression for inline
    ``params.get(...)`` / subscript / attribute reads and take those.
    """
    found: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in binding_map:
            found |= binding_map[arg.id]
        else:
            found |= _collect_param_reads_in_expr(arg, params_vars, aliases)
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in binding_map:
            found |= binding_map[kw.value.id]
        else:
            found |= _collect_param_reads_in_expr(kw.value, params_vars, aliases)
    return found


def attribute_dispatch_site_params(
    branch_body: list[ast.stmt],
    binding_map: dict[str, set[str]],
    params_vars: set[str],
    aliases: dict[str, str],
) -> set[str]:
    """Walk one dispatch branch and attribute params to the command.

    For every ``Call`` node found anywhere in ``branch_body`` (typically
    the handler call, but also any helper calls a dispatch arm makes
    inline before / after the handler):

    * Every positional argument that is a ``Name`` whose id is a key in
      ``binding_map`` contributes ``binding_map[id]`` (the params the
      bound local carries).
    * Every keyword argument whose value is such a ``Name`` does the same.
    * Inline ``params.get("X")`` / ``params["X"]`` / ``params.X`` /
      ``demisto.params().get("X")`` reads appearing anywhere in the
      Call's arguments are walked with ``_ParamAccessVisitor`` and
      attributed to this command (Cases 1 and 7 in the contract suite).
    """
    found: set[str] = set()
    for stmt in branch_body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                found |= _attribute_call_args(sub, binding_map, params_vars, aliases)
    return found


def attribute_dict_dispatch_shared_args(
    main_fn: ast.FunctionDef,
    binding_map: dict[str, set[str]],
    params_vars: set[str],
    aliases: dict[str, str],
) -> set[str]:
    """Attribute the shared ``commands[command](...)`` call site's args.

    Dict-dispatch routes every command through one shared call site. Any
    ``Name`` argument at that site that's a key in ``binding_map``
    represents a value passed to **every** dispatched command — so the
    params carried by that Name fan out to every command. This restores
    the Case-4 fan-out for the common ``client = Client(...)`` +
    ``commands[command](client, ...)`` pattern when the dispatch table
    is a dict.
    """
    found: set[str] = set()
    for call in find_dict_dispatch_call_sites(main_fn):
        found |= _attribute_call_args(call, binding_map, params_vars, aliases)
    return found


def _find_in_if_chain(main_fn: ast.FunctionDef, command: str) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(main_fn):
        if not isinstance(node, ast.If):
            continue
        if _if_test_matches_command(node.test, command):
            out.extend(_iter_calls(node.body))
    return out


def _is_command_ref(node: ast.AST) -> bool:
    """True if *node* is the canonical 'current command' reference.

    Recognized forms:

    * ``command``                — a local variable bound from
      ``demisto.command()`` earlier in main().
    * ``demisto.command()``      — the chained inline form (matches the
      same pattern we recognize for ``demisto.params()``).

    Without the chained form, the analyzer would miss ``elif
    demisto.command() == "X":`` style dispatch chains used heavily by
    older integrations like CrowdStrikeFalcon (causing every command in
    such an integration to be treated as having "no dispatch site",
    which collapses Scope-2 to empty).
    """
    if isinstance(node, ast.Name) and node.id == "command":
        return True
    if (
        isinstance(node, ast.Call)
        and not node.args
        and not node.keywords
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "command"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "demisto"
    ):
        return True
    return False


def _if_test_matches_command(test: ast.AST, command: str) -> bool:
    # <ref> == "X"  or  "X" == <ref>
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        for a, b in ((left, right), (right, left)):
            if _is_command_ref(a) and isinstance(b, ast.Constant) and b.value == command:
                return True
    # <ref> in ("X", "Y")
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.In):
        if _is_command_ref(test.left):
            container = test.comparators[0]
            if isinstance(container, (ast.Tuple, ast.List, ast.Set)):
                for elt in container.elts:
                    if isinstance(elt, ast.Constant) and elt.value == command:
                        return True
    return False


def _find_in_match(main_fn: ast.FunctionDef, command: str) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(main_fn):
        if not isinstance(node, ast.Match):
            continue
        for case in node.cases:
            pattern = case.pattern
            if isinstance(pattern, ast.MatchValue):
                v = pattern.value
                if isinstance(v, ast.Constant) and v.value == command:
                    out.extend(_iter_calls(case.body))
    return out


def _find_in_dict_dispatch(main_fn: ast.FunctionDef, command: str) -> list[ast.Call]:
    """Handle ``commands = {"X": handler_X, ...}; commands[command](...)``."""
    out: list[ast.Call] = []
    for node in ast.walk(main_fn):
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        if not (isinstance(target, ast.Name) and target.id == "commands"):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for key, val in zip(node.value.keys, node.value.values):
            if isinstance(key, ast.Constant) and key.value == command:
                # Build a synthetic Call node so the recursion picks up the
                # named handler function.
                if isinstance(val, ast.Name):
                    out.append(ast.Call(func=val, args=[], keywords=[]))
                elif isinstance(val, ast.Attribute):
                    out.append(ast.Call(func=val, args=[], keywords=[]))
    return out


def _iter_calls(stmts: list[ast.stmt]) -> list[ast.Call]:
    out: list[ast.Call] = []
    for stmt in stmts:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call):
                out.append(sub)
    return out


def trace_params_in_function(
    fn: ast.FunctionDef,
    func_map: dict[str, ast.FunctionDef],
    aliases: dict[str, str],
    depth: int,
    visited: set[str],
    module_params_vars: set[str] | None = None,
) -> set[str]:
    """Recursively collect param accesses in ``fn`` up to ``depth`` levels deep.

    ``module_params_vars`` are names bound to ``demisto.params()`` at module
    scope (e.g. a global ``PARAMS = demisto.params()``). They're seeded
    into the candidate set for every traced function so accesses to those
    globals — common in older / large integrations like CrowdStrikeFalcon —
    are not silently dropped. The chained ``demisto.params().X`` form is
    also recognized via :func:`_is_demisto_params_call` inside the visitor
    and does not require any candidate name to be present.
    """
    if depth < 0 or fn.name in visited:
        return set()
    visited = visited | {fn.name}

    # Determine the params variable name(s) inside this function.
    # Priority: function-signature names that match the alias set; else
    # the canonical "params". Module-level params globals (e.g. PARAMS)
    # are unioned in so handlers that read them as globals are covered.
    sig_params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    candidates = (sig_params & PARAMS_VAR_ALIASES) or {"params"}
    if module_params_vars:
        candidates = candidates | module_params_vars

    visitor = _ParamAccessVisitor(candidates, aliases)
    visitor.visit(fn)
    found = set(visitor.found)

    # Recurse into called functions defined in this module that look like
    # they receive a params-shaped argument. (Unscoped accesses inside
    # those callees — e.g. ``demisto.params().get(...)`` or reads of a
    # module-level PARAMS — are still reachable via this visitor when
    # the recursion fires; the gate exists to avoid falsely visiting
    # arbitrary helpers that happen to share the module.)
    for call in _iter_calls(fn.body):
        target_fn = _resolve_call_target(call, func_map)
        if target_fn is None:
            continue
        if not _call_passes_params(call, candidates):
            continue
        found |= trace_params_in_function(
            target_fn, func_map, aliases, depth - 1, visited, module_params_vars
        )
    return found


def _resolve_call_target(call: ast.Call, func_map: dict[str, ast.FunctionDef]) -> ast.FunctionDef | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func_map.get(func.id)
    if isinstance(func, ast.Attribute):
        return func_map.get(func.attr)
    return None


def _call_passes_params(call: ast.Call, candidates: set[str]) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in candidates:
            return True
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in candidates:
            return True
    return False


def analyze_static(
    py_source: str,
    command: str,
    language: str | None = None,
    integration_name: str = "",
    verbose: bool = True,
) -> tuple[set[str], set[str]]:
    """Run scope-1 + scope-2 static analysis for one command. Returns YML names.

    Returns ``(scope_1, scope_2)``:

    * ``scope_1`` — pre-dispatch params accessed in ``main()`` before the
      command-dispatch construct, **plus** module-level reads of any
      ``PARAMS = demisto.params()`` global. These are shared across
      **every** command because they execute regardless of which command
      is invoked (e.g., ``Client(...)`` constructor in the fan-out
      pattern, or eager module-load reads like ``SERVER = PARAMS.get("url")``).
    * ``scope_2`` — params traced through the per-command handler (and up
      to two further call levels). These are specific to this command.
      The tracer recognizes both formal-parameter access (``params.get(...)``
      where ``params`` is a function arg) and the chained inline form
      (``demisto.params().get(...)``), and seeds module-level globals
      into the candidate set so handlers that read globals are covered.

    Callers that want the full static signal use ``scope_1 | scope_2``.
    Callers that have HTTP evidence from dynamic analysis can narrow
    ``scope_1`` to the params dynamic actually saw on the wire and keep
    ``scope_2`` intact.

    When ``verbose`` is True (default), per-command breadcrumbs are
    written to stderr explaining which dispatch pattern matched, how
    many handler calls were found, and whether any module-level
    ``PARAMS`` globals were detected. This makes silent under-coverage
    observable without re-running the analyzer in a debugger.

    Non-Python integrations (``language`` not in ``{"python", None}``) are
    the **only** acceptable graceful skip: log a stderr note and return
    two empty sets. Any other failure (including a real ``SyntaxError``
    in the integration's ``.py``) propagates to the caller.

    Binding-narrowing
    -----------------
    Before computing Scope-1 / Scope-2, ``analyze_static`` builds a
    ``binding_map: dict[var_name, set[param_name]]`` covering every
    pre-dispatch ``<Name> = RHS`` statement in ``main()`` whose RHS reads
    one or more YML params (directly via ``params.get("X")`` etc., or
    transitively by referencing another already-bound local). The
    pre-dispatch Scope-1 collector then **excludes** those binding
    statements — bound reads are no longer attributed blindly to every
    command.

    For each command, the dispatch branch (``if command == "X": ...`` or
    the matching ``case "X":``) is walked separately by
    :func:`attribute_dispatch_site_params`. That walk:

    * unions ``binding_map[arg.id]`` for every handler-call argument
      (positional or keyword) that is a ``Name`` already in the map —
      so ``handler(client, mapper_out)`` carries only the params that
      ``client`` and ``mapper_out`` actually represent;
    * walks any inline ``params.get(...)`` / subscript / attribute /
      ``demisto.params().get(...)`` expressions appearing as arguments
      and attributes those param names to this command — fixing the
      "inline read at dispatch site" gap (Cases 1 and 7).

    The result is added to Scope-2 for that command. Pre-dispatch
    statements that are **not** bare ``Name = RHS`` assignments — for
    example ``Client(api_key=params.get("apikey"))`` standing alone as
    an expression statement — keep their reads in Scope-1, preserving
    fan-out for the legitimate "read directly into a constructor whose
    result feeds every command" pattern (Case 4).

    A binding whose result is consumed by a constructor whose result
    fans out (``api_key = params.get("apikey"); client =
    Client(api_key=api_key); cmd_x(client); cmd_y(client)``) is handled
    transitively: the second binding records ``binding_map["client"] =
    {"apikey"}`` because its RHS references the already-mapped
    ``api_key``. Both ``cmd_x`` and ``cmd_y`` then re-acquire ``apikey``
    via dispatch-site attribution (Case 14 negative constraint).

    Module-level ``PARAMS = demisto.params(); SERVER = PARAMS.get("url")``
    globals continue to fan out unchanged (Case 3) — they're collected
    by :func:`collect_module_level_params` and live outside the
    binding-narrowing pipeline.
    """
    if language and language.lower() not in {"python", "python2", "python3"}:
        print(
            f"[static] skipping non-Python integration {integration_name!r} "
            f"(language={language!r}); static analysis is Python-only",
            file=sys.stderr,
        )
        return set(), set()
    if not py_source:
        # No .py file at all: nothing to analyze, but this is not a graceful
        # skip case — caller decides whether that's an error.
        if verbose:
            print(
                f"[static] {command}: no Python source available; "
                f"static analysis returns empty",
                file=sys.stderr,
            )
        return set(), set()
    tree = ast.parse(py_source)  # may raise SyntaxError -> propagate.
    func_map = build_function_map(tree)
    main_fn = find_main(func_map)
    if main_fn is None:
        if verbose:
            print(
                f"[static] {command}: no top-level main() function found; "
                f"static analysis returns empty",
                file=sys.stderr,
            )
        return set(), set()
    aliases = find_pydantic_aliases(tree)
    params_var = find_params_var(main_fn) or "params"
    module_params_vars = find_module_level_params_vars(tree)
    # Candidate names for the visitor: in-main()-bound name + canonical
    # aliases + module-level globals. This single union covers
    # ``params``, ``PARAMS``, ``integration_params``, ``config``, plus
    # any other ``X = demisto.params()`` binding the integration uses.
    params_vars = {params_var} | PARAMS_VAR_ALIASES | module_params_vars
    dispatch_line = find_command_dispatch_line(main_fn)
    scope_1_in_main = collect_pre_dispatch_params(
        main_fn, params_vars, aliases, dispatch_line
    )
    # Module-level scope-1 fan-out: catches ``SERVER = PARAMS.get("url")``
    # and similar patterns that execute at import time and apply to
    # every command equally. Also catches the chained
    # ``demisto.params().get(...)`` form at module scope.
    scope_1_module = collect_module_level_params(
        tree if isinstance(tree, ast.Module) else ast.Module(body=[], type_ignores=[]),
        main_fn,
        params_vars,
        aliases,
    )
    scope_1 = scope_1_in_main | scope_1_module

    # Binding-narrowing: build the local-var → carried-params map from
    # pre-dispatch statements, then attribute per command at the
    # matching dispatch branch. See the docstring section
    # "Binding-narrowing" above.
    binding_map = build_binding_maps(main_fn, params_vars, aliases, dispatch_line)

    scope_2: set[str] = set()
    handler_calls = find_command_handler_calls(main_fn, command)
    resolved_targets: list[str] = []
    for call in handler_calls:
        target = _resolve_call_target(call, func_map)
        if target is None:
            continue
        resolved_targets.append(target.name)
        scope_2 |= trace_params_in_function(
            target,
            func_map,
            aliases,
            depth=2,
            visited=set(),
            module_params_vars=module_params_vars,
        )

    # Per-command dispatch-branch attribution: bound locals + inline
    # reads at the handler-call site.
    for branch_body in find_command_dispatch_branches(main_fn, command):
        scope_2 |= attribute_dispatch_site_params(
            branch_body, binding_map, params_vars, aliases
        )

    # Dict-dispatch shared call site (``commands[command](client, ...)``)
    # — args at that site flow to every dispatched command, so the
    # binding-map params they carry must fan out. Only applied when the
    # command is recognized as a dispatch target (handler_calls
    # non-empty), to avoid attributing the shared site to commands
    # that aren't actually in the dispatch dict.
    if handler_calls:
        scope_2 |= attribute_dict_dispatch_shared_args(
            main_fn, binding_map, params_vars, aliases
        )

    if verbose:
        if not handler_calls:
            print(
                f"[static] {command}: no dispatch site found in main(); "
                f"scope_2 will be empty (only Scope-1 fan-out applies)",
                file=sys.stderr,
            )
        elif not resolved_targets:
            print(
                f"[static] {command}: dispatch found ({len(handler_calls)} call site(s)) "
                f"but handler function(s) not defined in this module; "
                f"scope_2 will be empty",
                file=sys.stderr,
            )
        else:
            module_note = (
                f"; module-level params globals: {sorted(module_params_vars)}"
                if module_params_vars
                else ""
            )
            print(
                f"[static] {command}: handler(s) resolved → "
                f"{sorted(set(resolved_targets))}{module_note}",
                file=sys.stderr,
            )

    return scope_1, scope_2


# --------------------------------------------------------------------------
# Dynamic analysis (sentinel-based)
# --------------------------------------------------------------------------


class DynamicPrepError(RuntimeError):
    """Raised when dynamic preparation cannot produce a runnable unified .py.

    Under the current loud-fail policy this propagates to the CLI; there is
    no silent fallback to static-only.
    """


class DynamicAnalysisError(RuntimeError):
    """Raised when the dynamic child crashes in a way we cannot tolerate.

    Specifically: ``rc != 0`` with zero captured HTTP requests, or a child
    process timeout. A non-zero ``rc`` after at least one captured request
    is tolerated (the param signal is intact) and does not raise.
    """


def _resolve_repo_root() -> Path:
    """Best-effort: assume this script is at <repo>/connectus/."""
    return Path(__file__).resolve().parent.parent


def _find_first_existing(rel_paths: tuple[str, ...]) -> Path | None:
    root = _resolve_repo_root()
    for rel in rel_paths:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return None


def prepare_unified_content(
    integration_path: Path, out_dir: Path
) -> tuple[Path, Path]:
    """Run ``demisto-sdk prepare-content`` and produce a runnable bundle.

    Writes two files into ``out_dir``:

    * ``unified_integration.py`` — ``CommonServerPython`` + the integration
      source, ready for the child interpreter to ``exec_module``.
    * ``mock_dir/demistomock.py`` — our seeded mock that the child reaches
      via ``import demistomock as demisto``. The child puts ``mock_dir``
      at the front of ``sys.path`` so this file wins over anything else.

    Returns ``(unified_py_path, mock_dir_path)``. Any failure raises
    :class:`DynamicPrepError`.
    """
    import time as _t

    if shutil.which("demisto-sdk") is None:
        raise DynamicPrepError(
            "demisto-sdk not found on PATH; install it or pass --static-only"
        )
    yaml_out = out_dir / "unified.yml"
    cmd = [
        "demisto-sdk",
        "prepare-content",
        "-i",
        str(integration_path),
        "-o",
        str(yaml_out),
    ]
    print(f"[dynamic] prepare-content: starting for {integration_path}", file=sys.stderr)
    _t0 = _t.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as exc:
        raise DynamicPrepError(f"prepare-content timed out after 120s: {exc}") from exc
    except FileNotFoundError as exc:
        raise DynamicPrepError(f"prepare-content failed to launch: {exc}") from exc
    elapsed = _t.time() - _t0
    if result.returncode != 0 or not yaml_out.is_file():
        raise DynamicPrepError(
            f"prepare-content failed: rc={result.returncode} "
            f"stderr={result.stderr.strip()[:500]}"
        )
    print(
        f"[dynamic] prepare-content: ok in {elapsed:.1f}s -> {yaml_out.name}",
        file=sys.stderr,
    )

    py_source = _extract_python_from_unified_yaml(yaml_out)
    final_text = _build_runnable_unified(py_source)
    py_out = out_dir / "unified_integration.py"
    py_out.write_text(final_text, encoding="utf-8")

    # Write the seeded demistomock.py to a sibling dir. The child puts
    # this dir at sys.path[0] so ``import demistomock`` resolves here.
    # We also drop a no-op DemistoClassApiModule.py to override the real
    # one in Packs/Base/Scripts/CommonServerPython, which would otherwise
    # do ``demisto = Demisto({})`` and clobber our seeded params.
    mock_dir = out_dir / "mock"
    mock_dir.mkdir(exist_ok=True)
    (mock_dir / "demistomock.py").write_text(_DEMISTOMOCK_TEMPLATE, encoding="utf-8")
    (mock_dir / "DemistoClassApiModule.py").write_text(
        _DEMISTO_CLASS_API_MODULE_TEMPLATE, encoding="utf-8"
    )

    # Sanity check: the unified .py we hand to the child interpreter MUST
    # parse. If it doesn't, the child would die on import with a SyntaxError
    # and we'd never know what really happened.
    try:
        ast.parse(final_text)
    except SyntaxError as exc:
        raise DynamicPrepError(
            f"unified content is not valid Python: {exc}"
        ) from exc
    try:
        ast.parse(_DEMISTOMOCK_TEMPLATE)
    except SyntaxError as exc:
        raise DynamicPrepError(
            f"demistomock template is not valid Python: {exc}"
        ) from exc
    return py_out, mock_dir


def _extract_python_from_unified_yaml(yaml_path: Path) -> str:
    """Pull the integration's Python source out of a unified YAML file.

    ``demisto-sdk prepare-content`` typically nests the source at
    ``script.script``; older / variant layouts may put it directly under
    ``script`` (as a string).
    """
    with yaml_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise DynamicPrepError(
            f"prepare-content output is not a YAML mapping: top-level "
            f"type={type(data).__name__}"
        )
    script = data.get("script")
    if isinstance(script, dict):
        py = script.get("script")
        if isinstance(py, str) and py.strip():
            return py
        raise DynamicPrepError(
            f"prepare-content output missing script.script (script keys: "
            f"{sorted(script.keys())})"
        )
    if isinstance(script, str) and script.strip():
        return script
    raise DynamicPrepError(
        f"prepare-content output missing script.script (top-level keys: "
        f"{sorted(data.keys())})"
    )


def _build_runnable_unified(integration_py: str) -> str:
    """Prepend ``CommonServerPython`` to the integration source.

    We do NOT prepend demistomock anymore — the parent writes a real
    ``demistomock.py`` to a temp dir and prepends that dir to ``sys.path``
    in the child. That way ``import demistomock as demisto`` (which the
    integration almost always does) deterministically resolves to OUR
    seeded mock instead of an inline class block whose attributes we'd
    otherwise have to monkeypatch post-import.

    ``from __future__`` imports must appear at the very top of a file, so
    we pull every ``from __future__`` line out of both sources and emit
    them first (deduplicated), followed by the rest of each source.
    """
    csp_path = _find_first_existing((COMMON_SERVER_PYTHON_REL,))
    if csp_path is None:
        raise DynamicPrepError(
            f"could not locate CommonServerPython at {COMMON_SERVER_PYTHON_REL}"
        )
    sources = [
        csp_path.read_text(encoding="utf-8"),
        integration_py,
    ]
    future_lines: list[str] = []
    seen_futures: set[str] = set()
    cleaned: list[str] = []
    for src in sources:
        kept: list[str] = []
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("from __future__"):
                if stripped not in seen_futures:
                    seen_futures.add(stripped)
                    future_lines.append(stripped)
                continue
            kept.append(line)
        cleaned.append("\n".join(kept))
    header = "\n".join(future_lines)
    return (header + "\n" if header else "") + "\n".join(cleaned)


# YML param ``type`` integers (Cortex/XSOAR convention).
YML_TYPE_SHORT_TEXT = 0
YML_TYPE_ENCRYPTED = 4
YML_TYPE_BOOL = 8
YML_TYPE_CREDENTIALS = 9
YML_TYPE_MULTI_SELECT = 10
YML_TYPE_SINGLE_SELECT = 12
YML_TYPE_LONG_TEXT = 13
YML_TYPE_INCIDENT_TYPE = 14
YML_TYPE_NUMERIC = 15
YML_TYPE_CSV = 16
YML_TYPE_AUTH = 17
YML_TYPE_MULTI_LINE = 19


def _coerce_default_value(raw: Any, yml_type: int | None) -> Any:
    """Coerce a YML ``defaultvalue`` string to the right Python type."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return raw  # already a non-string scalar/list/dict
    text = raw.strip()
    if yml_type == YML_TYPE_BOOL:
        low = text.lower()
        if low in {"true", "yes", "1"}:
            return True
        if low in {"false", "no", "0", ""}:
            return False
        return bool(text)
    if yml_type == YML_TYPE_NUMERIC:
        try:
            if "." in text:
                return float(text)
            return int(text)
        except ValueError:
            return text
    if yml_type in {YML_TYPE_MULTI_SELECT, YML_TYPE_CSV}:
        # Most consumers do .split(","); leaving as a CSV string is fine.
        return text
    return raw


def build_param_values(
    yml_params: list[dict[str, Any]],
    proxy_url: str,
    ignore: set[str],
) -> tuple[dict[str, Any], dict[str, list[str]], set[str]]:
    """Build the params dict + sentinel map + non-traceable param set.

    Returns a 3-tuple:

    * ``values`` — the dict to pass to the integration as ``demisto.params()``.
    * ``sentinels`` — ``{yml_name: [sentinel_string, ...]}``. Each list holds
      one or more strings to grep captured requests for; a hit on ANY of
      them counts as the param being relevant. Empty lists are allowed for
      non-traceable params (booleans, numeric, etc.) and are skipped during
      detection.
    * ``non_traceable`` — names of params we sent without a traceable
      sentinel value. Useful for diagnostics and to make
      ``detect_sentinel_hits`` deterministic.

    YML param ``type`` drives the value shape (see the design doc table).
    A YML ``defaultvalue`` overrides the type-based default, but is parsed
    into the right Python type rather than left as a raw string.
    """
    values: dict[str, Any] = {}
    sentinels: dict[str, list[str]] = {}
    non_traceable: set[str] = set()
    for p in yml_params:
        name = p["name"]
        # We must STILL send a value for every YML param even if it's on
        # the ignore list — many integrations read those params at module
        # import time (e.g. SERVER = demisto.params().get("server")) and
        # crash if they're missing. The ignore list only suppresses output
        # reporting, not execution. The trick: don't add an ignored param
        # to ``sentinels`` so it never participates in the per-command
        # detection result.
        ignored = name in ignore
        yml_type = p.get("type")
        sentinel = f"{SENTINEL_PREFIX}{name}"

        def _record(value: Any, tokens: list[str], traceable: bool) -> None:
            values[name] = value
            if not ignored:
                sentinels[name] = tokens
                if not traceable:
                    non_traceable.add(name)

        is_url = name in URL_PARAM_NAMES
        if is_url:
            # URL-shaped param -> point at our proxy, ALWAYS, even if the
            # YML carries a real default URL like https://api.example.com.
            # If we honored the default, the integration would issue HTTP
            # to the real upstream (or fail DNS) instead of hitting our
            # capture proxy, and we'd see zero captures.
            _record(proxy_url, [proxy_url], traceable=True)
            continue

        # Honor YML default first, but coerce to the right Python type so
        # boolean params don't get sent as the string "true".
        if "defaultvalue" in p and p["defaultvalue"] is not None:
            coerced = _coerce_default_value(p["defaultvalue"], yml_type)
            if isinstance(coerced, str) and len(coerced) >= 6:
                _record(coerced, [coerced], traceable=True)
            else:
                _record(coerced, [], traceable=False)
            continue

        if yml_type == YML_TYPE_BOOL:
            _record(True, [], traceable=False)
            continue

        if yml_type == YML_TYPE_CREDENTIALS:
            id_sent = f"{sentinel}_identifier"
            pw_sent = f"{sentinel}_password"
            _record({"identifier": id_sent, "password": pw_sent},
                    [id_sent, pw_sent], traceable=True)
            continue

        if yml_type == YML_TYPE_NUMERIC:
            _record(1, [], traceable=False)
            continue

        if yml_type == YML_TYPE_SINGLE_SELECT:
            options = p.get("options")
            if isinstance(options, list) and options:
                first = options[0]
                if isinstance(first, str) and len(first) >= 4:
                    _record(first, [first], traceable=True)
                else:
                    _record(first, [], traceable=False)
            else:
                _record(sentinel, [sentinel], traceable=True)
            continue

        # Default for: short text, encrypted, multi-select, CSV, long text,
        # incident type, auth, multi-line, missing/unknown — string sentinel.
        _record(sentinel, [sentinel], traceable=True)
    return values, sentinels, non_traceable


# Source for ``DemistoClassApiModule.py`` — the unified file does
# ``from DemistoClassApiModule import *`` near the end of CommonServerPython
# (around line ~13920). The real DemistoClassApiModule (in
# Packs/Base/Scripts/CommonServerPython/) imports demistomock and then
# REASSIGNS ``demisto = Demisto({})`` with an empty context, which
# clobbers any seeded params we set on our mock. We override it with a
# no-op module that just keeps our seeded ``demisto`` intact.
_DEMISTO_CLASS_API_MODULE_TEMPLATE = textwrap.dedent(
    '''
    """No-op DemistoClassApiModule that preserves the seeded demisto."""
    import demistomock as demisto  # noqa: F401
    # Provide a Demisto class for any ``isinstance(x, Demisto)`` checks but
    # do NOT reassign ``demisto`` — keep the seeded module-level instance.
    class Demisto:  # noqa: D401
        pass
    '''
).lstrip()


# Source for the on-disk ``demistomock.py`` we drop next to the unified
# integration. Writing a real .py file (and putting its directory on
# ``sys.path``) is more robust than monkeypatching ``sys.modules`` because:
#
#   * The unified file has ``demistomock.py`` content prepended (lines 1-N
#     define a ``Demisto`` class and ``demisto = Demisto({})`` instance);
#     line N+ then does ``import demistomock as demisto`` which REBINDS
#     ``demisto`` to whatever the import resolves to.
#   * If we only patch ``sys.modules["demistomock"]``, the inline class
#     might still win in subtle ways (caching, loader order, etc.).
#   * With a real file at high-priority path, ``import demistomock``
#     deterministically resolves to OUR module, and that module's
#     ``demisto`` attribute is a real object whose ``.params()``,
#     ``.command()``, ``.args()`` we control.
#
# The mock reads ``CHECK_PARAMS_JSON``, ``CHECK_COMMAND`` from the env at
# import time so seeded values are visible to module-level code in the
# integration (e.g. ``SERVER = demisto.params().get("server")``).
_DEMISTOMOCK_TEMPLATE = textwrap.dedent(
    '''
    """On-disk demistomock used by check_command_params.py dynamic runs."""
    import json as _json
    import os as _os
    import sys as _sys

    _PARAMS = _json.loads(_os.environ.get("CHECK_PARAMS_JSON", "{}"))
    _COMMAND = _os.environ.get("CHECK_COMMAND", "")


    class _Demisto:
        callingContext = {"context": {}, "params": _PARAMS, "command": _COMMAND}
        def params(self): return _PARAMS
        def command(self): return _COMMAND
        def args(self): return {}
        def results(self, *a, **k): return None
        def getLastRun(self): return {}
        def setLastRun(self, *a, **k): return None
        def incidents(self, *a, **k): return []
        def getIntegrationContext(self, *a, **k): return {}
        def setIntegrationContext(self, *a, **k): return None
        def info(self, *a, **k): return None
        def debug(self, *a, **k): return None
        def error(self, *a, **k): return None
        def log(self, *a, **k): return None
        def getLicenseID(self): return ""
        def demistoVersion(self): return {"version": "8.0.0", "buildNumber": "0"}
        def getFilePath(self, *a, **k): return {"path": "", "name": ""}
        def getLastMirrorRun(self): return {}
        def setLastMirrorRun(self, *a, **k): return None
        def investigation(self): return {"id": "0"}
        def internalHttpRequest(self, *a, **k): return {}
        def executeCommand(self, *a, **k): return []
        def dt(self, *a, **k): return None
        def context(self): return {}
        def uniqueFile(self): return ""
        def getAllSupportedCommands(self): return {}
        def searchIndicators(self, *a, **k): return {"iocs": []}
        def createIndicators(self, *a, **k): return None
        def handleEntitlementForUser(self, *a, **k): return None
        def updateModuleHealth(self, *a, **k): return None
        def mapObject(self, *a, **k): return {}
        def get(self, *a, **k): return None
        def getModules(self): return {}
        def getIndexHash(self): return ""
        def setAssetsLastRun(self, *a, **k): return None
        def getAssetsLastRun(self): return {}
        def __getattr__(self, name):
            return lambda *a, **k: None


    demisto = _Demisto()


    # Module-level callables (some integrations do ``demistomock.params()``
    # AFTER ``import demistomock as demisto``, treating the module itself
    # as the demisto object).
    def params(): return _PARAMS
    def command(): return _COMMAND
    def args(): return {}
    def results(*a, **k): return None
    def info(*a, **k): return None
    def debug(*a, **k): return None
    def error(*a, **k): return None
    def log(*a, **k): return None
    def getLastRun(): return {}
    def setLastRun(*a, **k): return None
    def getLicenseID(): return ""
    def demistoVersion(): return {"version": "8.0.0", "buildNumber": "0"}
    def getFilePath(*a, **k): return {"path": "", "name": ""}
    def getLastMirrorRun(): return {}
    def setLastMirrorRun(*a, **k): return None
    def investigation(): return {"id": "0"}
    def internalHttpRequest(*a, **k): return {}
    def executeCommand(*a, **k): return []
    def dt(*a, **k): return None
    def context(): return {}
    def uniqueFile(): return ""
    def getAllSupportedCommands(): return {}
    def searchIndicators(*a, **k): return {"iocs": []}
    def createIndicators(*a, **k): return None
    def handleEntitlementForUser(*a, **k): return None
    def updateModuleHealth(*a, **k): return None
    def mapObject(*a, **k): return {}
    def getModules(): return {}
    def getIndexHash(): return ""
    def setAssetsLastRun(*a, **k): return None
    def getAssetsLastRun(): return {}
    def integrationInstance(): return ""
    def isTimeSensitive(): return False
    def get_incidents(): return []
    def incident(): return {}
    def get_alerts(): return []
    def alert(): return {}
    def parentEntry(): return {}
    def incidents(*a, **k): return []
    def fetchResults(*a, **k): return None
    def credentials(*a, **k): return None
    def getArg(arg, defaultParam=None): return defaultParam
    def getParam(p): return _PARAMS.get(p)
    def get(obj, field, defaultParam=None):
        if not obj:
            return defaultParam
        for part in field.split("."):
            if obj and part in obj:
                obj = obj[part]
            else:
                return defaultParam
        return obj
    def gets(obj, field): return str(get(obj, field))
    def demistoUrls(): return {}
    def heartbeat(*a, **k): return None
    def fetchIncidents(): return False
    def isFetch(): return False
    def isFetchEvents(): return False
    def isFetchAssets(): return False


    # Catch-all for any helper not enumerated above so a stray method
    # access doesn't crash the integration at import time.
    def _missing_attr(name):
        return lambda *a, **k: None
    import types as _types
    class _ModuleWithFallback(_types.ModuleType):
        def __getattr__(self, name):
            return lambda *a, **k: None
    _sys.modules[__name__].__class__ = _ModuleWithFallback


    # callingContext is read both as ``demisto.callingContext`` AND
    # ``demistomock.callingContext`` by various code paths.
    callingContext = {"context": {}, "params": _PARAMS, "command": _COMMAND}
    '''
).lstrip()


# Bootstrap script run in the child interpreter. Critical ordering:
#
#   1. Insert the directory containing our on-disk ``demistomock.py``
#      (written by the parent before the run) at the FRONT of sys.path so
#      ``import demistomock`` resolves to our file, not anything else.
#
#   2. Execute the unified integration. Its module-level reads of
#      ``demisto.params()`` etc. now see our seeded values from the
#      ``CHECK_PARAMS_JSON`` env var.
#
#   3. Patch ``return_error`` in BOTH ``CommonServerPython`` and the
#      unified module's namespace, post-import, to exit with rc=7. This
#      turns "silent return_error before any HTTP request" into a loud
#      per-command failure that the parent recognises.
#
#   4. Call ``main()``.
#
# Inputs: ``CHECK_PARAMS_JSON`` (env), ``CHECK_COMMAND`` (env),
# ``CHECK_UNIFIED_PATH`` (env), ``CHECK_MOCK_DIR`` (env, dir holding
# demistomock.py). Using env vars avoids CLI/stdin escaping issues.
_BOOTSTRAP_TEMPLATE = textwrap.dedent(
    '''
    import os, sys, importlib.util, traceback

    sys.path.insert(0, os.environ["CHECK_MOCK_DIR"])

    UNIFIED_PATH = os.environ["CHECK_UNIFIED_PATH"]

    # ---- Step 1: load and execute the unified integration. ----
    spec = importlib.util.spec_from_file_location(
        "integration_under_test", UNIFIED_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["integration_under_test"] = module
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(2)

    # ---- Step 2: patch return_error AFTER import. ----
    def _patched_return_error(message="", error="", outputs=None, dbot_score=None,
                              **kwargs):
        msg = str(message)[:500]
        print("RETURN_ERROR_PATCHED: " + msg, file=sys.stderr)
        sys.exit(7)

    if hasattr(module, "return_error"):
        module.return_error = _patched_return_error
    csp = sys.modules.get("CommonServerPython")
    if csp is not None and hasattr(csp, "return_error"):
        csp.return_error = _patched_return_error

    # ---- Step 3: run main(). ----
    main_fn = getattr(module, "main", None)
    if main_fn is None:
        print("BOOTSTRAP_NO_MAIN", file=sys.stderr)
        sys.exit(4)
    try:
        main_fn()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        sys.exit(5)
    sys.exit(0)
    '''
).strip()


# Distinct exit code raised by the patched ``return_error`` in the child.
RC_RETURN_ERROR_PATCHED = 7


# --------------------------------------------------------------------------
# Docker runtime configuration
# --------------------------------------------------------------------------


@dataclass
class DockerConfig:
    """How the analyzer launches the per-command child process.

    ``mode``: one of ``"auto"``, ``"always"``, ``"never"``.

    ``default_image``: image used by default. Always set to
    :data:`DEFAULT_DOCKER_IMAGE` (``demisto/py3-native``) unless overridden
    explicitly via ``--docker-image``. Production runs should never change
    this.

    ``use_integration_docker``: when ``True``, the analyzer reads
    ``script.dockerimage`` from the integration's YML and uses that image
    for the per-command child instead of ``default_image``. This is
    opt-in for two reasons:

      1. **Reproducibility.** The pinned ``py3-native`` image gives every
         integration the same baseline runtime so one missing third-party
         package can be triaged once and reported uniformly via the
         ``module_not_found`` status.
      2. **Footprint.** Per-integration images can be large (some are
         600MB+) and pulling N different images during a batch run is
         expensive on bandwidth and disk.

    Opt in (e.g., when the AI hits a ``module_not_found`` and wants to
    re-run that one integration with its real runtime) via
    ``--use-integration-docker`` on the CLI. The flag is harmless when
    the YML doesn't declare ``script.dockerimage`` — we fall back to
    ``default_image`` and log a one-line note.

    ``effective_use_docker``: resolved boolean — whether THIS analyzer run
    should actually invoke Docker. Set by :func:`resolve_docker_config`
    after probing the host. ``None`` until resolved.

    ``pulled_images``: set of image refs we've already verified for this
    analyzer-process run. Saves a redundant ``docker image inspect`` on
    every command of the same integration.
    """

    mode: str = "auto"
    default_image: str = DEFAULT_DOCKER_IMAGE
    use_integration_docker: bool = False
    effective_use_docker: bool | None = None
    pulled_images: set[str] = field(default_factory=set)

    def resolve_image_for(self, yml_data: dict[str, Any] | None) -> str:
        """Pick the runtime image for one integration.

        When ``use_integration_docker`` is enabled and the YML declares a
        ``script.dockerimage``, return it. Otherwise fall back to
        ``default_image``. The returned value is the only image the
        per-integration child run will use; lazy-pull caching is keyed
        on it via ``pulled_images``.
        """
        if not self.use_integration_docker or not yml_data:
            return self.default_image
        script = yml_data.get("script") or {}
        image = script.get("dockerimage") if isinstance(script, dict) else None
        if isinstance(image, str) and image.strip():
            return image.strip()
        return self.default_image


def _docker_available() -> bool:
    """True iff the ``docker`` CLI is on PATH and the daemon answers."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


def resolve_docker_config(cfg: DockerConfig) -> DockerConfig:
    """Decide whether this run actually uses Docker, given ``cfg.mode``.

    * ``never`` → host python3.
    * ``always`` → require Docker; raise :class:`DynamicAnalysisError` if
      it's not available.
    * ``auto`` → use Docker if available, else log a warning and fall back
      to host python3.
    """
    if cfg.mode == "never":
        cfg.effective_use_docker = False
        return cfg
    available = _docker_available()
    if cfg.mode == "always":
        if not available:
            raise DynamicAnalysisError(
                "--docker always: docker CLI not on PATH or daemon not "
                "responding"
            )
        cfg.effective_use_docker = True
        return cfg
    # auto
    if available:
        cfg.effective_use_docker = True
        print(
            f"[dynamic] Docker available; child processes will run in "
            f"containers (default image: {cfg.default_image})",
            file=sys.stderr,
        )
    else:
        cfg.effective_use_docker = False
        print(
            "[dynamic] Docker not available; falling back to host python3 "
            "(some integrations may fail with ModuleNotFoundError)",
            file=sys.stderr,
        )
    return cfg


def _ensure_image_pulled(image: str, pulled_cache: set[str]) -> None:
    """Make sure ``image`` exists locally; pull lazily on first use."""
    if image in pulled_cache:
        return
    print(
        f"[docker] ensuring image {image} is available...", file=sys.stderr
    )
    inspect = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
    )
    if inspect.returncode != 0:
        print(f"[docker] pulling {image}...", file=sys.stderr)
        try:
            pull = subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired as exc:
            raise DynamicAnalysisError(
                f"docker pull {image} timed out after 300s"
            ) from exc
        if pull.returncode != 0:
            raise DynamicAnalysisError(
                f"docker pull {image} failed: rc={pull.returncode} "
                f"stderr={pull.stderr.strip()[:500]}"
            )
    pulled_cache.add(image)


def _docker_proxy_host(proxy_url: str) -> tuple[str, list[str]]:
    """Translate the host proxy URL for a child running in Docker.

    Returns ``(in_container_proxy_url, extra_docker_args)``.

    * Linux: ``--network host`` works. Use the original ``127.0.0.1`` URL.
    * macOS / Windows: ``--network host`` does NOT bridge to the host on
      Docker Desktop. Use ``--add-host=host.docker.internal:host-gateway``
      (a no-op on Desktop, where the alias already exists, but explicit
      and self-documenting) and rewrite the URL host accordingly.
    """
    sysname = platform.system()
    if sysname == "Linux":
        return proxy_url, ["--network", "host"]
    rewritten = proxy_url.replace("127.0.0.1", "host.docker.internal").replace(
        "localhost", "host.docker.internal"
    )
    return rewritten, ["--add-host=host.docker.internal:host-gateway"]


def _docker_invocation_error(rc: int, stderr: str) -> str | None:
    """If ``rc`` is a Docker-engine error (not the wrapped command), describe it.

    Returns a human-readable string when ``rc`` indicates Docker itself
    failed; ``None`` otherwise (in which case the caller should treat
    ``rc`` as the wrapped child's exit code).
    """
    if rc == DOCKER_DAEMON_RC:
        return f"docker daemon error (rc=125): {stderr.strip()[:500]}"
    if rc == DOCKER_NOT_EXECUTABLE_RC:
        return f"docker container command not executable (rc=126): {stderr.strip()[:500]}"
    if rc == DOCKER_CMD_NOT_FOUND_RC:
        return f"docker container command not found (rc=127): {stderr.strip()[:500]}"
    return None


def _build_child_env(
    params: dict[str, Any],
    command: str,
    proxy_url: str,
    unified_path: str,
    mock_dir: str,
) -> dict[str, str]:
    """Build the env vars the bootstrap script reads to drive one command."""
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": "",
        "CHECK_PARAMS_JSON": json.dumps(params),
        "CHECK_COMMAND": command,
        "CHECK_UNIFIED_PATH": unified_path,
        "CHECK_MOCK_DIR": mock_dir,
    }


def _decode_subprocess_streams(
    out_raw: Any, err_raw: Any
) -> tuple[str, str]:
    """Best-effort decode for ``subprocess`` stdout/stderr (bytes or str)."""
    out = (
        out_raw.decode("utf-8", errors="replace")
        if isinstance(out_raw, (bytes, bytearray))
        else (out_raw or "")
    )
    err = (
        err_raw.decode("utf-8", errors="replace")
        if isinstance(err_raw, (bytes, bytearray))
        else (err_raw or "")
    )
    return out, err


def _run_child_host(
    bootstrap_path: Path,
    env: dict[str, str],
    timeout: int,
) -> tuple[int, str, str, bool]:
    """Run the child via the host's ``sys.executable`` (legacy path)."""
    full_env = dict(os.environ)
    full_env.update(env)
    try:
        proc = subprocess.run(
            [sys.executable, str(bootstrap_path)],
            capture_output=True,
            text=True,
            env=full_env,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as exc:
        out, err = _decode_subprocess_streams(exc.stdout, exc.stderr)
        return -1, out, err, True


def _run_child_docker(
    tmp_dir: Path,
    env: dict[str, str],
    timeout: int,
    image: str,
    pulled_cache: set[str],
    proxy_url: str,
) -> tuple[int, str, str, bool]:
    """Run the child inside a Docker container.

    The caller must already have written ``bootstrap.py``,
    ``unified_integration.py``, and ``mock/`` into ``tmp_dir``. We mount
    ``tmp_dir`` read-only at ``/check`` and execute
    ``python3 /check/bootstrap.py`` inside ``image``.
    """
    _ensure_image_pulled(image, pulled_cache)
    container_proxy, network_args = _docker_proxy_host(proxy_url)
    # Override container-side env to match the rewritten proxy host (macOS).
    docker_env = dict(env)
    docker_env["HTTP_PROXY"] = container_proxy
    docker_env["HTTPS_PROXY"] = container_proxy
    docker_env["http_proxy"] = container_proxy
    docker_env["https_proxy"] = container_proxy
    # Container-side paths for the unified integration + mock dir.
    docker_env["CHECK_UNIFIED_PATH"] = "/check/unified_integration.py"
    docker_env["CHECK_MOCK_DIR"] = "/check/mock"

    cmd: list[str] = [
        "docker",
        "run",
        "--rm",
        # demisto/py3-native is built for linux/amd64. Pinning the platform
        # explicitly silences the "image platform does not match host" warning
        # that Docker Desktop emits when the host is arm64 (Apple Silicon).
        "--platform",
        "linux/amd64",
        *network_args,
        "-v",
        f"{tmp_dir}:/check:ro",
    ]
    for key, value in docker_env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.extend([image, "python3", "/check/bootstrap.py"])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        out, err = _decode_subprocess_streams(exc.stdout, exc.stderr)
        return -1, out, err, True
    invocation_err = _docker_invocation_error(proc.returncode, proc.stderr)
    if invocation_err is not None:
        raise DynamicAnalysisError(f"docker invocation failed: {invocation_err}")
    return proc.returncode, proc.stdout, proc.stderr, False


def run_integration(
    unified_path: Path,
    mock_dir: Path,
    command: str,
    params: dict[str, Any],
    proxy_url: str,
    timeout: int,
    docker_cfg: DockerConfig | None = None,
    image: str | None = None,
) -> tuple[int, str, str, bool]:
    """Run the integration in a child process. Returns ``(rc, stdout, stderr, timed_out)``.

    When ``docker_cfg.effective_use_docker`` is true, the child runs in a
    container based on ``image`` (or, when ``image`` is ``None``,
    ``docker_cfg.default_image``). Callers that want per-integration
    runtime selection (``--use-integration-docker``) resolve the image
    once via :meth:`DockerConfig.resolve_image_for` and pass it in
    here, so every per-command run for that integration uses the same
    container.

    Otherwise the legacy host-python path is used. If the integration
    needs a different runtime than what the child has and the AI did
    NOT opt into the integration docker, the child crashes with
    ``ModuleNotFoundError`` and the caller surfaces ``module_not_found``.
    """
    use_docker = bool(docker_cfg and docker_cfg.effective_use_docker)

    # The bootstrap script must live next to ``unified_integration.py`` so
    # that mounting the tmp dir at ``/check`` exposes everything together.
    tmp_dir = unified_path.parent
    bootstrap_path = tmp_dir / "bootstrap.py"
    if not bootstrap_path.is_file():
        bootstrap_path.write_text(_BOOTSTRAP_TEMPLATE, encoding="utf-8")

    env = _build_child_env(
        params=params,
        command=command,
        proxy_url=proxy_url,
        unified_path=str(unified_path),
        mock_dir=str(mock_dir),
    )

    if not use_docker:
        return _run_child_host(bootstrap_path, env, timeout)

    assert docker_cfg is not None  # narrowed by use_docker
    effective_image = image or docker_cfg.default_image
    return _run_child_docker(
        tmp_dir=tmp_dir,
        env=env,
        timeout=timeout,
        image=effective_image,
        pulled_cache=docker_cfg.pulled_images,
        proxy_url=proxy_url,
    )


def detect_sentinel_hits(
    requests: list[dict[str, Any]],
    sentinels: dict[str, list[str]],
) -> set[str]:
    """Return the set of YML param names whose sentinel(s) appear in any request.

    A param is considered relevant if ANY of its sentinel strings appears
    anywhere in the captured request blob (method, URL, headers, body).
    Params with an empty sentinel list (non-traceable: bools, numerics,
    short defaults) are skipped silently.
    """
    if not requests:
        return set()
    blob_parts: list[str] = []
    for req in requests:
        blob_parts.append(req.get("method", ""))
        blob_parts.append(req.get("url", ""))
        for k, v in (req.get("headers") or {}).items():
            blob_parts.append(f"{k}: {v}")
        blob_parts.append(req.get("body", "") or "")
    blob = "\n".join(blob_parts)
    hits: set[str] = set()
    for name, tokens in sentinels.items():
        if not tokens:
            continue
        if any(tok and tok in blob for tok in tokens):
            hits.add(name)
    return hits


def _short_stderr(stderr: str, limit: int = 240) -> str:
    """Pick the most useful single line from a child's stderr for a log msg.

    Preference order (highest first):

    1. ``RETURN_ERROR_PATCHED:`` marker line — the explicit signal from
       our patched ``return_error``.
    2. Any line containing ``SENTINEL_PARAM_`` — strong evidence that a
       seeded sentinel value caused the failure (the param name is right
       there in the message).
    3. The last non-empty line — usually the exception summary.
    """
    if not stderr:
        return ""
    lines = stderr.splitlines()
    # 1. Patched return_error marker.
    for line in lines:
        if "RETURN_ERROR_PATCHED:" in line:
            return line.strip()[:limit]
    # 2. Any line that names a sentinel — that is the actionable error.
    for line in lines:
        if "SENTINEL_PARAM_" in line:
            return line.strip()[:limit]
    # 3. Last non-empty line.
    for line in reversed(lines):
        s = line.strip()
        if s:
            return s[:limit]
    return ""


# Regex matching ``SENTINEL_PARAM_<name>`` in any text blob (stderr,
# return_error message, exception text). Captures only the param name.
_SENTINEL_PARAM_RE = re.compile(r"SENTINEL_PARAM_([A-Za-z_][A-Za-z0-9_]*)")


def extract_failing_params(text: str, yml_param_names: set[str]) -> list[str]:
    """Pick the param names that appear as ``SENTINEL_PARAM_<name>`` in *text*.

    Cross-references each captured name against ``yml_param_names`` so a
    sentinel-looking substring whose suffix is not a real YML param (e.g.,
    a typo in the integration source) is dropped.

    Returns a sorted list of unique names.
    """
    if not text:
        return []
    found = {m.group(1) for m in _SENTINEL_PARAM_RE.finditer(text)}
    return sorted(found & yml_param_names)


# Module name captured from a child's ``ModuleNotFoundError`` line, e.g.
# ``ModuleNotFoundError: No module named 'pymisp'``.
_MODULE_NOT_FOUND_RE = re.compile(
    r"ModuleNotFoundError: No module named ['\"]([^'\"]+)['\"]"
)


def extract_missing_module(stderr: str) -> tuple[str, str] | None:
    """If *stderr* contains a ``ModuleNotFoundError`` line, return ``(module, line)``.

    Returns ``None`` when no such line is found. The returned ``line`` is
    the matched ``ModuleNotFoundError: ...`` text, useful as a
    ``failure_excerpt`` for the diagnostic.
    """
    if not stderr:
        return None
    for line in stderr.splitlines():
        match = _MODULE_NOT_FOUND_RE.search(line)
        if match:
            return match.group(1), line.strip()
    return None


@dataclass
class CommandDiagnostic:
    """Per-command outcome metadata surfaced in the JSON ``diagnostics`` field.

    ``status`` values: ``ok`` / ``ok_no_capture`` / ``param_caused_failure``
    / ``no_data`` / ``timeout`` / ``docker_error`` / ``module_not_found``.
    See module docstring for the full enum.

    ``scope_1_narrowed`` / ``scope_1_dropped`` are set only when the
    hybrid Scope-1 narrowing path fired for this command (status ``ok``
    with HTTP captures and at least one sentinel hit). They tell the
    calling agent that the per-command list was trimmed using HTTP
    evidence — the agent can trust those cells more, but should still
    verify against source if something expected is missing.
    """

    status: str
    captured_requests: int = 0
    failure_excerpt: str = ""
    failing_params: list[str] = field(default_factory=list)
    missing_module: str | None = None
    scope_1_narrowed: bool = False
    scope_1_dropped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Render the diagnostic as a plain dict for JSON serialization."""
        out: dict[str, Any] = {
            "status": self.status,
            "captured_requests": self.captured_requests,
        }
        if self.failure_excerpt and self.status not in {"ok", "ok_no_capture"}:
            out["failure_excerpt"] = self.failure_excerpt[:500]
        if self.failing_params:
            out["failing_params"] = self.failing_params
        if self.missing_module is not None:
            out["missing_module"] = self.missing_module
        if self.scope_1_narrowed:
            out["scope_1_narrowed"] = True
            out["scope_1_dropped"] = self.scope_1_dropped
        return out


def analyze_dynamic_for_command(
    proxy: CaptureProxy,
    unified_path: Path,
    mock_dir: Path,
    command: str,
    yml_params: list[dict[str, Any]],
    ignore: set[str],
    timeout: int,
    docker_cfg: DockerConfig | None = None,
    image: str | None = None,
) -> tuple[set[str], CommandDiagnostic]:
    """Return ``(captured_param_names, diagnostic)`` for one command.

    The caller merges the captured set into ``dynamic_results[cmd]`` and
    forwards the diagnostic into the JSON ``diagnostics`` field.

    Decision table (see design doc "Handling Exceptions in Dynamic Analysis"):

    * timeout → :class:`DynamicAnalysisError` (status will be ``timeout``).
    * Failure classification when the child fails AND zero captures
      (first match wins):

      1. ``ModuleNotFoundError`` in stderr → status ``module_not_found``
         with ``missing_module`` set; returns cleanly (no exception).
      2. ``SENTINEL_PARAM_<name>`` in stderr → status
         ``param_caused_failure`` with those names elevated.
      3. Otherwise → ``no_data`` (loud-fail :class:`DynamicAnalysisError`).

    * ``rc == 7`` AND captured > 0 → tolerated; status ``ok``.
    * ``rc != 0`` AND captured > 0 → tolerated; status ``ok``.
    * ``rc == 0`` AND captured > 0 → status ``ok``.
    * ``rc == 0`` AND zero captured → status ``ok_no_capture``.
    """
    import time as _t

    proxy_url = f"http://127.0.0.1:{proxy.port}"
    values, sentinels, _non_traceable = build_param_values(
        yml_params, proxy_url, ignore
    )
    yml_param_names = {p["name"] for p in yml_params}
    session_id = proxy.new_session()
    _t0 = _t.time()
    rc, _stdout, stderr, timed_out = run_integration(
        unified_path,
        mock_dir,
        command,
        values,
        proxy_url,
        timeout,
        docker_cfg=docker_cfg,
        image=image,
    )
    elapsed = _t.time() - _t0
    captured = proxy.get_requests(session_id)
    proxy.delete_session(session_id)

    if timed_out:
        raise DynamicAnalysisError(
            f"command {command!r} timed out after {timeout}s "
            f"(use --timeout to extend)\nchild stderr:\n{stderr}"
        )

    short_excerpt = _short_stderr(stderr, limit=500)

    # Failure-before-HTTP paths (rc=7 short-circuit, or any non-zero rc with
    # zero captures): classify the failure. Order matters — first match wins.
    if (rc == RC_RETURN_ERROR_PATCHED and not captured) or (
        rc != 0 and not captured
    ):
        # 1. ModuleNotFoundError → integration needs a third-party package
        #    not present in the pinned analyzer runtime image. Surface
        #    cleanly so the calling agent can read the source manually
        #    (analogous to how JS / PowerShell integrations are handled).
        missing = extract_missing_module(stderr)
        if missing is not None:
            module_name, error_line = missing
            print(
                f"[dyn] {command}: child crashed with ModuleNotFoundError "
                f"(missing {module_name!r}); reporting module_not_found",
                file=sys.stderr,
            )
            diag = CommandDiagnostic(
                status="module_not_found",
                captured_requests=0,
                failure_excerpt=error_line[:500],
                missing_module=module_name,
            )
            return set(), diag
        # 2. Sentinel attribution.
        failing = extract_failing_params(stderr, yml_param_names)
        if failing:
            print(
                f"[dyn] {command}: failure attributed to params {failing} "
                f"(rc={rc}); elevating them as relevant",
                file=sys.stderr,
            )
            diag = CommandDiagnostic(
                status="param_caused_failure",
                captured_requests=0,
                failure_excerpt=short_excerpt,
                failing_params=failing,
            )
            return set(failing), diag
        # 3. No specific attribution → fall back to the loud-fail behaviour.
        if rc == RC_RETURN_ERROR_PATCHED:
            raise DynamicAnalysisError(
                f"command {command!r} called return_error before any HTTP "
                f"request: {short_excerpt}"
            )
        raise DynamicAnalysisError(
            f"command {command!r} failed before issuing any HTTP request: "
            f"rc={rc}\nchild stderr:\n{stderr}"
        )

    print(
        f"[dyn] {command}: captured {len(captured)} requests in {elapsed:.2f}s "
        f"(rc={rc})",
        file=sys.stderr,
    )
    if rc == RC_RETURN_ERROR_PATCHED:
        print(
            f"[dyn] {command}: short-circuited via return_error after "
            f"{len(captured)} captured requests; sentinel scan still applies",
            file=sys.stderr,
        )
    elif rc != 0:
        print(
            f"[dyn] {command}: child returned rc={rc} after "
            f"{len(captured)} captured requests; proceeding with sentinel scan",
            file=sys.stderr,
        )
    hits = detect_sentinel_hits(captured, sentinels)
    status = "ok" if captured else "ok_no_capture"
    diag = CommandDiagnostic(status=status, captured_requests=len(captured))
    return hits, diag


# --------------------------------------------------------------------------
# Top-level orchestration
# --------------------------------------------------------------------------


def _classify_dynamic_error(exc: DynamicAnalysisError) -> str:
    """Map a :class:`DynamicAnalysisError` message to a diagnostic ``status``.

    Used when the per-command runner raises instead of returning a
    diagnostic of its own (timeout / docker invocation / generic no-data).
    """
    msg = str(exc)
    if "timed out after" in msg:
        return "timeout"
    if "docker invocation failed" in msg or "docker daemon error" in msg:
        return "docker_error"
    return "no_data"


def _merge_command_params(
    command: str,
    static_pair: tuple[set[str], set[str]],
    captured: set[str],
    diag: CommandDiagnostic | None,
) -> set[str]:
    """Merge per-command static and dynamic results with hybrid Scope-1 narrowing.

    When dynamic actually exercised the command end-to-end (status ``ok``,
    ``captured_requests > 0``, and at least one captured sentinel hit), use
    the captured set as evidence to **narrow** Scope-1 to params that
    actually reached the wire for this command. Scope-2 (per-command
    handler-traced params) is preserved as-is. This eliminates the
    ``Client(...)`` fan-out false positive where every command appears to
    use every Client-init param.

    When dynamic did not run, captured nothing, or hit zero sentinels,
    fall back to the full ``scope_1 | scope_2`` static union (we cannot
    safely narrow without HTTP evidence).

    Side effect: when narrowing fires, ``diag.scope_1_narrowed`` is set
    to ``True`` and ``diag.scope_1_dropped`` is populated with the
    Scope-1 params that were dropped. The diagnostic is mutated in place.
    """
    scope_1, scope_2 = static_pair
    can_narrow = (
        diag is not None
        and diag.status == "ok"
        and diag.captured_requests > 0
        and bool(captured)
    )
    if can_narrow:
        assert diag is not None  # for type checkers; can_narrow guarantees it
        narrowed_scope_1 = scope_1 & captured
        diag.scope_1_narrowed = True
        diag.scope_1_dropped = sorted(scope_1 - captured)
        return narrowed_scope_1 | scope_2 | captured
    return scope_1 | scope_2 | captured


def analyze_integration(
    integration_path: Path,
    commands_filter: list[str] | None,
    static_only: bool,
    ignore: set[str],
    timeout: int,
    docker_cfg: DockerConfig | None = None,
) -> dict[str, Any]:
    """Run the full analysis pipeline for one integration.

    Loud-fail policy: any error other than "static AST is being asked to
    look at a non-Python integration" propagates to the caller.

    The returned dict always contains ``integration`` and ``commands``.
    When dynamic analysis ran (``static_only`` is False), it additionally
    contains a ``diagnostics`` key with one entry per command. Under
    ``--static-only`` the ``diagnostics`` key is omitted entirely (see
    module docstring).
    """
    yml_path, py_path = find_integration_files(integration_path)
    yml_data = load_yml(yml_path)
    yml_params = get_yml_params(yml_data)
    all_param_names = [p["name"] for p in yml_params]
    language = (yml_data.get("script") or {}).get("type")
    integration_name = display_name(yml_data, integration_path.name)

    discovered = discover_commands(yml_data)
    if commands_filter:
        commands = [c for c in commands_filter if c in discovered or c in {"test-module"}]
    else:
        commands = discovered

    py_source = py_path.read_text(encoding="utf-8") if py_path is not None else ""

    print(
        f"[static] analyzing {integration_name!r} ({len(commands)} commands)",
        file=sys.stderr,
    )
    static_results: dict[str, tuple[set[str], set[str]]] = {}
    for cmd in commands:
        static_results[cmd] = analyze_static(
            py_source, cmd, language=language, integration_name=integration_name
        )

    dynamic_results: dict[str, set[str]] = {cmd: set() for cmd in commands}
    diagnostics: dict[str, CommandDiagnostic] = {}
    if not static_only:
        # Resolve the runtime image once per integration. When
        # --use-integration-docker is set and the YML declares
        # script.dockerimage, we use that; otherwise we use the pinned
        # default. Logging the chosen image makes the AI's choice
        # observable in the stderr stream.
        chosen_image: str | None = None
        if docker_cfg is not None:
            chosen_image = docker_cfg.resolve_image_for(yml_data)
            if (
                docker_cfg.use_integration_docker
                and chosen_image == docker_cfg.default_image
            ):
                print(
                    f"[dynamic] {integration_name!r}: --use-integration-docker "
                    f"set but YML declares no script.dockerimage; using "
                    f"default image {chosen_image}",
                    file=sys.stderr,
                )
            elif chosen_image != docker_cfg.default_image:
                print(
                    f"[dynamic] {integration_name!r}: using integration "
                    f"docker image {chosen_image} (per YML script.dockerimage)",
                    file=sys.stderr,
                )
        print(f"[dynamic] analyzing {integration_name!r}", file=sys.stderr)
        _run_dynamic_phase(
            integration_path,
            commands,
            yml_params,
            ignore,
            timeout,
            dynamic_results,
            diagnostics,
            integration_name=integration_name,
            docker_cfg=docker_cfg,
            image=chosen_image,
        )

    out_commands: dict[str, list[str]] = {}
    for cmd in commands:
        merged_set = _merge_command_params(
            cmd,
            static_results[cmd],
            dynamic_results[cmd],
            diagnostics.get(cmd),
        )
        out_commands[cmd] = sorted(
            name for name in all_param_names
            if name in merged_set and name not in ignore
        )

    result: dict[str, Any] = {
        "integration": integration_name,
        "commands": out_commands,
    }
    if not static_only:
        result["diagnostics"] = {cmd: diag.to_dict() for cmd, diag in diagnostics.items()}
    return result


def _run_dynamic_phase(
    integration_path: Path,
    commands: list[str],
    yml_params: list[dict[str, Any]],
    ignore: set[str],
    timeout: int,
    dynamic_results: dict[str, set[str]],
    diagnostics: dict[str, CommandDiagnostic],
    integration_name: str = "",
    docker_cfg: DockerConfig | None = None,
    image: str | None = None,
) -> None:
    """Drive prepare-content + per-command dynamic runs.

    Populates *dynamic_results* (captured param names per command) and
    *diagnostics* (one :class:`CommandDiagnostic` per command).

    Setup-level failures (``DynamicPrepError`` from
    :func:`prepare_unified_content`) propagate — those mean the unified
    .py couldn't even be built, and there's no useful per-command work
    we could do.

    Per-command failures (:class:`DynamicAnalysisError`) are caught and
    logged, with an empty captured set stored for that command so the
    static signal still flows to the merged output, and a diagnostic
    entry recording the failure status. If EVERY command fails, that's
    logged as a structural warning (likely an import-time crash hiding
    behind a misleading rc) but the function still returns normally —
    the static-only result remains valid.
    """
    with tempfile.TemporaryDirectory(prefix="ccp_") as tmp:
        tmp_dir = Path(tmp)
        unified, mock_dir = prepare_unified_content(integration_path, tmp_dir)
        proxy = CaptureProxy(port=0)
        proxy.start()
        print(f"[dynamic] proxy listening on port {proxy.port}", file=sys.stderr)
        failures = 0
        try:
            for cmd in commands:
                try:
                    captured_set, diag = analyze_dynamic_for_command(
                        proxy,
                        unified,
                        mock_dir,
                        cmd,
                        yml_params,
                        ignore,
                        timeout,
                        docker_cfg=docker_cfg,
                        image=image,
                    )
                    dynamic_results[cmd] = captured_set
                    diagnostics[cmd] = diag
                    if diag.status == "param_caused_failure":
                        failures += 1
                except DynamicAnalysisError as exc:
                    failures += 1
                    dynamic_results[cmd] = set()
                    short = str(exc).splitlines()[0][:240]
                    print(f"[dyn] {cmd}: FAILED — {short}", file=sys.stderr)
                    diagnostics[cmd] = CommandDiagnostic(
                        status=_classify_dynamic_error(exc),
                        captured_requests=0,
                        failure_excerpt=str(exc)[:500],
                    )
        finally:
            proxy.stop()
        if commands and failures == len(commands):
            print(
                f"[dynamic] all {len(commands)} commands failed for "
                f"{integration_name or integration_path.name}; static-only "
                f"result will still be emitted",
                file=sys.stderr,
            )


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze which YML params each command of an XSOAR integration uses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "integration_path",
        help="Path to the integration directory (e.g., Packs/HelloWorld/Integrations/HelloWorldV2).",
    )
    parser.add_argument(
        "--commands",
        nargs="+",
        default=None,
        help="Subset of commands to analyze. Default: all commands discovered from YML.",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Skip dynamic (proxy-based) analysis. Static AST analysis only.",
    )
    parser.add_argument(
        "--ignore-params",
        nargs="+",
        default=None,
        help="Param names to drop from analysis (omitted from output entirely).",
    )
    parser.add_argument(
        "--ignore-params-file",
        type=Path,
        default=None,
        help="File with one param name per line (# comments allowed) to ignore.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_DYNAMIC_TIMEOUT_S,
        help=f"Per-command dynamic timeout in seconds (default: {DEFAULT_DYNAMIC_TIMEOUT_S}).",
    )
    parser.add_argument(
        "--docker",
        choices=("auto", "always", "never"),
        default="auto",
        help=(
            "Where to run the integration child process. "
            "'auto' (default): use Docker if available, else host python3. "
            "'always': require Docker (fail if not available). "
            "'never': use host python3 (legacy behavior)."
        ),
    )
    parser.add_argument(
        "--docker-image",
        default=DEFAULT_DOCKER_IMAGE,
        help=(
            f"Override the pinned analyzer runtime image (default: "
            f"{DEFAULT_DOCKER_IMAGE}). Used as the BASE image when "
            f"--use-integration-docker is not set, OR as the fallback "
            f"when --use-integration-docker is set but the integration "
            f"YML doesn't declare script.dockerimage. Provided for "
            f"testing/debugging — under normal use the default is correct."
        ),
    )
    parser.add_argument(
        "--use-integration-docker",
        action="store_true",
        help=(
            "Use the integration's own script.dockerimage from its YML "
            "instead of the pinned default image. Opt-in because the "
            "pinned image keeps batch runs reproducible and avoids "
            "pulling many large per-integration images. Use this when "
            "the default analyzer image hits 'module_not_found' for an "
            "integration that needs a third-party Python package "
            "(e.g., httpx, pymisp) only present in its real runtime. "
            "When the YML doesn't declare a dockerimage we silently fall "
            "back to --docker-image."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Exit codes:
    * ``0`` — success.
    * ``2`` — bad CLI args / missing path / missing ignore-file.
    * ``3`` — any other unhandled failure during analysis (full traceback
      goes to stderr).
    """
    import traceback

    args = _parse_args(argv if argv is not None else sys.argv[1:])
    integration_path = Path(args.integration_path).resolve()
    if not integration_path.is_dir():
        print(
            f"ERROR: integration path is not a directory: {integration_path}",
            file=sys.stderr,
        )
        return 2
    try:
        ignore = load_ignore_params(args.ignore_params, args.ignore_params_file)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    docker_cfg = DockerConfig(
        mode=args.docker,
        default_image=args.docker_image,
        use_integration_docker=args.use_integration_docker,
    )
    if not args.static_only:
        try:
            resolve_docker_config(docker_cfg)
        except DynamicAnalysisError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 3
    try:
        result = analyze_integration(
            integration_path=integration_path,
            commands_filter=args.commands,
            static_only=args.static_only,
            ignore=ignore,
            timeout=args.timeout,
            docker_cfg=docker_cfg,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — loud-fail policy
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 3
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
