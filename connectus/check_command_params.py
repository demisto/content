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

    python3 connectus/check_command_params.py [<integration_path>] \\
        [--commands cmd1 cmd2 ...] \\
        [--static-only] \\
        [--ignore-params PARAM [PARAM ...]] \\
        [--ignore-params-file PATH] \\
        [--integration-id ID] \\
        [--use-integration-docker] \\
        [--no-sentinel-coercion] \\
        [--no-auto-retry-integration-docker] \\
        [--seed-param NAME=VALUE [--seed-param NAME=VALUE ...]]

The positional ``<integration_path>`` is OPTIONAL: supply it directly,
OR supply ``--integration-id ID`` and the path is resolved from the
workflow CSV's ``Integration File Path`` column (via
:func:`resolve_integration_path`). Exactly one of the two is required.
If both are given the explicit path wins, and ``--integration-id`` still
contributes the auth-aware ignore set described below. Inside the
migration workflow this lets the canonical invocation drop the redundant
hand-typed path and pass only ``--integration-id``.

Three behaviour gates added in the latest analyzer revision:

* **Hidden YML param exclusion (Change #1).** Any param whose YML
  ``hidden:`` key is ``true`` OR a non-empty list (the per-platform
  form, e.g. ``[xsoar]``, ``[marketplacev2, platform]``) is filtered
  out of every analyzer artifact: the seed dict (no sentinel slot
  wasted on it), the static walker (no Scope-1 fan-out via reads of
  it), and every per-command output list. Hidden names are also
  silently absorbed into the effective ignore set as a fourth source
  (after inline / file / auth-derived) and logged on stderr as
  ``[ignore] Hidden YML params excluded: [...]``. See
  :func:`is_hidden_param`.

* **Cert/key/thumbprint sentinel coercion (Change #2 / Fix F).** When
  seeding a YML param whose name contains ``thumbprint`` /
  ``private_key`` / ``certificate`` (case-insensitive substring), the
  generic ``SENTINEL_PARAM_<name>`` string is replaced with a
  syntactically-valid stub (40 hex chars for thumbprint; PEM blocks
  for the others) so format validators like ``binascii.a2b_hex`` and
  PEM regexes don't crash at module import. The coerced values do NOT
  contain ``SENTINEL_PARAM_<name>`` so sentinel-attribution by name
  match cannot find them on the wire — that's the explicit trade-off
  versus 100% ``no_data`` everywhere. Use ``--no-sentinel-coercion``
  to disable. See :func:`coerce_sentinel_for_param`. **Operator
  escape hatch:** ``--seed-param NAME=VALUE`` (repeatable) overrides
  the seeded value for any named YML param, winning over the YML
  defaultvalue, the auto-coercion above, and the generic sentinel.
  Use this when an integration tripping a format validator that the
  auto-coercion didn't anticipate (e.g. a custom regex on a free-form
  text param). The skill (``connectus-migration-SKILL.md``)
  documents the recovery loop.

* **Fail-fast / auto-retry on module_not_found (Change #3 / Fix G).**
  After the FIRST command's dynamic phase completes, the analyzer
  checks the diagnostic. If ``status == "module_not_found"`` AND
  ``--use-integration-docker`` was NOT already in effect AND auto-retry
  is enabled (default), the entire dynamic phase restarts with
  ``--use-integration-docker`` flipped on. If integration docker is
  already in use (or auto-retry is disabled via
  ``--no-auto-retry-integration-docker``), every remaining command is
  fast-failed as ``module_not_found`` without invoking its child —
  saving ~30s × (N-1) seconds. Known false-positive: when only some
  commands need the missing package, the others are incorrectly
  attributed (the trade-off is intentional; empirically the package
  is needed at module import for the common case).

The optional ``--integration-id`` flag pulls the integration's
auth-derived ignore set from
``connectus/workflow_state.py auth-params <id>`` and unions it into the
analyzer's ignore set, guaranteeing that any param already declared in
``Auth Details`` (auth secrets + ``other_connection``) cannot leak into
the per-command output. Standalone runs outside the migration workflow
can omit it; ``--ignore-params-file`` continues to work on its own.

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
      }
      # NOTE: "diagnostics" is OPT-IN. By default the analyzer emits
      # ONLY {"integration", "commands"} so the stdout JSON can be
      # piped verbatim into
      #   workflow_state.py set-params-to-commands "<id>" '<json>'
      # whose strict schema validator
      # (validate_params_to_commands) rejects any extra top-level
      # key. To get the diagnostic-rich payload (interactive / debug
      # use only — must NOT be persisted to the pipeline CSV), pass
      # --with-diagnostics. See "Diagnostics payload" below.
    }

When ``--with-diagnostics`` is set, the analyzer additionally emits a
top-level ``diagnostics`` key::

    {
      "integration": "<display name>",
      "commands": { ... },
      "diagnostics": {              # dynamic-only; omitted under --static-only
        "<cmd>": {
          "status": "ok" | "ok_no_capture" | "param_caused_failure"
                  | "no_data" | "timeout" | "docker_error"
                  | "module_not_found",
          "captured_requests": <int>,
          "failure_excerpt": "<str, optional, max 500 chars>",
          "failing_params": ["<param>", ...],  # only if param_caused_failure
          "missing_module": "<str>",           # only if module_not_found
          "limitation": "<str, optional>"      # known analyzer limitation,
                                               # e.g. 'capture_proxy_bypassed'
                                               # for boto3-based integrations
        }
      }
    }

**BREAKING CHANGE (default-flip):** prior revisions emitted the
``diagnostics`` payload by default in dynamic mode. That allowed the
key to leak into ``Params to Commands`` when the agent piped stdout
verbatim. The new default is the clean two-key payload; callers that
relied on the old shape MUST pass ``--with-diagnostics``. Static mode
(``--static-only``) is unaffected — it never emitted diagnostics.

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

The ``diagnostics`` field is internal AI-consumed metadata. It is now
opt-in via ``--with-diagnostics`` (was: emitted-by-default in dynamic
mode); the agent flow that pipes analyzer stdout into
``workflow_state.py set-params-to-commands`` MUST NOT pass the flag
because the workflow_state strict-schema validator rejects any extra
top-level key. Under ``--static-only`` the field is omitted entirely
(unchanged).

**Hybrid Scope-1 narrowing.** When a command's dynamic phase actually
captured ``>=1`` HTTP request **and** at least one sentinel hit was
detected, the analyzer assumes that captured-set is an authoritative
bound on which params reached the wire for that command. It then
**narrows** the static Scope-1 set (pre-dispatch + module-level fan-out
params shared across all commands) to the intersection with the
captured params. Scope-2 (per-command handler-traced params, including
binding-narrowed dispatch-site reads) is preserved unchanged.

This is the only mechanism that trims the **module-level globals**
fan-out pattern, because :func:`collect_module_level_params` is
explicitly outside the static binding-narrowing pipeline (see the
"Binding-narrowing" section in :func:`analyze_static`). Static
binding-narrowing handles the ``Client(api_key=params.get("apikey"))``
intra-``main()`` pattern, but cannot touch
``CLIENT_ID = PARAMS.get("client_id")`` written at module scope —
that read fans out to every command unconditionally. Empirically (see
``connectus/check_command_params_validation_report.md``, post-fix
verification), CrowdStrike Falcon's 65 successfully-captured commands
each have 7 module-level Scope-1 false positives that ONLY dynamic
narrowing removes; without it those 7 params would be reported
everywhere.

When narrowing fires, the calling agent sees ``scope_1_narrowed: true``
and a non-empty ``scope_1_dropped`` list in ``diagnostics``. When
narrowing fires but the intersection equals the original Scope-1
(captured set was a superset — narrowing was applied but happened to
drop nothing), both fields are **omitted** to avoid the misleading
"narrowed but dropped nothing" reading. When dynamic did not capture
(status ``ok_no_capture``, ``module_not_found``, etc.) or hit zero
sentinels, the analyzer falls back to the full ``scope_1 | scope_2``
static union and adds no extra diagnostic field. Narrowing is silent
in ``commands`` and visible in ``diagnostics`` only.

**Known limitation: boto3 / AWS-family integrations bypass the capture
proxy.** The AWS Python SDK (``boto3`` / ``botocore``) does not honour
the ``HTTPS_PROXY`` / ``HTTP_PROXY`` environment variables in the same
way the capture proxy expects (it uses its own HTTP layer that has to
be configured per-client via ``Config(proxies=...)``). As a result,
every command of every ``boto3``-based integration will produce
``status: ok_no_capture`` (or ``no_data`` if the sentinel value
trips an early validator) regardless of whether the integration ran
successfully — the proxy simply never sees the request. **Hybrid
Scope-1 narrowing therefore does not fire for the AWS family** and
the per-command output is the full static ``scope_1 | scope_2``
union as-is. The narrowing safety-net at :func:`_merge_command_params`
correctly skips itself when ``captured_requests == 0`` (verified —
narrowing is only attempted when ``status == "ok"`` AND
``captured_requests > 0`` AND ``captured`` is non-empty), so there is
no risk of accidentally narrowing with an empty captured set and
zero-ing out the per-command output. Callers should expect AWS
integrations to receive the broader static surface and rely on the
analyzer's static fixes (helper-function recursion, alias-chain
matching, etc.) for correctness.

To make this discoverable at runtime, every per-command diagnostic for
a known proxy-bypassing integration is annotated with
``limitation: "capture_proxy_bypassed"`` so the calling agent can
flag the per-command lists as needing manual verification (the
analyzer cannot prove the static surface is exact when no request
ever reached the proxy). Detection is by static module-import
inspection: if the integration's source imports ``boto3``,
``botocore``, or any module ending in ``boto3`` / ``botocore``, the
limitation is attached to every command's diagnostic.

``commands`` lists, for each command, the params that are relevant to
it (case-sensitive, sorted). Params absent from the list (or excluded
via ``--ignore-params`` / ``--ignore-params-file``) are not relevant or
were explicitly excluded.

Example (real ``--use-integration-docker`` output for QRadar v3 — the
``adv_params`` sentinel trips a parser early in ``main()`` so every
command reports ``param_caused_failure`` with that param elevated; the
``long-running-execution`` row shows the broader Scope-2 fan-out of the
fetch loop)::

    {
      "integration": "IBM QRadar v3",
      "commands": {
        "test-module": ["adv_params", "fetch_interval"],
        "qradar-offenses-list": ["adv_params", "fetch_interval"],
        "long-running-execution": [
          "adv_params", "enrichment", "events_columns", "events_limit",
          "fetch_interval", "fetch_mode", "first_fetch", "incident_type",
          "limit_assets", "mirror_options", "offenses_per_fetch",
          "query", "retry_events_fetch"
        ]
      },
      "diagnostics": {
        "test-module": {
          "status": "param_caused_failure",
          "captured_requests": 0,
          "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
          "failing_params": ["adv_params"]
        },
        "long-running-execution": {
          "status": "param_caused_failure",
          "captured_requests": 0,
          "failure_excerpt": "integration_under_test.DemistoException: Failed to parse advanced parameter: SENTINEL_PARAM_adv_params - please make sure you entered it correctly",
          "failing_params": ["adv_params"]
        }
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


# Change 1: verdict labels emitted on ParamAttribution to power the
# consumer-side AI triage rule "review everything except provably 0%
# and provably 100%". Three values:
#
# * ``proven_used`` — rollup_confidence == 1.0 AND at least one source
#   is in {dynamic_capture, handler_body}. The "100% from the script"
#   case.
# * ``proven_unused`` — NO sources fired AND the analyzer is confident
#   in its reachability walk (high-quality analysis_status, no
#   walk_uncertain, no dynamic dispatch hit). The "provably 0%" case.
# * ``needs_review`` — everything else: any rollup in (0.0, 1.0)
#   exclusive, OR a silent zero where the walk WAS uncertain.
VERDICT_PROVEN_USED = "proven_used"
VERDICT_PROVEN_UNUSED = "proven_unused"
VERDICT_NEEDS_REVIEW = "needs_review"


# Change 1: analysis_status labels emitted on CommandDiagnostic. Each
# command gets exactly one status describing what reachability path
# the analyzer was able to use. Consumers gate the ``proven_unused``
# verdict on this status being one of the "high-quality" values
# (analyzed_handler_body / analyzed_via_helper_chain /
# analyzed_module_scope / analyzed_dict_dispatch).
ANALYSIS_STATUS_HANDLER_BODY = "analyzed_handler_body"
ANALYSIS_STATUS_HELPER_CHAIN = "analyzed_via_helper_chain"
ANALYSIS_STATUS_MODULE_SCOPE = "analyzed_module_scope"
ANALYSIS_STATUS_DICT_DISPATCH = "analyzed_dict_dispatch"
ANALYSIS_STATUS_HANDLER_NOT_FOUND = "handler_not_found"
ANALYSIS_STATUS_DISPATCH_UNRESOLVED = "dispatch_unresolved"
ANALYSIS_STATUS_MODULE_SCOPE_BLIND = "module_scope_dispatch_blind"
ANALYSIS_STATUS_DICT_DISPATCH_BLIND = "dict_dispatch_blind"
ANALYSIS_STATUS_SCATTERED_TRUNCATED = "scattered_dispatch_window_truncated"

# The set of statuses that are "high-quality enough" for a no-evidence
# param to be labelled proven_unused. Anything outside this set
# downgrades silent-zero to ``needs_review`` (the AI must triage).
_HIGH_QUALITY_ANALYSIS_STATUSES = frozenset(
    {
        ANALYSIS_STATUS_HANDLER_BODY,
        ANALYSIS_STATUS_HELPER_CHAIN,
        ANALYSIS_STATUS_MODULE_SCOPE,
        ANALYSIS_STATUS_DICT_DISPATCH,
    }
)
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


# Stub / shared-tooling files that may be checked into an integration
# directory by mistake (or left behind from a test fixture / global
# tooling pass) but which never define the integration's ``main()``.
# When the integration directory contains ANY of these, we MUST NOT pick
# them as the "the integration .py" — doing so causes static analysis to
# return empty for every command (the real bug exposed by AzureSentinel
# in the AWS+MSFT spot-check). The deny-list is matched on file name
# only (case-sensitive); the YML-stem-matching fallback below covers any
# other shared module names.
_INTEGRATION_PY_STUB_DENYLIST = frozenset(
    {
        "demistomock.py",
        "CommonServerPython.py",
        "CommonServerUserPython.py",
        "DemistoClassApiModule.py",
        "conftest.py",
    }
)


def find_integration_files(integration_path: Path) -> tuple[Path, Path | None]:
    """Locate the integration YML and (optional) Python source.

    Returns ``(yml_path, py_path_or_None)``. Raises ``FileNotFoundError`` if
    no YML is found.

    Picker contract for the ``.py`` file (in priority order):

    1. The file whose stem matches the integration directory name (the
       ``demisto-sdk`` convention — e.g. ``AzureSentinel.py`` inside
       ``Packs/AzureSentinel/Integrations/AzureSentinel/``).
    2. The file whose stem matches the chosen YML's stem (covers a few
       integrations whose .py and dir disagree).
    3. Any other ``.py`` after filtering out ``_test.py`` /
       ``test_*.py`` / well-known stub files (``demistomock.py``,
       ``CommonServerPython.py``, ``*ApiModule.py``, etc.). The list is
       sorted alphabetically as a final tie-breaker so the picker is
       fully deterministic across filesystems.

    Without this discipline, an unsorted ``Path.glob("*.py")`` pick can
    return ``demistomock.py`` first when stub files have been
    accidentally committed (see ``check_command_params_validation_report.md``,
    AzureSentinel gap #3).
    """
    if not integration_path.is_dir():
        raise FileNotFoundError(f"Integration path is not a directory: {integration_path}")
    ymls = sorted(p for p in integration_path.glob("*.yml") if not p.name.endswith("_test.yml"))
    if not ymls:
        raise FileNotFoundError(f"No .yml file found in {integration_path}")
    yml_path = ymls[0]

    def _is_candidate(p: Path) -> bool:
        if p.name.endswith("_test.py") or p.name.startswith("test_"):
            return False
        if p.name in _INTEGRATION_PY_STUB_DENYLIST:
            return False
        # Common Microsoft / shared-helper modules that ``demisto-sdk
        # prepare-content`` would normally inject at unify time and which
        # are sometimes also present as standalone files in the
        # integration directory. Their stem ends in ``ApiModule`` by
        # convention.
        if p.stem.endswith("ApiModule"):
            return False
        return True

    pys = sorted(
        (p for p in integration_path.glob("*.py") if _is_candidate(p)),
        key=lambda p: p.name,
    )
    if not pys:
        return yml_path, None

    # Priority 1: stem matches the integration directory name.
    dir_match = next((p for p in pys if p.stem == integration_path.name), None)
    if dir_match is not None:
        return yml_path, dir_match
    # Priority 2: stem matches the chosen YML's stem.
    yml_match = next((p for p in pys if p.stem == yml_path.stem), None)
    if yml_match is not None:
        return yml_path, yml_match
    # Priority 3: deterministic fallback (already sorted).
    return yml_path, pys[0]


def load_yml(yml_path: Path) -> dict[str, Any]:
    """Load and return the integration YML as a dict."""
    with yml_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# --------------------------------------------------------------------------
# YML interrogation
# --------------------------------------------------------------------------


def is_hidden_param(param: dict[str, Any]) -> bool:
    """Return ``True`` iff the YML configuration param is hidden.

    A param is hidden when its ``hidden:`` key is EITHER:

    * the boolean ``True`` (the legacy form), OR
    * a *non-empty* list of platform names (the per-platform form, e.g.
      ``[xsoar]``, ``[marketplacev2, platform]``).

    All of the following are NOT hidden:

    * ``hidden: false`` (explicit opt-out)
    * ``hidden: []`` (empty list)
    * ``hidden:`` with no value (parsed as ``None``)
    * ``hidden`` key missing entirely

    The rule is intentionally coarse: ANY non-empty list means "hidden
    somewhere", and the analyzer treats that as "hidden everywhere".
    Per-platform interpretation is not attempted — the analyzer's job is
    only to keep hidden params out of every artifact (seed dict, ignore
    set logging, per-command output).
    """
    if not isinstance(param, dict):
        return False
    raw = param.get("hidden")
    if raw is True:
        return True
    if isinstance(raw, list) and len(raw) > 0:
        return True
    return False


def get_yml_params(yml_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the list of *visible* param dicts from the YML configuration block.

    Hidden params (see :func:`is_hidden_param`) are filtered out at the
    source so they never reach downstream consumers — they don't waste a
    sentinel slot in the seed dict, never trigger Scope-1 fan-out via
    reads of them, and never appear in any per-command output. Callers
    that need the raw, unfiltered list (e.g. the analyzer's hidden-param
    logging path) should use :func:`get_yml_params_raw`.
    """
    return [p for p in get_yml_params_raw(yml_data) if not is_hidden_param(p)]


def get_yml_params_raw(yml_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the unfiltered list of param dicts from the YML config block.

    Includes hidden params. Used by the analyzer to log which params were
    excluded as hidden and to seed the effective ignore set; production
    code paths should call :func:`get_yml_params` instead.
    """
    config = yml_data.get("configuration") or []
    return [p for p in config if isinstance(p, dict) and p.get("name")]


def get_hidden_param_names(yml_data: dict[str, Any]) -> list[str]:
    """Return the sorted list of hidden YML param names."""
    return sorted(p["name"] for p in get_yml_params_raw(yml_data) if is_hidden_param(p))


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


def compose_ignore_set(
    inline: list[str] | None,
    file_path: Path | None,
    integration_id: str | None,
) -> set[str]:
    """Build the analyzer's effective ignore set from all sources.

    The composed set is the union of:

    * ``inline`` — bare param names from the ``--ignore-params`` CLI flag.
    * ``file_path`` — one-name-per-line file from ``--ignore-params-file``
      (default: ``connectus/default_ignore_params.txt``).
    * ``auth_param_ids(integration_id)`` — when ``integration_id`` is
      provided, every YML param id declared in the integration's
      ``Auth Details`` cell (auth_types-projected + ``other_connection``).

    Behaviour notes:

    * ``integration_id=None`` → only the file/inline sources are used
      (preserves backward compatibility with standalone analyzer runs).
    * If ``integration_id`` is supplied but the workflow CSV doesn't
      contain it, OR ``Auth Details`` for that row is unset / malformed,
      a single-line stderr WARNING is logged and we proceed with just
      the file-based ignore set. The analyzer must remain runnable on
      integrations that haven't been classified yet.
    * On success with a non-empty auth-derived set, a single-line
      stderr INFO message is logged listing the pulled params.
    """
    out = load_ignore_params(inline, file_path)

    if integration_id is None:
        return out

    # Lazy import to keep ``check_command_params.py`` runnable as a
    # standalone script when workflow_state.py / its CSV is missing.
    # Both files live in connectus/, so the in-package import path
    # mirrors the existing capture_proxy import style at the top of
    # this module.
    try:
        from workflow_state import auth_param_ids, WorkflowError
    except Exception as exc:  # noqa: BLE001 — analyzer must keep running
        print(
            f"[ignore] WARNING: could not import workflow_state for "
            f"--integration-id {integration_id!r}: {type(exc).__name__}: "
            f"{exc}; proceeding with file-based ignore set only.",
            file=sys.stderr,
        )
        return out

    try:
        pulled = auth_param_ids(integration_id)
    except WorkflowError as exc:
        print(
            f"[ignore] WARNING: --integration-id {integration_id!r}: "
            f"{exc}; proceeding with file-based ignore set only.",
            file=sys.stderr,
        )
        return out
    except Exception as exc:  # noqa: BLE001 — analyzer must keep running
        print(
            f"[ignore] WARNING: --integration-id {integration_id!r}: "
            f"{type(exc).__name__}: {exc}; proceeding with file-based "
            f"ignore set only.",
            file=sys.stderr,
        )
        return out

    if pulled:
        # Format mirrors the spec: comma-separated, single line.
        joined = ", ".join(pulled)
        print(
            f"[ignore] Auth-aware ignore: pulled {len(pulled)} params "
            f"from Auth Details for {integration_id}: [{joined}]",
            file=sys.stderr,
        )
    else:
        print(
            f"[ignore] Auth-aware ignore: pulled 0 params from Auth "
            f"Details for {integration_id} (empty after projection); "
            f"no additional ignore entries.",
            file=sys.stderr,
        )

    out.update(pulled)
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


def build_function_map(
    tree: ast.AST,
) -> dict[str, ast.FunctionDef | ast.ClassDef]:
    """Map top-level + nested function/class names to their AST nodes.

    Fix A: ``ClassDef`` entries are included alongside ``FunctionDef`` /
    ``AsyncFunctionDef`` so that :func:`_resolve_call_target` can resolve
    a constructor call ``UserMappingObject(...)`` to the class's
    ``__init__`` method (via :func:`_class_init_or_none`). Callers that
    only want function-shaped entries (e.g. :func:`find_main`) must
    narrow with ``isinstance(entry, ast.FunctionDef)``.
    """
    out: dict[str, ast.FunctionDef | ast.ClassDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # First definition wins; ignore later overrides.
            out.setdefault(node.name, node)  # type: ignore[arg-type]
    return out


def find_main(
    func_map: dict[str, ast.FunctionDef | ast.ClassDef],
) -> ast.FunctionDef | None:
    """Return the top-level ``main()`` ``FunctionDef`` or ``None``.

    Fix A: ``func_map`` may carry ``ClassDef`` entries now, so we narrow
    explicitly. A class accidentally named ``main`` is ignored — only a
    function is acceptable.
    """
    entry = func_map.get("main")
    if isinstance(entry, ast.FunctionDef):
        return entry
    return None


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
    """Return the line number of the first command-dispatch construct.

    Change 4: an ``if command == "X":`` block whose body ends in an
    unconditional early-return (``return`` / ``raise`` / ``sys.exit(...)``)
    is treated as a **guard**, not the real dispatcher. The real
    dispatch site is the first dispatch construct that does NOT end
    in early-return. This fixes the SplunkPy v2 ``splunk-parse-raw``
    case where the early-return guard at the top of ``main()`` was
    mistakenly anchoring the pre-dispatch window, hiding every
    subsequent setup statement (mapper construction, etc.) from
    pre-dispatch attribution.

    The skip is order-preserving — we walk the function body in
    source order (via ``ast.walk`` which is preorder DFS over the
    AST), iterating dispatch nodes and returning the first one that
    is NOT a guard. Multiple consecutive guards are skipped in a
    single pass.
    """
    for node in ast.walk(main_fn):
        if not _is_dispatch_node(node):
            continue
        # An ``If`` dispatch node that is itself a guard (body ends
        # in early-return) does not anchor pre-dispatch — keep
        # looking. ``Match`` blocks and ``commands = {...}`` literals
        # are never guards in this sense; they always anchor.
        if isinstance(node, ast.If) and _is_early_return_guard(node):
            continue
        return getattr(node, "lineno", 10**9)
    return 10**9  # no dispatch found -> entire function is "pre-dispatch"


def _is_early_return_guard(if_node: ast.If) -> bool:
    """Change 4: is ``if_node`` an early-return guard?

    Returns True when ``if_node`` is an ``if command == "..."`` /
    ``elif`` block whose body ends in an unconditional early-return
    statement: ``return``, ``raise``, or ``sys.exit(...)``.

    The check is intentionally shallow — it only inspects the LAST
    statement of the immediate ``If.body`` (not nested branches);
    that's enough to catch the SplunkPy v2 ``splunk-parse-raw``
    shape AND any sibling guards that follow the same idiom.

    NOTE: this helper takes only an ``ast.If`` (the dispatch detector
    has already narrowed via ``_is_dispatch_node``); it does NOT
    re-verify that the test is a command-comparison.
    """
    if not if_node.body:
        return False
    last = if_node.body[-1]
    if isinstance(last, ast.Return):
        return True
    if isinstance(last, ast.Raise):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        call = last.value
        # ``sys.exit(...)`` is the canonical hard-exit form. We also
        # accept bare ``exit(...)`` even though it's discouraged.
        if isinstance(call.func, ast.Attribute) and call.func.attr == "exit":
            return True
        if isinstance(call.func, ast.Name) and call.func.id == "exit":
            return True
    return False


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


def _iter_pre_dispatch_stmts(
    body: list[ast.stmt], dispatch_line: int
) -> list[ast.stmt]:
    """Flatten a function body into the linear sequence of statements that
    execute before the dispatch line.

    Recursively descends into compound constructs whose bodies always
    execute on the way to the dispatch site (``Try``, ``With``,
    ``AsyncWith``, ``If`` whose test is constant-True / ``__name__``
    style guard, etc.). For ``Try`` we walk ``body``, ``orelse``, and
    ``finalbody`` as if they were sequential — orelse runs when the
    ``try`` succeeds, ``finalbody`` always; conservatively unioning
    their reads is safe for binding-narrowing (we only ever ADD to the
    binding map / Scope-1).

    Critically, the iteration stops as soon as we encounter a statement
    whose ``lineno >= dispatch_line`` — this preserves the existing
    "bindings declared after dispatch are not pre-dispatch" guarantee
    even when the dispatch is itself nested inside a ``Try`` whose
    earlier sibling statements include the binding (e.g. MDATP's
    ``try: client = MsClient(...); if command == "X": ...``).

    For ``If``, both branches are walked (we don't try to evaluate the
    test); for ``For``/``While`` the body is walked once. Statements
    that are themselves dispatch sites (``If`` whose test references
    ``command``) are NOT descended — they would otherwise leak the
    dispatch-arm bodies into the pre-dispatch sequence.

    The returned list preserves source order. Callers MUST still apply
    their own per-statement filters (e.g. binding vs fan-out
    classification) — this helper only handles the "where do
    pre-dispatch statements live in the AST" problem.
    """
    out: list[ast.stmt] = []

    def _walk(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            lineno = getattr(stmt, "lineno", 0)
            if lineno and lineno >= dispatch_line:
                # Anything from this statement onward is at-or-after the
                # dispatch line — stop walking this list (later stmts
                # inside a sibling Try body still get walked when we
                # recurse into THAT Try, because their dispatch_line
                # check happens locally).
                return
            if _is_dispatch_node(stmt):
                # The dispatch construct itself is not part of
                # "pre-dispatch" — its arms are handled separately by
                # find_command_dispatch_branches.
                continue
            if isinstance(stmt, ast.Try):
                # body / orelse / finalbody all may run on the way to
                # dispatch; ExceptHandlers are skipped because they only
                # run on failure (and any binding they create is a
                # superset of the success path's, which we already
                # have). The parent Try node itself is NOT emitted —
                # we emit only its leaves so visitors don't double-walk.
                _walk(stmt.body)
                _walk(stmt.orelse)
                _walk(stmt.finalbody)
                continue
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                _walk(stmt.body)
                continue
            if isinstance(stmt, ast.If):
                # Not a dispatch If (filtered above). Both branches may
                # run; descend into each so any binding statements they
                # contain are seen. The parent If node is NOT emitted
                # for the same double-walk reason as Try; its test
                # expression is walked separately when callers want to
                # attribute Scope-1 reads inside the test.
                _walk(stmt.body)
                _walk(stmt.orelse)
                continue
            out.append(stmt)

    _walk(body)
    return out


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

    Compound constructs (``Try``, ``With``, ``If``) wrapping the
    pre-dispatch code are flattened by :func:`_iter_pre_dispatch_stmts`,
    so binding-narrowing fires correctly for the common ``try: client =
    Client(...); if command == "X": ...`` shape used by MDATP and
    similar Microsoft integrations.
    """
    globals_in_main = _collect_global_decls(main_fn)
    visitor = _ParamAccessVisitor(params_vars, aliases)
    for stmt in _iter_pre_dispatch_stmts(main_fn.body, dispatch_line):
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


def _params_consumed_by_function(
    fn: ast.FunctionDef,
    func_map: dict[str, ast.FunctionDef | ast.ClassDef],
    params_vars: set[str],
    aliases: dict[str, str],
    depth: int = 2,
    visited: frozenset[str] | None = None,
) -> set[str]:
    """Return the set of YML param names ``fn`` reads, recursing up to ``depth``.

    Used by :func:`build_binding_maps` to attribute the credential set of
    a helper function (e.g. AWS-EC2's ``build_client(args)`` reading
    eleven module-level ``PARAMS.get(...)`` values) back to the local
    binding being assigned in main: ``client = build_client(args)`` →
    ``binding_map["client"] |= {access_key, secret_key, ...}``.

    The visitor seed-set is the union of:

    * the function's own signature names that match ``PARAMS_VAR_ALIASES``
      (so a helper declared ``def build_client(params, args): ...``
      still finds ``params.get(...)`` reads); and
    * ``params_vars`` from the caller — which already includes the
      caller's local ``params`` variable name and any module-level
      ``PARAMS = demisto.params()`` global. This is what lets the
      AWS-EC2 ``build_client(args)`` body — which reads
      ``PARAMS.get("access_key")`` directly without ever taking
      ``params`` as a formal arg — be attributed.

    The chained ``demisto.params().get(...)`` form is recognized
    automatically by the visitor regardless of any seed set.

    Recursion is bounded by ``depth`` and a ``visited`` set keyed on
    function name to prevent infinite loops on mutual recursion. The
    default depth of 2 mirrors :func:`trace_params_in_function` so the
    two recursion budgets stay aligned.
    """
    if visited is None:
        visited = frozenset()
    if depth < 0 or fn.name in visited:
        return set()
    visited = visited | {fn.name}

    sig_params = {a.arg for a in fn.args.args} | {
        a.arg for a in fn.args.kwonlyargs
    }
    seed = (sig_params & PARAMS_VAR_ALIASES) | params_vars
    visitor = _ParamAccessVisitor(seed, aliases)
    visitor.visit(fn)
    found = set(visitor.found)

    # Recurse into module-resolvable callees regardless of arg shape.
    # Unlike :func:`trace_params_in_function` we do NOT gate on
    # ``_call_passes_params``: the AWS-EC2 idiom calls
    # ``build_client(args)`` (no params-shaped arg) but the callee reads
    # module-level ``PARAMS.get(...)`` directly. Gating would silently
    # drop those reads. The depth budget keeps the recursion bounded.
    for call in _iter_calls(fn.body):
        target = _resolve_call_target(call, func_map)
        if target is None:
            continue
        found |= _params_consumed_by_function(
            target, func_map, params_vars, aliases, depth - 1, visited
        )
    return found


def build_binding_maps(
    main_fn: ast.FunctionDef,
    params_vars: set[str],
    aliases: dict[str, str],
    dispatch_line: int,
    func_map: dict[str, ast.FunctionDef | ast.ClassDef] | None = None,
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
    * **Helper-function recursion** (when ``func_map`` is supplied): if
      the RHS contains a ``Call`` whose target resolves to a function
      defined in this module, the params consumed by that function
      (including its own callees, up to depth 2) are unioned into the
      binding. This closes the AWS-EC2 ``client = build_client(args)``
      false negative — ``build_client`` reads eleven module-level
      ``PARAMS.get(...)`` values that would otherwise be silently
      dropped because the call doesn't pass a params-shaped argument.

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

    Compound constructs (``Try``, ``With``, ``If``) wrapping the
    pre-dispatch code are flattened by :func:`_iter_pre_dispatch_stmts`
    so bindings nested inside ``try: client = MsClient(...); if command
    == "X": ...`` (the MDATP shape) are recorded.
    """
    globals_in_main = _collect_global_decls(main_fn)
    binding_map: dict[str, set[str]] = {}
    for stmt in _iter_pre_dispatch_stmts(main_fn.body, dispatch_line):
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
        from_helpers: set[str] = set()
        if func_map is not None:
            for sub in ast.walk(rhs):
                if not isinstance(sub, ast.Call):
                    continue
                target_fn = _resolve_call_target(sub, func_map)
                if target_fn is None:
                    continue
                from_helpers |= _params_consumed_by_function(
                    target_fn, func_map, params_vars, aliases
                )
        binding_map[target_name] = direct | transitive | from_helpers
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


def _collect_local_dict_assignments(
    main_fn: ast.FunctionDef,
) -> dict[str, ast.Dict]:
    """Map every ``<NAME> = {...}`` local in ``main_fn`` to the Dict node.

    Walks the entire body (including nested ``Try``, ``With``, ``If``)
    so we capture dispatch-table dicts no matter where they're written.
    Used by :func:`_if_test_matches_command_in_local_dict` and the
    dict-dispatch helpers to recognize ``if command in <named_dict>:``
    and ``<named_dict>[command](...)`` dispatches even when the
    dispatch table isn't named the canonical ``commands``.

    We use ``ast.walk`` directly here (rather than
    :func:`_iter_pre_dispatch_stmts`) because the canonical
    ``commands = {"X": ...}`` dict assignment is itself recognised as a
    dispatch construct by :func:`_is_dispatch_node` and would be
    filtered out of the pre-dispatch sequence — but we still need to
    see it to resolve handlers / membership tests.
    """
    out: dict[str, ast.Dict] = {}
    for node in ast.walk(main_fn):
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Dict)
        ):
            continue
        out[node.targets[0].id] = node.value
    return out


def _dict_contains_command(d: ast.Dict, command: str) -> bool:
    """True if literal Dict ``d`` has a string-constant key equal to ``command``."""
    for key in d.keys:
        if isinstance(key, ast.Constant) and key.value == command:
            return True
    return False


def _if_test_matches_command_in_local_dict(
    test: ast.AST, command: str, local_dicts: dict[str, ast.Dict]
) -> bool:
    """True if ``test`` is ``command in <NAME>`` where ``<NAME>`` resolves
    to a local Dict literal containing ``command`` as a key.

    Mirrors AzureKeyVault's dispatch shape::

        commands_with_args = {"azure-key-vault-key-get": get_key_command, ...}
        if command in commands_with_args:
            return_results(commands_with_args[command](client, args))

    Without this recognizer, ``find_command_dispatch_branches`` would
    return an empty list and the per-command client params would never
    surface.
    """
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.In)
        and _is_command_ref(test.left)
    ):
        return False
    container = test.comparators[0]
    if isinstance(container, ast.Name):
        d = local_dicts.get(container.id)
        if d is not None and _dict_contains_command(d, command):
            return True
    return False


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

    Also handles the "named-dict membership test" idiom (AzureKeyVault):
    ``commands_with_args = {...}; if command in commands_with_args:
    return_results(commands_with_args[command](...))``. The ``If``
    branch body is the per-command branch in that case.
    """
    out: list[list[ast.stmt]] = []
    local_dicts = _collect_local_dict_assignments(main_fn)
    for node in ast.walk(main_fn):
        if isinstance(node, ast.If) and (
            _if_test_matches_command(node.test, command)
            or _if_test_matches_command_in_local_dict(
                node.test, command, local_dicts
            )
        ):
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
    """Return any ``<dispatch_dict>[<...>](...)`` invocation sites in ``main()``.

    The classic dict-dispatch idiom (used by MongoDB, Cherwell, GitLab,
    Slack IAM, etc.) is::

        commands = {"foo": foo_handler, "bar": bar_handler}
        commands[command](client, **args)

    AzureKeyVault and similar use a named variant::

        commands_with_args = {"foo": foo_handler, ...}
        if command in commands_with_args:
            return_results(commands_with_args[command](client, args))

    The single call site is shared across **every** command listed in
    that dict. Its ``Name`` arguments — typically a ``client`` built via
    ``Client(api_key=params.get("apikey"), ...)`` — therefore fan out
    to every command in the dict. We expose those call sites so
    :func:`analyze_static` can replay binding-map attribution for each
    dispatched command.

    Recognized receivers: any ``Name`` whose id is the target of a
    ``<NAME> = {...}`` Dict assignment in ``main_fn`` (resolved by
    :func:`_collect_local_dict_assignments`). The legacy hard-coded
    ``commands`` is kept as a fallback for integrations that bind the
    dispatch table at module scope or via a non-trivial expression we
    don't model.
    """
    out: list[ast.Call] = []
    local_dicts = _collect_local_dict_assignments(main_fn)
    receiver_names = set(local_dicts.keys()) | {"commands"}
    for node in ast.walk(main_fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Subscript):
            continue
        receiver = func.value
        if isinstance(receiver, ast.Name) and receiver.id in receiver_names:
            out.append(node)
    return out


def _attribute_call_args(
    call: ast.Call,
    binding_map: dict[str, set[str]],
    params_vars: set[str],
    aliases: dict[str, str],
) -> set[str]:
    """Walk one ``Call`` node's positional + keyword args + method receiver.

    For each arg that is a ``Name`` already in ``binding_map``, take
    its carried params. Otherwise walk the arg expression for inline
    ``params.get(...)`` / subscript / attribute reads and take those.

    Method receivers count too: in
    ``iam_command.update_user(client, args)`` the receiver
    ``iam_command`` is an object built from one or more bound params
    (mapper-in/out, create-user-enabled, …). Calling a method on it
    inside a dispatch branch implicitly consumes those params — they
    must be attributed to the command.
    """
    found: set[str] = set()
    # Method receiver: ``<receiver>.method(...)`` where <receiver> is a Name in binding_map.
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        if func.value.id in binding_map:
            found |= binding_map[func.value.id]
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
    # ``<ref> == "X" or <ref> == "Y"`` — the alias-command idiom seen in
    # AWS-IAM and other older integrations. We recursively check every
    # arm of the BoolOp; if ANY arm matches the command literal, the
    # branch body fires for that command.
    #
    # We deliberately do NOT match ``ast.And``: an And of equality tests
    # against different command literals can never simultaneously be
    # true, so treating it as a match would wrongly attribute params to
    # every command listed.
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(_if_test_matches_command(v, command) for v in test.values)
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
    """Handle dict-table dispatch: any ``<NAME> = {"X": handler_X, ...}``
    local in ``main()`` whose value is a Dict literal containing
    ``command`` as a key — the matching value (a Name or Attribute) is
    treated as the handler for that command. Covers both the canonical
    ``commands = {...}; commands[command](...)`` idiom (MongoDB, etc.)
    and the named-table membership-test idiom
    (``commands_with_args = {...}; if command in commands_with_args:
    return_results(commands_with_args[command](...))``) used by
    AzureKeyVault and similar.
    """
    out: list[ast.Call] = []
    for d in _collect_local_dict_assignments(main_fn).values():
        for key, val in zip(d.keys, d.values):
            if isinstance(key, ast.Constant) and key.value == command:
                # Build a synthetic Call node so the recursion picks up the
                # named handler function.
                if isinstance(val, (ast.Name, ast.Attribute)):
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
    func_map: dict[str, ast.FunctionDef | ast.ClassDef],
    aliases: dict[str, str],
    depth: int = 3,
    visited: set[str] | None = None,
    module_params_vars: set[str] | None = None,
) -> set[str]:
    """Recursively collect param accesses in ``fn`` up to ``depth`` levels deep.

    Fix A: default ``depth`` bumped from 2 to **3** to recover
    transitive helper reads (``handler → wrapper → leaf_helper``) that
    integrations like SplunkPy v2 hit (e.g. ``update_remote_system``
    sitting at depth-3 below ``fetch_incidents``). The CLI flag
    ``--call-graph-depth`` (validated [1, 5]) overrides this default
    end-to-end. The hard cap at 5 keeps pathological call graphs from
    blowing recursion or wall time — empirically REST integrations have
    call-graph fan-out under 3.

    ``module_params_vars`` are names bound to ``demisto.params()`` at module
    scope (e.g. a global ``PARAMS = demisto.params()``). They're seeded
    into the candidate set for every traced function so accesses to those
    globals — common in older / large integrations like CrowdStrikeFalcon —
    are not silently dropped. The chained ``demisto.params().X`` form is
    also recognized via :func:`_is_demisto_params_call` inside the visitor
    and does not require any candidate name to be present.
    """
    if visited is None:
        visited = set()
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
    #
    # Also recurse into helpers that read a known params source
    # directly without taking it as an argument. The classic AWS-EC2
    # case: ``client = build_client(args)`` calls a helper that reads
    # ``PARAMS.get(...)`` (a module-level global) for every credential.
    # Without this second branch the credential surface is silently
    # dropped from per-command Scope-2.
    for call in _iter_calls(fn.body):
        target_fn = _resolve_call_target(call, func_map)
        if target_fn is None:
            continue
        if not (
            _call_passes_params(call, candidates)
            or _function_reads_params_directly(target_fn, module_params_vars)
        ):
            continue
        found |= trace_params_in_function(
            target_fn, func_map, aliases, depth - 1, visited, module_params_vars
        )
    return found


def _function_reads_params_directly(
    fn: ast.FunctionDef, module_params_vars: set[str] | None
) -> bool:
    """True if ``fn`` reads ``demisto.params()`` (chained) or a known
    module-level ``PARAMS = demisto.params()`` global.

    Used by :func:`trace_params_in_function` to decide whether to recurse
    into a helper whose call site does NOT pass a params-shaped argument
    (the AWS-EC2 ``build_client(args)`` shape). Without this opt-in, the
    helper's credential reads are silently dropped from per-command
    Scope-2.

    Conservative: only matches direct attribute / call accesses on a
    module-level params global or the chained ``demisto.params()`` form;
    does NOT recurse transitively into the helper's own callees here
    (``trace_params_in_function`` will do that on its own when this
    helper is visited). This keeps the gate cheap and avoids a quadratic
    walk on large integrations.
    """
    globals_set = module_params_vars or set()
    for sub in ast.walk(fn):
        if _is_demisto_params_call(sub):
            return True
        if isinstance(sub, ast.Name) and sub.id in globals_set:
            # Bare reference to ``PARAMS`` — by itself sufficient
            # evidence that the helper consumes module-level params.
            return True
    return False


def _class_init_or_none(class_def: ast.ClassDef) -> ast.FunctionDef | None:
    """Return ``class_def``'s ``__init__`` ``FunctionDef``, or ``None``.

    Fix A helper: lets :func:`_resolve_call_target` model
    constructor calls (``UserMappingObject(...)``) as a call into the
    class's ``__init__`` body, so reads of ``params.get(...)`` inside
    that constructor become reachable from a handler that receives the
    constructed instance — or from ``main()`` itself for the
    pre-dispatch case.
    """
    for stmt in class_def.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "__init__":
            return stmt
    return None


def _resolve_call_target(
    call: ast.Call, func_map: dict[str, ast.FunctionDef | ast.ClassDef]
) -> ast.FunctionDef | None:
    """Resolve a ``Call`` node to its target ``FunctionDef``.

    Fix A: when the lookup lands on an :class:`ast.ClassDef` (i.e. the
    call site is a constructor, ``Cls(...)``), return that class's
    ``__init__`` method via :func:`_class_init_or_none`. Returns
    ``None`` when the call target isn't resolvable to a function defined
    in this module (or when the class has no ``__init__``).
    """
    func = call.func
    target: ast.FunctionDef | ast.ClassDef | None = None
    if isinstance(func, ast.Name):
        target = func_map.get(func.id)
    elif isinstance(func, ast.Attribute):
        target = func_map.get(func.attr)
    if isinstance(target, ast.ClassDef):
        return _class_init_or_none(target)
    if isinstance(target, ast.FunctionDef):
        return target
    return None


def _call_passes_params(call: ast.Call, candidates: set[str]) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in candidates:
            return True
    for kw in call.keywords:
        if isinstance(kw.value, ast.Name) and kw.value.id in candidates:
            return True
    return False


# --------------------------------------------------------------------------
# Fix B — confidence-tier attribution helpers
# --------------------------------------------------------------------------
#
# Module-level def-use index, attributed reachability walk, and
# pre-dispatch attribution. These feed the per-command attribution
# assembler in :func:`_build_attributions`. The design is documented
# in :doc:`plans/check-command-params-splunkpy-diagnosis.md` §4.B.


# Sentinel emitted into ``module_const_to_params`` to mark "the
# constant's RHS contains a ``params.get(<non-literal>)`` call". Lets
# the attribution layer flip the source from ``module_const_referenced``
# (0.5) to ``module_const_hedged`` (0.1) without losing the constant.
_NON_LITERAL_PARAM_KEY = "<non-literal>"


def _is_dynamic_dispatch_node(node: ast.AST) -> bool:
    """True when ``node`` looks like dynamic dispatch into a handler.

    Used as a reachability-uncertainty signal: any pattern like
    ``globals()[name]()``, ``getattr(obj, name)()``, or
    ``command_map[name]()`` means the analyzer can't statically
    enumerate which function actually runs. Triggers the
    ``module_const_hedged`` downgrade in :func:`_build_attributions`.
    """
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    # Subscript on a Name/Call value: ``command_map[name]()`` or
    # ``globals()[name]()``.
    if isinstance(func, ast.Subscript):
        return True
    # ``getattr(...)()`` chained pattern.
    if isinstance(func, ast.Call):
        inner = func.func
        if isinstance(inner, ast.Name) and inner.id == "getattr":
            return True
        if (
            isinstance(inner, ast.Attribute)
            and inner.attr == "getattr"
        ):
            return True
    return False


def _params_get_arg_is_string_literal(call: ast.Call) -> bool:
    """True if ``call`` is ``<receiver>.get(<string literal>, ...)``.

    Used to detect the non-literal-key form
    ``params.get(some_var)`` — that branch must hedge the entire
    binding because the analyzer can't tell which YML param the read
    targets.
    """
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "get"):
        return False
    if not call.args:
        return False
    arg0 = call.args[0]
    return isinstance(arg0, ast.Constant) and isinstance(arg0.value, str)


def _expr_contains_params_get_call(
    expr: ast.AST, params_vars: set[str]
) -> tuple[bool, bool]:
    """Return ``(has_params_get, has_non_literal_key)`` for ``expr``.

    Walks ``expr`` looking for ``<receiver>.get(...)`` calls where the
    receiver is a known params source (a Name in ``params_vars`` OR
    chained ``demisto.params()``). Used to recognize module-level
    constants whose RHS reads params.
    """
    has_params_get = False
    has_non_literal = False
    for sub in ast.walk(expr):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func
        if not (isinstance(func, ast.Attribute) and func.attr == "get"):
            continue
        receiver = func.value
        is_params_receiver = (
            isinstance(receiver, ast.Name) and receiver.id in params_vars
        ) or _is_demisto_params_call(receiver)
        if not is_params_receiver:
            continue
        has_params_get = True
        if not _params_get_arg_is_string_literal(sub):
            has_non_literal = True
    # Also count direct subscript reads of params (e.g.
    # ``PARAMS["foo"]``) as params_get for purposes of "the RHS
    # touches params". Non-literal keys (PARAMS[var]) hedge the same
    # way.
    for sub in ast.walk(expr):
        if not isinstance(sub, ast.Subscript):
            continue
        receiver = sub.value
        is_params_receiver = (
            isinstance(receiver, ast.Name) and receiver.id in params_vars
        ) or _is_demisto_params_call(receiver)
        if not is_params_receiver:
            continue
        has_params_get = True
        sl = sub.slice
        if not (isinstance(sl, ast.Constant) and isinstance(sl.value, str)):
            has_non_literal = True
    return has_params_get, has_non_literal


def _build_module_const_index(
    tree: ast.Module,
    params_vars: set[str],
    aliases: dict[str, str],
) -> tuple[dict[str, set[str]], set[str]]:
    """Walk module-scope assignments to build the def-use index for Fix B.

    Returns ``(module_const_to_params, hedged_constants)``.

    * ``module_const_to_params[NAME]`` is the set of YML param names
      whose ``params.get("X")`` reads appear in the RHS of any
      module-level assignment to ``NAME``. Repeated assignments to the
      same NAME union.
    * ``hedged_constants`` contains every NAME whose RHS ever
      contained a ``params.get(<non-literal>)`` (or
      ``PARAMS[var]``) — those constants get
      ``module_const_hedged`` (0.1) instead of
      ``module_const_referenced`` (0.5).

    Handled shapes:

    * ``NAME = expr`` (single-target Assign).
    * ``NAME: T = expr`` (AnnAssign).
    * Tuple unpacking ``A, B = ..., ...`` (best-effort positional).
    * Wrapped exprs ``int(params.get("X"))``, or-chains, etc. —
      handled by walking the entire RHS expression.

    Skipped shapes:

    * ``NAME = demisto.params()`` (that's a params-var alias, not a
      const). Excluded via :func:`_is_demisto_params_assign`.
    """
    out: dict[str, set[str]] = {}
    hedged: set[str] = set()
    if not isinstance(tree, ast.Module):
        return out, hedged

    def _ingest(name: str, rhs: ast.AST) -> None:
        params = _collect_param_reads_in_expr(rhs, params_vars, aliases)
        has_get, non_literal = _expr_contains_params_get_call(
            rhs, params_vars
        )
        if not has_get and not params:
            # RHS touches no params — skip (don't pollute the index).
            return
        bucket = out.setdefault(name, set())
        bucket |= params
        if non_literal:
            bucket.add(_NON_LITERAL_PARAM_KEY)
            hedged.add(name)

    for stmt in tree.body:
        # Skip the ``NAME = demisto.params()`` aliasing pattern — it's a
        # params-var binding, not a const definition.
        if _is_demisto_params_assign(stmt) is not None:
            continue
        if isinstance(stmt, ast.Assign):
            # Tuple unpacking: best-effort positional binding.
            if (
                len(stmt.targets) == 1
                and isinstance(stmt.targets[0], (ast.Tuple, ast.List))
                and isinstance(stmt.value, (ast.Tuple, ast.List))
                and len(stmt.targets[0].elts) == len(stmt.value.elts)
            ):
                for tgt, val in zip(stmt.targets[0].elts, stmt.value.elts):
                    if isinstance(tgt, ast.Name):
                        _ingest(tgt.id, val)
                continue
            # Single-target Name = RHS.
            if (
                len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                _ingest(stmt.targets[0].id, stmt.value)
                continue
            # Chained ``A = B = RHS``: attribute the same RHS to every
            # Name target, ignore non-Name targets.
            if all(isinstance(t, ast.Name) for t in stmt.targets):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        _ingest(tgt.id, stmt.value)
                continue
        if (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.value is not None
        ):
            _ingest(stmt.target.id, stmt.value)
    return out, hedged


def _trace_with_attribution(
    fn: ast.FunctionDef,
    func_map: dict[str, ast.FunctionDef | ast.ClassDef],
    aliases: dict[str, str],
    max_depth: int,
    current_depth: int,
    visited: set[str],
    module_params_vars: set[str] | None,
    out_evidence: list[tuple[str, ParamSourceEvidence]],
    out_referenced_consts: set[str],
) -> bool:
    """Walk ``fn`` recursively, recording per-tier attribution evidence.

    Sibling to :func:`trace_params_in_function` (kept separate for
    backward compatibility — see the completion summary's "B.4 choice"
    note). Mutates the two ``out_*`` accumulators in place.

    Returns ``walk_uncertain``: True iff any branch hit an unresolved
    call target, a dynamic-dispatch construct (``globals()[x]()``,
    ``getattr(self, cmd)()``, ``command_map[cmd]()``), a
    non-literal-key ``params.get(var)`` call, or the depth budget.

    ``current_depth`` is the depth at which ``fn`` was entered relative
    to the handler: the handler itself is depth 0, its direct callees
    are depth 1, etc. The ``source`` label written into the evidence
    list is ``"handler_body"`` for depth 0 and ``"helper"`` for
    depth >= 1 (with ``call_graph_depth`` set on the latter).
    """
    if fn.name in visited:
        return False
    visited.add(fn.name)

    sig_params = {a.arg for a in fn.args.args} | {
        a.arg for a in fn.args.kwonlyargs
    }
    candidates = (sig_params & PARAMS_VAR_ALIASES) or {"params"}
    if module_params_vars:
        candidates = candidates | module_params_vars

    # Collect direct param reads inside fn.
    visitor = _ParamAccessVisitor(candidates, aliases)
    visitor.visit(fn)
    for param_name in sorted(visitor.found):
        if current_depth == 0:
            source = "handler_body"
            confidence = TIER_CONFIDENCE["handler_body"]
            evidence_msg = (
                f"params read in handler {fn.name!r}"
            )
            depth: int | None = None
        else:
            source = "helper"
            confidence = helper_confidence(current_depth)
            evidence_msg = (
                f"params.get() reached at helper depth="
                f"{current_depth} via {fn.name!r}"
            )
            depth = current_depth
        out_evidence.append(
            (
                param_name,
                ParamSourceEvidence(
                    source=source,
                    confidence=confidence,
                    evidence=evidence_msg,
                    call_graph_depth=depth,
                ),
            )
        )

    # Record every Name reference in the function body for the
    # module-const reachability test ("if NAME in referenced_const_names
    # then the command's code path touches that constant").
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Name):
            out_referenced_consts.add(sub.id)

    walk_uncertain = False

    # Detect non-literal-key params.get(...) anywhere in this function.
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            func = sub.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and (
                    (
                        isinstance(func.value, ast.Name)
                        and func.value.id in candidates
                    )
                    or _is_demisto_params_call(func.value)
                )
                and sub.args
                and not (
                    isinstance(sub.args[0], ast.Constant)
                    and isinstance(sub.args[0].value, str)
                )
            ):
                walk_uncertain = True
                break

    # Detect dynamic-dispatch call shapes anywhere in this function.
    if not walk_uncertain:
        for sub in ast.walk(fn):
            if _is_dynamic_dispatch_node(sub):
                walk_uncertain = True
                break

    # Recurse into resolvable callees, applying the same recursion
    # gate as :func:`trace_params_in_function`. Depth budget is the
    # number of additional callee-frames we can descend from
    # current_depth; when it hits 0 we mark uncertain (the budget cut
    # the walk short).
    if current_depth >= max_depth:
        # No budget for further descent. Any reachable callee from
        # here is unanalyzed; flag uncertain only if at least one
        # call site exists (we don't penalise leaf helpers).
        for call in _iter_calls(fn.body):
            target_fn = _resolve_call_target(call, func_map)
            if target_fn is not None and target_fn.name not in visited:
                # Would have descended but budget is exhausted.
                walk_uncertain = True
                break
        return walk_uncertain

    for call in _iter_calls(fn.body):
        target_fn = _resolve_call_target(call, func_map)
        if target_fn is None:
            # Unresolved target (built-in, dynamic dispatch already
            # caught above, or an attribute on an instance whose
            # class is in another module). Only flag uncertain when
            # the call looks like a real direct call — Attribute
            # calls on receiver objects are extremely common
            # (``client.get_thing()``) and would over-flag everything.
            # Treat unresolved bare Name calls and unresolved
            # Attribute calls whose name isn't a known built-in
            # as uncertainty signals.
            if isinstance(call.func, ast.Name):
                walk_uncertain = True
            continue
        if not (
            _call_passes_params(call, candidates)
            or _function_reads_params_directly(target_fn, module_params_vars)
        ):
            continue
        sub_uncertain = _trace_with_attribution(
            target_fn,
            func_map,
            aliases,
            max_depth=max_depth,
            current_depth=current_depth + 1,
            visited=visited,
            module_params_vars=module_params_vars,
            out_evidence=out_evidence,
            out_referenced_consts=out_referenced_consts,
        )
        if sub_uncertain:
            walk_uncertain = True

    return walk_uncertain


def _find_dispatch_anchor_line(main_fn: ast.FunctionDef) -> int:
    """Return the line below which ``main()`` is considered post-dispatch.

    Mirrors :func:`find_command_dispatch_line` but is explicit about
    the fallback semantics: if no dispatch construct is identified,
    treat ALL of ``main()`` as pre-dispatch (conservative — every
    params.get() seen gets ``pre_dispatch_main`` attribution).
    """
    line = find_command_dispatch_line(main_fn)
    if line == 10**9:
        return 10**9
    return line


def _collect_pre_dispatch_attribution(
    main_fn: ast.FunctionDef,
    func_map: dict[str, ast.FunctionDef | ast.ClassDef],
    params_vars: set[str],
    module_params_vars: set[str] | None,
    aliases: dict[str, str],
) -> dict[str, str]:
    """Find params read in ``main()`` pre-dispatch, including via constructors.

    Returns ``{param_name: evidence_str}``. Each YML param read in
    ``main()`` above the dispatch site, OR inside a constructor
    invoked by a pre-dispatch Call (resolved via
    :func:`_resolve_call_target` + Fix A's class-to-``__init__`` step),
    is attributed to every command as ``pre_dispatch_main``.
    """
    dispatch_line = _find_dispatch_anchor_line(main_fn)
    pre_stmts = _iter_pre_dispatch_stmts(main_fn.body, dispatch_line)

    out: dict[str, str] = {}

    # 1) Direct reads in main()'s own pre-dispatch statements.
    for stmt in pre_stmts:
        for param in _collect_param_reads_in_expr(stmt, params_vars, aliases):
            out.setdefault(
                param, "params.get() in main() before dispatch"
            )

    # 2) Reads inside __init__ for each constructor invoked
    #    pre-dispatch. Walks the Call list in pre-dispatch statements
    #    (using _iter_calls), resolves to a FunctionDef (which for a
    #    ClassDef target is its __init__ via Fix A), and runs the
    #    param visitor on that __init__ body. Doesn't recurse
    #    further — keeping the surface tight for the pre-dispatch
    #    tier specifically.
    seen_ctors: set[str] = set()
    for call in _iter_calls(pre_stmts):
        target_fn = _resolve_call_target(call, func_map)
        if target_fn is None:
            continue
        if target_fn.name != "__init__":
            # Only the constructor body counts here. Non-constructor
            # callees inside main() pre-dispatch are walked
            # elsewhere via the binding-narrowing machinery.
            continue
        # Resolve the class name for the evidence string. The call
        # site's func.id (Name) is the class name.
        cls_name = (
            call.func.id if isinstance(call.func, ast.Name) else "<class>"
        )
        key = f"{cls_name}.__init__"
        if key in seen_ctors:
            continue
        seen_ctors.add(key)
        sig_params = {a.arg for a in target_fn.args.args} | {
            a.arg for a in target_fn.args.kwonlyargs
        }
        candidates = (sig_params & PARAMS_VAR_ALIASES) or {"params"}
        if module_params_vars:
            candidates = candidates | module_params_vars
        visitor = _ParamAccessVisitor(candidates, aliases)
        visitor.visit(target_fn)
        for param in visitor.found:
            out.setdefault(
                param,
                f"params.get() in {cls_name}.__init__ called from "
                f"main() before dispatch",
            )

    return out


def _classify_verdict(
    by_source: dict[str, ParamSourceEvidence],
    rollup_confidence: float,
    analysis_status: str,
    walk_uncertain: bool,
) -> str:
    """Assign one of {proven_used, proven_unused, needs_review} per Change 1.

    Rules (verbatim from the task spec):

    * ``proven_used`` ↔ ``rollup_confidence == 1.0`` AND at least one
      source ∈ {dynamic_capture, handler_body}. The "100% from the
      script" case.
    * ``proven_unused`` ↔ NO sources fired AND the analyzer's
      reachability walk is confident:
      ``analysis_status`` in ``_HIGH_QUALITY_ANALYSIS_STATUSES``
      AND ``walk_uncertain`` is False.
    * ``needs_review`` ↔ everything else (rollup ∈ (0.0, 1.0)
      exclusive, OR silent zero where analyzer wasn't confident).
    """
    if rollup_confidence >= 1.0 and any(
        src in {"dynamic_capture", "handler_body"} for src in by_source
    ):
        return VERDICT_PROVEN_USED
    if not by_source:
        if (
            analysis_status in _HIGH_QUALITY_ANALYSIS_STATUSES
            and not walk_uncertain
        ):
            return VERDICT_PROVEN_UNUSED
        return VERDICT_NEEDS_REVIEW
    return VERDICT_NEEDS_REVIEW


def _build_attributions(
    handler_evidence: list[tuple[str, ParamSourceEvidence]],
    pre_dispatch_evidence: dict[str, str],
    module_const_to_params: dict[str, set[str]],
    hedged_constants: set[str],
    referenced_const_names: set[str],
    walk_uncertain: bool,
    captured: set[str],
    dynamic_confirmed_no_execution: bool = False,
    yml_param_names: set[str] | None = None,
    analysis_status: str = ANALYSIS_STATUS_DISPATCH_UNRESOLVED,
    emit_proven_unused: bool = True,
    access_spy_params: set[str] | None = None,
) -> list[ParamAttribution]:
    """Compose per-(command, param) attributions from every evidence source.

    Merge by ``param``: same param from multiple sources → single
    :class:`ParamAttribution` whose ``by_source`` collects all entries
    keyed by source label and whose ``rollup_confidence`` is the
    ``max`` over confidences (Q2(a)).

    Source assembly:

    1. **Handler / helper** evidence from the per-command attributed
       walk (B.4). Already labelled ``handler_body`` /``helper`` with
       the right confidence and depth.
    2. **Module-level constants** referenced by the command's
       reachable code: emits ``module_const_referenced`` (0.5) for
       each YML param the constant binds, OR ``module_const_hedged``
       (0.1) when the constant was bound to a non-literal-key
       ``params.get(var)`` OR when ``walk_uncertain`` is True for this
       command's static walk.
    3. **Pre-dispatch main()** evidence (B.5): every param goes in at
       ``pre_dispatch_main`` (0.2) — OR
       ``pre_dispatch_main_dynamic_disproven`` (0.1) if Fix C wired
       the ``dynamic_confirmed_no_execution`` flag True for this
       command (Q3 downgrade hook; gated off today).
    4. **Dynamic capture** evidence: each captured param folds in as
       ``dynamic_capture`` (1.0).
    """
    # by_param[param][source] = ParamSourceEvidence (one per source).
    by_param: dict[str, dict[str, ParamSourceEvidence]] = {}

    def _add(param: str, evidence: ParamSourceEvidence) -> None:
        bucket = by_param.setdefault(param, {})
        existing = bucket.get(evidence.source)
        # When the same source fires twice for the same param (e.g. a
        # helper read at depth 1 and again at depth 2), keep the
        # higher-confidence (lower-depth) entry — matches the
        # "minimum depth at which the read was first seen" rule from
        # §4.B.3 and matches the Q2(a) max-rollup semantics for the
        # sub-source as well.
        if existing is None or evidence.confidence > existing.confidence:
            bucket[evidence.source] = evidence

    # 1) Handler-body and helper evidence: one entry per (param,
    #    source). Multiple helper hits for the same (param, source)
    #    pair merge to the highest-confidence (shallowest-depth) one
    #    via _add()'s prior-vs-new comparison above.
    for param, ev in handler_evidence:
        _add(param, ev)

    # 2) Module-level constants.
    for const_name, params_set in module_const_to_params.items():
        if const_name not in referenced_const_names:
            continue
        # Drop the non-literal sentinel before iterating — it's only
        # a hedge marker.
        real_params = {
            p for p in params_set if p != _NON_LITERAL_PARAM_KEY
        }
        if not real_params:
            continue
        const_is_hedged = const_name in hedged_constants
        # Hedge when: the const itself is hedged (non-literal RHS), OR
        # the command's static walk is uncertain.
        hedged_now = const_is_hedged or walk_uncertain
        for param in real_params:
            if hedged_now:
                source = "module_const_hedged"
                confidence = TIER_CONFIDENCE["module_const_hedged"]
                reason = (
                    "uncertain walk"
                    if (walk_uncertain and not const_is_hedged)
                    else "non-literal key in binding"
                )
                evidence_msg = (
                    f"NAME={const_name} referenced in handler "
                    f"(hedged: {reason})"
                )
            else:
                source = "module_const_referenced"
                confidence = TIER_CONFIDENCE["module_const_referenced"]
                evidence_msg = (
                    f"NAME={const_name} referenced in handler"
                )
            _add(
                param,
                ParamSourceEvidence(
                    source=source,
                    confidence=confidence,
                    evidence=evidence_msg,
                ),
            )

    # 3) Pre-dispatch main(): every param fans out to this command.
    if dynamic_confirmed_no_execution:
        pre_source = "pre_dispatch_main_dynamic_disproven"
        pre_conf = TIER_CONFIDENCE[
            "pre_dispatch_main_dynamic_disproven"
        ]
    else:
        pre_source = "pre_dispatch_main"
        pre_conf = TIER_CONFIDENCE["pre_dispatch_main"]
    for param, evidence_msg in pre_dispatch_evidence.items():
        _add(
            param,
            ParamSourceEvidence(
                source=pre_source,
                confidence=pre_conf,
                evidence=evidence_msg,
            ),
        )

    # 4) Params-access spy: the param was READ at runtime during this
    #    command's execution, above the startup baseline. Strong (0.9) but
    #    below on-wire capture so the verdict stays needs_review.
    for param in access_spy_params or set():
        _add(
            param,
            ParamSourceEvidence(
                source="dynamic_access",
                confidence=TIER_CONFIDENCE["dynamic_access"],
                evidence="read at runtime (params-access spy, above baseline)",
            ),
        )

    # 5) Dynamic capture: authoritative, fold in last.
    for param in captured:
        _add(
            param,
            ParamSourceEvidence(
                source="dynamic_capture",
                confidence=TIER_CONFIDENCE["dynamic_capture"],
                evidence="observed in dynamic capture",
            ),
        )

    attributions: list[ParamAttribution] = []
    for param in sorted(by_param):
        sources = by_param[param]
        rollup = max(ev.confidence for ev in sources.values())
        verdict = _classify_verdict(
            sources, rollup, analysis_status, walk_uncertain
        )
        attributions.append(
            ParamAttribution(
                param=param,
                by_source=sources,
                rollup_confidence=rollup,
                verdict=verdict,
            )
        )

    # Change 1: synthesize silent-zero rows for every YML-declared
    # param that received NO positive evidence. The verdict on each
    # row tells the consumer's AI whether to skip (``proven_unused``)
    # or review (``needs_review``). When ``emit_proven_unused`` is
    # False, suppress the proven_unused rows only — needs_review
    # rows (where the analyzer wasn't confident) still get emitted
    # so the AI knows it must triage them.
    if yml_param_names:
        attributed = {attr.param for attr in attributions}
        silent_zero_params = sorted(yml_param_names - attributed)
        for param in silent_zero_params:
            verdict = _classify_verdict(
                {}, 0.0, analysis_status, walk_uncertain
            )
            if verdict == VERDICT_PROVEN_UNUSED and not emit_proven_unused:
                continue
            attributions.append(
                ParamAttribution(
                    param=param,
                    by_source={},
                    rollup_confidence=0.0,
                    verdict=verdict,
                )
            )
    return attributions


def _filter_attributions_by_min_confidence(
    attributions: list[ParamAttribution], min_confidence: float
) -> list[ParamAttribution]:
    """Drop ``by_source`` rows whose confidence is below ``min_confidence``.

    If a :class:`ParamAttribution` loses all of its sources after
    filtering, it is dropped entirely. Otherwise ``rollup_confidence``
    is recomputed over the surviving sources. ``min_confidence`` of
    0.0 (the default) is a no-op (no rows ever fall below).

    See B.8's CLI flag description: this implements the "filter
    sub-threshold tiers from attributions[*].by_source" semantics.
    """
    if min_confidence <= 0.0:
        return attributions
    out: list[ParamAttribution] = []
    for attr in attributions:
        kept = {
            src: ev
            for src, ev in attr.by_source.items()
            if ev.confidence >= min_confidence
        }
        if not kept:
            continue
        rollup = max(ev.confidence for ev in kept.values())
        out.append(
            ParamAttribution(
                param=attr.param,
                by_source=kept,
                rollup_confidence=rollup,
            )
        )
    return out


def analyze_static(
    py_source: str,
    command: str,
    language: str | None = None,
    integration_name: str = "",
    verbose: bool = True,
    call_graph_depth: int = 3,
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
    # ``func_map`` is passed so binding RHS expressions that call a
    # module-defined helper (e.g. AWS-EC2's ``client = build_client(args)``)
    # can recursively attribute the helper's param reads to the local
    # variable being bound. Without this, helpers that take a non-params
    # argument and read ``PARAMS.get(...)`` directly would have all of
    # their credential reads silently dropped.
    binding_map = build_binding_maps(
        main_fn, params_vars, aliases, dispatch_line, func_map=func_map
    )

    scope_2: set[str] = set()
    handler_calls = find_command_handler_calls(main_fn, command)
    resolved_targets: list[str] = []
    for call in handler_calls:
        target = _resolve_call_target(call, func_map)
        if target is None:
            continue
        resolved_targets.append(target.name)
        # Fix A: depth threaded from the CLI ``--call-graph-depth`` knob
        # (default 3, max 5). Was hard-coded to 2 — that's the depth
        # ceiling SplunkPy v2's ``update_remote_system`` (depth-3 below
        # ``fetch_incidents``) tripped over.
        scope_2 |= trace_params_in_function(
            target,
            func_map,
            aliases,
            depth=call_graph_depth,
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


def analyze_static_attributions(
    py_source: str,
    command: str,
    captured: set[str] | None = None,
    dynamic_confirmed_no_execution: bool = False,
    language: str | None = None,
    integration_name: str = "",
    call_graph_depth: int = 3,
    yml_param_names: set[str] | None = None,
    emit_proven_unused: bool = True,
) -> tuple[set[str], set[str], list[ParamAttribution]]:
    """Run :func:`analyze_static` plus build the Fix B per-command attributions.

    Returns ``(scope_1, scope_2, attributions)``. ``scope_1``/``scope_2``
    are identical to :func:`analyze_static` for backward compatibility.
    ``attributions`` is the per-param confidence-tier breakdown
    (always populated; never filtered here — headline filtering lives
    in :func:`analyze_integration`).

    ``captured`` is the dynamic-phase captured set for this command
    (or ``None`` / empty in static-only mode); folded in as
    ``dynamic_capture`` sources at confidence 1.0.

    ``dynamic_confirmed_no_execution`` gates the Q3 downgrade hook:
    when True, ``pre_dispatch_main`` (0.2) is replaced by
    ``pre_dispatch_main_dynamic_disproven`` (0.1) for every param on
    this command. Defaults False; Fix C populates the flag.

    Verbose mode is off here — the breadcrumbs come from
    :func:`analyze_static` proper, which the caller invokes
    separately. Calling this function is otherwise self-contained.
    """
    scope_1, scope_2, attributions, _status = analyze_static_attributions_with_status(
        py_source,
        command,
        captured=captured,
        dynamic_confirmed_no_execution=dynamic_confirmed_no_execution,
        language=language,
        integration_name=integration_name,
        call_graph_depth=call_graph_depth,
        yml_param_names=yml_param_names,
        emit_proven_unused=emit_proven_unused,
    )
    return scope_1, scope_2, attributions


def find_module_scope_dispatch(tree: ast.Module) -> list[ast.stmt] | None:
    """Change 2: locate dispatch at module top-level (for no-main() integrations).

    Many small integrations (Shodan_v2 is the canonical example) do
    NOT wrap their dispatch in a ``def main()``. Instead they dispatch
    directly at module scope, optionally inside a top-level ``try``
    block:

        # Shape A — direct
        if demisto.command() == "ip":
            return_results(ip_command(...))
        elif demisto.command() == "search":
            return_results(search_command(...))

        # Shape B — wrapped in try
        try:
            command = demisto.command()
            if command == "ip":
                ip_command(...)
            elif command == "search":
                search_command(...)
        except Exception as e:
            return_error(...)

    Returns the body (``list[ast.stmt]``) of the smallest construct
    that *contains* the dispatch. For Shape A that's the module body
    itself; for Shape B it's the ``Try.body``. Returns ``None`` if
    no dispatch construct is detected at module scope.

    Detection rule: the returned region must contain at least one
    statement that :func:`_is_dispatch_node` recognises (an ``If``
    whose test references ``command`` / ``demisto.command()``, a
    ``Match`` on the same, or a ``commands = {...}`` literal
    assignment).
    """
    if not isinstance(tree, ast.Module):
        return None
    # Module-scope walk: check each top-level statement (and the body
    # of top-level Try / With / If-__name__ wrappers) for a dispatch
    # construct.
    def _body_has_dispatch(body: list[ast.stmt]) -> bool:
        for stmt in body:
            if _is_dispatch_node(stmt):
                return True
        return False

    # Shape A: dispatch lives directly in module body.
    if _body_has_dispatch(tree.body):
        return list(tree.body)

    # Shape B: dispatch lives inside a top-level Try / With body.
    for stmt in tree.body:
        if isinstance(stmt, ast.Try) and _body_has_dispatch(stmt.body):
            return list(stmt.body)
        if isinstance(stmt, (ast.With, ast.AsyncWith)) and _body_has_dispatch(stmt.body):
            return list(stmt.body)
        # Shape C: ``if __name__ == "__main__":`` wrapper containing
        # the dispatch.
        if isinstance(stmt, ast.If) and _body_has_dispatch(stmt.body):
            return list(stmt.body)
    return None


def _synth_main_from_module(body: list[ast.stmt]) -> ast.FunctionDef:
    """Change 2: synthesize a FunctionDef wrapping a module-scope dispatch body.

    The rest of the analyzer pipeline (``find_command_handler_calls``,
    ``collect_pre_dispatch_params``, ``_collect_pre_dispatch_attribution``)
    treats its input as a ``main()`` FunctionDef. To support
    module-scope dispatch without forking every helper, we synthesize
    a minimal FunctionDef whose body IS the module-scope dispatch
    region. The synthesized node carries ``lineno=1`` so downstream
    line-comparison logic sees every wrapped statement as living "in
    main()".

    The synthesized function has no formal parameters and an empty
    decorator list — the analyzer's param-tracer keys off ``params``
    /aliases via :func:`find_params_var`, which still works because
    that helper walks the body, not the signature.
    """
    if not body:
        body = [ast.Pass(lineno=1, col_offset=0)]
    fn = ast.FunctionDef(
        name="main",
        args=ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        ),
        body=list(body),
        decorator_list=[],
        returns=None,
        type_comment=None,
    )
    fn.lineno = 1
    fn.col_offset = 0
    fn.end_lineno = max(
        (getattr(s, "end_lineno", getattr(s, "lineno", 1)) for s in body),
        default=1,
    )
    fn.end_col_offset = 0
    return fn


def extract_dict_dispatch_map(
    main_fn: ast.FunctionDef,
) -> tuple[dict[str, str] | None, bool]:
    """Change 3: extract a command → handler-name map from a dispatch dict literal.

    Walks ``main_fn`` for an ``ast.Assign`` whose RHS is an
    ``ast.Dict`` literal and whose target is a single ``Name``
    (typically ``commands`` but any name is accepted — we recognise
    the shape, not the name). The Dict must contain only
    string-constant keys and ``ast.Name`` values; each matching
    entry contributes ``map[key.value] = value.id``.

    Returns ``(map, dict_blind)``:

    * ``map`` is the ``{command: handler_name}`` dict when at least
      one well-formed entry was found. ``None`` if no such literal
      exists in ``main_fn`` at all.
    * ``dict_blind`` is True iff a dict literal IS present but
      contains AT LEAST ONE non-string-key OR non-Name-value
      entry (the canonical "blind" shape — comprehensions like
      ``{k: v for k, v in ...}`` produce an ``ast.DictComp`` not an
      ``ast.Dict``, so they are picked up here by emitting an empty
      ``map``-shape with ``dict_blind=True`` instead of letting them
      silently degrade to legacy resolution).

    The first eligible Assign wins — Cherwell / Jira / Gmail /
    PATHelpdeskAdvanced and friends all bind their dispatch dict
    exactly once near the top of ``main()`` so this matches the
    universal shape.
    """
    if main_fn is None:
        return None, False
    # Walk the function body breadth-first so a top-level
    # ``commands = {...}`` wins over any nested helper-local dict.
    # Accept both plain ``Assign`` (``commands = {...}``) and the
    # annotated form ``commands: Dict[str, Callable] = {...}``
    # (``AnnAssign``); both shapes are common in production
    # integrations (Jira uses the annotated form).
    candidate_assigns: list[ast.Assign | ast.AnnAssign] = []
    comprehension_seen = False
    for node in ast.walk(main_fn):
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(
                node.targets[0], ast.Name
            ):
                continue
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name) or node.value is None:
                continue
            target = node.target
            value = node.value
        else:
            continue
        # Surface comprehension-bound dispatch tables as "blind".
        if isinstance(value, ast.DictComp):
            comprehension_seen = True
            continue
        if isinstance(value, ast.Dict):
            candidate_assigns.append(node)
    if not candidate_assigns and not comprehension_seen:
        return None, False
    if comprehension_seen and not candidate_assigns:
        # Only comprehension-bound dispatch tables exist — emit
        # blind so the consumer knows we couldn't resolve handlers.
        return None, True

    # Prefer the largest dict (most realistic dispatch table). If
    # multiple have the same size, the first one wins.
    def _dict_size(a: ast.Assign | ast.AnnAssign) -> int:
        v = a.value
        if isinstance(v, ast.Dict):
            return len(v.keys)
        return 0

    candidate_assigns.sort(key=lambda a: -_dict_size(a))
    out: dict[str, str] = {}
    dict_blind = False
    for assign in candidate_assigns:
        d = assign.value
        if not isinstance(d, ast.Dict):
            continue
        for k, v in zip(d.keys, d.values):
            if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
                dict_blind = True
                continue
            # Extract handler name. Accept bare Name and direct
            # Lambda (we still register the str so the analyzer
            # knows the command exists).
            handler_name: str | None = None
            if isinstance(v, ast.Name):
                handler_name = v.id
            else:
                dict_blind = True
                continue
            # First entry wins for a given key; ignore subsequent
            # rebinds to keep the resolver deterministic.
            out.setdefault(k.value, handler_name)
        if out:
            # Stop at the first dict that yielded at least one
            # well-formed entry — the analyzer treats it as THE
            # dispatch table.
            break

    if not out:
        return None, dict_blind or comprehension_seen
    return out, dict_blind or comprehension_seen


def _detect_scattered_truncated(
    main_fn: ast.FunctionDef, command: str
) -> bool:
    """Change 4: True iff at least one early-return guard exists in main().

    The analyzer marks every post-guard command's ``analysis_status``
    as ``scattered_dispatch_window_truncated`` when this function
    returns True AND the command's handler was resolved (which means
    the command sits AFTER the guard — so its setup statements
    inside the now-larger pre-dispatch window need a human/AI
    double-check). The guard command itself still resolves normally
    (its handler IS the guard body) so the AI sees the
    scattered-truncated tag for the post-guard commands only.

    Detection: walk ``main_fn`` for any dispatch ``If`` whose body
    ends in an early-return (per :func:`_is_early_return_guard`).
    """
    if main_fn is None:
        return False
    for node in ast.walk(main_fn):
        if (
            isinstance(node, ast.If)
            and _is_dispatch_node(node)
            and _is_early_return_guard(node)
        ):
            return True
    return False


def analyze_static_attributions_with_status(
    py_source: str,
    command: str,
    captured: set[str] | None = None,
    dynamic_confirmed_no_execution: bool = False,
    language: str | None = None,
    integration_name: str = "",
    call_graph_depth: int = 3,
    yml_param_names: set[str] | None = None,
    emit_proven_unused: bool = True,
    access_spy_params: set[str] | None = None,
) -> tuple[set[str], set[str], list[ParamAttribution], str]:
    """Same as :func:`analyze_static_attributions` plus per-command analysis_status.

    Change 1: returns a 4-tuple ``(scope_1, scope_2, attributions,
    analysis_status)`` where ``analysis_status`` is one of the
    ``ANALYSIS_STATUS_*`` constants. The 3-tuple
    :func:`analyze_static_attributions` is a thin wrapper that drops
    the status (kept for backward compatibility with the existing
    test suite and the validator runner).
    """
    scope_1, scope_2 = analyze_static(
        py_source,
        command,
        language=language,
        integration_name=integration_name,
        verbose=False,
        call_graph_depth=call_graph_depth,
    )
    captured = captured or set()
    if language and language.lower() not in {"python", "python2", "python3"}:
        # Non-Python: skip static analysis entirely; analysis_status is
        # dispatch_unresolved (we never even parsed an AST).
        return scope_1, scope_2, [], ANALYSIS_STATUS_DISPATCH_UNRESOLVED
    if not py_source:
        return scope_1, scope_2, [], ANALYSIS_STATUS_DISPATCH_UNRESOLVED

    try:
        tree = ast.parse(py_source)
    except SyntaxError:
        # analyze_static already raised at this point in real use;
        # keep the safety net so unit tests with broken source don't
        # crash before scope_1/scope_2 short-circuit returns.
        return scope_1, scope_2, [], ANALYSIS_STATUS_DISPATCH_UNRESOLVED
    if not isinstance(tree, ast.Module):
        return scope_1, scope_2, [], ANALYSIS_STATUS_DISPATCH_UNRESOLVED
    func_map = build_function_map(tree)
    main_fn = find_main(func_map)
    # Change 2 hook: when find_main() returns None we'll fall back to
    # module-scope dispatch detection (find_module_scope_dispatch) in
    # the next commit. For now, the no-main path produces an empty
    # attribution set with dispatch_unresolved status.
    used_module_scope = False
    used_dict_dispatch = False
    used_scattered_truncated = False
    if main_fn is None:
        # Change 2: module-scope dispatch fallback.
        module_dispatch_body = find_module_scope_dispatch(tree)
        if module_dispatch_body is None:
            # No main() and no module-scope dispatch construct: we
            # cannot resolve any handler — mark blind for every
            # command.
            status = ANALYSIS_STATUS_MODULE_SCOPE_BLIND
            attributions = _build_attributions(
                handler_evidence=[],
                pre_dispatch_evidence={},
                module_const_to_params={},
                hedged_constants=set(),
                referenced_const_names=set(),
                walk_uncertain=True,
                captured=captured,
                dynamic_confirmed_no_execution=dynamic_confirmed_no_execution,
                yml_param_names=yml_param_names,
                analysis_status=status,
                emit_proven_unused=emit_proven_unused,
                access_spy_params=access_spy_params,
            )
            return scope_1, scope_2, attributions, status
        # Synthesize a function-like wrapper so the rest of the
        # pipeline can treat module-scope dispatch identically to
        # main()-scope dispatch. We use a FunctionDef whose body is
        # the dispatch region; lineno is set to 1 so the
        # dispatch-line filter behaves the same way.
        main_fn = _synth_main_from_module(module_dispatch_body)
        used_module_scope = True
    aliases = find_pydantic_aliases(tree)
    params_var = find_params_var(main_fn) or "params"
    module_params_vars = find_module_level_params_vars(tree)
    params_vars = {params_var} | PARAMS_VAR_ALIASES | module_params_vars

    # B.3 — module-level def-use index.
    module_const_to_params, hedged_constants = _build_module_const_index(
        tree, params_vars, aliases
    )

    # Change 3: dict-dispatch table preference. If a top-level
    # ``commands = {...}`` literal is present in main() and contains
    # only string-keyed Name handlers, use it as the primary handler
    # resolver. dict_dispatch_blind is emitted when a dict literal IS
    # present but contains non-literal entries (comprehensions etc.).
    dict_map, dict_blind = extract_dict_dispatch_map(main_fn)

    # B.4 — per-command attributed reachability walk over every
    # resolved handler. Visited set is shared across handlers for the
    # same command (multiple dispatch sites for the same command name
    # behave like one). Walk_uncertain ORs across handlers.
    handler_evidence: list[tuple[str, ParamSourceEvidence]] = []
    referenced_consts: set[str] = set()
    walk_uncertain = False
    visited_handlers: set[str] = set()
    handler_resolved = False
    helper_chain_seen = False

    if dict_map is not None and command in dict_map:
        # Change 3: resolve handler via the dispatch dict map.
        handler_name = dict_map[command]
        target = func_map.get(handler_name)
        if isinstance(target, ast.FunctionDef):
            used_dict_dispatch = True
            handler_resolved = True
            sub_uncertain = _trace_with_attribution(
                target,
                func_map,
                aliases,
                max_depth=call_graph_depth,
                current_depth=0,
                visited=visited_handlers,
                module_params_vars=module_params_vars,
                out_evidence=handler_evidence,
                out_referenced_consts=referenced_consts,
            )
            if sub_uncertain:
                walk_uncertain = True
            # Detect helper-chain attribution for status downgrade.
            if any(
                ev.source == "helper"
                for _p, ev in handler_evidence
            ):
                helper_chain_seen = True

    # If dict-dispatch didn't fire (or the command wasn't in the dict),
    # fall through to the legacy resolution path.
    handler_calls = find_command_handler_calls(main_fn, command)
    # Change 4 detection: if the dispatch_line returned by
    # find_command_dispatch_line() is past at least one early-return
    # guard, mark this command's status as
    # scattered_dispatch_window_truncated (informational; the actual
    # dispatch-line shift is done inside find_command_dispatch_line
    # itself per Change 4).
    used_scattered_truncated = _detect_scattered_truncated(main_fn, command)

    if not used_dict_dispatch:
        for call in handler_calls:
            target = _resolve_call_target(call, func_map)
            if target is None:
                # Unresolved handler is itself uncertainty.
                walk_uncertain = True
                continue
            if target.name in visited_handlers:
                continue
            handler_resolved = True
            sub_uncertain = _trace_with_attribution(
                target,
                func_map,
                aliases,
                max_depth=call_graph_depth,
                current_depth=0,
                visited=visited_handlers,
                module_params_vars=module_params_vars,
                out_evidence=handler_evidence,
                out_referenced_consts=referenced_consts,
            )
            if sub_uncertain:
                walk_uncertain = True
        # If no dispatch site was identified at all, the analyzer can't
        # prove anything about which module-level constants this command
        # reaches — hedge.
        if not handler_calls:
            walk_uncertain = True
        if any(ev.source == "helper" for _p, ev in handler_evidence):
            helper_chain_seen = True

    # B.5 — pre-dispatch main() walk (including constructors).
    pre_dispatch_evidence = _collect_pre_dispatch_attribution(
        main_fn,
        func_map,
        params_vars,
        module_params_vars,
        aliases,
    )

    # Change 1: determine analysis_status from observed states. Order
    # of precedence is high-quality → low-quality:
    #   dict_dispatch_blind > module_scope_blind > handler_not_found
    #   > dispatch_unresolved > scattered_dispatch_window_truncated
    #   > analyzed_dict_dispatch > analyzed_module_scope
    #   > analyzed_via_helper_chain > analyzed_handler_body
    if dict_blind and not handler_resolved:
        analysis_status = ANALYSIS_STATUS_DICT_DISPATCH_BLIND
    elif used_dict_dispatch and handler_resolved:
        analysis_status = ANALYSIS_STATUS_DICT_DISPATCH
    elif used_module_scope and handler_resolved:
        analysis_status = ANALYSIS_STATUS_MODULE_SCOPE
    elif handler_calls and not handler_resolved:
        # We found a dispatch site that matched the command but
        # couldn't resolve the handler function (e.g. handler is
        # imported / dynamic / undefined).
        analysis_status = ANALYSIS_STATUS_HANDLER_NOT_FOUND
    elif not handler_calls and not used_dict_dispatch:
        # Dispatch never matched this command at all.
        analysis_status = ANALYSIS_STATUS_DISPATCH_UNRESOLVED
    elif used_scattered_truncated:
        analysis_status = ANALYSIS_STATUS_SCATTERED_TRUNCATED
    elif helper_chain_seen:
        analysis_status = ANALYSIS_STATUS_HELPER_CHAIN
    else:
        analysis_status = ANALYSIS_STATUS_HANDLER_BODY

    # Change 4 special-case: when the dispatch window was truncated
    # by early-return guards AND the analyzer DID resolve a handler
    # for this command via the legacy path (i.e. this command lives
    # after the guard), surface the scattered_truncated tag so the AI
    # knows to double-check it.
    if (
        used_scattered_truncated
        and handler_resolved
        and not used_dict_dispatch
        and not used_module_scope
    ):
        analysis_status = ANALYSIS_STATUS_SCATTERED_TRUNCATED

    # B.6 — assemble.
    attributions = _build_attributions(
        handler_evidence=handler_evidence,
        pre_dispatch_evidence=pre_dispatch_evidence,
        module_const_to_params=module_const_to_params,
        hedged_constants=hedged_constants,
        referenced_const_names=referenced_consts,
        walk_uncertain=walk_uncertain,
        captured=captured,
        dynamic_confirmed_no_execution=dynamic_confirmed_no_execution,
        yml_param_names=yml_param_names,
        analysis_status=analysis_status,
        emit_proven_unused=emit_proven_unused,
        access_spy_params=access_spy_params,
    )
    return scope_1, scope_2, attributions, analysis_status


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


def _ensure_demisto_sdk_log_path() -> None:
    """Auto-apply the documented ``DEMISTO_SDK_LOG_FILE_PATH`` workaround.

    On macOS Sequoia, ``demisto-sdk`` subprocess invocations crash trying
    to open ``~/.demisto-sdk/logs/demisto_sdk_debug.log`` because of the
    ``com.apple.provenance`` xattr (see FIXES-TODO #2 / skill §"Set
    DEMISTO_SDK_LOG_FILE_PATH"). If the env var is unset, default it to
    a workspace-local ``<repo_root>/.tmp_migration/sdk-logs`` directory
    (created on demand). Respect any explicitly-set value.
    """
    if os.environ.get("DEMISTO_SDK_LOG_FILE_PATH"):
        return
    log_dir = _resolve_repo_root() / ".tmp_migration" / "sdk-logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If we can't create the dir, fall back to letting the SDK choose
        # — the user will see the original crash and can apply the
        # workaround manually. We don't want to hard-fail here.
        return
    os.environ["DEMISTO_SDK_LOG_FILE_PATH"] = str(log_dir)


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
    # Auto-apply the DEMISTO_SDK_LOG_FILE_PATH workaround (FIXES-TODO #2).
    # The subprocess inherits the current env, so setting it here is
    # sufficient — no need to pass an explicit ``env=`` dict.
    _ensure_demisto_sdk_log_path()
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

    # Language gate (FIXES-TODO #11): the unified YAML's script.type
    # declares the integration's language. For non-Python integrations
    # the script body is JS / PowerShell / etc. and would crash the
    # ``ast.parse`` sanity-check below with a confusing
    # SyntaxError-shaped DynamicPrepError ("invalid syntax" on a JS
    # comment, etc.). Raise a typed, recognizable error here so
    # callers can surface ``status="non_python"`` in the diagnostic
    # envelope. Per the cross-cutting Hints policy: prescription is
    # unambiguous, so the message points at ``--static-only``.
    try:
        _unified_data = yaml.safe_load(yaml_out.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — fall back to old behavior on YAML errors
        _unified_data = None
    _unified_lang = None
    if isinstance(_unified_data, dict):
        _script = _unified_data.get("script")
        if isinstance(_script, dict):
            _unified_lang = _script.get("type")
    if _unified_lang and _unified_lang not in {"python", "python2", "python3"}:
        raise DynamicPrepError(
            f"non-Python unified file: {_unified_lang!r}; "
            f"the dynamic phase cannot run on non-Python integrations. "
            f"Use --static-only for the structured graceful skip."
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


# --------------------------------------------------------------------------
# Change #2 (Fix F): cert/key/thumbprint sentinel coercion.
#
# Microsoft cert-auth integrations (Azure Sentinel, M365 Defender, etc.)
# fail at module import when the generic ``SENTINEL_PARAM_<name>`` string
# is fed into ``binascii.a2b_hex`` (raises ``Error: Odd-length string``)
# or into a PEM regex (raises ``ValueError`` on missing markers). Result:
# 100% ``no_data`` across every command of those integrations because the
# child crashes long before dispatch.
#
# Fix: when seeding a YML param whose NAME (case-insensitive substring
# match) contains ``thumbprint`` / ``private_key`` / ``certificate``,
# substitute a syntactically-valid format-checker satisfier in place of
# the generic sentinel. The values below are NOT cryptographically valid
# (they don't match a real CA, modulus is bogus, etc.) — they are just
# enough to make ``a2b_hex`` and PEM-parser regexes succeed so the
# dynamic phase can reach the actual command dispatch.
#
# Trade-off: because the coerced values DO NOT contain
# ``SENTINEL_PARAM_<name>``, sentinel-attribution by name match cannot
# find them in captured HTTP traffic. That's acceptable — the
# alternative is ``no_data`` everywhere, which gives the calling agent
# strictly less information. Operators who want strict-sentinel mode
# (e.g. for debugging the analyzer itself) can pass
# ``--no-sentinel-coercion`` on the CLI to disable this behaviour.
# --------------------------------------------------------------------------

# 40 hex chars = valid SHA-1 thumbprint that satisfies ``a2b_hex``.
_COERCED_THUMBPRINT_VALUE = "AABBCCDDEEFF00112233445566778899AABBCCDD"

# Stub PEM private key — won't pass cryptographic validation but the
# header / footer markers satisfy the common ``BEGIN PRIVATE KEY`` regex
# checks that integrations do at module load.
_COERCED_PRIVATE_KEY_VALUE = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL\n"
    "-----END PRIVATE KEY-----"
)

# Stub PEM certificate — same idea: passes header/footer regex, doesn't
# pass crypto validation.
_COERCED_CERTIFICATE_VALUE = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDazCCAlOgAwIBAgIUf\n"
    "-----END CERTIFICATE-----"
)


def coerce_sentinel_for_param(name: str) -> tuple[str, str] | None:
    """Return ``(coerced_value, matched_pattern)`` for cert/key/thumbprint params.

    Returns ``None`` when the param name does NOT match any coercion
    pattern. Match is a case-insensitive substring check on the YML
    param name.

    Order matters because of the substring overlap between
    ``certificate_thumbprint`` and ``certificate``: ``thumbprint`` is
    checked FIRST so a name like ``certificate_thumbprint`` is coerced
    to a 40-char hex string (the SHA-1 form), not a PEM cert. The
    ``private_key`` check runs before ``certificate`` so a name like
    ``private_key_certificate`` is treated as a private key.
    """
    if not isinstance(name, str) or not name:
        return None
    lname = name.lower()
    if "thumbprint" in lname:
        return _COERCED_THUMBPRINT_VALUE, "thumbprint"
    if "private_key" in lname:
        return _COERCED_PRIVATE_KEY_VALUE, "private_key"
    if "certificate" in lname:
        return _COERCED_CERTIFICATE_VALUE, "certificate"
    return None


def build_param_values(
    yml_params: list[dict[str, Any]],
    proxy_url: str,
    ignore: set[str],
    coerce_certs: bool = True,
    seed_overrides: dict[str, str] | None = None,
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

    Seed overrides (``--seed-param``) support two name shapes:

    * Flat ``<name>=<value>`` — replaces the whole value for any param
      type. For ``type: 9`` (credentials) params this is REJECTED with a
      hard error, because the integration code expects a dict-shaped
      value (``{"identifier": ..., "password": ...}``) and a flat string
      would crash the consumer with
      ``AttributeError: 'str' object has no attribute 'get'``. Use the
      dotted-leaf form instead.
    * Dotted leaf ``<name>.identifier=<value>`` / ``<name>.password=<value>``
      — valid ONLY for ``type: 9`` credentials params. Each leaf can be
      supplied independently; leaves not supplied keep their default
      sentinel form (``SENTINEL_PARAM_<name>_identifier`` /
      ``SENTINEL_PARAM_<name>_password``). The constructed dict is what
      the integration's ``params.get("<name>", {}).get("identifier")``
      / ``.get("password")`` consumer will see.

    Stray dotted-leaf overrides (parent doesn't exist, parent isn't
    type=9, leaf name isn't ``identifier``/``password``) are caught at
    the call site in ``analyze_integration`` before this function runs
    and surfaced as ``[seed] WARNING`` lines.
    """
    values: dict[str, Any] = {}
    sentinels: dict[str, list[str]] = {}
    non_traceable: set[str] = set()
    overrides = seed_overrides or {}
    # Build the credentials-leaf override view: for each parent name, the
    # leaves explicitly supplied (a dict {leaf: value}). This lets the
    # type=9 branch below decide which leaves to substitute without
    # re-scanning ``overrides`` per param.
    cred_leaf_overrides: dict[str, dict[str, str]] = {}
    for k, v in overrides.items():
        if "." in k:
            parent, _, leaf = k.partition(".")
            if leaf in ("identifier", "password"):
                cred_leaf_overrides.setdefault(parent, {})[leaf] = v
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

        # Highest-priority override: an operator-supplied value via
        # ``--seed-param NAME=VALUE`` on the CLI. This wins over the
        # YML defaultvalue, the cert/key coercion (Change #2), the URL
        # proxy redirect, and the generic sentinel. Use case: the
        # cert-coercion stub failed because the integration validates
        # against a real CA, OR an integration trips on a value we
        # couldn't anticipate (custom regex on a free-form text param,
        # etc.). The skill (connectus-migration-SKILL.md) documents
        # the recovery loop: see ``param_caused_failure`` / format-
        # validator crash → inspect YML → re-run with
        # ``--seed-param NAME=val``. The supplied value is treated as
        # traceable when it's long enough (>=4 chars) to make
        # incidental matches unlikely; sentinel-attribution by exact
        # match still works because the override value IS the sentinel.
        if name in overrides:
            # Special-case: a flat ``<name>=<value>`` override on a
            # ``type: 9`` credentials param is almost always wrong —
            # the integration code reads ``params.get(name, {}).get(
            # "identifier")`` / ``.get("password")`` and expects a dict.
            # A flat string replacement breaks the consumer with
            # ``AttributeError: 'str' object has no attribute 'get'``.
            # We fail loudly with an actionable message instead of
            # silently producing the wrong shape.
            if yml_type == YML_TYPE_CREDENTIALS:
                raise ValueError(
                    f"--seed-param {name!r} targets a YML type:9 "
                    f"credentials widget but uses the flat NAME=VALUE "
                    f"form. Credentials widgets expect a dict-shaped "
                    f"value at runtime; a flat string would crash the "
                    f"integration's "
                    f"`params.get({name!r}, {{}}).get(...)` consumer.\n"
                    f"\n"
                    f"Use the dotted-leaf form to seed the identifier "
                    f"and password leaves independently:\n"
                    f"  --seed-param {name}.identifier=<user-or-email>\n"
                    f"  --seed-param {name}.password=<secret-or-json>\n"
                    f"\n"
                    f"Either leaf may be omitted; omitted leaves keep "
                    f"their default sentinel value "
                    f"(SENTINEL_PARAM_{name}_identifier / _password)."
                )
            override_val = overrides[name]
            print(
                f"[seed] Operator override for {name!r}: using "
                f"--seed-param value (length={len(override_val)})",
                file=sys.stderr,
            )
            traceable = len(override_val) >= 4
            _record(
                override_val,
                [override_val] if traceable else [],
                traceable=traceable,
            )
            continue

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

        # Change #2 (Fix F): cert/key/thumbprint coercion. When the param
        # name matches a known cert/key/thumbprint substring, swap the
        # generic sentinel for a syntactically-valid format-checker
        # satisfier so the integration's module-load validators
        # (``binascii.a2b_hex``, PEM regexes) pass. The coerced value
        # does NOT contain ``SENTINEL_PARAM_<name>`` so sentinel-attribution
        # by name match cannot find it on the wire — that's the explicit
        # trade-off documented at :data:`_COERCED_THUMBPRINT_VALUE`. The
        # YML ``defaultvalue`` branch above takes priority so an operator
        # who hard-codes a real test cert in YML still gets it.
        #
        # IMPORTANT: cert-coercion runs only for flat-shaped params
        # (type != 9). For ``type:9`` credentials widgets — which a
        # ``creds_certificate`` widget is — the per-leaf coercion lives
        # below inside the ``YML_TYPE_CREDENTIALS`` branch so that the
        # dict shape ``{"identifier": ..., "password": ...}`` is
        # preserved (a flat-string replacement would crash the
        # integration's ``params.get(name, {}).get("identifier")``
        # consumer with ``AttributeError: 'str' object has no attribute
        # 'get'``).
        if coerce_certs and yml_type != YML_TYPE_CREDENTIALS:
            coerced_pair = coerce_sentinel_for_param(name)
            if coerced_pair is not None:
                coerced_val, matched_pattern = coerced_pair
                print(
                    f"[seed] Coerced sentinel for {name!r} (matched "
                    f"{matched_pattern}) to satisfy format validation",
                    file=sys.stderr,
                )
                # Mark non-traceable: the coerced value is unique-ish but
                # has no ``SENTINEL_PARAM_<name>`` substring so it cannot
                # participate in name-keyed sentinel attribution. Tokens
                # list is left empty to keep ``detect_sentinel_hits``
                # deterministic (same convention as bools / numerics).
                _record(coerced_val, [], traceable=False)
                continue

        if yml_type == YML_TYPE_BOOL:
            _record(True, [], traceable=False)
            continue

        if yml_type == YML_TYPE_CREDENTIALS:
            id_sent = f"{sentinel}_identifier"
            pw_sent = f"{sentinel}_password"
            leaf_overrides = cred_leaf_overrides.get(name, {})
            id_val: Any = leaf_overrides.get("identifier", id_sent)
            pw_val: Any = leaf_overrides.get("password", pw_sent)
            # Per-leaf cert/key/thumbprint coercion. The convention for
            # XSOAR cert-auth widgets (e.g. ``creds_certificate``) is:
            # ``.identifier`` holds the thumbprint (40-char hex);
            # ``.password`` holds the PEM private key. When the parent
            # name matches the cert/key/thumbprint pattern AND the
            # corresponding leaf has NOT been operator-overridden, swap
            # the leaf sentinel for a syntactically-valid stub so the
            # integration's module-load validators (``binascii.a2b_hex``,
            # PEM regexes) pass instead of crashing on
            # ``SENTINEL_PARAM_<name>_<leaf>``. The coerced stubs do NOT
            # contain the SENTINEL_PARAM string so they cannot
            # participate in name-keyed sentinel attribution — same
            # trade-off as the flat-param coercion above.
            id_coerced = False
            pw_coerced = False
            if (
                coerce_certs
                and "identifier" not in leaf_overrides
                and coerce_sentinel_for_param(name) is not None
            ):
                # The thumbprint stub is the natural fit for the
                # identifier leaf on a cert-widget. (Even if the parent
                # name matches "private_key" or "certificate" rather
                # than "thumbprint", the thumbprint stub is the safest
                # default — it satisfies the most common module-load
                # validator, `binascii.a2b_hex(thumbprint)`.)
                id_val = _COERCED_THUMBPRINT_VALUE
                id_coerced = True
            if (
                coerce_certs
                and "password" not in leaf_overrides
                and coerce_sentinel_for_param(name) is not None
            ):
                # The PEM private key stub fits the password leaf.
                pw_val = _COERCED_PRIVATE_KEY_VALUE
                pw_coerced = True
            if id_coerced or pw_coerced:
                coerced_leaves = [
                    leaf for leaf, flag in
                    [("identifier", id_coerced), ("password", pw_coerced)]
                    if flag
                ]
                print(
                    f"[seed] Coerced sentinel for {name!r} credentials "
                    f"leaves {coerced_leaves} to satisfy format "
                    f"validation",
                    file=sys.stderr,
                )
            # Tracing tokens: for any leaf we overrode (operator), the
            # seeded value IS the sentinel (>= 4 chars). For any leaf
            # left at its default sentinel, the generated
            # SENTINEL_PARAM_<name>_<leaf> string is the sentinel.
            # Coerced cert/PEM stubs are NOT traceable (no sentinel
            # substring), same convention as the flat-coercion branch.
            tokens: list[str] = []
            if not id_coerced and isinstance(id_val, str) and len(id_val) >= 4:
                tokens.append(id_val)
            if not pw_coerced and isinstance(pw_val, str) and len(pw_val) >= 4:
                tokens.append(pw_val)
            if leaf_overrides:
                seeded_leaves = sorted(leaf_overrides.keys())
                print(
                    f"[seed] Operator override for {name!r} credentials "
                    f"leaves {seeded_leaves}: using --seed-param values",
                    file=sys.stderr,
                )
            _record(
                {"identifier": id_val, "password": pw_val},
                tokens,
                traceable=bool(tokens),
            )
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


# --------------------------------------------------------------------------
# Command-ARGUMENT seeding (mirrors param seeding above).
#
# The dynamic phase invokes each command with ``demisto.args()``. Without
# seeding, ``args()`` returns ``{}`` and any handler whose YML arguments
# are passed as REQUIRED POSITIONAL parameters (e.g.
# ``check_ip_command(reliability, ip, ...)`` invoked as
# ``handler(**demisto.args())``) crashes with ``TypeError: missing
# required positional argument`` BEFORE issuing any HTTP request — so the
# param-flow capture sees nothing (status ``no_data``). Seeding args from
# the command's YML ``arguments`` (defaultValue, else a type-appropriate
# value) lets those handlers run far enough to exercise their param reads.
# ``--seed-arg CMD:NAME=VALUE`` lets the operator/AI override any single
# arg value per command.
# --------------------------------------------------------------------------

ARG_SENTINEL_PREFIX = "SENTINEL_ARG_"


def get_command_args(yml_data: dict[str, Any], command: str) -> list[dict[str, Any]]:
    """Return the YML ``arguments`` list for *command* (empty if none).

    ``test-module`` and other synthetic commands (fetch-incidents, etc.)
    have no YML ``arguments`` entry and yield ``[]``.
    """
    script = yml_data.get("script") or {}
    for entry in script.get("commands") or []:
        if isinstance(entry, dict) and entry.get("name") == command:
            args = entry.get("arguments") or []
            return [a for a in args if isinstance(a, dict) and a.get("name")]
    return []


def build_arg_values(
    command_args: list[dict[str, Any]],
    *,
    seed_args: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the ``demisto.args()`` dict for one command.

    Value-selection precedence per argument (highest first):

    1. ``--seed-arg CMD:NAME=VALUE`` operator override (``seed_args`` here
       is already scoped to this command — see :func:`parse_seed_args`).
    2. YML ``defaultValue`` (camelCase, the command-argument spelling),
       parsed to a sensible Python type.
    3. First ``predefined`` option, when the argument is an enum-style
       ``predefined`` list (commonly ``true``/``false`` or a format
       selector) — picking a valid value avoids enum-validation crashes.
    4. A grep-able string sentinel ``SENTINEL_ARG_<name>`` so the value is
       traceable in captured HTTP, mirroring the param sentinel.

    Every declared argument gets a value (so required-positional handlers
    never crash on a missing kwarg). The returned dict is JSON-serialized
    into ``CHECK_ARGS_JSON`` for the child's ``demisto.args()``.
    """
    overrides = seed_args or {}
    values: dict[str, Any] = {}
    for arg in command_args:
        name = arg["name"]
        # 1. Operator override wins outright.
        if name in overrides:
            values[name] = overrides[name]
            continue
        # 2. YML defaultValue (command args use camelCase ``defaultValue``;
        #    tolerate the lowercase ``defaultvalue`` just in case).
        raw_default = arg.get("defaultValue", arg.get("defaultvalue"))
        if raw_default is not None and raw_default != "":
            values[name] = raw_default
            continue
        # 3. First predefined option (enum-style arg).
        predefined = arg.get("predefined")
        if isinstance(predefined, list) and predefined:
            values[name] = predefined[0]
            continue
        # 4. Grep-able sentinel.
        values[name] = f"{ARG_SENTINEL_PREFIX}{name}"
    return values


def parse_seed_args(raw_pairs: list[str] | None) -> dict[str, dict[str, str]]:
    """Parse ``--seed-arg CMD:NAME=VALUE`` pairs into a nested dict.

    Returns ``{command: {arg_name: value}}``. Each raw pair MUST be of
    the form ``CMD:NAME=VALUE`` — the ``CMD:`` prefix scopes the override
    to a single command so the same arg name on different commands can
    take different values. Malformed pairs (missing ``:`` or ``=``) raise
    ``ValueError`` with an actionable message.
    """
    out: dict[str, dict[str, str]] = {}
    for pair in raw_pairs or []:
        if ":" not in pair or "=" not in pair.split(":", 1)[1]:
            raise ValueError(
                f"--seed-arg {pair!r} is malformed; expected "
                f"CMD:NAME=VALUE (e.g. --seed-arg ip:ip=1.1.1.1)."
            )
        cmd, rest = pair.split(":", 1)
        name, _, value = rest.partition("=")
        cmd, name = cmd.strip(), name.strip()
        if not cmd or not name:
            raise ValueError(
                f"--seed-arg {pair!r} is malformed; CMD and NAME must be "
                f"non-empty (e.g. --seed-arg ip:ip=1.1.1.1)."
            )
        out.setdefault(cmd, {})[name] = value
    return out


# --------------------------------------------------------------------------
# Params-ACCESS spy.
#
# The sentinel-on-the-wire scan only detects params whose seeded value
# travels into an outgoing HTTP request. It misses params that are read
# but never sent — control-flow booleans (``if params.get("disregard_
# quota")``), post-response/client-side params (``integrationReliability``
# used to compute a DBot label), and short YML-default values that are
# recorded non-traceable. The access spy closes that gap: it replaces the
# params dict with an instrumented mapping that records every key READ at
# runtime, then reports the accessed-key set back to the parent.
#
# Attribution rule (see skill): a baseline run (startup / test-module)
# captures the "always-read" key set; only keys read ABOVE that baseline
# for a given command are elevated. Pre-dispatch / module-import reads
# fall into the baseline and stay at their existing low static tier. A
# spy hit is scored at the ``dynamic_access`` tier (high but < the on-wire
# ``dynamic_capture`` gold tier) so the agent still double-checks.
#
# The class SOURCE lives in one string so the importable Python class
# (for unit tests) and the mock-template copy (run in the child process,
# which cannot import this module) never drift.
# --------------------------------------------------------------------------

_TRACKING_MAPPING_SRC = '''
class TrackingMapping(dict):
    """A dict that records every key read via __getitem__/.get()/__contains__.

    Subclasses dict so any ``isinstance(x, dict)`` checks in integration
    code still pass and all non-recorded dict behavior is inherited.
    ``.get(k)`` records ``k`` even when absent (the READ intent matters,
    e.g. ``params.get("disregard_quota")`` returning None still means the
    integration consulted that param).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Use object.__setattr__-free plain attribute; dict allows it.
        self.accessed_keys = set()

    def __getitem__(self, key):
        self.accessed_keys.add(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.accessed_keys.add(key)
        return super().get(key, default)

    def __contains__(self, key):
        self.accessed_keys.add(key)
        return super().__contains__(key)
'''

# Build the importable class by executing the shared source.
_tracking_ns: dict[str, Any] = {}
exec(_TRACKING_MAPPING_SRC, _tracking_ns)  # noqa: S102 - trusted constant
TrackingMapping = _tracking_ns["TrackingMapping"]


def parse_access_report(text: str | None) -> set[str]:
    """Parse the child's emitted accessed-keys report into a set.

    The child writes a JSON list of key strings to ``CHECK_ACCESS_OUT``.
    Robust to empty/missing/garbled content (returns an empty set) so a
    truncated child report never crashes the parent.
    """
    if not text:
        return set()
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return set()
    if isinstance(data, list):
        return {str(k) for k in data}
    return set()


def attribute_access_spy(
    command_accessed: set[str],
    baseline_accessed: set[str],
    yml_param_names: set[str],
    ignore: set[str],
) -> set[str]:
    """Return the YML params to elevate from the access spy for one command.

    Elevate a key iff it was read during THIS command's run, NOT in the
    startup baseline (so pre-dispatch / module-import globals are excluded),
    IS a declared YML config param, and is NOT on the ignore set.
    """
    above_baseline = command_accessed - baseline_accessed
    return (above_baseline & yml_param_names) - ignore


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
# The mock reads ``CHECK_PARAMS_JSON``, ``CHECK_COMMAND``, and
# ``CHECK_ARGS_JSON`` from the env at import time so seeded values are
# visible to module-level code in the integration (e.g.
# ``SERVER = demisto.params().get("server")``) and so seeded command
# arguments are returned by ``demisto.args()`` (mirroring how params are
# seeded — lets the dynamic phase get past required-positional command
# args that would otherwise crash the handler before any HTTP call).
_DEMISTOMOCK_TEMPLATE = textwrap.dedent(
    '''
    """On-disk demistomock used by check_command_params.py dynamic runs."""
    import atexit as _atexit
    import json as _json
    import os as _os
    import sys as _sys

    __TRACKING_MAPPING_INJECTION__

    _RAW_PARAMS = _json.loads(_os.environ.get("CHECK_PARAMS_JSON", "{}"))
    # Wrap params in the access-spy mapping so every key READ is recorded,
    # even reads whose value never reaches an HTTP request (control-flow
    # booleans, post-response params). The parent diffs this against a
    # startup baseline to attribute command-specific reads.
    _PARAMS = TrackingMapping(_RAW_PARAMS)
    _COMMAND = _os.environ.get("CHECK_COMMAND", "")
    _ARGS = _json.loads(_os.environ.get("CHECK_ARGS_JSON", "{}"))

    # On exit (normal OR sys.exit from the patched return_error), dump the
    # set of accessed param keys to CHECK_ACCESS_OUT for the parent to read.
    def _dump_access_report():
        _out = _os.environ.get("CHECK_ACCESS_OUT")
        if not _out:
            return
        try:
            with open(_out, "w", encoding="utf-8") as _f:
                _json.dump(sorted(_PARAMS.accessed_keys), _f)
        except Exception:
            pass
    _atexit.register(_dump_access_report)


    class _Demisto:
        callingContext = {"context": {}, "params": _PARAMS, "command": _COMMAND, "args": _ARGS}
        def params(self): return _PARAMS
        def command(self): return _COMMAND
        def args(self): return _ARGS
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
        def getFilePath(self, *a, **k):
            # File-upload commands resolve a war-room entry id to a local
            # path via getFilePath and then open() it before any HTTP call.
            # With an empty path they crash on open(). When the harness sets
            # CHECK_FILE_PATH to a real (temp) file, return it so those
            # commands run far enough to issue their request.
            _p = _os.environ.get("CHECK_FILE_PATH", "")
            return {"path": _p, "name": _os.path.basename(_p) if _p else ""}
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
    def args(): return _ARGS
    def results(*a, **k): return None
    def info(*a, **k): return None
    def debug(*a, **k): return None
    def error(*a, **k): return None
    def log(*a, **k): return None
    def getLastRun(): return {}
    def setLastRun(*a, **k): return None
    def getLicenseID(): return ""
    def demistoVersion(): return {"version": "8.0.0", "buildNumber": "0"}
    def getFilePath(*a, **k):
        _p = _os.environ.get("CHECK_FILE_PATH", "")
        return {"path": _p, "name": _os.path.basename(_p) if _p else ""}
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

# Inject the shared TrackingMapping class source (column-0) into the mock
# template so the child process has the access-spy mapping without needing
# to import this analyzer module. Single source of truth: the same
# _TRACKING_MAPPING_SRC backs the importable TrackingMapping above.
_DEMISTOMOCK_TEMPLATE = _DEMISTOMOCK_TEMPLATE.replace(
    "__TRACKING_MAPPING_INJECTION__", _TRACKING_MAPPING_SRC.strip()
)


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
    args: dict[str, Any] | None = None,
    access_out: str | None = None,
) -> dict[str, str]:
    """Build the env vars the bootstrap script reads to drive one command.

    ``args`` is the seeded command-argument dict the mock exposes via
    ``demisto.args()`` (defaults to ``{}`` for backward compatibility).
    ``access_out`` is the file path the child writes its params-access-spy
    report to (a JSON list of read keys); omitted/empty disables the spy
    for that run.
    """
    env = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": "",
        "CHECK_PARAMS_JSON": json.dumps(params),
        "CHECK_COMMAND": command,
        "CHECK_ARGS_JSON": json.dumps(args or {}),
        "CHECK_UNIFIED_PATH": unified_path,
        "CHECK_MOCK_DIR": mock_dir,
    }
    if access_out:
        env["CHECK_ACCESS_OUT"] = access_out
    return env


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
    extra_mounts: list[tuple[str, str, str]] | None = None,
) -> tuple[int, str, str, bool]:
    """Run the child inside a Docker container.

    The caller must already have written ``bootstrap.py``,
    ``unified_integration.py``, and ``mock/`` into ``tmp_dir``. We mount
    ``tmp_dir`` read-only at ``/check`` and execute
    ``python3 /check/bootstrap.py`` inside ``image``.

    ``extra_mounts`` is an optional list of ``(host_path, container_path,
    mode)`` triples forwarded as ``-v`` flags. The auth-parity harness
    uses this to expose its self-signed MITM cert dir at the same host
    path inside the container so env-var-honoring HTTP clients can pin
    their CA bundle at it.
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
    if extra_mounts:
        for host_path, container_path, mode in extra_mounts:
            cmd.extend(["-v", f"{host_path}:{container_path}:{mode}"])
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
    *,
    args: dict[str, Any] | None = None,
    access_out_host: Path | None = None,
    extra_env: dict[str, str] | None = None,
    extra_mounts: list[tuple[str, str, str]] | None = None,
) -> tuple[int, str, str, bool]:
    """Run the integration in a child process. Returns ``(rc, stdout, stderr, timed_out)``.

    ``access_out_host`` (when given) is a writable HOST file path the child
    writes its params-access-spy report to. In host mode the child writes
    there directly; in docker mode the file's parent dir is bind-mounted
    writable into the container and ``CHECK_ACCESS_OUT`` is set to the
    in-container path. The caller reads the host file after the run.

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

    # Access-spy output path. Host mode: child writes the host path
    # directly. Docker mode: bind-mount the file's parent dir writable and
    # point CHECK_ACCESS_OUT at the in-container path.
    access_out_for_child: str | None = None
    spy_mounts: list[tuple[str, str, str]] = []
    if access_out_host is not None:
        if use_docker:
            container_access_dir = "/check_spy"
            access_out_for_child = f"{container_access_dir}/{access_out_host.name}"
            spy_mounts.append(
                (str(access_out_host.parent), container_access_dir, "rw")
            )
        else:
            access_out_for_child = str(access_out_host)

    env = _build_child_env(
        params=params,
        command=command,
        proxy_url=proxy_url,
        unified_path=str(unified_path),
        mock_dir=str(mock_dir),
        args=args,
        access_out=access_out_for_child,
    )
    if extra_env:
        env.update(extra_env)

    if not use_docker:
        return _run_child_host(bootstrap_path, env, timeout)

    assert docker_cfg is not None  # narrowed by use_docker
    effective_image = image or docker_cfg.default_image
    merged_mounts = list(extra_mounts or []) + spy_mounts
    return _run_child_docker(
        tmp_dir=tmp_dir,
        env=env,
        timeout=timeout,
        image=effective_image,
        pulled_cache=docker_cfg.pulled_images,
        proxy_url=proxy_url,
        extra_mounts=merged_mounts or None,
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


# Known proxy-bypassing tags that the analyzer attaches to per-command
# diagnostics so the calling agent knows the dynamic phase could not
# observe HTTP traffic for a structural reason and the per-command
# param list MUST be cross-checked against source manually.
LIMITATION_CAPTURE_PROXY_BYPASSED = "capture_proxy_bypassed"


# --------------------------------------------------------------------------
# Fix B — confidence-tier attribution
# --------------------------------------------------------------------------
#
# Per-(command, param) confidence values. The diagnosis report's §4.B.1
# tier table is the source of truth; this constant is the single
# in-code home of those numbers so the calibration pass (§4.B.7) can
# adjust them in one place.
#
# Authoritative tiers (`dynamic_capture`, `handler_body`) are 1.0.
# Helper tiers decay with call-graph depth per Q1(b) step-decay:
# depth=1 -> 0.8, depth=2 -> 0.7, depth=3 -> 0.5, depth>=4 -> 0.3.
# Module-level constant attribution: ``module_const_referenced`` (0.5)
# when the command's reachable AST references the constant, else
# ``module_const_hedged`` (0.1) when the walk hit uncertainty.
# ``pre_dispatch_main`` (0.2) fans out to every command. The
# ``pre_dispatch_main_dynamic_disproven`` (0.1) tier is the Q3
# downgrade target reserved for Fix C wiring; today the downgrade
# hook is present but gated on a flag that defaults to False.
TIER_CONFIDENCE: dict[str, float] = {
    "dynamic_capture": 1.0,
    "handler_body": 1.0,
    # Params-access spy: the param was READ at runtime during this
    # command's execution, above the startup baseline. Strong evidence —
    # but below the on-wire dynamic_capture gold tier so the agent still
    # double-checks (verdict stays needs_review, not proven_used).
    "dynamic_access": 0.9,
    "helper_depth_1": 0.8,
    "helper_depth_2": 0.7,
    "helper_depth_3": 0.5,
    "helper_depth_4_plus": 0.3,
    "module_const_referenced": 0.5,
    "pre_dispatch_main": 0.2,
    "pre_dispatch_main_dynamic_disproven": 0.1,
    "module_const_hedged": 0.1,
}


def helper_confidence(depth: int) -> float:
    """Confidence for a ``helper`` source at the given call-graph depth.

    Implements the Q1(b) step-decay schedule from the diagnosis report:
    depth=1 -> 0.8, depth=2 -> 0.7, depth=3 -> 0.5, depth>=4 -> 0.3.
    A depth of 0 is treated as the depth-1 tier (a helper IS at depth-1
    relative to the handler that called it); callers should never pass
    a negative depth.
    """
    if depth <= 1:
        return TIER_CONFIDENCE["helper_depth_1"]
    if depth == 2:
        return TIER_CONFIDENCE["helper_depth_2"]
    if depth == 3:
        return TIER_CONFIDENCE["helper_depth_3"]
    return TIER_CONFIDENCE["helper_depth_4_plus"]


@dataclass(frozen=True)
class ParamSourceEvidence:
    """One piece of evidence that a command uses a YML param.

    ``source`` is one of the keys in :data:`TIER_CONFIDENCE` (minus the
    ``_depth_N`` suffix — for helper sources we use ``"helper"`` here
    and carry the depth separately in ``call_graph_depth``).

    ``evidence`` is a short human-readable "why" string used by both
    the JSON debug payload and the calibration pass.

    ``call_graph_depth`` is set only for ``helper`` and (the Fix C
    extension) ``pre_dispatch_main`` constructor-derived rows; for all
    other sources it is ``None``.
    """

    source: str
    confidence: float
    evidence: str
    call_graph_depth: int | None = None


@dataclass(frozen=True)
class ParamAttribution:
    """Per-(command, param) attribution row.

    ``by_source`` is keyed by source label (so the same param reached
    via ``handler_body`` AND ``module_const_referenced`` has two
    entries, not one). ``rollup_confidence`` is ``max()`` over the
    confidences of every entry in ``by_source`` per Q2(a). Both fields
    are always populated; ``rollup_confidence`` is recomputed by the
    builder rather than left for downstream consumers to derive.

    Change 1: ``verdict`` is the consumer-side triage label
    (``proven_used`` / ``proven_unused`` / ``needs_review``). Always
    set by the builder — the consumer's AI uses ``needs_review`` as
    its review queue. Defaults to ``needs_review`` for backward
    compatibility with code paths that build ParamAttribution
    instances directly without going through the verdict layer.
    """

    param: str
    by_source: dict[str, ParamSourceEvidence]
    rollup_confidence: float
    verdict: str = VERDICT_NEEDS_REVIEW


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

    ``limitation`` is set when the analyzer detects a known structural
    reason the dynamic signal will never fire for this integration —
    currently only ``"capture_proxy_bypassed"`` for ``boto3``-based
    integrations (botocore manages its own HTTP layer that does not
    honour the proxy env vars). Callers should treat the per-command
    param list as the static union and verify manually if narrowing
    was expected.

    Fix B: ``attributions`` carries the per-param confidence-tier
    breakdown computed by :func:`analyze_static`. Always populated
    when static analysis ran; consumers that only need the headline
    list can ignore it.
    """

    status: str
    captured_requests: int = 0
    failure_excerpt: str = ""
    failing_params: list[str] = field(default_factory=list)
    missing_module: str | None = None
    # Params-access spy: the raw set of param keys this command's child
    # run READ at runtime (via the TrackingMapping). Includes startup
    # globals; the parent diffs against the baseline before elevating.
    spy_accessed: set[str] = field(default_factory=set)
    scope_1_narrowed: bool = False
    scope_1_dropped: list[str] = field(default_factory=list)
    limitation: str | None = None
    attributions: list[ParamAttribution] = field(default_factory=list)
    # Fix C hook (gated to False today): when Fix C wires this up, set
    # True to downgrade ``pre_dispatch_main`` (0.2) to
    # ``pre_dispatch_main_dynamic_disproven`` (0.1) for this command.
    # The downgrade logic in :func:`_build_attributions` reads this
    # flag at attribution-build time. Today the flag is always False
    # for every command; Fix C populates it.
    dynamic_confirmed_no_execution: bool = False
    # Change 1: which reachability path produced these attributions
    # for this command. One of the ANALYSIS_STATUS_* constants above.
    # Required — every command must get a label. Defaults to
    # ``dispatch_unresolved`` so static-only test paths that build a
    # CommandDiagnostic without going through the analyzer pipeline
    # don't crash (the analyzer pipeline always assigns one
    # explicitly).
    analysis_status: str = ANALYSIS_STATUS_DISPATCH_UNRESOLVED

    def to_dict(self) -> dict[str, Any]:
        """Render the diagnostic as a plain dict for JSON serialization."""
        out: dict[str, Any] = {
            "status": self.status,
            "captured_requests": self.captured_requests,
            # Change 1: analysis_status is always present in the
            # serialized payload — the consumer's AI uses it together
            # with each attribution's verdict to triage.
            "analysis_status": self.analysis_status,
        }
        if self.failure_excerpt and self.status not in {"ok", "ok_no_capture"}:
            out["failure_excerpt"] = self.failure_excerpt[:500]
        if self.failing_params:
            out["failing_params"] = self.failing_params
        if self.missing_module is not None:
            out["missing_module"] = self.missing_module
        # Fix 3 (Option A): only surface the narrowing diagnostic fields
        # when narrowing actually dropped something. The flag with an
        # empty drop list is meaningless to the calling agent and was
        # previously misleading — readers of ``scope_1_narrowed: true,
        # scope_1_dropped: []`` couldn't tell whether narrowing fired
        # silently (captured set was a superset of Scope-1) or was
        # never attempted. By omitting both fields in that case, the
        # presence of ``scope_1_narrowed`` always means "narrowing
        # changed the per-command set". Emission still requires the
        # flag, so callers that key off its presence are unchanged.
        if self.scope_1_narrowed and self.scope_1_dropped:
            out["scope_1_narrowed"] = True
            out["scope_1_dropped"] = self.scope_1_dropped
        if self.limitation is not None:
            out["limitation"] = self.limitation
        # Fix B: serialize attributions when present. Each
        # ParamAttribution becomes ``{param, rollup_confidence,
        # by_source: {<source>: {confidence, evidence,
        # call_graph_depth?}, ...}}``. Always emit when populated —
        # the headline filter lives on the ``commands`` payload, not
        # here. ``--show-sources`` / opt-in surfacing is the consumer
        # layer's call.
        if self.attributions:
            out["attributions"] = [
                {
                    "param": attr.param,
                    "rollup_confidence": attr.rollup_confidence,
                    # Change 1: verdict surfaced for the consumer's
                    # AI triage filter.
                    "verdict": attr.verdict,
                    "by_source": {
                        src: {
                            k: v
                            for k, v in {
                                "confidence": ev.confidence,
                                "evidence": ev.evidence,
                                "call_graph_depth": ev.call_graph_depth,
                            }.items()
                            if v is not None
                        }
                        for src, ev in attr.by_source.items()
                    },
                }
                for attr in self.attributions
            ]
        return out


# Module names whose use signals "this integration's HTTP traffic
# bypasses the capture proxy" (per :ref:`Known limitation: boto3`
# in the module docstring). Detection is a substring check on
# ``import X`` / ``from X import ...`` statements in the integration
# source. Adding new entries here automatically annotates every
# command of any integration that imports them.
#
# ``AWSApiModule`` is the shared XSOAR module that wraps boto3 for the
# entire AWS family — every Cortex AWS integration uses it, and the
# integration source itself rarely imports boto3 directly (the actual
# import happens inside ``AWSApiModule`` after ``demisto-sdk
# prepare-content`` unifies the source). Including it lets us tag the
# AWS family as proxy-bypassed even when the integration .py only
# does ``from AWSApiModule import *``.
_PROXY_BYPASS_MODULE_PREFIXES: tuple[str, ...] = (
    "boto3",
    "botocore",
    "AWSApiModule",
)


def integration_uses_proxy_bypass(py_source: str) -> bool:
    """True if ``py_source`` imports a known proxy-bypassing module.

    Used by :func:`analyze_integration` to attach the
    ``capture_proxy_bypassed`` limitation tag to every command's
    diagnostic for the AWS family. Detection is purely static — we
    walk the AST and check ``Import`` / ``ImportFrom`` statements
    for any name that starts with a prefix in
    :data:`_PROXY_BYPASS_MODULE_PREFIXES`. Submodules
    (e.g. ``botocore.config``) are matched by prefix so we don't have
    to enumerate every import path.

    Returns ``False`` on empty / unparseable source — the analyzer
    must keep producing a result even when the source is broken; the
    limitation tag is purely informational.
    """
    if not py_source:
        return False
    try:
        tree = ast.parse(py_source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name or ""
                if any(
                    name == p or name.startswith(p + ".")
                    for p in _PROXY_BYPASS_MODULE_PREFIXES
                ):
                    return True
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(
                mod == p or mod.startswith(p + ".")
                for p in _PROXY_BYPASS_MODULE_PREFIXES
            ):
                return True
    return False


def _sanitize_cmd_filename(command: str) -> str:
    """Make a command name safe for use as a filename component."""
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in command) or "cmd"


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
    coerce_certs: bool = True,
    seed_overrides: dict[str, str] | None = None,
    command_args: list[dict[str, Any]] | None = None,
    seed_args: dict[str, str] | None = None,
    seed_command_args: bool = True,
    collect_access_spy: bool = True,
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
        yml_params,
        proxy_url,
        ignore,
        coerce_certs=coerce_certs,
        seed_overrides=seed_overrides,
    )
    # Build the seeded command-argument dict (ON by default). When
    # disabled (--no-seed-args), pass {} so demisto.args() stays empty
    # (legacy behavior). seed_args here is already scoped to this command.
    arg_values: dict[str, Any] = (
        build_arg_values(command_args or [], seed_args=seed_args)
        if seed_command_args
        else {}
    )
    yml_param_names = {p["name"] for p in yml_params}
    session_id = proxy.new_session()
    # Params-access spy output file (written next to the unified content so
    # the docker writable mount is a sibling of /check). Read back after
    # the run and stamped onto the diagnostic.
    access_out_host: Path | None = None
    if collect_access_spy:
        access_out_host = (
            unified_path.parent / f"access_{_sanitize_cmd_filename(command)}.json"
        )
        # Ensure a stale file from a prior run doesn't leak.
        try:
            access_out_host.unlink()
        except OSError:
            pass
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
        args=arg_values,
        access_out_host=access_out_host,
    )
    elapsed = _t.time() - _t0
    captured = proxy.get_requests(session_id)
    proxy.delete_session(session_id)
    # Read the access-spy report (best-effort; absent on crash-before-exit
    # is tolerated — the child's atexit hook runs even on sys.exit(7)).
    spy_accessed: set[str] = set()
    if access_out_host is not None:
        try:
            spy_accessed = parse_access_report(
                access_out_host.read_text(encoding="utf-8")
            )
        except OSError:
            spy_accessed = set()

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
                spy_accessed=spy_accessed,
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
                spy_accessed=spy_accessed,
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
    diag = CommandDiagnostic(
        status=status,
        captured_requests=len(captured),
        spy_accessed=spy_accessed,
    )
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
    coerce_certs: bool = True,
    auto_retry_integration_docker: bool = True,
    seed_overrides: dict[str, str] | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
    seed_command_args: bool = True,
    with_diagnostics: bool = False,
    call_graph_depth: int = 3,
    min_confidence: float = 0.0,
    headline_min_confidence: float = 0.5,
    emit_proven_unused: bool = True,
) -> dict[str, Any]:
    """Run the full analysis pipeline for one integration.

    Loud-fail policy: any error other than "static AST is being asked to
    look at a non-Python integration" propagates to the caller.

    The returned dict always contains ``integration`` and ``commands``.
    When dynamic analysis ran (``static_only`` is False) AND
    ``with_diagnostics`` is True, it additionally contains a
    ``diagnostics`` key with one entry per command. By default
    ``with_diagnostics`` is False so the returned payload is safe to
    pipe verbatim into the workflow_state ``set-params-to-commands``
    consumer (whose strict-schema validator rejects extra top-level
    keys). Under ``--static-only`` the ``diagnostics`` key is omitted
    entirely regardless of ``with_diagnostics`` (see module docstring).
    """
    yml_path, py_path = find_integration_files(integration_path)
    yml_data = load_yml(yml_path)
    # Change #1 (hidden-param exclusion): ``get_yml_params`` already
    # filters hidden params at the source so they never reach the seed
    # dict / static walker. We additionally absorb their names into the
    # effective ignore set as a fourth source (after inline / file /
    # auth-derived) so the per-command output assembly below — which
    # filters by ``ignore`` — silently drops them as a final safety
    # net. A single stderr line lists the excluded names so the calling
    # agent can verify what was removed.
    hidden_names = get_hidden_param_names(yml_data)
    if hidden_names:
        joined = ", ".join(hidden_names)
        print(
            f"[ignore] Hidden YML params excluded: [{joined}]",
            file=sys.stderr,
        )
        ignore = set(ignore) | set(hidden_names)
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
            py_source,
            cmd,
            language=language,
            integration_name=integration_name,
            call_graph_depth=call_graph_depth,
        )

    # Detect known structural limitations once per integration. Currently
    # only ``capture_proxy_bypassed`` for boto3-based integrations: the
    # AWS Python SDK does not honour the proxy env vars, so the dynamic
    # phase will never observe HTTP traffic for those commands. We tag
    # every per-command diagnostic so the calling agent knows the
    # static fallback is the only signal and per-command lists need
    # manual cross-check.
    proxy_bypass = integration_uses_proxy_bypass(py_source)
    if proxy_bypass:
        print(
            f"[static] {integration_name!r}: imports a proxy-bypassing "
            f"module (e.g. boto3); per-command diagnostics will carry "
            f"limitation={LIMITATION_CAPTURE_PROXY_BYPASSED!r}",
            file=sys.stderr,
        )

    dynamic_results: dict[str, set[str]] = {cmd: set() for cmd in commands}
    diagnostics: dict[str, CommandDiagnostic] = {}
    # Language gate (FIXES-TODO #11): the dynamic phase shells out to
    # ``demisto-sdk prepare-content`` and then ``ast.parse``s the
    # resulting unified file as Python. For JavaScript / PowerShell
    # integrations, the unified file is JS / PowerShell source and
    # ``ast.parse`` crashes the entire run with a confusing
    # SyntaxError-shaped DynamicPrepError. The static phase already
    # treats non-Python as a graceful skip; force the dynamic phase
    # into the same shape here. ``language is None`` (no
    # ``script.type`` in the YML) is treated as "unknown, probably
    # Python, attempt" — only known non-Python languages skip. Per the
    # cross-cutting Hints policy: prescription is unambiguous, so we
    # include a one-line hint pointing at ``--static-only``.
    _PYTHON_LANGS = {"python", "python2", "python3"}
    if not static_only and language is not None and language not in _PYTHON_LANGS:
        print(
            f"[dynamic] skipping non-Python integration "
            f"(language={language!r}); the analyzer cannot trace param "
            f"flow through {language}. Use --static-only for the "
            f"structured graceful skip.",
            file=sys.stderr,
        )
        static_only = True
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
        # Validate seed_overrides against the visible YML param set.
        # An override that doesn't match a known YML param is almost
        # certainly a typo on the operator's part. Three failure modes
        # are surfaced as separate WARNING lines so the operator can
        # see exactly what went wrong:
        #
        #   1. Unknown name (flat form, no '.').
        #      `--seed-param foo=bar` where `foo` isn't in the YML.
        #
        #   2. Dotted leaf with unknown parent.
        #      `--seed-param foo.password=bar` where `foo` isn't in
        #      the YML.
        #
        #   3. Dotted leaf on a non-credentials parent (or unsupported
        #      leaf name).
        #      `--seed-param api_key.identifier=...` where `api_key`
        #      is a YML type=4 (encrypted) param, not type=9.
        #      Or `--seed-param creds.weird_leaf=...`.
        #
        # All three are warnings (not fatal) because build_param_values
        # below simply skips them. The flat-form-on-credentials misuse
        # is caught later inside build_param_values and raises a hard
        # error instead — that one IS fatal because the analyzer cannot
        # produce a sensible runtime value for the param.
        if seed_overrides:
            yml_by_name = {p["name"]: p for p in yml_params}
            visible_names = set(yml_by_name)
            unknown_flat: list[str] = []
            unknown_dotted_parent: list[str] = []
            bad_leaf_on_known_parent: list[str] = []
            for key in seed_overrides:
                if "." in key:
                    parent, _, leaf = key.partition(".")
                    if parent not in visible_names:
                        unknown_dotted_parent.append(key)
                    else:
                        parent_yml = yml_by_name[parent]
                        if parent_yml.get("type") != YML_TYPE_CREDENTIALS:
                            bad_leaf_on_known_parent.append(
                                f"{key} (parent type={parent_yml.get('type')!r}, "
                                f"expected 9/credentials)"
                            )
                        elif leaf not in ("identifier", "password"):
                            bad_leaf_on_known_parent.append(
                                f"{key} (leaf {leaf!r} not in "
                                f"{{'identifier', 'password'}})"
                            )
                else:
                    if key not in visible_names:
                        unknown_flat.append(key)
            if unknown_flat:
                print(
                    f"[seed] WARNING: --seed-param targets unknown param "
                    f"name(s) {sorted(unknown_flat)} (not in this "
                    f"integration's visible YML config); the override(s) "
                    f"will have no effect.",
                    file=sys.stderr,
                )
            if unknown_dotted_parent:
                print(
                    f"[seed] WARNING: --seed-param dotted-leaf override(s) "
                    f"{sorted(unknown_dotted_parent)} reference parent(s) "
                    f"that are not in this integration's visible YML "
                    f"config; the override(s) will have no effect.",
                    file=sys.stderr,
                )
            if bad_leaf_on_known_parent:
                print(
                    f"[seed] WARNING: --seed-param dotted-leaf override(s) "
                    f"{sorted(bad_leaf_on_known_parent)} are invalid. "
                    f"Dotted-leaf form is only supported for YML type:9 "
                    f"credentials widgets, with leaf name 'identifier' "
                    f"or 'password'. The override(s) will have no effect.",
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
            coerce_certs=coerce_certs,
            auto_retry_integration_docker=auto_retry_integration_docker,
            yml_data=yml_data,
            seed_overrides=seed_overrides,
            seed_args=seed_args,
            seed_command_args=seed_command_args,
        )

    # Fix B (B.6): for every command, build the per-(command, param)
    # attribution payload and attach it to the diagnostic. Always do
    # this — the headline list filter at ``headline_min_confidence``
    # consumes it, and the full ``attributions`` payload is emitted
    # under ``--with-diagnostics`` for the calling agent. Static-only
    # mode synthesizes a CommandDiagnostic per command (with status
    # ``ok_no_capture``) so the attribution field has a home — the
    # static-mode diagnostic is discarded at output time (the
    # ``diagnostics`` block is suppressed when ``static_only``).
    # Change 1: build the set of YML-declared params (minus ignored)
    # once so we can pass it to
    # analyze_static_attributions_with_status for silent-zero row
    # synthesis (the proven_unused / needs_review verdicts).
    yml_param_name_set = set(all_param_names) - ignore
    # Params-access-spy baseline: keys read at startup are read by EVERY
    # command, so they must NOT be elevated per-command. Use test-module's
    # accessed-key set as the baseline (it exercises the module-import +
    # main() startup path without command-specific args). Falls back to the
    # intersection of all commands' accessed sets if test-module is absent.
    # Baseline = keys read at startup (import + main() before dispatch),
    # which appear on EVERY command. Combine two robust signals so a flaky
    # test-module read can't shrink the baseline (a too-small baseline
    # would cause false per-command elevations):
    #   (a) test-module's accessed set (pure startup path), AND
    #   (b) the intersection of all commands' accessed sets (keys every
    #       command reads = startup-common, e.g. module-level globals).
    # Their UNION is the conservative baseline.
    baseline_accessed: set[str] = set()
    tm_diag = diagnostics.get("test-module")
    if tm_diag is not None and tm_diag.spy_accessed:
        baseline_accessed |= set(tm_diag.spy_accessed)
    spy_sets = [
        set(d.spy_accessed) for d in diagnostics.values() if d.spy_accessed
    ]
    if spy_sets:
        baseline_accessed |= set.intersection(*spy_sets)
    for cmd in commands:
        diag = diagnostics.get(cmd)
        if diag is None:
            diag = CommandDiagnostic(status="ok_no_capture")
            diagnostics[cmd] = diag
        # Compute the access-spy elevation set for this command: keys read
        # above the startup baseline, restricted to YML params (minus
        # ignored). Pre-dispatch/module-import reads fall into the baseline
        # and are intentionally NOT elevated (they stay at their static tier).
        access_spy_params = attribute_access_spy(
            command_accessed=set(diag.spy_accessed),
            baseline_accessed=baseline_accessed,
            yml_param_names=yml_param_name_set,
            ignore=ignore,
        )
        (
            _scope_1,
            _scope_2,
            attributions,
            analysis_status,
        ) = analyze_static_attributions_with_status(
            py_source,
            cmd,
            captured=dynamic_results.get(cmd, set()),
            dynamic_confirmed_no_execution=diag.dynamic_confirmed_no_execution,
            language=language,
            integration_name=integration_name,
            call_graph_depth=call_graph_depth,
            yml_param_names=yml_param_name_set,
            emit_proven_unused=emit_proven_unused,
            access_spy_params=access_spy_params,
        )
        # Change 1: surface the per-command analysis_status on the
        # diagnostic so the consumer's AI can gate its triage on it.
        diag.analysis_status = analysis_status
        # Drop ignored / out-of-YML attributions for the diagnostic too —
        # the attribution rows must mirror the headline list's name
        # universe to avoid confusing the calling agent with rows for
        # params that can't appear in the headline.
        attributions = [
            attr for attr in attributions
            if attr.param in all_param_names and attr.param not in ignore
        ]
        # Apply --min-confidence to the per-source breakdown (drops
        # sub-threshold sources; whole row dropped when all sources
        # fall). The default of 0.0 is a no-op.
        attributions = _filter_attributions_by_min_confidence(
            attributions, min_confidence
        )
        diag.attributions = attributions

    out_commands: dict[str, list[str]] = {}
    for cmd in commands:
        merged_set = _merge_command_params(
            cmd,
            static_results[cmd],
            dynamic_results[cmd],
            diagnostics.get(cmd),
        )
        # Fix B (B.7): filter the headline list by
        # ``headline_min_confidence`` over the per-param
        # ``rollup_confidence``. Params that pass the threshold are
        # kept; params present in ``merged_set`` but absent from
        # ``attributions`` (or below threshold) are dropped. Params
        # IN ``attributions`` but not in the static/dynamic merged
        # set are also kept (since the attribution layer is the
        # source of truth for confidence-based reachability now);
        # this captures the dynamic_capture-only and
        # module_const_referenced-only cases that the legacy merged
        # set might miss.
        diag = diagnostics[cmd]
        attr_by_param = {attr.param: attr for attr in diag.attributions}
        in_headline: set[str] = set()
        for name in all_param_names:
            if name in ignore:
                continue
            attr = attr_by_param.get(name)
            if attr is not None and attr.rollup_confidence >= headline_min_confidence:
                in_headline.add(name)
                continue
            # Backstop: keep params from the legacy static merge that
            # were captured by dynamic_capture but somehow missed
            # the attribution rebuild (shouldn't happen — defensive).
            if name in merged_set and attr is None:
                # No attribution row was built for this name. This
                # only happens for non-Python integrations (static
                # analysis returns empty everything) or when py_source
                # is absent. Fall back to the legacy merge.
                in_headline.add(name)
        out_commands[cmd] = sorted(in_headline)

    # Apply structural-limitation tags to every command's diagnostic.
    # We do this here (post-merge) because:
    #   * The detection is integration-wide, not per-command;
    #   * The tag is informational only — it MUST NOT change which
    #     params land in ``commands`` (the calling agent decides what
    #     to do with the limitation);
    #   * Doing it here keeps the dynamic phase pure (it only reports
    #     on what it actually observed).
    if not static_only and proxy_bypass:
        for cmd, diag in diagnostics.items():
            if diag.limitation is None:
                diag.limitation = LIMITATION_CAPTURE_PROXY_BYPASSED

    result: dict[str, Any] = {
        "integration": integration_name,
        "commands": out_commands,
    }
    # Diagnostics is OPT-IN (Fix B): suppressed by default so the
    # stdout JSON can be piped verbatim into
    # workflow_state.py set-params-to-commands without triggering its
    # strict-schema validator. Static mode never emitted diagnostics
    # (it has nothing dynamic to report); dynamic mode now requires
    # --with-diagnostics for the diagnostic-rich payload.
    if not static_only and with_diagnostics:
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
    coerce_certs: bool = True,
    auto_retry_integration_docker: bool = True,
    yml_data: dict[str, Any] | None = None,
    seed_overrides: dict[str, str] | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
    seed_command_args: bool = True,
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

    Change #3 (Fix G): module_not_found fail-fast / auto-retry. After
    the FIRST command runs, we inspect its diagnostic. If it returned
    ``status == "module_not_found"`` AND ``--use-integration-docker``
    was NOT already in effect AND ``auto_retry_integration_docker`` is
    True (default), we abandon the in-progress phase, flip
    ``docker_cfg.use_integration_docker = True``, re-resolve the image,
    and restart the loop. If the integration's own image ALSO has the
    missing module (or auto-retry is disabled), every remaining command
    is fast-failed as ``module_not_found`` without invoking the child —
    this saves ~30s × (N-1) seconds per integration when the runtime
    image fundamentally lacks the package. KNOWN FALSE-POSITIVE: if
    only some commands need the missing package (e.g. only one search
    command needs ``splunklib``), every other command will be
    incorrectly marked ``module_not_found``. The trade-off is intentional
    — empirically the package is almost always needed at module-import
    time.
    """
    # Number of times we've already restarted the phase. Caps at 1 to
    # prevent infinite loops if the integration image is itself missing
    # something pinned to the analyzer image (very rare, but possible).
    retries_done = 0
    while True:
        # Reset accumulated state when retrying.
        for k in list(dynamic_results.keys()):
            dynamic_results[k] = set()
        diagnostics.clear()
        retry_triggered = _run_dynamic_phase_once(
            integration_path,
            commands,
            yml_params,
            ignore,
            timeout,
            dynamic_results,
            diagnostics,
            integration_name=integration_name,
            docker_cfg=docker_cfg,
            image=image,
            coerce_certs=coerce_certs,
            auto_retry_integration_docker=auto_retry_integration_docker,
            yml_data=yml_data,
            seed_overrides=seed_overrides,
            seed_args=seed_args,
            seed_command_args=seed_command_args,
        )
        if not retry_triggered or retries_done >= 1:
            return
        # Re-resolve the image with use_integration_docker=True. The
        # caller-side ``DockerConfig`` is already mutated by
        # ``_run_dynamic_phase_once``; just re-derive the image here.
        retries_done += 1
        if docker_cfg is not None and yml_data is not None:
            image = docker_cfg.resolve_image_for(yml_data)
            print(
                f"[dynamic] {integration_name or integration_path.name}: "
                f"retrying dynamic phase under integration image {image!r}",
                file=sys.stderr,
            )


def _run_dynamic_phase_once(
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
    coerce_certs: bool = True,
    auto_retry_integration_docker: bool = True,
    yml_data: dict[str, Any] | None = None,
    seed_overrides: dict[str, str] | None = None,
    seed_args: dict[str, dict[str, str]] | None = None,
    seed_command_args: bool = True,
) -> bool:
    """Run one pass of the dynamic phase.

    Returns ``True`` iff the caller should restart the phase under
    ``--use-integration-docker`` because the FIRST command failed with
    ``module_not_found`` and auto-retry is enabled. Otherwise returns
    ``False`` (success or terminal failure — caller is done).

    All exit paths populate *dynamic_results* and *diagnostics* so the
    caller can render a partial result even when retry is signalled
    (the caller wipes them before retrying — see :func:`_run_dynamic_phase`).
    """
    with tempfile.TemporaryDirectory(prefix="ccp_") as tmp:
        tmp_dir = Path(tmp)
        unified, mock_dir = prepare_unified_content(integration_path, tmp_dir)
        proxy = CaptureProxy(port=0)
        proxy.start()
        print(f"[dynamic] proxy listening on port {proxy.port}", file=sys.stderr)
        failures = 0
        # Module-not-found fast-fail bookkeeping. When we decide to
        # short-circuit the rest of the loop, we capture the missing
        # module name and excerpt from the FIRST command's diagnostic
        # so every fast-failed command's diagnostic carries the same
        # attribution. This is the documented false-positive: only the
        # first command's import was actually exercised.
        fast_fail_active = False
        fast_fail_module: str | None = None
        fast_fail_excerpt: str = ""
        try:
            for idx, cmd in enumerate(commands):
                if fast_fail_active:
                    # Fast-fail path: synthesize the diagnostic without
                    # invoking the child. ``failure_excerpt`` keeps the
                    # original ModuleNotFoundError line so the calling
                    # agent can see what was missing.
                    print(
                        f"[dyn] {cmd}: fast-failed as module_not_found "
                        f"(missing {fast_fail_module!r}); skipping child "
                        f"invocation to save time",
                        file=sys.stderr,
                    )
                    dynamic_results[cmd] = set()
                    diagnostics[cmd] = CommandDiagnostic(
                        status="module_not_found",
                        captured_requests=0,
                        failure_excerpt=fast_fail_excerpt[:500],
                        missing_module=fast_fail_module,
                    )
                    failures += 1
                    continue
                try:
                    cmd_args = (
                        get_command_args(yml_data, cmd) if yml_data is not None else []
                    )
                    cmd_seed_args = (seed_args or {}).get(cmd)
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
                        coerce_certs=coerce_certs,
                        seed_overrides=seed_overrides,
                        command_args=cmd_args,
                        seed_args=cmd_seed_args,
                        seed_command_args=seed_command_args,
                    )
                    dynamic_results[cmd] = captured_set
                    diagnostics[cmd] = diag
                    if diag.status == "param_caused_failure":
                        failures += 1
                    # Change #3: after the FIRST command, decide whether
                    # to auto-retry under integration docker (if not
                    # already there) or fast-fail the remaining commands.
                    if (
                        idx == 0
                        and diag.status == "module_not_found"
                    ):
                        already_using_integration_docker = (
                            docker_cfg is not None
                            and docker_cfg.use_integration_docker
                        )
                        if (
                            auto_retry_integration_docker
                            and not already_using_integration_docker
                            and docker_cfg is not None
                        ):
                            # Signal restart — caller will wipe
                            # results/diagnostics and call us again.
                            print(
                                f"[dynamic] First command {cmd!r} failed "
                                f"with module_not_found (missing: "
                                f"{diag.missing_module!r}); auto-retrying "
                                f"entire dynamic phase with "
                                f"--use-integration-docker.",
                                file=sys.stderr,
                            )
                            docker_cfg.use_integration_docker = True
                            return True
                        # Otherwise: integration docker already in use
                        # (or auto-retry disabled). Fast-fail every
                        # remaining command with the same attribution
                        # to save ~30s × (N-1) seconds.
                        if already_using_integration_docker:
                            scope_msg = (
                                "under integration's own runtime image; "
                                "the analyzer cannot run this integration"
                            )
                        else:
                            scope_msg = (
                                "and --auto-retry-integration-docker is "
                                "disabled; cannot escalate"
                            )
                        print(
                            f"[dynamic] First command {cmd!r} failed with "
                            f"module_not_found (missing: "
                            f"{diag.missing_module!r}) {scope_msg}. Exiting "
                            f"dynamic phase early; remaining commands will "
                            f"use the static union with status="
                            f"'module_not_found' (known false-positive: "
                            f"if only some commands need the missing "
                            f"package, others are incorrectly attributed).",
                            file=sys.stderr,
                        )
                        fast_fail_active = True
                        fast_fail_module = diag.missing_module
                        fast_fail_excerpt = diag.failure_excerpt
                except DynamicAnalysisError as exc:
                    failures += 1
                    dynamic_results[cmd] = set()
                    short = str(exc).splitlines()[0][:240]
                    print(f"[dyn] {cmd}: FAILED — {short}", file=sys.stderr)
                    # Fix 2: the per-command runner only attributed
                    # ``failing_params`` from the child stderr it had
                    # in scope. When it raises, we still have the full
                    # exception text (which embeds the child stderr —
                    # see ``run_integration``'s ``DynamicAnalysisError``
                    # message templates). Re-scan that full message
                    # for ``SENTINEL_PARAM_<name>`` substrings against
                    # the YML param set. If anything matches, promote
                    # the diagnostic from ``no_data`` to
                    # ``param_caused_failure`` so the calling agent
                    # gets concrete attribution instead of a generic
                    # "command failed" cell. Bounded by the YML param
                    # name set, so a stray sentinel fragment in an
                    # unrelated traceback line cannot fabricate a
                    # bogus param. ``failure_excerpt`` stays trimmed
                    # to 500 chars in :meth:`CommandDiagnostic.to_dict`.
                    full_text = str(exc)
                    yml_param_names = {p["name"] for p in yml_params}
                    failing = extract_failing_params(full_text, yml_param_names)
                    status = _classify_dynamic_error(exc)
                    if failing and status == "no_data":
                        print(
                            f"[dyn] {cmd}: full-stderr sentinel scan "
                            f"attributed failure to {failing}; "
                            f"promoting no_data → param_caused_failure",
                            file=sys.stderr,
                        )
                        dynamic_results[cmd] = set(failing)
                        diagnostics[cmd] = CommandDiagnostic(
                            status="param_caused_failure",
                            captured_requests=0,
                            failure_excerpt=full_text[:500],
                            failing_params=failing,
                        )
                    else:
                        diagnostics[cmd] = CommandDiagnostic(
                            status=status,
                            captured_requests=0,
                            failure_excerpt=full_text[:500],
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
    return False


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def resolve_integration_path(integration_id: str) -> Path:
    """Resolve an integration directory from its workflow-CSV id.

    Looks up ``integration_id`` in the workflow CSV (via
    :func:`workflow_state.get_integration_files`) and returns the
    integration's directory as an absolute :class:`~pathlib.Path`.

    Raises ``ValueError`` with an actionable message when the id is
    unknown, the row has no ``Integration File Path``, or the recorded
    path is stale on disk — mirroring the analyzer's loud-fail policy.
    The caller turns this into a non-zero CLI exit.
    """
    try:
        from workflow_state import get_integration_files

        files = get_integration_files(integration_id)
    except Exception as exc:  # noqa: BLE001 — surface as a CLI error
        raise ValueError(
            f"could not use workflow_state to resolve "
            f"--integration-id {integration_id!r}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    if "error" in files:
        raise ValueError(
            f"--integration-id {integration_id!r}: {files['error']} "
            f"Pass an explicit integration_path instead, or fix the "
            f"'Integration File Path' column in the workflow CSV."
        )
    yml_rel = files.get("yml")
    if not yml_rel:
        raise ValueError(
            f"--integration-id {integration_id!r}: workflow CSV row has "
            f"no resolvable YML path. Pass an explicit integration_path "
            f"instead."
        )
    # ``yml`` is repo-relative; its parent directory is the integration dir.
    return (Path(yml_rel).resolve()).parent


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze which YML params each command of an XSOAR integration uses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "integration_path",
        nargs="?",
        default=None,
        help=(
            "Path to the integration directory (e.g., "
            "Packs/HelloWorld/Integrations/HelloWorldV2). OPTIONAL when "
            "--integration-id is supplied: the path is then resolved from "
            "the workflow CSV's 'Integration File Path' column. If both are "
            "given, this explicit path wins (and --integration-id still "
            "supplies the auth-aware ignore set). Exactly one of "
            "integration_path / --integration-id is required."
        ),
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
        "--integration-id",
        default=None,
        help=(
            "OPTIONAL. When supplied, the analyzer also pulls every YML "
            "param id declared in the integration's 'Auth Details' row "
            "(via connectus/workflow_state.py auth-params <id>) and "
            "unions them into the ignore set. This guarantees that "
            "params already declared as auth-secret / connection-adjacent "
            "cannot leak into 'Params to Commands'. Standalone runs "
            "outside the migration workflow can omit this flag — the "
            "--ignore-params-file behaviour is unchanged."
        ),
    )
    parser.add_argument(
        "--single-capability-test-module-only",
        action="store_true",
        help=(
            "OPTIMIZATION (requires --integration-id). When the integration "
            "resolves to exactly ONE collected capability (read back from the "
            "'Collect Capabilities' cell), narrow analysis to 'test-module' "
            "only. Rationale: with a single capability, every command trivially "
            "routes to that one capability in 'Params to Capabilities', so the "
            "only per-command param analysis still needed for the connection is "
            "the connectivity test. When the capability count is 0 (not yet "
            "collected) or >1, this flag is a no-op and a full analysis runs. "
            "Has no effect if --commands is also passed (explicit filter wins). "
            "Mirrors the auto-runner heuristic in run_pre_manifest_steps.py."
        ),
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
    # Change #2: opt-out of the cert/key/thumbprint sentinel coercion. By
    # default we substitute syntactically-valid stub values for params
    # whose name contains 'thumbprint' / 'private_key' / 'certificate'
    # so Microsoft cert-auth integrations don't crash at module import
    # under the generic SENTINEL_PARAM_<name> string. Pass
    # --no-sentinel-coercion to send the generic sentinel everywhere
    # (useful for analyzer self-debugging).
    parser.add_argument(
        "--no-sentinel-coercion",
        action="store_true",
        help=(
            "Disable the cert/key/thumbprint sentinel coercion (Fix F). "
            "By default, params whose name contains 'thumbprint', "
            "'private_key', or 'certificate' are seeded with a "
            "syntactically-valid stub instead of the generic "
            "'SENTINEL_PARAM_<name>' so format validators "
            "(binascii.a2b_hex, PEM regexes) don't crash at module load. "
            "Use this flag when you want strict-sentinel mode for "
            "debugging the analyzer itself."
        ),
    )
    # Change #3: control the auto-retry-on-module_not_found behaviour.
    # Default is ON: when the FIRST command fails with module_not_found
    # under the pinned image and --use-integration-docker was not
    # passed, the analyzer auto-retries the entire dynamic phase under
    # the integration's own image. Pass --no-auto-retry-integration-docker
    # to disable. The companion --auto-retry-integration-docker is
    # accepted for symmetry but is the default; it has no effect
    # standalone.
    parser.add_argument(
        "--auto-retry-integration-docker",
        action="store_true",
        default=True,
        help=(
            "DEFAULT ON. When set (the default), the FIRST command "
            "failing with 'module_not_found' under the pinned analyzer "
            "image triggers an automatic retry of the entire dynamic "
            "phase with --use-integration-docker. Use "
            "--no-auto-retry-integration-docker to disable; in that "
            "case all remaining commands are fast-failed as "
            "module_not_found without invoking the child (saves "
            "~30s × (N-1) seconds per integration)."
        ),
    )
    parser.add_argument(
        "--no-auto-retry-integration-docker",
        dest="auto_retry_integration_docker",
        action="store_false",
        help=(
            "Disable the auto-retry-on-module_not_found behaviour "
            "(Change #3 / Fix G). When disabled, a module_not_found on "
            "the first command immediately fast-fails the rest of the "
            "phase with the same status, without restarting under "
            "--use-integration-docker."
        ),
    )
    # Fix B (default-flip): emit the diagnostics top-level key only on
    # explicit opt-in. Default-OFF keeps stdout pipe-safe for
    # workflow_state.py set-params-to-commands (whose strict-schema
    # validator rejects extras). Use this flag for interactive /
    # debugging analysis only.
    parser.add_argument(
        "--with-diagnostics",
        action="store_true",
        default=False,
        help=(
            "INTERACTIVE / DEBUG USE ONLY. Emit the per-command "
            "'diagnostics' top-level key in the stdout JSON. The default "
            "is OFF so the JSON can be piped verbatim into "
            "'workflow_state.py set-params-to-commands' (whose strict "
            "schema validator rejects extra top-level keys, including "
            "'diagnostics'). MUST NOT be set by anything that pipes "
            "into set-params-to-commands or persists the payload to "
            "the migration CSV. Has no effect under --static-only "
            "(static mode never emits diagnostics)."
        ),
    )
    # Change #2 escape hatch: explicit per-param seed override. Repeatable.
    # The AI uses this to recover from format-validator crashes that the
    # automatic cert/key/thumbprint coercion did not anticipate (e.g. a
    # custom validation regex on a free-form text param). The override
    # wins over the YML default, the auto-coercion, and the generic
    # sentinel. Documented in connectus/connectus-migration-SKILL.md.
    parser.add_argument(
        "--seed-param",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help=(
            "Explicitly seed YML param NAME with VALUE for the dynamic "
            "phase, overriding the YML defaultvalue, the cert/key/"
            "thumbprint auto-coercion (Change #2), and the generic "
            "SENTINEL_PARAM_<name> string. Repeatable: pass once per "
            "param. Use this when the analyzer's automatic seeding "
            "still trips a format validator at module load. For YML "
            "type:9 (credentials) widgets, use the dotted-leaf form "
            "NAME.identifier=<v> / NAME.password=<v> (either leaf may "
            "be omitted; omitted leaves keep their default sentinel). "
            "Flat NAME=VALUE on a credentials widget is rejected with "
            "a hard error because the integration expects a dict-shaped "
            "value at runtime. The skill "
            "(connectus/connectus-migration-SKILL.md) documents the "
            "recovery loop."
        ),
    )
    parser.add_argument(
        "--seed-arg",
        action="append",
        default=None,
        metavar="CMD:NAME=VALUE",
        help=(
            "Explicitly seed command-ARGUMENT NAME with VALUE for command "
            "CMD during the dynamic phase, overriding the YML "
            "defaultValue / first-predefined / SENTINEL_ARG_<name> "
            "default. Repeatable. The CMD: prefix scopes the override to "
            "one command, so the same arg name on different commands can "
            "differ, e.g. --seed-arg ip:ip=1.1.1.1 "
            "--seed-arg abuseipdb-report-ip:ip=8.8.8.8. Use this when a "
            "required command argument needs a specific value to traverse "
            "a code path (e.g. a real IP/CIDR) that the auto-seeded "
            "sentinel doesn't satisfy."
        ),
    )
    parser.add_argument(
        "--no-seed-args",
        action="store_true",
        help=(
            "Disable automatic command-argument seeding (ON by default). "
            "When set, demisto.args() returns {} during the dynamic phase "
            "(legacy behavior). Handlers whose YML arguments are required "
            "positional parameters will then crash before any HTTP call "
            "(status no_data). Use only for strict/debug runs."
        ),
    )
    # Fix A: --call-graph-depth knob (default 3, clamped [1, 5]).
    # Bumped from the implicit hard-coded depth=2 so transitive helper
    # reads at depth-3 (SplunkPy v2 ``update_remote_system`` shape) are
    # recovered. Validation lives in :func:`main` so argparse can keep
    # emitting friendly error text.
    parser.add_argument(
        "--call-graph-depth",
        type=int,
        default=3,
        metavar="N",
        help=(
            "Max recursion depth when tracing params.get() calls "
            "through helper functions (default: 3, max: 5)."
        ),
    )
    # Fix B: --min-confidence filters sub-threshold sources out of the
    # per-param structured `attributions[*].by_source` payload. A row
    # whose only source(s) fall below this threshold is dropped from
    # `attributions` entirely. Default 0.0 = no-op (every tier
    # emitted). Independent of --headline-min-confidence (which
    # filters the flat list ONLY).
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        metavar="FLOAT",
        help=(
            "Filter sub-threshold tiers from the per-param "
            "attributions[*].by_source structured output (range "
            "[0.0, 1.0]; default 0.0 = no filtering). Independent of "
            "--headline-min-confidence (which filters the flat "
            "headline list instead)."
        ),
    )
    # Fix B: --headline-min-confidence is the consumer-facing filter
    # on the flat `commands[cmd]` list. Default 0.5 keeps
    # `module_const_referenced` (0.5) and above; suppresses
    # `pre_dispatch_main` (0.2) and `module_const_hedged` (0.1) by
    # default so the migration pipeline doesn't drown in 0.1 noise.
    parser.add_argument(
        "--headline-min-confidence",
        type=float,
        default=0.5,
        metavar="FLOAT",
        help=(
            "Filter the flat per-command headline list "
            "(commands[cmd]) by rollup_confidence (range [0.0, 1.0]; "
            "default 0.5 keeps handler_body/helper_depth_{1,2}/"
            "module_const_referenced and above)."
        ),
    )
    # Change 1: --emit-proven-unused controls whether attribution
    # rows with verdict=='proven_unused' are included in the
    # structured payload. Default True per the task spec — the
    # consumer's AI consumes the full rowset so it can mechanically
    # skip the proven_unused entries and review the rest. The flat
    # headline list is unaffected (proven_unused rows have
    # rollup_confidence=0.0 and are below any headline threshold).
    parser.add_argument(
        "--emit-proven-unused",
        dest="emit_proven_unused",
        action="store_true",
        default=True,
        help=(
            "Include attribution rows with verdict=='proven_unused' "
            "in the structured per-command attributions payload "
            "(default True; pass --no-emit-proven-unused to exclude)."
        ),
    )
    parser.add_argument(
        "--no-emit-proven-unused",
        dest="emit_proven_unused",
        action="store_false",
        help=(
            "Suppress attribution rows with verdict=='proven_unused' "
            "from the structured payload."
        ),
    )
    return parser.parse_args(argv)


def parse_seed_overrides(raw: list[str] | None) -> dict[str, str]:
    """Parse ``--seed-param NAME=VALUE`` entries into a ``{name: value}`` dict.

    Each ``raw`` entry must contain at least one ``=`` separator. The
    NAME must be non-empty; VALUE may be the empty string (operator
    explicitly seeding an empty value). Duplicates raise ``ValueError``
    so a typo doesn't silently shadow the first definition.

    Returns an empty dict when ``raw`` is falsy.
    """
    if not raw:
        return {}
    out: dict[str, str] = {}
    for entry in raw:
        if "=" not in entry:
            raise ValueError(
                f"--seed-param entry missing '=' separator: {entry!r}; "
                f"expected NAME=VALUE"
            )
        name, _, value = entry.partition("=")
        name = name.strip()
        if not name:
            raise ValueError(
                f"--seed-param entry has empty NAME: {entry!r}; "
                f"expected NAME=VALUE"
            )
        if name in out:
            raise ValueError(
                f"--seed-param NAME={name!r} supplied more than once"
            )
        out[name] = value
    return out


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Exit codes:
    * ``0`` — success.
    * ``2`` — bad CLI args / missing path / missing ignore-file.
    * ``3`` — any other unhandled failure during analysis (full traceback
      goes to stderr).

    JSON contract on stdout:
    * Default (Fix B): ``{"integration": ..., "commands": ...}`` —
      exactly two top-level keys; safe to pipe into
      ``workflow_state.py set-params-to-commands``.
    * With ``--with-diagnostics``: additionally a top-level
      ``"diagnostics"`` key. INTERACTIVE / DEBUG ONLY; must not be
      piped into the workflow_state setter.
    """
    import traceback

    # Auto-apply the DEMISTO_SDK_LOG_FILE_PATH workaround at CLI entry
    # (FIXES-TODO #2). Same call also fires inside ``prepare_unified_content``
    # — this earlier call ensures the env is set for any code path,
    # including the static-only one.
    _ensure_demisto_sdk_log_path()
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    # Resolve the integration directory. Exactly one of
    # ``integration_path`` (explicit) / ``--integration-id`` (CSV lookup)
    # is required. When both are supplied the explicit path wins and the
    # id still drives the auth-aware ignore set (see compose_ignore_set).
    if args.integration_path is not None:
        integration_path = Path(args.integration_path).resolve()
    elif args.integration_id is not None:
        try:
            integration_path = resolve_integration_path(args.integration_id)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(
            f"[resolve] integration_path resolved from "
            f"--integration-id {args.integration_id!r}: {integration_path}",
            file=sys.stderr,
        )
    else:
        print(
            "ERROR: provide an integration_path positional argument OR "
            "--integration-id (one is required).",
            file=sys.stderr,
        )
        return 2
    if not integration_path.is_dir():
        print(
            f"ERROR: integration path is not a directory: {integration_path}",
            file=sys.stderr,
        )
        return 2
    try:
        ignore = compose_ignore_set(
            args.ignore_params,
            args.ignore_params_file,
            args.integration_id,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    # Single-capability optimization: when the integration resolves to exactly
    # one collected capability, every command trivially routes to it in
    # 'Params to Capabilities', so only 'test-module' needs per-command
    # analysis for the connection. Narrow the commands_filter accordingly.
    # An explicit --commands always wins; capability count of 0 (not yet
    # collected) or >1 is a no-op (full analysis). Mirrors the harness
    # heuristic in run_pre_manifest_steps.step_2_params_to_commands.
    commands_filter = args.commands
    if args.single_capability_test_module_only:
        if args.integration_id is None:
            print(
                "ERROR: --single-capability-test-module-only requires "
                "--integration-id (the capability count is read from the "
                "integration's 'Collect Capabilities' cell).",
                file=sys.stderr,
            )
            return 2
        if commands_filter is not None:
            print(
                "[optimize] --single-capability-test-module-only ignored: "
                "explicit --commands filter takes precedence.",
                file=sys.stderr,
            )
        else:
            try:
                from workflow_state import collected_capabilities
                caps = collected_capabilities(args.integration_id)
            except Exception as exc:  # noqa: BLE001 — degrade to full analysis
                print(
                    f"[optimize] could not read collected capabilities "
                    f"({type(exc).__name__}: {exc}); running full analysis.",
                    file=sys.stderr,
                )
                caps = []
            if len(caps) == 1:
                print(
                    f"[optimize] single capability ({caps[0]!r}) — "
                    "analyzing test-module only.",
                    file=sys.stderr,
                )
                commands_filter = ["test-module"]
            else:
                print(
                    f"[optimize] capability count is {len(caps)} "
                    "(not exactly 1) — running full analysis.",
                    file=sys.stderr,
                )
    try:
        seed_overrides = parse_seed_overrides(args.seed_param)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        seed_args = parse_seed_args(args.seed_arg)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    # Fix A: validate --call-graph-depth (range [1, 5]). Reject loud
    # so a typo of 0 or 10 surfaces immediately instead of silently
    # producing trash output.
    if not 1 <= args.call_graph_depth <= 5:
        print(
            f"ERROR: --call-graph-depth must be in [1, 5]; got "
            f"{args.call_graph_depth}",
            file=sys.stderr,
        )
        return 2
    # Fix B: validate confidence-tier filter thresholds.
    if not 0.0 <= args.min_confidence <= 1.0:
        print(
            f"ERROR: --min-confidence must be in [0.0, 1.0]; got "
            f"{args.min_confidence}",
            file=sys.stderr,
        )
        return 2
    if not 0.0 <= args.headline_min_confidence <= 1.0:
        print(
            f"ERROR: --headline-min-confidence must be in [0.0, 1.0]; "
            f"got {args.headline_min_confidence}",
            file=sys.stderr,
        )
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
            commands_filter=commands_filter,
            static_only=args.static_only,
            ignore=ignore,
            timeout=args.timeout,
            docker_cfg=docker_cfg,
            coerce_certs=not args.no_sentinel_coercion,
            auto_retry_integration_docker=args.auto_retry_integration_docker,
            seed_overrides=seed_overrides,
            seed_args=seed_args,
            seed_command_args=not args.no_seed_args,
            with_diagnostics=args.with_diagnostics,
            call_graph_depth=args.call_graph_depth,
            min_confidence=args.min_confidence,
            headline_min_confidence=args.headline_min_confidence,
            emit_proven_unused=args.emit_proven_unused,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        # ValueError is raised by build_param_values for
        # operator-input misuse (specifically: flat NAME=VALUE on a
        # type=9 credentials widget). Treat as a CLI-arg error (rc=2),
        # no traceback — the exception message is the actionable
        # guidance and tracebacks just obscure it.
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
