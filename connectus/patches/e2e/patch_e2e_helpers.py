"""Black-box harness for the ``add_vault_support`` patch end-to-end suite.

This module owns the *infrastructure* for on-disk, black-box E2E tests of the
``add_vault_support.py`` patch (which is itself driven by the thin pytest module
``add_vault_support_e2e_test.py``). It deliberately mirrors the proven patterns
in ``connectus_migration/e2e/e2e_helpers.py``:

* the script under test is run as a real SUBPROCESS via ``sys.executable`` —
  a true black box; nothing is monkeypatched in-process;
* every case is SANDBOXED — the case's ``input/`` tree is copied into a tmp dir
  and the patch is pointed at the tmp ``connectors`` root via ``--connectors-dir``
  so the real repo is never mutated;
* ``connection.yaml`` files are compared SEMANTICALLY — parsed to plain Python,
  order-canonicalized, and with the leading ``# yaml-language-server`` schema
  directive (and any other leading comment/blank lines) stripped — rather than
  byte-compared, so formatting noise never causes a false failure.

Fixture layout
--------------
Each case is a directory under ``patches/e2e/fixtures/<case>/`` with::

    case.json
        Metadata + CLI inputs. Recognised keys::

            {
              "description":     "human readable, optional",
              "connector":       "remoteaccess",      # OPTIONAL — restrict the
                                                       # patch to one connector via
                                                       # --path (default: whole
                                                       # sandbox connectors dir)
              "extra_args":      ["--flatten-unresolved"],  # OPTIONAL passthrough
              "csv":             "connectus-migration-pipeline.csv",  # OPTIONAL —
                                                       # relative name of the
                                                       # discovery CSV in input/;
                                                       # wired in via --pipeline-csv
              "expect_modified": true                  # OPTIONAL — whether the LIVE
                                                       # run is expected to change
                                                       # the tree (drives the
                                                       # dry-run report assertion).
                                                       # Defaults to true.
            }

    input/
        ``input/connectors/<slug>/connection.yaml`` — the BEFORE manifest tree
        (copied into the sandbox; this is what the patch rewrites in place).
        ``input/connectors/<slug>/components/handlers/<h>/handler.yaml`` — the
        handler linkage the patch uses to resolve a profile's owning source
        integration (mirrors ``flatten_non_type9_nesting``).
        ``input/connectus-migration-pipeline.csv`` — OPTIONAL discovery CSV
        mapping connector -> source integration YML path.

    expected/
        ``expected/connectors/<slug>/connection.yaml`` — the AFTER manifest the
        patch must produce (semantic-equal to the live-patched sandbox tree).

CLI flag contract ASSUMED for add_vault_support.py
--------------------------------------------------
This harness pins the flag contract the future patch must honour (kept
consistent with ``flatten_non_type9_nesting.py``):

    python3 patches/add_vault_support.py \
        --connectors-dir <tmp>/connectors \
        [--path <connector>]          # restrict to one connector (case "connector")
        [--pipeline-csv <input>/connectus-migration-pipeline.csv]
        [--dry-run]                   # report only, write nothing
        [<extra_args...>]             # any case-specific passthrough flags

See ``patches/e2e/README.md`` for the full contract and TDD-red status.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# --------------------------------------------------------------------------- #
# Paths / constants
# --------------------------------------------------------------------------- #
# ``patches/e2e/`` lives under ``patches/``, which lives under ``connectus/``.
E2E_DIR = Path(__file__).resolve().parent
PATCHES_DIR = E2E_DIR.parent
# ``content/connectus`` — the base a case's relative ``script`` resolves against
# (and the subprocess CWD). Kept as a named constant so the generic ``script``
# key and the ``run_patch`` cwd stay in lock-step.
SCRIPT_BASE = PATCHES_DIR.parent
# The DEFAULT patch under test when a case does not declare its own ``script``
# (this one does NOT exist yet — TDD red). The test module guards the suite on
# this path's existence.
PATCH_SCRIPT = PATCHES_DIR / "add_vault_support.py"
FIXTURES_DIR = E2E_DIR / "fixtures"

# Subprocess timeout (seconds). The patch imports the connectus toolchain tree.
RUN_TIMEOUT = 300

# Filenames inside a case directory.
CASE_FILE = "case.json"
INPUT_DIR = "input"
EXPECTED_DIR = "expected"
CONNECTORS_DIRNAME = "connectors"
PIPELINE_CSV_DEFAULT = "connectus-migration-pipeline.csv"


# --------------------------------------------------------------------------- #
# Case model
# --------------------------------------------------------------------------- #
@dataclass
class PatchE2ECase:
    """A single discovered black-box patch test case."""

    name: str  # case-dir name — used as the pytest id
    path: Path  # the case directory
    description: str
    connector: str | None  # restrict the patch to this connector (--path) or None
    csv: str | None  # relative name of the discovery CSV in input/ (or None)
    extra_args: list[str]  # passthrough CLI flags
    expect_modified: bool  # whether the LIVE run is expected to change the tree
    # GENERIC harness support (both OPTIONAL; absent => legacy behavior):
    #   script: path to the python script to run for THIS case, overriding the
    #           module-level PATCH_SCRIPT default. Relative paths resolve against
    #           SCRIPT_BASE (content/connectus); absolute paths are used as-is.
    #   args:   an argv TEMPLATE that FULLY defines the script's arguments when
    #           present (placeholder tokens are substituted by build_cmd). When
    #           absent, build_cmd falls back to the legacy fixed-flag contract
    #           (--connectors-dir/--path/--pipeline-csv/--dry-run + extra_args).
    script: str | None = None
    args: list[str] | None = None

    @property
    def input_dir(self) -> Path:
        return self.path / INPUT_DIR

    @property
    def expected_dir(self) -> Path:
        return self.path / EXPECTED_DIR

    @property
    def input_connectors(self) -> Path:
        return self.input_dir / CONNECTORS_DIRNAME

    @property
    def expected_connectors(self) -> Path:
        return self.expected_dir / CONNECTORS_DIRNAME

    @property
    def input_csv(self) -> Path | None:
        """Absolute path to the case's discovery CSV in ``input/`` (or None)."""
        if not self.csv:
            return None
        return self.input_dir / self.csv

    @property
    def resolved_script(self) -> Path:
        """The script to run for this case.

        A per-case ``script`` (from ``case.json``) wins and is resolved against
        ``SCRIPT_BASE`` (``content/connectus``) when relative, or used verbatim
        when absolute. When no ``script`` is declared, the module-level
        ``PATCH_SCRIPT`` default is used (legacy behavior).
        """
        if not self.script:
            return PATCH_SCRIPT
        candidate = Path(self.script)
        if candidate.is_absolute():
            return candidate
        return (SCRIPT_BASE / candidate).resolve()


def _load_case(case_json: Path) -> PatchE2ECase:
    data = json.loads(case_json.read_text())
    case_dir = case_json.parent
    raw_args = data.get("args")
    return PatchE2ECase(
        name=case_dir.name,
        path=case_dir,
        description=data.get("description", ""),
        connector=data.get("connector"),
        csv=data.get("csv"),
        extra_args=list(data.get("extra_args", [])),
        expect_modified=bool(data.get("expect_modified", True)),
        script=data.get("script"),
        args=list(raw_args) if raw_args is not None else None,
    )


def discover_cases() -> list[PatchE2ECase]:
    """Discover this suite's cases (a dir containing ``case.json``).

    Only DIRECT-CHILD case dirs of ``FIXTURES_DIR`` are returned — i.e.
    ``fixtures/<case>/case.json``. Cases nested one level deeper
    (``fixtures/<other_patch>/<case>/case.json``) belong to a SIBLING patch
    suite that scopes itself to its own dedicated subdirectory (e.g.
    ``propagate_advanced_flag/``) and are deliberately excluded here so this
    suite never runs its script against another patch's fixtures.

    Returns cases sorted by name for deterministic pytest ordering.
    """
    if not FIXTURES_DIR.is_dir():
        return []
    cases = [_load_case(p) for p in FIXTURES_DIR.glob(f"*/{CASE_FILE}")]
    return sorted(cases, key=lambda c: c.name)


# --------------------------------------------------------------------------- #
# Sandbox + subprocess run (true black box)
# --------------------------------------------------------------------------- #
@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    connectors_root: Path  # the tmp connectors root the patch ran against


def sandbox_inputs(case: PatchE2ECase, tmp_path: Path) -> Path:
    """Copy the case's ``input/connectors`` tree into ``tmp_path/connectors``.

    Returns the tmp connectors root. Nothing under the real repo is touched —
    the patch is later pointed at this copy via ``--connectors-dir``.
    """
    connectors_root = tmp_path / CONNECTORS_DIRNAME
    if connectors_root.exists():
        shutil.rmtree(connectors_root)
    if case.input_connectors.is_dir():
        shutil.copytree(case.input_connectors, connectors_root)
    else:
        connectors_root.mkdir(parents=True, exist_ok=True)
    return connectors_root


# Placeholder tokens recognised inside a case's ``args`` template. ``{dry_run}``
# is handled specially (expands to ``--dry-run`` on a dry run, and is DROPPED
# entirely otherwise). Every other token is a simple string substitution; a
# token whose resolved value is ``None`` causes that argv entry to be dropped.
_DRY_RUN_TOKEN = "{dry_run}"


def _token_values(
    case: PatchE2ECase,
    connectors_root: Path,
) -> dict[str, str | None]:
    """Resolve the substitution values for the ``args`` template tokens."""
    csv = case.input_csv
    return {
        "{connectors_dir}": str(connectors_root),
        "{path}": case.connector,
        "{csv}": str(csv.resolve()) if csv is not None else None,
        "{input_dir}": str(case.input_dir.resolve()),
        "{case_dir}": str(case.path.resolve()),
    }


def _render_args_template(
    case: PatchE2ECase,
    connectors_root: Path,
    dry_run: bool,
) -> list[str]:
    """Expand a case's ``args`` template into a concrete argv tail.

    ``{dry_run}`` expands to ``--dry-run`` on a dry run and is dropped otherwise.
    Any other recognised token is substituted; a token that resolves to ``None``
    drops that entry. Unknown ``{...}`` tokens are left verbatim so a script can
    receive literal braces if it needs to.
    """
    values = _token_values(case, connectors_root)
    rendered: list[str] = []
    for tok in case.args or []:
        if tok == _DRY_RUN_TOKEN:
            if dry_run:
                rendered.append("--dry-run")
            continue
        if tok in values:
            value = values[tok]
            if value is not None:
                rendered.append(value)
            continue
        rendered.append(tok)
    return rendered


def build_cmd(
    case: PatchE2ECase,
    connectors_root: Path,
    dry_run: bool = False,
) -> list[str]:
    """Assemble the subprocess argv for the script under test.

    Two modes:

    * GENERIC — when the case declares an ``args`` template, that template FULLY
      defines the script arguments (placeholder tokens substituted via
      :func:`_render_args_template`). This lets a case drive ANY script with ANY
      flag contract against the sandbox connector tree.
    * LEGACY — when no ``args`` template is given, the historical fixed-flag
      contract is emitted (``--connectors-dir/--path/--pipeline-csv/--dry-run``
      followed by ``extra_args``), keeping existing fixtures working unchanged.

    In both modes the executable is ``sys.executable`` and the script is
    :pyattr:`PatchE2ECase.resolved_script` (the per-case ``script`` override, or
    the module-level ``PATCH_SCRIPT`` default).
    """
    cmd = [sys.executable, str(case.resolved_script)]

    if case.args is not None:
        cmd += _render_args_template(case, connectors_root, dry_run)
        cmd += list(case.extra_args)
        return cmd

    # Legacy fixed-flag contract (backward compatible).
    cmd += ["--connectors-dir", str(connectors_root)]
    if case.connector:
        cmd += ["--path", case.connector]
    if case.input_csv is not None:
        cmd += ["--pipeline-csv", str(case.input_csv.resolve())]
    if dry_run:
        cmd += ["--dry-run"]
    cmd += list(case.extra_args)
    return cmd


def run_patch(
    case: PatchE2ECase,
    connectors_root: Path,
    dry_run: bool = False,
) -> RunResult:
    """Run ``add_vault_support.py`` as a subprocess against the sandbox tree."""
    cmd = build_cmd(case, connectors_root, dry_run=dry_run)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT,
        cwd=str(PATCHES_DIR.parent),  # content/connectus
    )
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        connectors_root=connectors_root,
    )


# --------------------------------------------------------------------------- #
# Semantic YAML comparison (mirror of e2e_helpers)
# --------------------------------------------------------------------------- #
def _strip_schema_directive(text: str) -> str:
    """Drop leading comment / blank lines (e.g. the ``# yaml-language-server``
    schema directive) so we compare YAML *content*, not formatting noise."""
    lines = text.splitlines(keepends=True)
    idx = 0
    while idx < len(lines):
        stripped = lines[idx].strip()
        if stripped.startswith("#") or stripped == "":
            idx += 1
            continue
        break
    return "".join(lines[idx:])


def load_yaml_semantic(path: Path) -> Any:
    """Load a YAML file as a plain Python object, directive line stripped."""
    return yaml.safe_load(_strip_schema_directive(path.read_text())) or {}


def _canonicalize(value: Any) -> Any:
    """Order-insensitive canonical form of a parsed-YAML object.

    Mirrors ``e2e_helpers._canonicalize``: dicts are compared order-insensitively
    (Python default), lists are sorted by a stable key derived from each
    element's canonical JSON serialization, scalars are unchanged. Duplicate
    detection is preserved (a list with two identical entries stays length-2).
    """
    if isinstance(value, dict):
        return {k: _canonicalize(v) for k, v in value.items()}
    if isinstance(value, list):
        canonical_items = [_canonicalize(item) for item in value]
        return sorted(
            canonical_items,
            key=lambda item: json.dumps(item, sort_keys=True, default=str),
        )
    return value


def _relative_files(root: Path) -> set[str]:
    """Set of POSIX relative paths for every file under ``root`` (empty if absent)."""
    if not root.is_dir():
        return set()
    return {
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    }


@dataclass
class TreeDiff:
    """Result of comparing a patched connector tree to its golden."""

    missing: set[str] = field(default_factory=set)  # in expected, not produced
    extra: set[str] = field(default_factory=set)  # in produced, not expected
    yaml_mismatches: list[str] = field(default_factory=list)  # "<rel>: <detail>"
    content_mismatches: list[str] = field(default_factory=list)  # non-yaml diffs

    @property
    def ok(self) -> bool:
        return not (
            self.missing
            or self.extra
            or self.yaml_mismatches
            or self.content_mismatches
        )

    def as_message(self) -> str:
        parts: list[str] = []
        if self.missing:
            parts.append(f"missing files: {sorted(self.missing)}")
        if self.extra:
            parts.append(f"unexpected files: {sorted(self.extra)}")
        if self.yaml_mismatches:
            parts.append(
                "YAML mismatches:\n  - " + "\n  - ".join(self.yaml_mismatches)
            )
        if self.content_mismatches:
            parts.append(
                "content mismatches:\n  - " + "\n  - ".join(self.content_mismatches)
            )
        return "\n".join(parts) if parts else "trees match"


def compare_connection_yaml(produced: Path, expected: Path) -> str | None:
    """Semantically compare TWO ``connection.yaml`` files.

    Returns None when they are semantically equal, else a human-readable diff
    string. The ``# yaml-language-server`` directive line, formatting, key order
    and list ordering are all ignored.
    """
    p_data = _canonicalize(load_yaml_semantic(produced))
    e_data = _canonicalize(load_yaml_semantic(expected))
    if p_data == e_data:
        return None
    return f"produced={p_data!r}\nexpected={e_data!r}"


def compare_trees(produced: Path, expected: Path) -> TreeDiff:
    """Semantically compare a patched connector tree against the golden.

    Only the files PRESENT in ``expected`` are asserted (the patch leaves the
    rest of the sandbox — handlers, CSV — untouched, and the golden only carries
    the ``connection.yaml`` we care about). ``*.yaml`` files are compared by
    parsed-content deep equality (directive line, formatting, key/list order
    ignored); other files by raw bytes.
    """
    diff = TreeDiff()
    expected_files = _relative_files(expected)
    produced_files = _relative_files(produced)
    diff.missing = expected_files - produced_files

    for rel in sorted(expected_files & produced_files):
        p_file = produced / rel
        e_file = expected / rel
        if rel.endswith((".yaml", ".yml")):
            detail = compare_connection_yaml(p_file, e_file)
            if detail is not None:
                diff.yaml_mismatches.append(f"{rel}: {detail}")
        else:
            if p_file.read_bytes() != e_file.read_bytes():
                diff.content_mismatches.append(rel)
    return diff


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Capture raw bytes of every file under ``root`` keyed by relative path.

    Used by the dry-run assertion to prove the sandbox tree is byte-for-byte
    unchanged after a ``--dry-run`` invocation.
    """
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }
