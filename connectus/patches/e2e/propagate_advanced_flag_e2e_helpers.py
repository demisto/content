"""Black-box harness for the ``propagate_advanced_flag`` patch end-to-end suite.

This module is a near-verbatim clone of ``patch_e2e_helpers.py`` (which targets
``add_vault_support.py``), with two minimal substantive changes:

  1. ``PATCH_SCRIPT`` points at ``propagate_advanced_flag.py``.
  2. ``FIXTURES_DIR`` is SCOPED to its own subdirectory
     ``patches/e2e/fixtures/propagate_advanced_flag/`` so cases authored for
     this patch never collide with the existing ``add_vault_support`` cases
     (which live directly under ``patches/e2e/fixtures/``).

Fixtures-dir scoping decision
-----------------------------
The original helper's ``discover_cases()`` does ``FIXTURES_DIR.glob("**/case.json")``
— a recursive sweep that returns ANY case anywhere under the shared fixtures
root. If both patches' helpers shared ``FIXTURES_DIR``, each would discover the
OTHER patch's cases and run the wrong script against them. Two safe options
existed:

    (a) Filter by a known case-name prefix or an explicit allow-list.
    (b) Use a dedicated subdirectory.

Option (b) is chosen here: it requires zero filtering logic, keeps the original
helper unchanged, and makes the on-disk layout self-documenting (every fixture
under ``fixtures/propagate_advanced_flag/`` is unambiguously for this patch).
Cases authored for this patch MUST live at
``patches/e2e/fixtures/propagate_advanced_flag/<case>/`` (the e2e test module
also pins this expectation by name).

Everything else — the case JSON contract, sandbox copy semantics, subprocess
invocation, semantic YAML comparison and ``RunResult`` / ``TreeDiff`` shapes —
is unchanged.
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
# The DEFAULT patch under test when a case does not declare its own ``script``.
# Until the implementation lands the test module xfails on
# (not PATCH_SCRIPT.is_file()) AND empty FIXTURES_DIR.
PATCH_SCRIPT = PATCHES_DIR / "propagate_advanced_flag.py"
# Scoped to a dedicated subdir to avoid collisions with add_vault_support's
# cases under the shared ``e2e/fixtures/`` root. See module docstring.
FIXTURES_DIR = E2E_DIR / "fixtures" / "propagate_advanced_flag"

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
    """Discover every case (a dir containing ``case.json``) under ``FIXTURES_DIR``.

    Returns cases sorted by name for deterministic pytest ordering.
    """
    if not FIXTURES_DIR.is_dir():
        return []
    cases = [_load_case(p) for p in FIXTURES_DIR.glob(f"**/{CASE_FILE}")]
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
    """Run ``propagate_advanced_flag.py`` as a subprocess against the sandbox tree."""
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
    """Order-insensitive canonical form of a parsed-YAML object."""
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
    """Semantically compare TWO YAML files (works for configurations.yaml AND
    connection.yaml — the helper is shape-agnostic). Returns None when
    semantically equal, else a human-readable diff string."""
    p_data = _canonicalize(load_yaml_semantic(produced))
    e_data = _canonicalize(load_yaml_semantic(expected))
    if p_data == e_data:
        return None
    return f"produced={p_data!r}\nexpected={e_data!r}"


def compare_trees(produced: Path, expected: Path) -> TreeDiff:
    """Semantically compare a patched connector tree against the golden."""
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
    """Capture raw bytes of every file under ``root`` keyed by relative path."""
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }
