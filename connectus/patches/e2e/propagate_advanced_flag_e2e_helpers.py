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
# The patch under test. Until the implementation lands the test module xfails
# on (not PATCH_SCRIPT.is_file()) AND empty FIXTURES_DIR.
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


def _load_case(case_json: Path) -> PatchE2ECase:
    data = json.loads(case_json.read_text())
    case_dir = case_json.parent
    return PatchE2ECase(
        name=case_dir.name,
        path=case_dir,
        description=data.get("description", ""),
        connector=data.get("connector"),
        csv=data.get("csv"),
        extra_args=list(data.get("extra_args", [])),
        expect_modified=bool(data.get("expect_modified", True)),
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


def build_cmd(
    case: PatchE2ECase,
    connectors_root: Path,
    dry_run: bool = False,
) -> list[str]:
    """Assemble the subprocess argv for the patch under test.

    Mirrors the assumed CLI flag contract (see module docstring / README).
    """
    cmd = [
        sys.executable,
        str(PATCH_SCRIPT),
        "--connectors-dir",
        str(connectors_root),
    ]
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
