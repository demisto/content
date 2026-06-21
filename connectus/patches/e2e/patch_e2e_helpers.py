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
# The patch under test (does NOT exist yet — TDD red). The test module guards
# the suite on this path's existence.
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
    """Discover every case (a dir containing ``case.json``) under ``fixtures/``.

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
