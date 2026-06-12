"""Helpers for the ConnectUs ``generate_manifest`` end-to-end (golden-file) suite.

This module owns the *infrastructure* for black-box, on-disk E2E tests of
``manifest_generator.py``. The test driver (``manifest_generator_e2e_test.py``)
stays thin and delegates everything mechanical here.

The contract
------------
Each test *case* is a directory under ``e2e/fixtures/<feature>/<case>/`` with:

``case.json``
    Metadata + CLI inputs. Recognised keys::

        {
          "description":   "human readable, optional",
          "connector_title": "GitHub",          # REQUIRED — see note below
          "mapped_params":   { ... },            # JSON for the CLI arg (default {})
          "auth_methods":    { ... },            # JSON for the CLI arg (default {})
          "manual_fields":   { "serializer": {...}, ... },  # optional --manual-* overrides
          "expect_failure":  false,              # optional; negative cases
          "expect_stderr_contains": "FileExistsError"  # optional, with expect_failure
        }

``input/``
    ``input/integration.yml`` — the XSOAR content integration to generate from.
    ``input/connectors/<slug>/...`` — OPTIONAL pre-existing connectus manifest
    tree (the "already migrated" connector). When present the generator takes
    its *add-handler-to-existing-connector* path; when absent it scaffolds from
    scratch.

``expected/``
    The golden output. ``expected/connectors/<slug>/...`` is the connector tree
    the generator must produce. ``expected/CODEOWNERS`` (optional) is the
    sandboxed CODEOWNERS file the generator writes at the connectors-root parent.

Two hard subprocess constraints (cannot be monkeypatched in a real subprocess)
------------------------------------------------------------------------------
1. ``connector_title`` MUST be a key in ``connector_to_author_image.json`` — the
   CLI looks the title up unconditionally (``manifest_generator.py`` ~L7962).
2. Every sub-capability id the run produces (``<capability>_<integration-slug>``)
   MUST exist in ``sub_capabilities_to_licenses.json`` or the run raises
   ``RuntimeError``. Keep each case's ``mapped_params`` license-safe.

UPDATE_GOLDEN workflow
----------------------
Run with ``UPDATE_GOLDEN=1`` to (re)write each case's ``expected/`` from the
generator's *actual* output instead of asserting. The produced tree is treated
as a snapshot — **you must human-review the resulting diff before committing**;
blindly regenerating will happily bless bugs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------
# ``e2e/`` lives directly under ``connectus_migration/``, which lives under
# ``connectus/``, which lives under the content repo root.
E2E_DIR = Path(__file__).resolve().parent
MIGRATION_DIR = E2E_DIR.parent
MANIFEST_GENERATOR = MIGRATION_DIR / "manifest_generator.py"
FIXTURES_DIR = E2E_DIR / "fixtures"

# The content repo root (``.../content``) is the parent of ``connectus/``. The
# generator is run with this as ``cwd`` so the from-scratch path can resolve the
# author image, whose recorded path is relative to the content root
# (e.g. ``Packs/GitHub/Integrations/GitHub/GitHub_image.png``). The add-handler
# path ignores the image, so this only matters for from-scratch cases.
CONTENT_ROOT = MIGRATION_DIR.parent.parent

# Subprocess timeout (seconds). The generator imports a large module tree.
RUN_TIMEOUT = 300

# Filenames inside a case directory.
CASE_FILE = "case.json"
INPUT_DIR = "input"
EXPECTED_DIR = "expected"
INTEGRATION_YML = "integration.yml"
CONNECTORS_DIRNAME = "connectors"

# Map of case.json ``manual_fields`` keys -> the CLI option name.
_MANUAL_FIELD_OPTIONS = {
    "connector": "--manual-connector-fields",
    "handler": "--manual-handler-fields",
    "summary": "--manual-summary-fields",
    "capabilities": "--manual-capabilities-fields",
    "configurations": "--manual-configurations-fields",
    "serializer": "--manual-serializer-fields",
    "connection": "--manual-connection-fields",
}


def update_golden_enabled() -> bool:
    """Return True when the harness should (re)write goldens instead of asserting."""
    return os.environ.get("UPDATE_GOLDEN", "").strip().lower() in {"1", "true", "yes"}


# ---------------------------------------------------------------------------
# Case model
# ---------------------------------------------------------------------------
@dataclass
class E2ECase:
    """A single discovered end-to-end test case."""

    name: str  # "<feature>/<case-dir-name>" — used as the pytest id
    path: Path  # the case directory
    description: str
    connector_title: str
    mapped_params: dict[str, Any]
    auth_methods: dict[str, Any]
    manual_fields: dict[str, Any]
    expect_failure: bool
    expect_stderr_contains: str | None

    @property
    def input_dir(self) -> Path:
        return self.path / INPUT_DIR

    @property
    def expected_dir(self) -> Path:
        return self.path / EXPECTED_DIR

    @property
    def integration_yml(self) -> Path:
        return self.input_dir / INTEGRATION_YML

    @property
    def input_connectors(self) -> Path:
        """The optional pre-seeded connectus manifest tree (may not exist)."""
        return self.input_dir / CONNECTORS_DIRNAME

    @property
    def expected_connectors(self) -> Path:
        return self.expected_dir / CONNECTORS_DIRNAME


def _load_case(case_json: Path) -> E2ECase:
    data = json.loads(case_json.read_text())
    case_dir = case_json.parent
    feature = case_dir.parent.name
    name = f"{feature}/{case_dir.name}"

    title = data.get("connector_title")
    if not title:
        raise ValueError(f"{case_json}: 'connector_title' is required.")

    return E2ECase(
        name=name,
        path=case_dir,
        description=data.get("description", ""),
        connector_title=title,
        mapped_params=data.get("mapped_params", {}),
        auth_methods=data.get("auth_methods", {}),
        manual_fields=data.get("manual_fields", {}),
        expect_failure=bool(data.get("expect_failure", False)),
        expect_stderr_contains=data.get("expect_stderr_contains"),
    )


def discover_cases(feature: str | None = None) -> list[E2ECase]:
    """Discover every case (a dir containing ``case.json``) under ``fixtures/``.

    Args:
        feature: when given, restrict discovery to ``fixtures/<feature>/``.

    Returns:
        Cases sorted by name for deterministic pytest ordering.
    """
    root = FIXTURES_DIR / feature if feature else FIXTURES_DIR
    if not root.is_dir():
        return []
    cases = [_load_case(p) for p in root.glob(f"**/{CASE_FILE}")]
    return sorted(cases, key=lambda c: c.name)


# ---------------------------------------------------------------------------
# Running the generator (subprocess — true black box)
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    connectors_root: Path  # the tmp connectors root the generator wrote under


def run_generator(case: E2ECase, tmp_path: Path) -> RunResult:
    """Run ``manifest_generator.py`` as a subprocess for ``case``.

    Copies any pre-seeded ``input/connectors`` tree into ``tmp_path/connectors``
    (so the generator's add-handler path sees the "already migrated" connector),
    then invokes the CLI with ``--connectors-root`` pointing at that tmp root.
    Nothing under the real repo is mutated: ``--connectors-root`` is explicit and
    the generator's CODEOWNERS write resolves to ``tmp_path/CODEOWNERS``.
    """
    connectors_root = tmp_path / CONNECTORS_DIRNAME
    if case.input_connectors.is_dir():
        shutil.copytree(case.input_connectors, connectors_root)
    else:
        connectors_root.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(MANIFEST_GENERATOR),
        str(case.integration_yml.resolve()),
        case.connector_title,
        json.dumps(case.mapped_params),
        json.dumps(case.auth_methods),
        "--connectors-root",
        str(connectors_root),
    ]
    for key, value in case.manual_fields.items():
        option = _MANUAL_FIELD_OPTIONS.get(key)
        if option is None:
            raise ValueError(
                f"{case.name}: unknown manual_fields key {key!r}; "
                f"expected one of {sorted(_MANUAL_FIELD_OPTIONS)}"
            )
        cmd.extend([option, json.dumps(value)])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT,
        # Run from the content repo root so the from-scratch path can resolve
        # the author image (path is relative to the content root). All other
        # paths we pass (integration yml, --connectors-root) are absolute.
        cwd=str(CONTENT_ROOT),
    )
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        connectors_root=connectors_root,
    )


# ---------------------------------------------------------------------------
# Semantic YAML comparison
# ---------------------------------------------------------------------------
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


def _relative_files(root: Path) -> set[str]:
    """Set of POSIX relative paths for every file under ``root`` (empty if absent)."""
    if not root.is_dir():
        return set()
    return {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file()
    }


@dataclass
class TreeDiff:
    """Result of comparing a produced connector tree to its golden."""

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
            parts.append("YAML mismatches:\n  - " + "\n  - ".join(self.yaml_mismatches))
        if self.content_mismatches:
            parts.append(
                "content mismatches:\n  - " + "\n  - ".join(self.content_mismatches)
            )
        return "\n".join(parts) if parts else "trees match"


def compare_trees(produced: Path, expected: Path) -> TreeDiff:
    """Semantically compare a produced connector tree against the golden.

    * File-set must match exactly (catches missing/extra files).
    * ``*.yaml`` files compared by parsed-content deep equality (formatting,
      key order and the schema-directive line are ignored).
    * Other files (e.g. ``*.svg``) compared by raw bytes.
    """
    diff = TreeDiff()
    produced_files = _relative_files(produced)
    expected_files = _relative_files(expected)
    diff.missing = expected_files - produced_files
    diff.extra = produced_files - expected_files

    for rel in sorted(produced_files & expected_files):
        p_file = produced / rel
        e_file = expected / rel
        if rel.endswith((".yaml", ".yml")):
            p_data = load_yaml_semantic(p_file)
            e_data = load_yaml_semantic(e_file)
            if p_data != e_data:
                diff.yaml_mismatches.append(
                    f"{rel}: produced={p_data!r} expected={e_data!r}"
                )
        else:
            if p_file.read_bytes() != e_file.read_bytes():
                diff.content_mismatches.append(rel)
    return diff


# ---------------------------------------------------------------------------
# Golden regeneration (UPDATE_GOLDEN=1)
# ---------------------------------------------------------------------------
def regenerate_golden(case: E2ECase, result: RunResult) -> None:
    """Snapshot the produced connector tree into the case's ``expected/`` dir.

    Wipes and rewrites ``expected/connectors`` from the generator output and
    captures the sandboxed ``CODEOWNERS`` (written at the connectors-root parent)
    when present. The result is a *snapshot* — review the diff before committing.
    """
    expected_connectors = case.expected_connectors
    if expected_connectors.exists():
        shutil.rmtree(expected_connectors)
    expected_connectors.parent.mkdir(parents=True, exist_ok=True)
    if result.connectors_root.is_dir():
        shutil.copytree(result.connectors_root, expected_connectors)

    codeowners = result.connectors_root.parent / "CODEOWNERS"
    if codeowners.is_file():
        shutil.copy2(codeowners, case.expected_dir / "CODEOWNERS")
