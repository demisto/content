"""Stage E (APPLY): write a validated doc-spec into the five connector YAMLs.

Deterministic, comment-preserving (ruamel round-trip), **dry-run by default**,
and idempotent. The apply step performs NO judgment — it only transcribes the
already-validated doc-spec and sets the canonical metadata strings (§8.1 silent
override).

What it writes
--------------
* ``connector.yaml``    -> ``metadata.description`` = spec.connector.description.
* ``capabilities.yaml`` -> ``metadata.title``/``description`` = canonical;
                            each ``capabilities[].description`` = table value for
                            its id (top-level only; sub_capabilities untouched).
* ``connection.yaml``   -> ``metadata.title``/``description`` = canonical;
                            each ``view_groups[].help_text`` from the spec
                            (matched by id).
* ``configurations.yaml``-> ``metadata.title``/``description`` = canonical;
                            ``view_groups[].help_text`` for the (optional) ids
                            present in the spec.
* ``summary.yaml``      -> ``metadata.title``/``description`` = canonical;
                            ``metadata.next_steps`` set only when the spec
                            provides a non-null value (else the key is removed).

Safety
------
* DRY-RUN by default: prints a unified diff of every file; writes nothing unless
  ``--apply`` is passed.
* IDEMPOTENT: applying twice produces no second change (verified by test).
* Round-trip: the ``# yaml-language-server`` schema comment and all existing
  structure/comments are preserved.

Usage::

    python3 apply_doc_spec.py <slug> <doc-spec.json>            # dry-run diff
    python3 apply_doc_spec.py <slug> <doc-spec.json> --apply    # write files
"""

from __future__ import annotations

import argparse
import difflib
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString

sys.path.insert(0, os.path.dirname(__file__))

from resolvers import ConnectorPaths, doc_spec_path, resolve_connector  # noqa: E402

# Canonical fixed metadata strings (§8.1–§8.5).
CANONICAL_METADATA = {
    "capabilities": ("Capabilities", "Name and configure the instance capabilities"),
    "connection": ("Connection", "Enter the credentials to securely authorize the connection"),
    "configurations": ("Configuration", "Adjust and refine your configuration settings"),
    "summary": ("Summary", "Review your instance configuration"),
}

_CAP_TABLE_PATH = Path(__file__).resolve().parent / "capability_descriptions.json"


def _make_yaml() -> YAML:
    """A ruamel YAML configured for faithful round-trip editing."""
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096  # avoid line-wrapping long help_text values
    y.indent(mapping=2, sequence=2, offset=0)
    return y


def _load_capability_table() -> Dict[str, str]:
    data = json.loads(_CAP_TABLE_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _dump_to_str(yaml: YAML, data) -> str:
    buf = io.StringIO()
    yaml.dump(data, buf)
    return buf.getvalue()


@dataclass
class FileChange:
    """A pending edit to a single YAML file."""

    path: Path
    before: str
    after: str

    @property
    def changed(self) -> bool:
        return self.before != self.after

    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.before.splitlines(keepends=True),
                self.after.splitlines(keepends=True),
                fromfile=str(self.path),
                tofile=str(self.path),
            )
        )


@dataclass
class ApplyResult:
    """Outcome of an apply (or dry-run)."""

    changes: List[FileChange] = field(default_factory=list)
    written: bool = False
    errors: List[str] = field(default_factory=list)

    @property
    def changed_files(self) -> List[FileChange]:
        return [c for c in self.changes if c.changed]


# --------------------------------------------------------------------------- #
# Per-file transforms (operate on a parsed ruamel structure in place)
# --------------------------------------------------------------------------- #
def _set_metadata(doc: dict, title: str, description: str) -> None:
    meta = doc.get("metadata")
    if meta is None:
        meta = {}
        doc["metadata"] = meta
    meta["title"] = title
    meta["description"] = description


def _apply_connector(doc: dict, spec: dict) -> None:
    desc = (spec.get("connector") or {}).get("description", "")
    meta = doc.get("metadata")
    if meta is None:
        meta = {}
        doc["metadata"] = meta
    meta["description"] = desc


def _apply_capabilities(doc: dict, spec: dict, table: Dict[str, str], errors: List[str]) -> None:
    title, description = CANONICAL_METADATA["capabilities"]
    _set_metadata(doc, title, description)
    for cap in doc.get("capabilities") or []:
        if not isinstance(cap, dict):
            continue
        cid = cap.get("id")
        if cid in table:
            cap["description"] = table[cid]
        else:
            errors.append(
                f"capabilities.yaml: capability id {cid!r} not in the closed "
                f"table; cannot set its description."
            )


# A list-item line: ordered ("1." / "1)") or unordered ("-" / "*" / "+").
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")
# An ATX heading line ("# ", "## ", ...).
_HEADING_LINE_RE = re.compile(r"^\s*#{1,6}\s+")


def normalize_help_text_markdown(text: str) -> str:
    """Make help_text render reliably in the strict tooltip Markdown renderer.

    The connection/configuration ``help_text`` is shown as Markdown inside a
    hover tooltip (README §field options). Strict renderers require a BLANK LINE
    before a list or heading block, otherwise an ordered list immediately
    following a heading/paragraph fails to parse (numbers stripped, items merged
    into the preceding paragraph).

    This inserts a single blank line before any heading or list block that
    directly follows a non-blank line which is itself NOT part of that same list.
    It is idempotent and leaves already-spaced content untouched. Trailing
    whitespace per line is trimmed.

    This returns a plain ``str``. The block-scalar wrapping that controls how the
    value is *serialized* in YAML is applied separately in
    :func:`_as_block_scalar` / :func:`_apply_view_group_help`.

    Args:
        text: the raw help_text Markdown.

    Returns:
        Normalized Markdown.
    """
    if not text:
        return text
    lines = [ln.rstrip() for ln in text.split("\n")]
    out: List[str] = []
    for i, line in enumerate(lines):
        prev = out[-1] if out else ""
        is_list = bool(_LIST_ITEM_RE.match(line))
        is_heading = bool(_HEADING_LINE_RE.match(line))
        prev_is_blank = prev.strip() == ""
        prev_is_list = bool(_LIST_ITEM_RE.match(prev))
        if line.strip() and not prev_is_blank:
            # Heading after any non-blank line → needs a blank line.
            if is_heading:
                out.append("")
            # First list item after a non-blank, non-list line → needs a blank.
            elif is_list and not prev_is_list:
                out.append("")
        out.append(line)
    result = "\n".join(out)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip("\n")


def _as_block_scalar(text: str) -> LiteralScalarString:
    """Wrap ``text`` so ruamel serializes it as a YAML literal block scalar (``|``).

    A plain ``str`` containing newlines is dumped by ruamel as a DOUBLE-QUOTED
    scalar with literal ``\\n`` escape sequences (e.g. ``help_text: "a\\nb"``).
    The tooltip Markdown renderer shows those ``\\n`` verbatim instead of breaking
    lines, so lists and headings never render. Emitting a block scalar (matching
    the salesforce-example connector) puts REAL line breaks in the file::

        help_text: |
          ## API keys generating steps

          1. ...

    A trailing newline is required for ``|`` (clip) style; without it ruamel falls
    back to ``|-`` (strip), which is still fine but ``|`` matches the example.
    """
    return LiteralScalarString((text or "") + "\n")


def _apply_view_group_help(doc: dict, spec_section: dict, section_name: str) -> None:
    """Apply ``view_groups[].help_text`` from the spec, matched by id (§8.3b).

    The doc-spec entry carries THREE states, distinguished on the SPEC entry
    (NOT a coalesced dict that loses the difference):

    * **non-empty string** -> set/overwrite help_text as a block scalar (via
      :func:`_as_block_scalar` + :func:`normalize_help_text_markdown`).
    * **explicit ``null``** (``"help_text" in entry and entry["help_text"] is
      None``) -> DELETE the existing ``help_text`` key on the matching connector
      view_group; NO-OP (not an error) when the key is already absent.
    * **view_group absent from the spec, or no ``help_text`` key** -> leave the
      connector view_group untouched.
    """
    # value-strings to SET, keyed by id.
    set_by_id: Dict[str, str] = {}
    # ids whose help_text must be DELETED (explicit null sentinel).
    delete_ids: set = set()
    for entry in (spec_section or {}).get("view_groups", []) or []:
        if not isinstance(entry, dict) or "help_text" not in entry:
            continue  # absent key -> untouched
        value = entry["help_text"]
        if value is None:
            delete_ids.add(entry.get("id"))
        else:
            set_by_id[entry.get("id")] = value
    for vg in doc.get("view_groups") or []:
        if not isinstance(vg, dict):
            continue
        vg_id = vg.get("id")
        if vg_id in set_by_id:
            vg["help_text"] = _as_block_scalar(
                normalize_help_text_markdown(set_by_id[vg_id])
            )
        elif vg_id in delete_ids and "help_text" in vg:
            del vg["help_text"]


def _apply_profiles(doc: dict, spec: dict, errors: List[str]) -> None:
    """Set ``profiles[].title``/``description`` from the spec, matched by id (§8.3a.4).

    Each field carries the THREE-state contract (§8.3a.5), distinguished on the
    SPEC entry (NOT a coalesced dict that loses the difference):

    * **non-empty string** -> set/overwrite the field as a PLAIN scalar (NOT a
      block scalar) — title/description are short single-line strings, so the
      raw ``str`` lets ruamel emit a normal inline scalar.
    * **explicit ``null``** (``"description" in entry and entry["description"]
      is None``) -> DELETE the existing key on the matching profile; NO-OP (not
      an error) when the key is already absent (idempotent).
    * **key ABSENT from the entry** -> leave the existing value untouched
      (ruamel keeps the node + comments).

    Both ``title`` and ``description`` get the SAME three-state treatment; per
    §8.3a the title is normally KEPT, so a ``title: null`` removal is rare while
    ``description: null`` is the common new case.

    An unknown profile id appends to ``errors`` (mirroring the unknown
    capability-id behavior in :func:`_apply_capabilities`); because
    :func:`apply_doc_spec` only writes when ``not result.errors``, a single
    unknown id aborts the ENTIRE apply (no partial writes).
    """
    spec_by_id = {
        p["id"]: p
        for p in (spec.get("connection") or {}).get("profiles", []) or []
        if isinstance(p, dict) and "id" in p
    }
    if not spec_by_id:
        return
    existing_ids = {
        prof.get("id")
        for prof in (doc.get("profiles") or [])
        if isinstance(prof, dict)
    }
    for pid in spec_by_id:
        if pid not in existing_ids:
            errors.append(
                f"connection.yaml: profile id {pid!r} not found in profiles[]; "
                f"cannot set its title/description."
            )
    for prof in doc.get("profiles") or []:
        if not isinstance(prof, dict):
            continue
        entry = spec_by_id.get(prof.get("id"))
        if entry is None:
            continue
        for field in ("title", "description"):
            if field not in entry:
                continue  # absent key -> untouched
            value = entry[field]
            if value is None:
                # explicit null sentinel -> delete; no-op when already absent.
                if field in prof:
                    del prof[field]
            else:
                # non-empty string -> set/overwrite as a PLAIN scalar.
                prof[field] = value


def _apply_connection(doc: dict, spec: dict, errors: List[str]) -> None:
    title, description = CANONICAL_METADATA["connection"]
    _set_metadata(doc, title, description)
    _apply_view_group_help(doc, spec.get("connection") or {}, "connection")
    _apply_profiles(doc, spec, errors)


def _apply_configurations(doc: dict, spec: dict) -> None:
    title, description = CANONICAL_METADATA["configurations"]
    _set_metadata(doc, title, description)
    # OPTIONAL (§8.4): only ids present in the spec are touched.
    _apply_view_group_help(doc, spec.get("configurations") or {}, "configurations")


def _apply_summary(doc: dict, spec: dict) -> None:
    title, description = CANONICAL_METADATA["summary"]
    _set_metadata(doc, title, description)
    meta = doc["metadata"]
    next_steps = ((spec.get("summary") or {}).get("metadata") or {}).get("next_steps")
    if next_steps:
        meta["next_steps"] = next_steps
    elif "next_steps" in meta:
        del meta["next_steps"]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def _transform_file(
    yaml: YAML, path: Optional[Path], transform, errors: List[str]
) -> Optional[FileChange]:
    """Load ``path``, apply ``transform(doc)`` in place, return a FileChange."""
    if path is None or not path.exists():
        errors.append(f"required YAML missing: {path}")
        return None
    before = path.read_text(encoding="utf-8")
    doc = yaml.load(before)
    transform(doc)
    after = _dump_to_str(yaml, doc)
    return FileChange(path=path, before=before, after=after)


def build_changes(
    paths: ConnectorPaths, spec: dict, table: Optional[Dict[str, str]] = None
) -> ApplyResult:
    """Compute (but do not write) the FileChanges for all five YAMLs."""
    yaml = _make_yaml()
    table = table if table is not None else _load_capability_table()
    result = ApplyResult()

    plan = [
        (paths.connector_yaml, lambda d: _apply_connector(d, spec)),
        (paths.capabilities_yaml, lambda d: _apply_capabilities(d, spec, table, result.errors)),
        (paths.connection_yaml, lambda d: _apply_connection(d, spec, result.errors)),
        (paths.configurations_yaml, lambda d: _apply_configurations(d, spec)),
        (paths.summary_yaml, lambda d: _apply_summary(d, spec)),
    ]
    for path, transform in plan:
        change = _transform_file(yaml, path, transform, result.errors)
        if change is not None:
            result.changes.append(change)
    return result


def apply_doc_spec(
    slug: str,
    spec: dict,
    write: bool = False,
    spec_path: Optional[Path] = None,
    cleanup_spec: bool = True,
) -> ApplyResult:
    """Apply a validated doc-spec to the connector's YAMLs.

    Args:
        slug: connector slug.
        spec: the validated doc-spec.json.
        write: when False (default), computes the diff but writes nothing
            (dry-run). When True, writes the changed files.
        spec_path: on-disk path of the doc-spec (the intermediate artifact).
            When provided and ``cleanup_spec`` is True, it is deleted after a
            successful write so it never lingers next to the connector files.
        cleanup_spec: delete ``spec_path`` after a successful write (default
            True). Ignored for dry-runs and when there is nothing to delete.

    Returns:
        An :class:`ApplyResult`.
    """
    paths = resolve_connector(slug)
    result = build_changes(paths, spec)
    if write and not result.errors:
        for change in result.changed_files:
            change.path.write_text(change.after, encoding="utf-8")
        result.written = True
        if cleanup_spec and spec_path is not None and Path(spec_path).exists():
            Path(spec_path).unlink()
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply a validated connector doc-spec.json to its YAMLs (dry-run by default)."
    )
    parser.add_argument("slug", help="connector slug, e.g. akamai")
    parser.add_argument(
        "doc_spec", nargs="?", default=None,
        help="path to doc-spec.json (default: the .doc_specs/<slug>.json staging path).",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="write the files (default is a dry-run diff only).",
    )
    parser.add_argument(
        "--keep-spec", action="store_true",
        help="do NOT delete the doc-spec after a successful --apply (default deletes it).",
    )
    args = parser.parse_args(argv)

    spec_file = Path(args.doc_spec) if args.doc_spec else doc_spec_path(args.slug)
    if not spec_file.exists():
        print(f"ERROR doc-spec not found: {spec_file}")
        return 1
    spec = json.loads(spec_file.read_text(encoding="utf-8"))
    result = apply_doc_spec(
        args.slug, spec, write=args.apply,
        spec_path=spec_file, cleanup_spec=not args.keep_spec,
    )

    for err in result.errors:
        print(f"ERROR {err}")
    if result.errors:
        print("FAIL  apply aborted (no files written).")
        return 1

    changed = result.changed_files
    if not changed:
        print(f"OK    no changes needed for '{args.slug}' (already up to date).")
        return 0

    for change in changed:
        print(change.diff())
    if result.written:
        msg = f"OK    wrote {len(changed)} file(s) for '{args.slug}'."
        if not args.keep_spec:
            msg += f" Removed intermediate doc-spec {spec_file.name}."
        print(msg)
    else:
        print(
            f"DRY-RUN  {len(changed)} file(s) would change for '{args.slug}'. "
            f"Re-run with --apply to write."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
