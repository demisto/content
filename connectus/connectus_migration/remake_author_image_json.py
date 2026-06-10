"""Remake the author-image CSV as a connector-to-author-image JSON map.

For every connector that appears in ``connectus-migration-pipeline.csv`` this
script resolves a single author-image path using the following ordered
fallback chain:

1. **Exact CSV lookup** — if the connector id appears in
   ``connector-id-to-author-image.csv``, use the author image path from there.
2. **Suffix-stripped CSV lookup** — if no exact match, retry the lookup after
   removing a known trailing suffix from the connector id (e.g.
   ``"... Automation and Collection"``).
3. **Pack author image** — otherwise, look for a ``Author_image.png`` at the
   root of any pack related to that connector (first found, in pipeline row
   order).
4. **Integration image** — otherwise, look for any integration image
   (``*_image.png`` sitting next to an integration ``.yml``) under any pack
   related to that connector (first found, in pipeline row order).

The resolved map is written to ``connector_to_author_image.json`` and the list
of connectors for which no image could be found at all is printed to stdout.

Related packs for a connector are derived from the ``Integration File Path``
column of the pipeline CSV (the ``Packs/<PackName>`` prefix).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# --- Paths (defaults, relative to the repo root) ---------------------------

# This file lives at: <repo>/connectus/connectus_migration/<this file>
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PIPELINE_CSV = REPO_ROOT / "connectus" / "connectus-migration-pipeline.csv"
DEFAULT_IMAGE_CSV = REPO_ROOT / "connectus" / "connector-id-to-author-image.csv"
DEFAULT_OUTPUT_JSON = (
    REPO_ROOT / "connectus" / "connectus_migration" / "connector_to_author_image.json"
)

# Trailing suffixes stripped from a connector id when an exact CSV lookup fails.
# Order matters: the longest / most specific suffixes come first.
SUFFIXES_TO_STRIP = (
    " Automation and Collection",
    " Automation-and-Remediation",
    " Collection",
)

PACK_AUTHOR_IMAGE_NAME = "Author_image.png"
INTEGRATION_IMAGE_GLOB = "*_image.png"


# --- CSV loading -----------------------------------------------------------


def load_pipeline(pipeline_csv: Path) -> tuple[list[str], dict[str, list[Path]]]:
    """Load the pipeline CSV.

    Returns a tuple of:
      * the ordered, de-duplicated list of connector ids (first-seen order), and
      * a mapping ``connector_id -> [pack_root, ...]`` preserving row order and
        skipping duplicate pack roots per connector.
    """
    connector_order: list[str] = []
    connector_to_packs: dict[str, list[Path]] = {}

    with pipeline_csv.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            connector_id = (row.get("Connector ID") or "").strip()
            if not connector_id:
                continue

            if connector_id not in connector_to_packs:
                connector_order.append(connector_id)
                connector_to_packs[connector_id] = []

            pack_root = _pack_root_from_integration_path(
                row.get("Integration File Path") or ""
            )
            if pack_root is not None and pack_root not in connector_to_packs[connector_id]:
                connector_to_packs[connector_id].append(pack_root)

    return connector_order, connector_to_packs


def _pack_root_from_integration_path(integration_file_path: str) -> Path | None:
    """Derive the ``Packs/<PackName>`` root from an integration file path."""
    integration_file_path = integration_file_path.strip()
    if not integration_file_path:
        return None

    parts = Path(integration_file_path).parts
    # Expect a path like: Packs/<PackName>/Integrations/<Int>/<Int>.yml
    if len(parts) >= 2 and parts[0] == "Packs":
        return Path(parts[0]) / parts[1]
    return None


def load_image_csv(image_csv: Path) -> dict[str, str]:
    """Load the connector-id -> author-image-path CSV into a dict."""
    mapping: dict[str, str] = {}
    with image_csv.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            connector_id = (row.get("Connector ID") or "").strip()
            image_path = (row.get("Author image path") or "").strip()
            if connector_id and image_path:
                mapping[connector_id] = image_path
    return mapping


# --- Resolution steps ------------------------------------------------------


def resolve_from_image_csv(connector_id: str, image_map: dict[str, str]) -> str | None:
    """Step 2: exact match, then match after stripping a known suffix."""
    if connector_id in image_map:
        return image_map[connector_id]

    for suffix in SUFFIXES_TO_STRIP:
        if connector_id.endswith(suffix):
            stripped = connector_id[: -len(suffix)].strip()
            if stripped in image_map:
                return image_map[stripped]
    return None


def resolve_pack_author_image(pack_roots: list[Path], repo_root: Path) -> str | None:
    """Step 3: first existing ``Packs/<Pack>/Author_image.png`` (row order)."""
    for pack_root in pack_roots:
        candidate = repo_root / pack_root / PACK_AUTHOR_IMAGE_NAME
        if candidate.is_file():
            return (pack_root / PACK_AUTHOR_IMAGE_NAME).as_posix()
    return None


def resolve_integration_image(pack_roots: list[Path], repo_root: Path) -> str | None:
    """Step 4: first integration ``*_image.png`` sitting next to an integration
    ``.yml`` under any related pack (row order)."""
    for pack_root in pack_roots:
        integrations_dir = repo_root / pack_root / "Integrations"
        if not integrations_dir.is_dir():
            continue
        for image_path in sorted(integrations_dir.glob(f"*/{INTEGRATION_IMAGE_GLOB}")):
            yml_sibling = image_path.with_name(
                image_path.name[: -len("_image.png")] + ".yml"
            )
            if yml_sibling.is_file():
                return image_path.relative_to(repo_root).as_posix()
    return None


def resolve_author_image(
    connector_id: str,
    pack_roots: list[Path],
    image_map: dict[str, str],
    repo_root: Path,
) -> str | None:
    """Run the full fallback chain for a single connector."""
    return (
        resolve_from_image_csv(connector_id, image_map)
        or resolve_pack_author_image(pack_roots, repo_root)
        or resolve_integration_image(pack_roots, repo_root)
    )


# --- Orchestration ---------------------------------------------------------


def build_connector_to_author_image(
    pipeline_csv: Path,
    image_csv: Path,
    repo_root: Path,
) -> tuple[dict[str, str], list[str]]:
    """Resolve every connector and return ``(resolved_map, not_found_list)``."""
    connector_order, connector_to_packs = load_pipeline(pipeline_csv)
    image_map = load_image_csv(image_csv)

    resolved: dict[str, str] = {}
    not_found: list[str] = []

    for connector_id in connector_order:
        pack_roots = connector_to_packs.get(connector_id, [])
        image_path = resolve_author_image(
            connector_id, pack_roots, image_map, repo_root
        )
        if image_path:
            resolved[connector_id] = image_path
        else:
            not_found.append(connector_id)

    return resolved, not_found


def write_json(resolved: dict[str, str], output_json: Path) -> None:
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with output_json.open("w", encoding="utf-8") as fh:
        json.dump(resolved, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pipeline-csv",
        type=Path,
        default=DEFAULT_PIPELINE_CSV,
        help="Path to connectus-migration-pipeline.csv",
    )
    parser.add_argument(
        "--image-csv",
        type=Path,
        default=DEFAULT_IMAGE_CSV,
        help="Path to connector-id-to-author-image.csv",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=DEFAULT_OUTPUT_JSON,
        help="Path to the output JSON file",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root used to resolve pack/integration image paths",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    resolved, not_found = build_connector_to_author_image(
        pipeline_csv=args.pipeline_csv,
        image_csv=args.image_csv,
        repo_root=args.repo_root,
    )

    write_json(resolved, args.output_json)

    print(f"Wrote {len(resolved)} connector image entries to {args.output_json}")
    print(f"\nConnectors with no image found at all ({len(not_found)}):")
    if not_found:
        for connector_id in not_found:
            print(f"  - {connector_id}")
    else:
        print("  (none)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
