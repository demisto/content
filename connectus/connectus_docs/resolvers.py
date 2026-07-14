"""Stage A (RESOLVE): map a grouped connector to its on-disk facts.

Given a connector slug (e.g. ``akamai``) these resolvers gather everything the
authoring + validation stages need, WITHOUT any AI judgment:

* :func:`resolve_connector` — locate the connector folder + its five YAMLs.
* :func:`resolve_members` — the per-integration member rows from the migration
  pipeline CSV (integration id + integration YML path), which is the
  authoritative connector -> integration mapping.
* :func:`resolve_member_files` — for each member: the integration YML, its
  ``<integration>_description.md`` (PRIMARY source, §2), the integration README
  and pack README (gap-fill), and the pack_metadata.json.
* :func:`resolve_view_groups` — the ``view_groups[]`` declared in
  ``connection.yaml`` (id/label/help_text).
* :func:`resolve_profiles_by_view_group` — profiles grouped by ``view_group``
  (read directly from ``connection.yaml``; no handler files needed — §5).
* :func:`resolve_config_params_by_view_group` — the configuration field ids bound
  to each view_group across connection + configurations YAMLs.
* :func:`slugify` — the canonical id slug rule (``lower()``, spaces -> ``-``)
  used by the §8.6 view_group-id correctness flag.

FAIL-LOUD CONTRACT
------------------
These resolvers MUST NOT silently swallow problems. Any condition that genuinely
blocks documentation — a connector folder that does not exist, an empty/missing
``Connector Folder Path`` match in the CSV, a member whose integration YML is
missing or unparseable, or a member whose PRIMARY ``<integration>_description.md``
is absent — raises :class:`ResolutionError`. The skill orchestration (SKILL.md)
catches these and asks the engineer how to proceed; it never produces a quietly
half-resolved doc-spec.

Only the genuinely-optional GAP-FILL sources (integration README, pack README,
pack_metadata.json) are allowed to be ``None`` — their absence is normal under
the §2 source-priority rules and is reported as ``warnings`` on
:class:`MemberFiles`, not raised.

Path model
----------
The repo root (``find_repo_root``) is the common parent of both the content repo
(``content/``) and the unified-connectors repo (``unified-connectors-content/``).
Integration YML paths in the CSV are relative to ``content/`` (``Packs/...``);
connector folder paths are relative to ``unified-connectors-content/``
(``connectors/...``).
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Shared connectus env loader (connectus/ is not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from env_loader import find_repo_root  # noqa: E402

try:
    from ruamel.yaml import YAML

    _yaml = YAML(typ="safe")

    def _load_yaml_raw(path: Path) -> dict:
        with open(path, encoding="utf-8") as fh:
            return _yaml.load(fh) or {}
except Exception:  # pragma: no cover - ruamel always present in repo
    import yaml

    def _load_yaml_raw(path: Path) -> dict:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}


# --------------------------------------------------------------------------- #
# Errors (fail-loud)
# --------------------------------------------------------------------------- #
class ResolutionError(Exception):
    """A blocking resolution problem the engineer must resolve.

    Raised (never swallowed) for conditions that prevent producing a complete,
    trustworthy doc-spec. Carries a human-readable message describing exactly
    what is missing/broken and where, so SKILL.md can present it and ask how to
    continue.
    """


def _load_yaml(path: Path) -> dict:
    """Load YAML, raising :class:`ResolutionError` on any failure."""
    try:
        return _load_yaml_raw(path)
    except FileNotFoundError as exc:
        raise ResolutionError(f"YAML file not found: {path}") from exc
    except Exception as exc:  # parse error, permission, etc.
        raise ResolutionError(f"Failed to parse YAML {path}: {exc}") from exc


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
_CONTENT_DIRNAME = "content"
_CONNECTUS_REPO_DIRNAME = "unified-connectors-content"
_PIPELINE_CSV_RELPATH = "connectus/connectus-migration-pipeline.csv"

# Default CONNECTUS_REPO_DIR env override (mirrors manifest_generator).
_CONNECTUS_REPO_ENV = "CONNECTUS_REPO_DIR"


def content_root() -> Path:
    """Return the content-repo root.

    ``find_repo_root()`` (env_loader) walks up to the nearest ``pyproject.toml``
    / ``.git`` marker. In this workspace that marker is the content repo itself
    (``content/``), so the repo root IS the content root. If instead a higher
    workspace root is returned, fall back to ``<root>/content``.
    """
    root = find_repo_root()
    if (root / "Packs").is_dir():
        return root
    nested = root / _CONTENT_DIRNAME
    if (nested / "Packs").is_dir():
        return nested
    return root


def connectus_repo_root() -> Path:
    """Return the unified-connectors-content repo root.

    Resolution order:
      1. ``$CONNECTUS_REPO_DIR`` when set (explicit override).
      2. A ``unified-connectors-content`` directory that is a SIBLING of the
         content root (the canonical workspace layout: ``content/`` and
         ``unified-connectors-content/`` side by side).
      3. ``<content-root>/unified-connectors-content`` (nested fallback).

    Raises:
        ResolutionError: if none of the candidates contain a ``connectors``
            directory — the engineer must point CONNECTUS_REPO_DIR at the
            checkout.
    """
    override = os.environ.get(_CONNECTUS_REPO_ENV)
    if override and override.strip():
        return Path(os.path.abspath(override.strip()))

    croot = content_root()
    candidates = [
        croot.parent / _CONNECTUS_REPO_DIRNAME,  # sibling (canonical)
        croot / _CONNECTUS_REPO_DIRNAME,         # nested fallback
        find_repo_root() / _CONNECTUS_REPO_DIRNAME,
    ]
    for cand in candidates:
        if (cand / "connectors").is_dir():
            return cand
    raise ResolutionError(
        "Could not locate the unified-connectors-content repo. Tried: "
        + ", ".join(str(c) for c in candidates)
        + ". Set CONNECTUS_REPO_DIR to the checkout path."
    )


def connectors_root() -> Path:
    """Return the ``connectors/`` directory under the connectus repo."""
    return connectus_repo_root() / "connectors"


# Git-ignored staging dir for intermediate doc-specs (NOT inside the connector
# folder, which holds only published files).
_DOC_SPEC_STAGING_DIRNAME = ".doc_specs"


def doc_spec_staging_dir() -> Path:
    """Return (creating if needed) the git-ignored doc-spec staging directory.

    Doc-specs are intermediate artifacts consumed by validate/apply; they live
    here under the connectus repo (``.doc_specs/``) instead of polluting the
    connector folder.
    """
    d = connectus_repo_root() / _DOC_SPEC_STAGING_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def doc_spec_path(slug: str) -> Path:
    """Return the staging path for a connector's doc-spec (``.doc_specs/<slug>.json``)."""
    return doc_spec_staging_dir() / f"{slug}.json"


def pipeline_csv_path() -> Path:
    """Return the absolute path to the migration pipeline CSV.

    Derived from :func:`content_root` (``<content>/connectus/...``).
    """
    return content_root() / _PIPELINE_CSV_RELPATH


# --------------------------------------------------------------------------- #
# Slug rule (§8.6)
# --------------------------------------------------------------------------- #
def slugify(value: str) -> str:
    """Canonical view_group id slug: ``lower()`` with spaces collapsed to ``-``.

    Matches the migration convention used to derive ``view_groups[].id`` from an
    integration's ``commonfields.id`` / ``commonfields.name``. Runs of
    whitespace become a single ``-``; surrounding whitespace is trimmed.

    Separating punctuation BETWEEN word characters (``.`` or ``/``, e.g. the dot
    in ``Tenable.io`` / ``AppSentinels.ai``) acts as a SEPARATOR and becomes a
    hyphen — matching the migration, which emits view_group ids ``tenable-io`` /
    ``tenable-sc`` (NOT ``tenableio``). Other punctuation (e.g. parentheses) is
    dropped; existing hyphens are kept as separators; then any run of whitespace
    and/or hyphens is collapsed to a single ``-`` (leading/trailing hyphens
    trimmed). This matches the migration's clean-slug convention, where ``AWS-EKS``
    stays ``aws-eks`` while ``... (O365 Azure Events)`` loses its parentheses.

    >>> slugify("GuardiCore v2")
    'guardicore-v2'
    >>> slugify("Akamai WAF SIEM")
    'akamai-waf-siem'
    >>> slugify("AWS-EKS")
    'aws-eks'
    >>> slugify("AWS - IAM (user lifecycle management)")
    'aws-iam-user-lifecycle-management'
    >>> slugify("Microsoft Management Activity API (O365 Azure Events)")
    'microsoft-management-activity-api-o365-azure-events'
    >>> slugify("AppSentinels.ai")
    'appsentinels-ai'
    >>> slugify("Tenable.io")
    'tenable-io'
    >>> slugify("abuse.ch SSL Blacklist Feed")
    'abuse-ch-ssl-blacklist-feed'
    """
    lowered = value.strip().lower()
    # Separating punctuation (``.`` / ``/``) BETWEEN word chars becomes a
    # separator (``Tenable.io`` -> ``tenable-io``), matching the migration.
    lowered = re.sub(r"(?<=[0-9a-z])[./](?=[0-9a-z])", "-", lowered)
    # Drop remaining punctuation EXCEPT hyphens and whitespace, then collapse
    # runs of whitespace/hyphens to a single hyphen.
    cleaned = re.sub(r"[^0-9a-z\s-]", "", lowered)
    return re.sub(r"[\s-]+", "-", cleaned).strip("-")


def _readme_fallback_allowed(integration_id: str) -> bool:
    """True if README-as-PRIMARY fallback is authorized for this integration.

    The engineer authorizes specific members (those that never shipped a
    ``*_description.md``) by listing their Integration IDs, comma-separated, in
    the ``DOC_README_FALLBACK`` environment variable. Matching is exact on the
    trimmed Integration ID. Empty/unset env var means no fallback (the
    no-invention default).
    """
    raw = os.environ.get("DOC_README_FALLBACK", "")
    allow = {part.strip() for part in raw.split(",") if part.strip()}
    return integration_id.strip() in allow


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ConnectorPaths:
    """Resolved connector folder and its five documentation YAMLs.

    A YAML path attribute is ``None`` only when that file legitimately does not
    exist; callers that REQUIRE a file (e.g. connection.yaml) must check and
    raise. The folder itself is validated to exist by :func:`resolve_connector`.
    """

    slug: str
    folder: Path
    connector_yaml: Optional[Path]
    capabilities_yaml: Optional[Path]
    connection_yaml: Optional[Path]
    configurations_yaml: Optional[Path]
    summary_yaml: Optional[Path]

    @property
    def is_grouped(self) -> bool:
        """True when ``connector.yaml settings.grouped`` is ``True``."""
        if not self.connector_yaml or not self.connector_yaml.exists():
            return False
        data = _load_yaml(self.connector_yaml)
        return bool((data.get("settings") or {}).get("grouped") is True)


@dataclass(frozen=True)
class MemberRow:
    """A single member integration row from the pipeline CSV."""

    integration_id: str        # CSV "Integration ID" == commonfields.name/id
    integration_yml_relpath: str  # relative to content/ (Packs/...)
    connector_id: str
    connector_folder_relpath: str  # relative to connectus repo (connectors/...)
    csv_row_index: int         # 1-based data row index (excludes header)


@dataclass(frozen=True)
class MemberFiles:
    """Resolved source files for one member integration.

    REQUIRED files (``integration_yml``, ``description_md``) are guaranteed
    non-``None`` — :func:`resolve_member_files` raises :class:`ResolutionError`
    if either is missing. The gap-fill files may be ``None``; their absence is
    recorded in ``warnings``.
    """

    integration_id: str
    expected_view_group_id: str    # slugify(commonfields.id)
    commonfields_id: Optional[str]
    commonfields_name: Optional[str]
    integration_yml: Path               # REQUIRED
    description_md: Path                 # REQUIRED — PRIMARY source (§2)
    integration_readme: Optional[Path]  # gap-fill (may be None)
    pack_readme: Optional[Path]         # gap-fill (may be None)
    pack_metadata: Optional[Path]       # gap-fill (may be None)
    warnings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ViewGroup:
    """A ``view_groups[]`` entry from connection.yaml."""

    id: str
    label: str
    help_text: str


@dataclass(frozen=True)
class ProfileInfo:
    """A ``profiles[]`` entry from connection.yaml (§8.3a.1).

    ``title``/``description`` are the CURRENT verbatim values (may be ``None``
    when the profile omits them — absence is normal, never raised).
    """

    id: str
    type: str
    view_group: str
    title: Optional[str]
    description: Optional[str]


@dataclass
class ConnectorResolution:
    """Everything stage A produces for one connector."""

    paths: ConnectorPaths
    members: List[MemberRow] = field(default_factory=list)
    view_groups: List[ViewGroup] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Resolvers
# --------------------------------------------------------------------------- #
def resolve_connector(slug: str) -> ConnectorPaths:
    """Locate a connector folder and its five documentation YAMLs by slug.

    Raises:
        ResolutionError: if the connector folder does not exist.
    """
    folder = connectors_root() / slug
    if not folder.is_dir():
        raise ResolutionError(
            f"Connector folder not found for slug '{slug}': {folder}. "
            f"Check the slug and that CONNECTUS_REPO_DIR points at the "
            f"unified-connectors-content checkout."
        )

    def _opt(name: str) -> Optional[Path]:
        p = folder / name
        return p if p.exists() else None

    return ConnectorPaths(
        slug=slug,
        folder=folder,
        connector_yaml=_opt("connector.yaml"),
        capabilities_yaml=_opt("capabilities.yaml"),
        connection_yaml=_opt("connection.yaml"),
        configurations_yaml=_opt("configurations.yaml"),
        summary_yaml=_opt("summary.yaml"),
    )


def _read_csv_rows(csv_path: Path) -> List[Dict[str, str]]:
    """Read the pipeline CSV into a list of dict rows (header-keyed).

    Raises:
        ResolutionError: if the CSV is missing or unreadable.
    """
    import csv

    if not csv_path.exists():
        raise ResolutionError(f"Pipeline CSV not found: {csv_path}")
    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except Exception as exc:
        raise ResolutionError(f"Failed to read pipeline CSV {csv_path}: {exc}") from exc


def resolve_members(slug: str, csv_path: Optional[Path] = None) -> List[MemberRow]:
    """Return the member integration rows for ``slug`` from the pipeline CSV.

    Matching is on the ``Connector Folder Path`` column, whose value is
    ``connectors/<slug>`` (or any path ending in ``/<slug>``). This is the
    authoritative connector -> integration(s) mapping.

    Raises:
        ResolutionError: if NO member rows match the slug (a grouped connector
            must have at least one member; zero matches means the slug is wrong
            or the CSV is out of sync — the engineer must decide).
    """
    csv_path = csv_path or pipeline_csv_path()
    rows = _read_csv_rows(csv_path)
    members: List[MemberRow] = []
    for i, row in enumerate(rows, start=1):
        folder = (row.get("Connector Folder Path") or "").strip()
        if not folder:
            continue
        folder_slug = folder.rstrip("/").rsplit("/", 1)[-1]
        if folder_slug != slug:
            continue
        members.append(
            MemberRow(
                integration_id=(row.get("Integration ID") or "").strip(),
                integration_yml_relpath=(row.get("Integration File Path") or "").strip(),
                connector_id=(row.get("Connector ID") or "").strip(),
                connector_folder_relpath=folder,
                csv_row_index=i,
            )
        )
    if not members:
        raise ResolutionError(
            f"No member rows found in the pipeline CSV for connector slug "
            f"'{slug}' (matched on 'Connector Folder Path' ending in '/{slug}'). "
            f"CSV: {csv_path}"
        )
    return members


def _integration_yml_abspath(relpath: str) -> Optional[Path]:
    """Resolve a CSV integration YML relpath (``Packs/...``) to an abs path."""
    if not relpath:
        return None
    p = content_root() / relpath
    return p if p.exists() else None


def resolve_member_files(member: MemberRow) -> MemberFiles:
    """Resolve all source files for a single member integration.

    Layout per AGENTS.md:
    ``Packs/<Pack>/Integrations/<Integration>/<Integration>.yml`` with a sibling
    ``<Integration>_description.md`` and ``README.md``; the pack README +
    ``pack_metadata.json`` live at ``Packs/<Pack>/``.

    Raises:
        ResolutionError: if the member has no ``Integration File Path``, if the
            integration YML does not exist, or if the PRIMARY
            ``<integration>_description.md`` is missing. These are blocking —
            documentation cannot be authored without them.
    """
    if not member.integration_yml_relpath:
        raise ResolutionError(
            f"Member '{member.integration_id}' (CSV row {member.csv_row_index}) "
            f"has an empty 'Integration File Path'."
        )

    yml = _integration_yml_abspath(member.integration_yml_relpath)
    if yml is None:
        raise ResolutionError(
            f"Integration YML not found for member '{member.integration_id}': "
            f"{content_root() / member.integration_yml_relpath} "
            f"(CSV row {member.csv_row_index})."
        )

    data = _load_yaml(yml)
    cf = data.get("commonfields") or {}
    commonfields_id = cf.get("id")
    # The view_group label is the integration's human-facing display name.
    # Prefer the top-level `display:` (e.g. "Microsoft Sentinel"); fall back to
    # the legacy `name:` and finally commonfields.id.
    commonfields_name = data.get("display") or data.get("name") or cf.get("id")

    integ_dir = yml.parent
    stem = yml.stem  # e.g. "Akamai_WAF"
    desc = integ_dir / f"{stem}_description.md"
    readme = integ_dir / "README.md"
    warnings: List[str] = []

    if not desc.exists():
        # No-invention default: a missing PRIMARY description.md is BLOCKING.
        # Exception: the engineer may explicitly authorize a README fallback for
        # specific members (e.g. integrations that never shipped a
        # *_description.md). Authorization is an allowlist of integration IDs in
        # the DOC_README_FALLBACK env var (comma-separated). Only those members
        # fall back to README.md AS the PRIMARY source; everyone else still
        # hard-stops so accidental gaps are never silently masked.
        if _readme_fallback_allowed(member.integration_id) and readme.exists():
            warnings.append(
                f"PRIMARY description.md missing for '{member.integration_id}'; "
                f"using README.md as the PRIMARY source per authorized "
                f"DOC_README_FALLBACK allowlist."
            )
            description_md = readme
        else:
            raise ResolutionError(
                f"PRIMARY description file missing for member "
                f"'{member.integration_id}': {desc}. The connection help_text is "
                f"authored from this file (§2); it cannot be invented. Ask the "
                f"engineer how to proceed. (To authorize a README fallback for "
                f"this member, add its Integration ID to the DOC_README_FALLBACK "
                f"environment variable.)"
            )
    else:
        description_md = desc

    integration_readme = readme if readme.exists() else None
    if integration_readme is None:
        warnings.append(f"No integration README at {readme} (gap-fill only).")

    # Pack root = parent of "Integrations/" (i.e. integ_dir.parent.parent).
    pack_dir = integ_dir.parent.parent
    p_readme = pack_dir / "README.md"
    pack_readme = p_readme if p_readme.exists() else None
    if pack_readme is None:
        warnings.append(f"No pack README at {p_readme} (gap-fill only).")

    p_meta = pack_dir / "pack_metadata.json"
    pack_metadata = p_meta if p_meta.exists() else None
    if pack_metadata is None:
        warnings.append(f"No pack_metadata.json at {p_meta} (gap-fill only).")

    basis = commonfields_id or member.integration_id
    expected_vg_id = slugify(basis) if basis else ""

    return MemberFiles(
        integration_id=member.integration_id,
        expected_view_group_id=expected_vg_id,
        commonfields_id=commonfields_id,
        commonfields_name=commonfields_name,
        integration_yml=yml,
        description_md=description_md,
        integration_readme=integration_readme,
        pack_readme=pack_readme,
        pack_metadata=pack_metadata,
        warnings=warnings,
    )


def resolve_view_groups(paths: ConnectorPaths) -> List[ViewGroup]:
    """Return the ``view_groups[]`` declared in connection.yaml.

    Raises:
        ResolutionError: if connection.yaml is missing (a grouped connector
            must have one) or declares no view_groups.
    """
    if not paths.connection_yaml or not paths.connection_yaml.exists():
        raise ResolutionError(
            f"connection.yaml not found for connector '{paths.slug}' at "
            f"{paths.folder / 'connection.yaml'}."
        )
    data = _load_yaml(paths.connection_yaml)
    raw = data.get("view_groups") or []
    out: List[ViewGroup] = []
    for vg in raw:
        if not isinstance(vg, dict):
            continue
        out.append(
            ViewGroup(
                id=str(vg.get("id", "")),
                label=str(vg.get("label", "")),
                help_text=str(vg.get("help_text", "")),
            )
        )
    if not out:
        raise ResolutionError(
            f"connection.yaml for connector '{paths.slug}' declares no "
            f"view_groups[]; a grouped connector must have at least one."
        )
    return out


def resolve_config_view_groups(paths: ConnectorPaths) -> List[ViewGroup]:
    """Return the ``view_groups[]`` declared in configurations.yaml (id/label/help_text).

    Unlike :func:`resolve_view_groups` (connection.yaml, REQUIRED), this is
    NON-RAISING: configurations.yaml is optional and a connector may legitimately
    declare no config view_groups. Returns ``[]`` when the file is missing or
    declares no view_groups. Surfaces the on-disk config help_text so the §9.13
    final-state audit can inspect migration boilerplate the doc-spec never
    addressed (e.g. ``"Configurations settings for X."``).
    """
    if not paths.configurations_yaml or not paths.configurations_yaml.exists():
        return []
    data = _load_yaml(paths.configurations_yaml)
    raw = data.get("view_groups") or []
    out: List[ViewGroup] = []
    for vg in raw:
        if not isinstance(vg, dict):
            continue
        out.append(
            ViewGroup(
                id=str(vg.get("id", "")),
                label=str(vg.get("label", "")),
                help_text=str(vg.get("help_text", "")),
            )
        )
    return out


def resolve_profiles_by_view_group(paths: ConnectorPaths) -> Dict[str, List[str]]:
    """Map ``view_group`` id -> list of profile ids bound to it (§5).

    Read directly from ``connection.yaml profiles[].view_group`` — handler files
    are NOT needed.

    Raises:
        ResolutionError: if connection.yaml is missing.
    """
    if not paths.connection_yaml or not paths.connection_yaml.exists():
        raise ResolutionError(
            f"connection.yaml not found for connector '{paths.slug}' at "
            f"{paths.folder / 'connection.yaml'}."
        )
    data = _load_yaml(paths.connection_yaml)
    result: Dict[str, List[str]] = {}
    for prof in data.get("profiles") or []:
        if not isinstance(prof, dict):
            continue
        vg = prof.get("view_group")
        if vg is None:
            continue
        result.setdefault(str(vg), []).append(str(prof.get("id", "")))
    return result


def resolve_profiles(paths: ConnectorPaths) -> List[ProfileInfo]:
    """Return the ``profiles[]`` declared in connection.yaml (§8.3a.1).

    Reads ``connection.yaml profiles[]`` once and emits a :class:`ProfileInfo`
    per profile, carrying the auth ``type``, owning ``view_group`` and the
    CURRENT ``title``/``description`` (``None`` when absent — absence is normal
    and never raised).

    Raises:
        ResolutionError: if connection.yaml is missing (fail-loud parity with
            :func:`resolve_profiles_by_view_group`).
    """
    if not paths.connection_yaml or not paths.connection_yaml.exists():
        raise ResolutionError(
            f"connection.yaml not found for connector '{paths.slug}' at "
            f"{paths.folder / 'connection.yaml'}."
        )
    data = _load_yaml(paths.connection_yaml)
    out: List[ProfileInfo] = []
    for prof in data.get("profiles") or []:
        if not isinstance(prof, dict):
            continue
        title = prof.get("title")
        description = prof.get("description")
        out.append(
            ProfileInfo(
                id=str(prof.get("id", "")),
                type=str(prof.get("type", "")),
                view_group=str(prof.get("view_group", "")),
                title=str(title) if title is not None else None,
                description=str(description) if description is not None else None,
            )
        )
    return out


def _iter_field_ids_with_view_group(node, inherited_vg=None):
    """Yield ``(view_group, field_id)`` from a connection/configurations tree.

    Walks profiles / capability groups that carry a ``view_group`` and collects
    every ``configurations[].fields[].id`` beneath them. ``inherited_vg`` lets a
    parent's view_group apply to nested field groups that do not restate it.
    """
    if isinstance(node, dict):
        vg = node.get("view_group", inherited_vg)
        if "fields" in node and isinstance(node["fields"], list):
            for fld in node["fields"]:
                if isinstance(fld, dict) and "id" in fld:
                    yield (vg, str(fld["id"]))
        for key, value in node.items():
            if key == "fields":
                continue
            yield from _iter_field_ids_with_view_group(value, vg)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_field_ids_with_view_group(item, inherited_vg)


def resolve_config_params_by_view_group(paths: ConnectorPaths) -> Dict[str, List[str]]:
    """Map ``view_group`` id -> configuration field ids bound to it.

    Aggregates field ids across BOTH ``connection.yaml`` and
    ``configurations.yaml`` so the authoring stage can describe the existing
    bound fields when no config prose exists (§8.4). Field ids are de-duplicated
    while preserving first-seen order; entries with no resolvable view_group are
    grouped under the empty-string key.
    """
    result: Dict[str, List[str]] = {}
    for yaml_path in (paths.connection_yaml, paths.configurations_yaml):
        if not yaml_path or not yaml_path.exists():
            continue
        data = _load_yaml(yaml_path)
        for vg, field_id in _iter_field_ids_with_view_group(data):
            key = str(vg) if vg is not None else ""
            bucket = result.setdefault(key, [])
            if field_id not in bucket:
                bucket.append(field_id)
    return result


def resolve(slug: str, csv_path: Optional[Path] = None) -> ConnectorResolution:
    """Convenience aggregate resolver for one connector (stage A).

    Raises:
        ResolutionError: propagated from any underlying resolver. Callers
            (SKILL.md) catch this and ask the engineer how to continue.
    """
    paths = resolve_connector(slug)
    return ConnectorResolution(
        paths=paths,
        members=resolve_members(slug, csv_path=csv_path),
        view_groups=resolve_view_groups(paths),
    )
