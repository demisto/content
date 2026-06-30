"""Stage B (GATHER): turn resolved files into clean source bundles for authoring.

The gatherers read the files located in stage A and apply the deterministic
mechanical trims from :mod:`markdown_processing` so the AI authoring stage (C)
receives ONLY ConnectUs-relevant, command-free prose:

* :func:`read_description_md` — the PRIMARY source (§2). Conditional-stripped
  (§10) and command-stripped (§3.2), since description.md may occasionally carry
  a stray command reference.
* :func:`read_readme_for_gapfill` — a README, command-stripped THEN
  conditional-stripped, labeled by origin.
* :func:`gather_member` — the full per-member bundle: primary text + gap-fill
  texts + the section index + the length-governor figure + bound profiles/config
  field ids + the resolver warnings.
* :func:`gather_connector` — every member bundle for a connector, plus the
  view_groups and the correctness-flag pre-check (§8.6) results.

FAIL-LOUD: gatherers propagate :class:`resolvers.ResolutionError` unchanged —
they never paper over a missing required source.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(__file__))

from markdown_processing import (  # noqa: E402
    Section,
    build_section_index,
    strip_command_sections,
    strip_conditionals,
)
from resolvers import (  # noqa: E402
    ConnectorPaths,
    MemberFiles,
    MemberRow,
    ProfileInfo,
    ViewGroup,
    resolve_config_params_by_view_group,
    resolve_config_view_groups,
    resolve_connector,
    resolve_member_files,
    resolve_members,
    resolve_profiles,
    resolve_profiles_by_view_group,
    resolve_view_groups,
)


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #
def _clean_markdown(text: str) -> str:
    """Apply the GATHER trims in canonical order: commands then conditionals.

    Command stripping first removes the whole ``## Commands`` block (and any
    stray command-slug blocks); conditional stripping then resolves
    platform conditionals on what remains.
    """
    return strip_conditionals(strip_command_sections(text))


def read_description_md(path: Path) -> str:
    """Read and clean the PRIMARY ``<integration>_description.md`` (§2).

    Args:
        path: Absolute path to the description.md.

    Returns:
        Cleaned Markdown (command + conditional stripped).
    """
    raw = path.read_text(encoding="utf-8")
    return _clean_markdown(raw)


def read_readme_for_gapfill(path: Path) -> str:
    """Read and clean a README used for gap-fill.

    Args:
        path: Absolute path to a README.md.

    Returns:
        Cleaned Markdown (command + conditional stripped).
    """
    raw = path.read_text(encoding="utf-8")
    return _clean_markdown(raw)


# --------------------------------------------------------------------------- #
# Bundles
# --------------------------------------------------------------------------- #
@dataclass
class ProfileSource:
    """Per-profile facts the author needs to judge the §8.3a high bar.

    Carries the auth ``type`` and CURRENT ``title``/``description`` (verbatim,
    ``None`` when absent) plus the owning view_group + member context. The
    validator's §9.11 jargon ban-list is built from ``type``.
    """

    id: str
    type: str
    view_group: str
    view_group_label: str
    title: Optional[str]
    description: Optional[str]
    integration_id: str
    commonfields_name: Optional[str]


@dataclass
class MemberBundle:
    """The cleaned, ready-to-author source bundle for one member integration."""

    integration_id: str
    expected_view_group_id: str
    commonfields_id: Optional[str]
    commonfields_name: Optional[str]

    # PRIMARY source (§2), cleaned.
    description_md: str
    description_md_len: int           # §2.2 length governor input (chars)
    description_sections: List[Section]

    # Gap-fill sources, cleaned + labeled (origin -> text). Only present files.
    gapfill: Dict[str, str] = field(default_factory=dict)

    # Structural context for the authoring + validation stages.
    profile_ids: List[str] = field(default_factory=list)
    config_field_ids: List[str] = field(default_factory=list)

    # Per-profile sources (§8.3a) scoped to this member's view_group. Additive
    # to profile_ids (which is retained for the existing checks).
    profiles: List[ProfileSource] = field(default_factory=list)

    # Non-blocking notices (missing gap-fill files, etc.).
    warnings: List[str] = field(default_factory=list)


@dataclass
class ViewGroupFlag:
    """A §8.6 correctness pre-check result for one view_group / member."""

    view_group_id: str
    label: str
    expected_id: str
    expected_label: str
    id_ok: bool
    label_ok: bool

    @property
    def is_flag(self) -> bool:
        """True when the view_group id or label does NOT match expectation."""
        return not (self.id_ok and self.label_ok)


@dataclass
class ConnectorBundle:
    """Every member bundle for a connector + structural metadata.

    ``view_groups`` carries the on-disk CONNECTION view_groups (connection.yaml,
    id/label/help_text); ``config_view_groups`` carries the on-disk
    CONFIGURATION view_groups (configurations.yaml). Both surface the real
    on-disk ``help_text`` so the §9.13 final-state audit can inspect migration
    boilerplate the doc-spec never authored. ``config_view_groups`` is additive
    and defaults to ``[]`` so existing bundle consumers are unaffected.
    """

    slug: str
    paths: ConnectorPaths
    view_groups: List[ViewGroup]
    members: List[MemberBundle] = field(default_factory=list)
    view_group_flags: List[ViewGroupFlag] = field(default_factory=list)
    config_view_groups: List[ViewGroup] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Gatherers
# --------------------------------------------------------------------------- #
def gather_member(
    member: MemberRow,
    profiles_by_vg: Dict[str, List[str]],
    config_by_vg: Dict[str, List[str]],
    profiles: Optional[List[ProfileInfo]] = None,
    view_group_labels: Optional[Dict[str, str]] = None,
) -> MemberBundle:
    """Build the cleaned source bundle for one member integration.

    Args:
        member: The CSV member row.
        profiles_by_vg: Output of ``resolve_profiles_by_view_group``.
        config_by_vg: Output of ``resolve_config_params_by_view_group``.
        profiles: Output of ``resolve_profiles`` (all connector profiles); the
            member's own profiles[] is filtered by view_group (§8.3a).
        view_group_labels: view_group id -> human label, for attaching the
            profile's ``view_group_label``.

    Returns:
        A :class:`MemberBundle`.

    Raises:
        resolvers.ResolutionError: propagated when a required source is missing.
    """
    files: MemberFiles = resolve_member_files(member)

    description_md = read_description_md(files.description_md)
    sections = build_section_index(description_md)

    gapfill: Dict[str, str] = {}
    if files.integration_readme is not None:
        text = read_readme_for_gapfill(files.integration_readme)
        if text.strip():
            gapfill["integration_readme"] = text
    if files.pack_readme is not None:
        text = read_readme_for_gapfill(files.pack_readme)
        if text.strip():
            gapfill["pack_readme"] = text

    vg_id = files.expected_view_group_id
    labels = view_group_labels or {}
    member_profiles = [
        ProfileSource(
            id=p.id,
            type=p.type,
            view_group=p.view_group,
            view_group_label=labels.get(p.view_group, ""),
            title=p.title,
            description=p.description,
            integration_id=files.integration_id,
            commonfields_name=files.commonfields_name,
        )
        for p in (profiles or [])
        if p.view_group == vg_id
    ]
    return MemberBundle(
        integration_id=files.integration_id,
        expected_view_group_id=vg_id,
        commonfields_id=files.commonfields_id,
        commonfields_name=files.commonfields_name,
        description_md=description_md,
        description_md_len=len(description_md),
        description_sections=sections,
        gapfill=gapfill,
        profile_ids=list(profiles_by_vg.get(vg_id, [])),
        config_field_ids=list(config_by_vg.get(vg_id, [])),
        profiles=member_profiles,
        warnings=list(files.warnings),
    )


def _view_group_flags(
    view_groups: List[ViewGroup], members: List[MemberBundle]
) -> List[ViewGroupFlag]:
    """Compute §8.6 correctness pre-checks pairing members to view_groups.

    For each member, the expected view_group id is ``slugify(commonfields.id)``
    and the expected label is the raw ``commonfields.name``. We look up the
    declared view_group with that id and compare the label.
    """
    vg_by_id = {vg.id: vg for vg in view_groups}
    flags: List[ViewGroupFlag] = []
    for m in members:
        declared = vg_by_id.get(m.expected_view_group_id)
        id_ok = declared is not None
        expected_label = m.commonfields_name or ""
        label_ok = declared is not None and declared.label == expected_label
        flags.append(
            ViewGroupFlag(
                view_group_id=(declared.id if declared else m.expected_view_group_id),
                label=(declared.label if declared else ""),
                expected_id=m.expected_view_group_id,
                expected_label=expected_label,
                id_ok=id_ok,
                label_ok=label_ok,
            )
        )
    return flags


def gather_connector(slug: str) -> ConnectorBundle:
    """Build the full GATHER bundle for a connector (all members).

    Args:
        slug: The connector slug (e.g. ``akamai``).

    Returns:
        A :class:`ConnectorBundle`.

    Raises:
        resolvers.ResolutionError: propagated from stage A when any required
            source is missing/broken (the skill then asks the engineer).
    """
    paths = resolve_connector(slug)
    view_groups = resolve_view_groups(paths)
    config_view_groups = resolve_config_view_groups(paths)
    profiles_by_vg = resolve_profiles_by_view_group(paths)
    config_by_vg = resolve_config_params_by_view_group(paths)
    profiles = resolve_profiles(paths)
    view_group_labels = {vg.id: vg.label for vg in view_groups}

    member_rows = resolve_members(slug)
    members = [
        gather_member(
            m, profiles_by_vg, config_by_vg, profiles, view_group_labels
        )
        for m in member_rows
    ]
    flags = _view_group_flags(view_groups, members)

    return ConnectorBundle(
        slug=slug,
        paths=paths,
        view_groups=view_groups,
        members=members,
        view_group_flags=flags,
        config_view_groups=config_view_groups,
    )


def bundle_to_dict(bundle: ConnectorBundle) -> dict:
    """Serialize a :class:`ConnectorBundle` to a JSON-friendly dict.

    This is the single payload the AI authoring stage (C) reads — it carries the
    cleaned per-member sources, the length-governor figures, the bound
    profiles/config field ids, and the §8.6 view_group flag pre-checks, so the
    author does NOT need to read the raw files again.
    """
    return {
        "slug": bundle.slug,
        "view_groups": [
            {"id": vg.id, "label": vg.label} for vg in bundle.view_groups
        ],
        "config_view_groups": [
            {"id": vg.id, "label": vg.label, "help_text": vg.help_text}
            for vg in bundle.config_view_groups
        ],
        "view_group_flags": [
            {
                "view_group_id": f.view_group_id,
                "label": f.label,
                "expected_id": f.expected_id,
                "expected_label": f.expected_label,
                "id_ok": f.id_ok,
                "label_ok": f.label_ok,
                "is_flag": f.is_flag,
            }
            for f in bundle.view_group_flags
        ],
        "members": [
            {
                "integration_id": m.integration_id,
                "view_group_id": m.expected_view_group_id,
                "commonfields_id": m.commonfields_id,
                "commonfields_name": m.commonfields_name,
                "description_md": m.description_md,
                "description_md_len": m.description_md_len,
                "sections": [s.title for s in m.description_sections],
                "gapfill": m.gapfill,
                "profile_ids": m.profile_ids,
                "profiles": [
                    {
                        "id": p.id,
                        "type": p.type,
                        "view_group": p.view_group,
                        "view_group_label": p.view_group_label,
                        "title": p.title,
                        "description": p.description,
                        "integration_id": p.integration_id,
                        "commonfields_name": p.commonfields_name,
                    }
                    for p in m.profiles
                ],
                "config_field_ids": m.config_field_ids,
                "warnings": m.warnings,
            }
            for m in bundle.members
        ],
    }


def main(argv=None) -> int:
    """CLI: print the gathered bundle for a connector as JSON (stage B output).

    Usage::

        python3 -m connectus_docs.gatherers <slug>
    """
    import argparse
    import json

    from resolvers import ResolutionError

    parser = argparse.ArgumentParser(description="Gather cleaned doc sources for a connector.")
    parser.add_argument("slug", help="connector slug, e.g. akamai")
    args = parser.parse_args(argv)
    try:
        bundle = gather_connector(args.slug)
    except ResolutionError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(bundle_to_dict(bundle), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
