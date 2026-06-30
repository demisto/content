"""Stage D (VALIDATE): gate an AI-authored doc-spec before it is applied.

This is the gate-first guardrail. It checks a ``doc-spec.json`` against:

1. The JSON schema (``doc-spec.schema.json``) — structural shape.
2. The custom §9 rules, cross-referenced against ON-DISK truth via the gatherers:
   * §9.2  connector.description >= 10 chars; <= ~4 lines (soft warn).
   * §9.3  every capability id present with a non-empty description drawn from
           the closed table (``capability_descriptions.json``); unknown id fails.
   * §9.4  connection: exactly one help_text per member (REQUIRED);
           configurations: help_text per member is OPTIONAL.
   * §9.5  no ``__FLAG__`` sentinel anywhere -> hard fail (lists each).
   * §9.6  summary.next_steps omitted/null OR a non-empty string.
   * §9.7  no-commands heuristic on every help_text + connector.description.
   * §9.8  length-governor soft-warn (help_text > ~2x description_md_len).
   * §9.9  view_group id == slugify(commonfields.id) AND label ==
           commonfields.name (hard fail per mismatch).
    * §9.10 link-preservation: every URL in the source description.md must appear
            in the member's connection help_text. HARD error when the help_text
            is AUTHORED (a dropped link is a fidelity loss); soft warn only when
            the help_text key was omitted (on-disk value untouched). help_text
            must use valid Markdown links.
    * §9.14 no stray escaped bang ``\\!`` in authored copy (hard fail).
    * §9.15 command-token preservation: any inline setup/auth command name in the
            source (``!foo-bar-baz`` slugs and ``!CamelCase`` bang-commands) must
            survive into AUTHORED connection help_text (hard fail when dropped /
            genericized / summarized away).
    * §9.17 terminology: the word "incident"/"incidents" in AUTHORED prose
            (help_text / connector.description / profile fields) is a hard fail;
            the platform term is "issue" ("fetch issues", not "fetch incidents").
            Machine field ids are not inspected.

Outcome: a :class:`ValidationReport` with errors (block apply) + warnings
(advisory). ``main`` exits non-zero on any error so it can act as a CI gate.

Usage::

    python3 validate_doc_spec.py <slug> <path/to/doc-spec.json>
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(__file__))

from gatherers import ConnectorBundle, gather_connector  # noqa: E402
from resolvers import ResolutionError, doc_spec_path, slugify  # noqa: E402

_FLAG_SENTINEL = "__FLAG__"
_SCHEMA_PATH = Path(__file__).resolve().parent / "doc-spec.schema.json"
_CAP_TABLE_PATH = Path(__file__).resolve().parent / "capability_descriptions.json"

# A bare command reference heading or base-command/context-output marker.
_COMMAND_MARKERS = (
    re.compile(r"^##\s+Commands\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^###\s+[a-z0-9]+(?:-[a-z0-9]+)*\s*$", re.MULTILINE),
    re.compile(r"^####\s+Base Command\s*$", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^####\s+Context Output\s*$", re.IGNORECASE | re.MULTILINE),
)
# INLINE command tokens in setup/auth instructions, for the §9.15 command-
# preservation fidelity gate. Two recognized shapes:
#   (a) a hyphenated slug with >=2 hyphen segments (e.g. `foo-bar-baz`,
#       `microsoft-teams-auth-start`) — the leading `!` is OPTIONAL; the slug
#       shape alone is command-like.
#   (b) a BANG-PREFIXED single token (e.g. `!CreateCertificate`, `!DeleteContext`)
#       — here the leading `!` is REQUIRED, since a bare CamelCase/word token is
#       not necessarily a command.
_INLINE_COMMAND_SLUG_RE = re.compile(r"!?\b[a-z][a-z0-9]*(?:-[a-z0-9]+){2,}\b")
_INLINE_COMMAND_BANG_RE = re.compile(r"!([A-Za-z][A-Za-z0-9_]+)\b")

# §9.17 terminology gate. The platform term is "issue", not "incident". Match the
# whole word "incident"/"incidents" (case-insensitive) in AUTHORED PROSE only.
# A whole-word boundary excludes machine identifiers like ``incidentType`` /
# ``incident-type`` (no word boundary between "incident" and "Type"/"-type"...
# actually ``-`` IS a boundary, so ``incident-type`` would match; but the doc-spec
# AUTHORED fields are prose — field ids/dynamicField keys live in the generated
# YAML, NOT in the doc-spec the validator inspects — so prose matches are safe).
_INCIDENT_TERM_RE = re.compile(r"\bincidents?\b", re.IGNORECASE)

# Any http(s) URL (used by the link-preservation check).
_URL_RE = re.compile(r"https?://[^\s)\]\"'>]+")

# §9.13 boilerplate templates. Matched WHOLE-STRING (anchored), case-insensitive,
# against the normalized help_text; ``<X>`` = ``.+``. See _normalize_for_boilerplate.
_BOILERPLATE_TEMPLATES = (
    re.compile(r"^configuration settings for .+$"),
    # Plural variants are the actual migration output (e.g.
    # "Configurations settings for HashiCorp Vault."), so they MUST be caught.
    re.compile(r"^configurations settings for .+$"),
    re.compile(r"^connection settings for .+$"),
    re.compile(r"^connections settings for .+$"),
    re.compile(r"^settings for .+$"),
    re.compile(r"^.+ settings$"),
    re.compile(r"^.+ configuration$"),
    re.compile(r"^.+ configuration settings$"),
)
# Trailing punctuation stripped during boilerplate normalization (step 3).
_BOILERPLATE_TRAILING_PUNCT = ".!:;,"

_MAX_DESCRIPTION_LINES = 4  # §9.2 soft cap
_LENGTH_GOVERNOR_FACTOR = 2.0  # §9.8 soft cap multiplier

# §9.11 profile title/description checks.
_PROFILE_JARGON_BASE = ("passthrough", "plain")  # literal banned jargon words
_PROFILE_TITLE_MAX = 60   # §9.11e soft cap
_PROFILE_DESC_MAX = 200   # §9.11e soft cap


@dataclass
class ValidationReport:
    """Result of validating a doc-spec."""

    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when there are no blocking errors."""
        return not self.errors

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _load_capability_table() -> Dict[str, str]:
    data = json.loads(_CAP_TABLE_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #
def _validate_schema(spec: dict, report: ValidationReport) -> None:
    """Validate ``spec`` against the JSON schema, if ``jsonschema`` is present.

    Degrades to a minimal structural check when ``jsonschema`` is unavailable so
    the validator still runs (the custom rules below catch most issues anyway).
    """
    try:
        import jsonschema  # type: ignore
    except Exception:
        # Minimal fallback: required top-level keys.
        for key in (
            "connector_slug", "members", "connector",
            "capabilities", "connection", "configurations", "summary",
        ):
            if key not in spec:
                report.error(f"[schema] missing required key: {key!r}")
        return

    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    for err in sorted(validator.iter_errors(spec), key=lambda e: e.path):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        report.error(f"[schema] {loc}: {err.message}")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _find_flags(node, path: str, out: List[str]) -> None:
    """Recursively collect any value containing the ``__FLAG__`` sentinel."""
    if isinstance(node, str):
        if _FLAG_SENTINEL in node:
            out.append(f"{path}: {node.strip()}")
    elif isinstance(node, dict):
        for k, v in node.items():
            _find_flags(v, f"{path}.{k}" if path else str(k), out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _find_flags(v, f"{path}[{i}]", out)


def _has_command_content(text: str) -> bool:
    return any(rx.search(text or "") for rx in _COMMAND_MARKERS)


def _urls(text: str) -> List[str]:
    return _URL_RE.findall(text or "")


def _inline_commands(text: str) -> set:
    """Return the set of inline command tokens (without a leading ``!``) that
    appear in SETUP/AUTH INSTRUCTION lines of ``text``.

    A command token is only counted when it sits on a line that reads like an
    instruction ("Run the ...", "... command", a login-url/auth mention) — this
    avoids treating an ordinary hyphenated phrase or a documentation URL slug as
    a command. URLs are stripped first so path segments never match.
    """
    found: set = set()
    for line in (text or "").splitlines():
        if not re.search(r"\brun the\b|\bcommand\b|login.?url|auth-", line, re.I):
            continue
        line_no_urls = _URL_RE.sub(" ", line)
        for m in _INLINE_COMMAND_SLUG_RE.finditer(line_no_urls):
            tok = m.group(0).lstrip("!")
            if "." in tok or "/" in tok:
                continue
            found.add(tok)
        for m in _INLINE_COMMAND_BANG_RE.finditer(line_no_urls):
            found.add(m.group(1))
    return found


# --------------------------------------------------------------------------- #
# §9 custom rules
# --------------------------------------------------------------------------- #
def _check_flags(spec: dict, report: ValidationReport) -> None:
    flags: List[str] = []
    _find_flags(spec, "", flags)
    for f in flags:
        report.error(f"[§9.5 flag] unresolved {_FLAG_SENTINEL} at {f}")


def _check_connector_description(spec: dict, report: ValidationReport) -> None:
    desc = (spec.get("connector") or {}).get("description", "")
    if not isinstance(desc, str) or len(desc.strip()) < 10:
        report.error("[§9.2] connector.description must be >= 10 chars.")
        return
    if len(desc.splitlines()) > _MAX_DESCRIPTION_LINES:
        report.warn(
            f"[§9.2] connector.description has {len(desc.splitlines())} lines "
            f"(soft cap {_MAX_DESCRIPTION_LINES})."
        )


def _check_capabilities(spec: dict, report: ValidationReport) -> None:
    table = _load_capability_table()
    items = (spec.get("capabilities") or {}).get("items", []) or []
    for item in items:
        cid = item.get("id", "")
        desc = item.get("description", "")
        if cid not in table:
            report.error(
                f"[§9.3] capability id {cid!r} not in the closed table "
                f"(capability_descriptions.json)."
            )
            continue
        if not desc or not desc.strip():
            report.error(f"[§9.3] capability {cid!r} has an empty description.")
        elif desc.strip() != table[cid].strip():
            report.warn(
                f"[§9.3] capability {cid!r} description differs from the table "
                f"(apply will use the table value)."
            )


def _check_summary(spec: dict, report: ValidationReport) -> None:
    meta = (spec.get("summary") or {}).get("metadata") or {}
    ns = meta.get("next_steps", None)
    if ns is None:
        return
    if not isinstance(ns, str) or not ns.strip():
        report.error("[§9.6] summary.metadata.next_steps must be null or a non-empty string.")


def _check_no_commands(spec: dict, report: ValidationReport) -> None:
    desc = (spec.get("connector") or {}).get("description", "")
    if _has_command_content(desc):
        report.error("[§9.7] connector.description contains command content.")
    for section_key in ("connection", "configurations"):
        for vg in (spec.get(section_key) or {}).get("view_groups", []) or []:
            if _has_command_content(vg.get("help_text", "")):
                report.error(
                    f"[§9.7] {section_key} help_text for view_group "
                    f"{vg.get('id')!r} contains command content."
                )


def _check_no_bad_escapes(spec: dict, report: ValidationReport) -> None:
    r"""§9.14 — HARD-fail on a stray backslash-escaped bang (``\!``).

    ``!`` is not a Markdown special character outside the image syntax ``![``,
    so an authored ``\!`` is always a mistake — it renders the literal
    backslash in the tooltip (e.g. ``\!azure-waf-auth-start``). LLM authors
    sometimes "escape" command-name bangs this way. There is no legitimate
    ``\!`` in our help_text/title/description copy, so ban it everywhere the
    doc-spec sets text: connector.description, connection/configurations
    view_group help_text, and connection.profiles[] title/description.
    Write ``!cmd`` (not ``\!cmd``).
    """
    def _scan(label: str, value) -> None:
        if isinstance(value, str) and "\\!" in value:
            report.error(
                f"[§9.14] {label} contains a stray escaped bang '\\!' "
                f"(write '!cmd', not '\\!cmd'); backslash would render literally."
            )

    _scan("connector.description", (spec.get("connector") or {}).get("description"))
    for section_key in ("connection", "configurations"):
        for vg in (spec.get(section_key) or {}).get("view_groups", []) or []:
            _scan(
                f"{section_key} help_text for view_group {vg.get('id')!r}",
                vg.get("help_text"),
            )
    for prof in (spec.get("connection") or {}).get("profiles", []) or []:
        pid = prof.get("id")
        _scan(f"profile {pid!r} title", prof.get("title"))
        _scan(f"profile {pid!r} description", prof.get("description"))


def _check_no_incident_term(spec: dict, report: ValidationReport) -> None:
    """§9.17 — HARD-fail on the word "incident"/"incidents" in AUTHORED prose.

    The platform's term is "issue", not "incident" (e.g. "fetch issues", not
    "fetch incidents"). Scans the doc-spec's authored prose fields only:
    connector.description, connection/configurations view_group help_text, and
    connection.profiles[] title/description. Machine field ids (incidentType,
    incident-type, ...) live in the generated YAML, NOT in the doc-spec, so they
    are never inspected here. If a genuine third-party/vendor product name uses
    "incident", rephrase to avoid the bare word or raise it with the engineer.
    """
    def _scan(label: str, value) -> None:
        if isinstance(value, str) and _INCIDENT_TERM_RE.search(value):
            report.error(
                f"[§9.17] {label} uses the word 'incident'; the platform term is "
                f"'issue' (e.g. 'fetch issues', not 'fetch incidents'). Rewrite "
                f"incident(s) -> issue(s). (Machine field ids are exempt and not "
                f"inspected; a genuine vendor product name should be rephrased.)"
            )

    _scan("connector.description", (spec.get("connector") or {}).get("description"))
    for section_key in ("connection", "configurations"):
        for vg in (spec.get(section_key) or {}).get("view_groups", []) or []:
            _scan(
                f"{section_key} help_text for view_group {vg.get('id')!r}",
                vg.get("help_text"),
            )
    for prof in (spec.get("connection") or {}).get("profiles", []) or []:
        pid = prof.get("id")
        _scan(f"profile {pid!r} title", prof.get("title"))
        _scan(f"profile {pid!r} description", prof.get("description"))


def _member_index(bundle: ConnectorBundle):
    """Map view_group_id -> member bundle for cross-referencing."""
    return {m.expected_view_group_id: m for m in bundle.members}


def _check_connection_and_config_coverage(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    members_by_vg = _member_index(bundle)
    required_vgs = set(members_by_vg.keys())

    # §9.4 (RELAXED): connection help_text is OPTIONAL — no per-member requirement.
    # Retain the structural guards: duplicate id and unknown-member id.
    conn_vgs = (spec.get("connection") or {}).get("view_groups", []) or []
    seen: Dict[str, int] = {}
    for vg in conn_vgs:
        seen[vg.get("id", "")] = seen.get(vg.get("id", ""), 0) + 1
    for vg_id in required_vgs:
        count = seen.get(vg_id, 0)
        if count > 1:
            report.error(f"[§9.4] connection has {count} help_texts for view_group {vg_id!r} (expect 1).")
    for vg_id in seen:
        if vg_id not in required_vgs:
            report.error(f"[§9.4] connection view_group {vg_id!r} is not a known member.")

    # configurations: OPTIONAL; only validate that any present id is a member.
    for vg in (spec.get("configurations") or {}).get("view_groups", []) or []:
        if vg.get("id") not in required_vgs:
            report.error(
                f"[§9.4] configurations view_group {vg.get('id')!r} is not a known member."
            )


def _normalize_for_boilerplate(text: str) -> str:
    """Normalize for §9.13 boilerplate comparison (applied to BOTH operands).

    (1) lower(); (2) strip(); (3) strip trailing punctuation in ``.!:;,``;
    (4) collapse internal whitespace runs to a single space.
    """
    s = (text or "").lower().strip()
    s = s.rstrip(_BOILERPLATE_TRAILING_PUNCT).strip()
    s = re.sub(r"\s+", " ", s)
    return s


def _check_help_text_boilerplate(spec: dict, report: ValidationReport) -> None:
    """§9.13 — HARD-reject filler help_text on connection/config view_groups.

    For each view_group whose ``help_text`` is a NON-EMPTY string (entries with
    ``help_text: null`` or no ``help_text`` key are SKIPPED — those are the
    removal-sentinel / untouched states, §8.3b), HARD-fails when the normalized
    help_text EQUALS the normalized view_group ``label`` OR matches one of the
    generic filler templates.
    """
    for section in ("connection", "configurations"):
        for vg in (spec.get(section) or {}).get("view_groups", []) or []:
            help_text = vg.get("help_text")
            # Skip removal sentinel (null) and untouched (absent/non-string).
            if not isinstance(help_text, str) or not help_text.strip():
                continue
            norm = _normalize_for_boilerplate(help_text)
            label_norm = _normalize_for_boilerplate(vg.get("label", "") or "")
            if label_norm and norm == label_norm:
                report.error(
                    f"[§9.13 boilerplate] {section} help_text for view_group "
                    f"{vg.get('id')!r} restates the view_group label; omit it (§8.3b)."
                )
                continue
            if any(rx.match(norm) for rx in _BOILERPLATE_TEMPLATES):
                report.error(
                    f"[§9.13 boilerplate] {section} help_text for view_group "
                    f"{vg.get('id')!r} matches generic filler template; omit it (§8.3b)."
                )


def _check_view_group_correctness(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    """§9.9 — id == slugify(commonfields.id) AND label == commonfields.name."""
    for flag in bundle.view_group_flags:
        if not flag.id_ok:
            report.error(
                f"[§9.9] view_group id {flag.expected_id!r} not declared in "
                f"connection.yaml (expected from commonfields.id)."
            )
        if not flag.label_ok:
            report.error(
                f"[§9.9] view_group {flag.view_group_id!r} label "
                f"{flag.label!r} != expected {flag.expected_label!r} "
                f"(commonfields.name)."
            )
    # Also confirm the doc-spec's own labels match (authoring drift guard).
    members_by_vg = _member_index(bundle)
    for vg in (spec.get("connection") or {}).get("view_groups", []) or []:
        member = members_by_vg.get(vg.get("id"))
        if member is None:
            continue
        expected_label = member.commonfields_name or ""
        if expected_label and vg.get("label") != expected_label:
            report.error(
                f"[§9.9] connection view_group {vg.get('id')!r} label "
                f"{vg.get('label')!r} != commonfields.name {expected_label!r}."
            )
        expected_id = slugify(member.commonfields_id or member.integration_id)
        if vg.get("id") != expected_id:
            report.error(
                f"[§9.9] connection view_group id {vg.get('id')!r} != "
                f"slugify(commonfields.id) {expected_id!r}."
            )


def _check_length_and_links(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    """§9.8 length-governor + §9.10 link-preservation, vs the source bundle."""
    members_by_vg = _member_index(bundle)
    for vg in (spec.get("connection") or {}).get("view_groups", []) or []:
        member = members_by_vg.get(vg.get("id"))
        if member is None:
            continue
        help_text = vg.get("help_text", "") or ""

        # §9.8 length governor (soft).
        cap = int(member.description_md_len * _LENGTH_GOVERNOR_FACTOR) + 200
        if len(help_text) > cap:
            report.warn(
                f"[§9.8] connection help_text for {vg.get('id')!r} is "
                f"{len(help_text)} chars; source description.md is "
                f"{member.description_md_len} (soft cap ~{cap})."
            )

        # If the doc-spec did not author this view_group's help_text (key
        # omitted -> on-disk value left untouched), the fidelity gates below do
        # not apply: there is nothing authored to compare against the source.
        authored = "help_text" in vg and isinstance(vg.get("help_text"), str)

        # §9.10 link preservation. When the help_text IS authored, a dropped
        # source link is a FIDELITY LOSS -> HARD error (was a soft warn; the
        # warn let real content losses through to disk). For omitted help_text
        # it stays a soft note.
        source_urls = set(_urls(member.description_md))
        help_urls = set(_urls(help_text))
        for url in source_urls - help_urls:
            msg = (
                f"[§9.10] connection help_text for {vg.get('id')!r} dropped a "
                f"source link: {url}"
            )
            if authored:
                report.error(msg)
            else:
                report.warn(msg)

        # §9.15 command-token preservation (HARD when authored): any inline
        # setup/auth command name in the SOURCE must survive into the authored
        # help_text. This catches over-summarization that genericizes or drops
        # command names the user must type (e.g. an Authorization-Code-flow
        # command list, a CreateCertificate/DeleteContext step).
        if authored:
            source_cmds = _inline_commands(member.description_md)
            help_cmds = _inline_commands(help_text)
            # Fall back to a raw token scan of the help_text too (the command may
            # survive on a line that doesn't match the instruction heuristic).
            _hclean = _URL_RE.sub(" ", help_text)
            help_raw = {
                m.group(0).lstrip("!")
                for m in _INLINE_COMMAND_SLUG_RE.finditer(_hclean)
                if "." not in m.group(0) and "/" not in m.group(0)
            }
            help_raw |= {m.group(1) for m in _INLINE_COMMAND_BANG_RE.finditer(_hclean)}
            for cmd in sorted(source_cmds - help_cmds - help_raw):
                report.error(
                    f"[§9.15] connection help_text for {vg.get('id')!r} dropped "
                    f"the source command name {cmd!r} (keep setup/auth command "
                    f"names verbatim; do not genericize or summarize them)."
                )

        # Malformed markdown link guard: a "](" with no scheme is suspicious.
        for m in re.finditer(r"\]\(([^)]*)\)", help_text):
            target = m.group(1).strip()
            if target and not re.match(r"^(https?://|mailto:|#|/)", target):
                report.warn(
                    f"[§9.10] connection help_text for {vg.get('id')!r} has a "
                    f"possibly-malformed link target: {target!r}"
                )


def _contains_whole_word(text: str, word: str) -> bool:
    """Case-insensitive WHOLE-WORD match of ``word`` in ``text`` (§9.11c).

    ``word`` may itself contain non-word characters (e.g. ``oauth2_client_``
    ``credentials`` or ``api_key``); the boundaries ``\\b`` anchor on the outer
    word characters so ``explained`` does NOT match the word ``plain``.
    """
    if not text or not word:
        return False
    pattern = r"\b" + re.escape(word.lower()) + r"\b"
    return re.search(pattern, text.lower()) is not None


def _check_profiles(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    """§9.11 — backstop the AI-authored ``connection.profiles[]`` (§8.3a).

    Builds the connector's real profiles from the bundle and validates each
    authored entry: id-exists (HARD), at-least-one field (HARD), jargon ban-list
    (HARD), no-commands (HARD), and length caps (SOFT).
    """
    profiles_by_id = {p.id: p for m in bundle.members for p in m.profiles}
    for entry in (spec.get("connection") or {}).get("profiles", []) or []:
        pid = entry.get("id", "")

        # (a) id exists.
        profile = profiles_by_id.get(pid)
        if profile is None:
            report.error(
                f"[§9.11 profile] profile id {pid} not found in "
                f"connection.yaml profiles[]."
            )
            continue

        title = entry.get("title")
        description = entry.get("description")

        # (b) at-least-one-OR-null field (§9.11b). Test KEY PRESENCE, NOT
        # truthiness: an entry with id + `description: null` carries the
        # description KEY (a real change — it deletes the description, §8.3a.5)
        # and PASSES; an entry with ONLY id (neither key) FAILS. This restated
        # rule also covers the no-`jsonschema` fallback path (the schema anyOf
        # is not enforced there).
        if not (("title" in entry) or ("description" in entry)):
            report.error(
                f"[§9.11 profile] profile {pid} must set at least one of "
                f"title/description."
            )
            continue

        # Per-profile ban set: base jargon + this profile's own raw type value.
        ban_words = set(_PROFILE_JARGON_BASE)
        if profile.type:
            ban_words.add(profile.type.lower())

        for fieldname, value, cap in (
            ("title", title, _PROFILE_TITLE_MAX),
            ("description", description, _PROFILE_DESC_MAX),
        ):
            if value is None:
                continue
            # (c) jargon ban-list (whole-word, case-insensitive).
            for word in sorted(ban_words):
                if _contains_whole_word(value, word):
                    report.error(
                        f"[§9.11 profile] profile {pid} {fieldname} contains "
                        f"banned jargon: {word}."
                    )
            # (d) no commands.
            if _has_command_content(value):
                report.error(
                    f"[§9.11 profile] profile {pid} {fieldname} contains "
                    f"command content."
                )
            # (e) length caps (soft).
            if len(value) > cap:
                report.warn(
                    f"[§9.11 profile] profile {pid} {fieldname} is "
                    f"{len(value)} chars (soft cap {cap})."
                )


# --------------------------------------------------------------------------- #
# §9.11c / §9.13 AUDIT of the FINAL on-disk state (effective value)
#
# The authored-content checks above only inspect what the doc-spec TOUCHED.
# Migration leftovers (jargon profiles, boilerplate help_text) the author never
# addressed slip through. These audits close that gap: they inspect the
# POST-APPLY EFFECTIVE state of EVERY on-disk profile / view_group, computed as:
#   effective = doc-spec value if the spec addresses it, else the on-disk value.
# Doc-spec authoring OVERRIDES on-disk (string overwrite, or `null` removal).
# --------------------------------------------------------------------------- #
def _profile_overrides_by_id(spec: dict) -> Dict[str, dict]:
    """Map profile id -> the doc-spec ``connection.profiles[]`` override entry."""
    out: Dict[str, dict] = {}
    for entry in (spec.get("connection") or {}).get("profiles", []) or []:
        pid = entry.get("id")
        if pid is not None:
            out[str(pid)] = entry
    return out


def _effective_profile_field(on_disk_value, override: Optional[dict], field_name: str):
    """Effective value of a profile field: doc-spec override if it addresses the
    field, else the on-disk value.

    The override "addresses" the field only when the KEY is present in the entry
    (so an entry that sets only ``title`` does not blank out ``description``).
    """
    if override is not None and field_name in override:
        return override[field_name]
    return on_disk_value


def _check_profile_jargon_audit(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    """§9.11c (scope expansion) — audit the EFFECTIVE final state of EVERY
    on-disk profile, independent of what the doc-spec authored.

    For each profile in ``bundle.members[].profiles[]``, compute its effective
    ``title``/``description`` (doc-spec override by id if present, else on-disk)
    and HARD-fail if either contains banned jargon (``passthrough``, ``plain``,
    or that profile's raw ``type`` value), using the existing whole-word,
    case-insensitive detection.
    """
    overrides = _profile_overrides_by_id(spec)
    for member in bundle.members:
        for profile in member.profiles:
            override = overrides.get(profile.id)
            eff_title = _effective_profile_field(profile.title, override, "title")
            eff_desc = _effective_profile_field(profile.description, override, "description")

            ban_words = set(_PROFILE_JARGON_BASE)
            if profile.type:
                ban_words.add(profile.type.lower())

            for fieldname, value in (("title", eff_title), ("description", eff_desc)):
                if not isinstance(value, str):
                    continue
                for word in sorted(ban_words):
                    if _contains_whole_word(value, word):
                        report.error(
                            f"[§9.11c audit] profile '{profile.id}' effective "
                            f"{fieldname} still contains banned jargon "
                            f"'{word}' (on-disk migration value left unaddressed). "
                            f"Author a connection.profiles[] entry for '{profile.id}' "
                            f"that rewrites it into clear, user-facing copy."
                        )


def _check_view_group_help_text_audit(
    spec: dict, bundle: ConnectorBundle, report: ValidationReport
) -> None:
    """§9.13 (scope expansion) — audit the EFFECTIVE final help_text of EVERY
    on-disk connection AND configuration view_group, independent of authoring.

    Effective help_text per view_group (three doc-spec states, §8.3b):
      * doc-spec entry sets a string  -> that string (overwrite)
      * doc-spec entry sets ``null``  -> None (removal -> passes)
      * doc-spec omits the view_group -> the on-disk help_text (untouched)
    HARD-fail when the effective help_text is non-empty boilerplate (matches a
    template OR equals the normalized view_group label).
    """
    sections = (
        ("connection", bundle.view_groups),
        ("configurations", bundle.config_view_groups),
    )
    for section, on_disk_vgs in sections:
        spec_vgs = (spec.get(section) or {}).get("view_groups", []) or []
        # Override map: id -> entry (only entries that carry the help_text key
        # participate in the SET/REMOVE override; an entry without the key leaves
        # the on-disk value in place, same as an omitted view_group).
        overrides = {
            str(vg.get("id")): vg
            for vg in spec_vgs
            if vg.get("id") is not None
        }
        for vg in on_disk_vgs:
            override = overrides.get(vg.id)
            if override is not None and "help_text" in override:
                effective = override["help_text"]  # string or None (removal)
            else:
                effective = vg.help_text  # untouched on-disk value

            if not isinstance(effective, str) or not effective.strip():
                continue  # removed / empty -> passes

            norm = _normalize_for_boilerplate(effective)
            label_norm = _normalize_for_boilerplate(vg.label or "")
            if label_norm and norm == label_norm:
                report.error(
                    f"[§9.13 audit] {section} view_group '{vg.id}' effective "
                    f"help_text restates the view_group label (on-disk migration "
                    f"boilerplate left unaddressed). Set \"help_text\": null to "
                    f"delete it, or replace it with substantive guidance."
                )
                continue
            if any(rx.match(norm) for rx in _BOILERPLATE_TEMPLATES):
                report.error(
                    f"[§9.13 audit] {section} view_group '{vg.id}' effective "
                    f"help_text is generic boilerplate (on-disk migration value "
                    f"left unaddressed). Set \"help_text\": null to delete it, or "
                    f"replace it with substantive guidance."
                )


# --------------------------------------------------------------------------- #
# Top-level
# --------------------------------------------------------------------------- #
def validate(spec: dict, slug: str, bundle: Optional[ConnectorBundle] = None) -> ValidationReport:
    """Validate a doc-spec for ``slug``.

    Args:
        spec: The parsed doc-spec.json.
        slug: The connector slug (must match ``spec['connector_slug']``).
        bundle: Optional pre-gathered :class:`ConnectorBundle`; resolved from
            disk when omitted. Cross-disk checks are skipped (with a warning) if
            gathering fails — but schema/flag/structural checks still run.

    Returns:
        A :class:`ValidationReport`.
    """
    report = ValidationReport()

    _validate_schema(spec, report)

    if spec.get("connector_slug") and spec["connector_slug"] != slug:
        report.error(
            f"[spec] connector_slug {spec['connector_slug']!r} != requested slug {slug!r}."
        )

    # Pure-spec checks (no disk needed).
    _check_flags(spec, report)
    _check_connector_description(spec, report)
    _check_capabilities(spec, report)
    _check_summary(spec, report)
    _check_no_commands(spec, report)
    _check_no_bad_escapes(spec, report)
    _check_no_incident_term(spec, report)
    _check_help_text_boilerplate(spec, report)

    # Disk-cross-referenced checks.
    if bundle is None:
        try:
            bundle = gather_connector(slug)
        except ResolutionError as exc:
            report.warn(
                f"[validate] could not gather on-disk sources for cross-checks: {exc}"
            )
            bundle = None
    if bundle is not None:
        _check_connection_and_config_coverage(spec, bundle, report)
        _check_view_group_correctness(spec, bundle, report)
        _check_length_and_links(spec, bundle, report)
        _check_profiles(spec, bundle, report)
        # P1: audit the FINAL on-disk state (effective value), independent of
        # what the doc-spec authored. These are additive HARD gates on top of the
        # authored-content checks above (which give better messages for authored
        # mistakes).
        _check_profile_jargon_audit(spec, bundle, report)
        _check_view_group_help_text_audit(spec, bundle, report)

    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a connector doc-spec.json (§9).")
    parser.add_argument("slug", help="connector slug, e.g. akamai")
    parser.add_argument(
        "doc_spec", nargs="?", default=None,
        help="path to doc-spec.json (default: the .doc_specs/<slug>.json staging path).",
    )
    args = parser.parse_args(argv)

    spec_file = Path(args.doc_spec) if args.doc_spec else doc_spec_path(args.slug)
    if not spec_file.exists():
        print(f"ERROR doc-spec not found: {spec_file}")
        return 1
    spec = json.loads(spec_file.read_text(encoding="utf-8"))
    report = validate(spec, args.slug)

    for w in report.warnings:
        print(f"WARN  {w}")
    for e in report.errors:
        print(f"ERROR {e}")
    if report.ok:
        print(f"OK    doc-spec for '{args.slug}' passed ({len(report.warnings)} warnings).")
        return 0
    print(f"FAIL  doc-spec for '{args.slug}': {len(report.errors)} error(s).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
