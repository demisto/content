"""Deterministic Markdown processors for the documentation GATHER stage (B).

These are pure, dependency-free functions. They do the *mechanical* trimming so
the AI authoring stage (C) receives clean, command-free, ConnectUs-relevant
prose before applying judgment.

Three contracts (see ``plans/connector-documentation-skill-design.md``):

* **Command sections (§3.2 / §2.3 — NO-COMMANDS rule).**
  XSOAR/XSIAM integration READMEs document all commands under a single
  ``## Commands`` level-2 heading; every command, its base-command block, args
  table, context outputs and examples live beneath it. The reliable cut is
  therefore: drop the ``## Commands`` heading and everything under it up to the
  next heading of the same or shallower level (``#`` or ``##``), or
  end-of-document. :func:`strip_command_sections` performs that cut.

  As a defensive secondary pass it also removes any stray *command-slug*
  ``### <slug>`` blocks that appear OUTSIDE a ``## Commands`` section (some
  hand-written READMEs inline a command heading). :func:`get_commands_sections`
  is the ported content-infra slug locator used for that pass and is exposed for
  reuse/testing.

* **Conditional stripping (§10).**
  Content is wrapped in platform conditionals like ``<~XSIAM>...</~XSIAM>``.
  Unwrapped text is kept. ``<~XSIAM>`` and ``<~Platform>`` blocks are kept and
  *unwrapped*. Every other conditional (notably ``<~XSOAR>``) is dropped.

* **Section index (§3.4 — lazy reads).**
  :func:`build_section_index` returns a map of every Markdown heading to its
  ``(start_line, end_line)`` body range so the authoring stage can read only the
  relevant section (e.g. just the connection portion) instead of the whole file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

# --------------------------------------------------------------------------- #
# Command sections (§3.2 / §2.3)
# --------------------------------------------------------------------------- #

# The canonical commands section: a level-2 heading whose text is exactly
# "Commands" (case-insensitive, tolerant of trailing whitespace).
_COMMANDS_HEADER_RE = re.compile(r"^##\s+Commands\s*$", re.IGNORECASE)

# Any ATX heading, used to find the section boundary and for the section index.
_ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")

# A command-slug heading is a level-3 ATX heading whose text is a command slug:
# all-lowercase tokens of [a-z0-9] joined by single hyphens, e.g.
#   ### akamai-get-network-lists
#   ### url
# It must be ONLY the slug (no trailing words like "### url reputation").
_COMMAND_HEADING_RE = re.compile(r"^###\s+([a-z0-9]+(?:-[a-z0-9]+)*)\s*$")

# Fenced code-block delimiter (``` or ~~~).
_FENCE_RE = re.compile(r"^\s*(```|~~~)")


def _commands_section_range(lines: List[str]) -> Tuple[int, int] | None:
    """Return the ``[start, end)`` line range of the ``## Commands`` section.

    ``start`` is the ``## Commands`` heading line; ``end`` is the first heading
    line of level <= 2 that follows it, or ``len(lines)``. Returns ``None`` when
    there is no ``## Commands`` heading. Code fences are respected so a "##"
    inside a fenced block is not mistaken for a heading.
    """
    in_fence = False
    start = None
    for idx, line in enumerate(lines):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if start is None:
            if _COMMANDS_HEADER_RE.match(line):
                start = idx
            continue
        # We are inside the commands section; stop at the next level-1/2 heading.
        m = _ANY_HEADING_RE.match(line)
        if m and len(m.group(1)) <= 2:
            return (start, idx)
    if start is None:
        return None
    return (start, len(lines))


def get_commands_sections(doc_text: str) -> Dict[str, Tuple[int, int]]:
    """Map each command-slug section to its ``(start_line, end_line)`` range.

    Ported from the content-infra ``get_commands_sections`` helper. Line numbers
    are 0-based indices into ``doc_text.splitlines()``. ``start_line`` is the
    command-slug heading line; ``end_line`` is the start line of the *next*
    command-slug heading (exclusive), or the total line count for the last
    command. Used as the defensive secondary pass for stray command headings —
    the primary cut is the ``## Commands`` section (see
    :func:`strip_command_sections`).

    Args:
        doc_text: Raw Markdown text.

    Returns:
        Ordered mapping ``{slug: (start_line, end_line)}`` in document order.
    """
    starts: Dict[str, int] = {}
    for line_nr, line_text in enumerate(doc_text.splitlines()):
        match = _COMMAND_HEADING_RE.match(line_text)
        if match:
            starts[match.group(1)] = line_nr

    slugs = list(starts.keys())
    line_positions = list(starts.values())
    total_lines = len(doc_text.splitlines())

    ranges: Dict[str, Tuple[int, int]] = {}
    for i, slug in enumerate(slugs):
        start = line_positions[i]
        end = line_positions[i + 1] if i < len(slugs) - 1 else total_lines
        ranges[slug] = (start, end)
    return ranges


def strip_command_sections(doc_text: str) -> str:
    """Remove the command reference from ``doc_text``.

    Primary cut: drop the ``## Commands`` section in full — the heading and
    everything beneath it up to the next level-1/2 heading (or end-of-document).
    This single, reliable rule removes the entire generated command reference
    (base commands, argument tables, context outputs, examples).

    Secondary, defensive cut: any leftover command-slug ``### <slug>`` block that
    sits OUTSIDE the commands section (rare hand-authored inlining) is also
    removed, via :func:`get_commands_sections`.

    Surviving text (and its blank lines) is preserved; trailing blank lines
    created by the removal are trimmed.

    Args:
        doc_text: Raw Markdown text (possibly containing a command reference).

    Returns:
        Markdown with the command reference removed.
    """
    if not doc_text:
        return doc_text

    lines = doc_text.splitlines()
    drop = [False] * len(lines)

    # Primary: the "## Commands" section.
    commands_range = _commands_section_range(lines)
    if commands_range is not None:
        start, end = commands_range
        for i in range(start, min(end, len(drop))):
            drop[i] = True

    # Secondary: stray command-slug blocks outside the commands section.
    for start, end in get_commands_sections(doc_text).values():
        # Skip slug blocks that are already inside the dropped commands section.
        if commands_range is not None and commands_range[0] <= start < commands_range[1]:
            continue
        for i in range(start, min(end, len(drop))):
            drop[i] = True

    if not any(drop):
        return doc_text

    kept = [line for i, line in enumerate(lines) if not drop[i]]
    # Trim trailing blank lines created by the removal.
    while kept and not kept[-1].strip():
        kept.pop()
    return "\n".join(kept)


# --------------------------------------------------------------------------- #
# Conditional stripping (§10)
# --------------------------------------------------------------------------- #

# Conditionals we KEEP (and unwrap). Case-insensitive on the tag name.
_KEEP_CONDITIONALS = {"xsiam", "platform"}

# Matches an opening conditional tag: <~XSIAM>, <~XSOAR>, <~Platform>, etc.
_OPEN_TAG_RE = re.compile(r"<~([A-Za-z0-9_]+)>")
# Matches the matching close tag for a given name.
_CLOSE_TAG_TEMPLATE = "</~{name}>"


def strip_conditionals(doc_text: str) -> str:
    """Resolve platform conditionals per the §10 contract.

    Rules:
        * Text outside any conditional -> KEEP.
        * ``<~XSIAM>`` / ``<~Platform>`` blocks -> KEEP and UNWRAP (tags removed,
          inner content retained and itself re-filtered for nested conditionals).
        * Any other conditional (e.g. ``<~XSOAR>``) -> DROP entirely.
        * Nested conditionals are handled outer-first; the inner content of a
          kept block is recursively re-filtered.

    The matcher is tolerant of unbalanced/orphan tags: an opening tag with no
    matching close is treated as spanning to end-of-text; a stray close tag is
    dropped.

    Args:
        doc_text: Raw Markdown that may contain ``<~NAME>...</~NAME>`` blocks.

    Returns:
        Markdown with conditionals resolved.
    """
    if not doc_text or "<~" not in doc_text:
        return doc_text

    result, _ = _resolve_conditionals(doc_text, 0)
    # Strip trailing whitespace left on each line by a removed inline block
    # (e.g. "head <~XSOAR>...</~XSOAR>" -> "head "), preserving line structure.
    result = "\n".join(line.rstrip() for line in result.split("\n"))
    # Collapse 3+ consecutive newlines (created by dropped blocks) to 2.
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip("\n")


def _resolve_conditionals(text: str, pos: int) -> Tuple[str, int]:
    """Recursively resolve conditionals starting at ``pos``.

    Returns the resolved string for the region and the position just past it.
    Stops (and returns) when it encounters a close tag belonging to an enclosing
    block, leaving ``pos`` pointing at that close tag.
    """
    out: List[str] = []
    i = pos
    n = len(text)
    while i < n:
        open_match = _OPEN_TAG_RE.search(text, i)
        close_idx = text.find("</~", i)

        # If the next thing is a close tag (belongs to the caller), stop here.
        if close_idx != -1 and (open_match is None or close_idx < open_match.start()):
            out.append(text[i:close_idx])
            return "".join(out), close_idx

        if open_match is None:
            out.append(text[i:])
            return "".join(out), n

        # Emit text before the opening tag.
        out.append(text[i:open_match.start()])
        name = open_match.group(1)
        inner_start = open_match.end()

        inner_resolved, after_inner = _resolve_conditionals(text, inner_start)

        close_tag = _CLOSE_TAG_TEMPLATE.format(name=name)
        if after_inner < n and text.startswith(close_tag, after_inner):
            next_pos = after_inner + len(close_tag)
        elif after_inner < n and text.startswith("</~", after_inner):
            # Mismatched close tag — consume it defensively to avoid a loop.
            end_of_close = text.find(">", after_inner)
            next_pos = end_of_close + 1 if end_of_close != -1 else n
        else:
            # No close tag at all (orphan open) — inner ran to end.
            next_pos = after_inner

        if name.lower() in _KEEP_CONDITIONALS:
            out.append(inner_resolved)
        # else: drop the whole block (emit nothing).

        i = next_pos
    return "".join(out), n


# --------------------------------------------------------------------------- #
# Section index (§3.4)
# --------------------------------------------------------------------------- #
# (Uses the module-level ``_ANY_HEADING_RE`` and ``_FENCE_RE`` defined above.)


@dataclass(frozen=True)
class Section:
    """A single Markdown section.

    Attributes:
        level: Heading level (1-6).
        title: Heading text (without the leading ``#`` markers).
        heading_line: 0-based index of the heading line.
        body_start: 0-based index of the first body line after the heading.
        body_end: 0-based index just past the section's last line (exclusive).
                  The section spans up to (but not including) the next heading of
                  the same or shallower level, or end-of-document.
    """

    level: int
    title: str
    heading_line: int
    body_start: int
    body_end: int


def build_section_index(doc_text: str) -> List[Section]:
    """Build an ordered index of every heading and its body range.

    Code fences are respected: ``#`` characters inside ```` ``` ```` or ``~~~``
    fenced blocks are not treated as headings.

    A section's ``body_end`` extends to the next heading whose level is the same
    as or shallower than its own (i.e. its subsections are *included* in its
    range), or to end-of-document.

    Args:
        doc_text: Raw Markdown text.

    Returns:
        Ordered list of :class:`Section` objects in document order.
    """
    lines = doc_text.splitlines()
    in_fence = False
    headings: List[Tuple[int, int, str]] = []  # (line, level, title)
    for idx, line in enumerate(lines):
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = _ANY_HEADING_RE.match(line)
        if m:
            headings.append((idx, len(m.group(1)), m.group(2)))

    sections: List[Section] = []
    total = len(lines)
    for i, (line_idx, level, title) in enumerate(headings):
        body_start = line_idx + 1
        body_end = total
        for line_idx_j, level_j, _ in headings[i + 1:]:
            if level_j <= level:
                body_end = line_idx_j
                break
        sections.append(
            Section(
                level=level,
                title=title,
                heading_line=line_idx,
                body_start=body_start,
                body_end=body_end,
            )
        )
    return sections


def get_section_text(doc_text: str, section: Section, include_heading: bool = True) -> str:
    """Return the text of ``section`` from ``doc_text``.

    Args:
        doc_text: The Markdown the section index was built from.
        section: A :class:`Section` produced by :func:`build_section_index`.
        include_heading: Whether to include the heading line itself.

    Returns:
        The section's text (heading + body, or body only).
    """
    lines = doc_text.splitlines()
    start = section.heading_line if include_heading else section.body_start
    return "\n".join(lines[start:section.body_end]).strip("\n")
