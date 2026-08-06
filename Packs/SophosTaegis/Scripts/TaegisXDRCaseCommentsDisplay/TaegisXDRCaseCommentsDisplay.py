# -*- coding: utf-8 -*-
"""
Dynamic-section display for Taegis XDR Case comments, sorted newest-first.

The built-in War Room timeline section (invTimeline / warRoomFilter) only renders
oldest -> newest, forcing users to scroll to the bottom for the latest comment.
This script fetches the same tagged War Room entries and renders them newest-first
with a uniform "Author - timestamp - direction" header followed by the comment body.

Why client-side tag filtering: passing `tags` to getEntries via executeCommand does
NOT filter (it returns every entry in the incident), unlike the `!getEntries tags=...`
CLI. So we always filter on the entry tags ourselves - bulletproof regardless.

Why author is parsed from the body: mirrored comment entries have an empty
Metadata.user. Inbound (Taegis) comments embed the author as a leading "**Name** - ts"
block in Contents; outbound (XSOAR) comments have no author, so we label by source.

Reusable: the 'tags' arg defaults to the Taegis comment tags but can be repointed at
any tag-filtered comment stream, so peers can drop this onto other case layouts.

Uses demisto.results() and demisto.get() (both native to the Demisto object) so no
CommonServerPython import is required - matches TaegisXDRAddCommentNote conventions.
"""

# Entry type: 1 = Note (markdown rendered in the layout section)
ENTRY_TYPE_NOTE = 1
# Default tags match the Taegis XDR integration comment tags (outbound + inbound mirror).
DEFAULT_TAGS = "xdrcomment,CommentFromTaegis"

# Per-tag presentation: direction label + fallback author when none is embedded.
# Add entries here to reuse this script for other tagged comment streams.
TAG_META = {
    "CommentFromTaegis": {"direction": "from Taegis XDR", "default_author": "Taegis XDR"},
    "xdrcomment": {"direction": "to Taegis XDR", "default_author": "Sophos (via XSOAR)"},
}
UNKNOWN_META = {"direction": "", "default_author": "Unknown"}


def _is_truthy(value):
    """Return True for 'true', '1', 'yes', True (case-insensitive)."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def _fetch_entries():
    """Call the built-in getEntries command and return a flat list of entry dicts."""
    res = demisto.executeCommand("getEntries", {})
    if not isinstance(res, list):
        res = [res] if res else []
    return res


def _entry_tags(ent):
    """Return the entry's tags as a list (top-level Tags, falling back to Metadata.tags)."""
    tags = demisto.get(ent, "Tags") or demisto.get(ent, "Metadata.tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return [t for t in tags if t]


def _meta_for(tags, wanted):
    """Pick presentation metadata for the first known wanted tag the entry carries."""
    for tag in wanted:
        if tag in tags and tag in TAG_META:
            return TAG_META[tag]
    return UNKNOWN_META


def _clean_timestamp(created):
    """Render an ISO8601 created stamp as 'YYYY-MM-DD HH:MM:SS UTC' without tz guessing."""
    if not created:
        return ""
    text = str(created)
    if "." in text:
        text = text.split(".", 1)[0]
    text = text.rstrip("Z").replace("T", " ")
    return "{} UTC".format(text) if text else ""


def _split_author_body(contents):
    """Pull an embedded '<author> - <ts>\\n\\n<body>' header out of a comment entry.

    Handles both shapes: Taegis inbound ('**Author** - ts\\n\\nbody') and our XSOAR
    outbound ('Author - ts\\n\\nbody'). Splits on the blank line, then on the em-dash,
    stripping any '*'. Returns (author or None, body); falls back to (None, raw text)
    when there is no such header. \\u2014 is the em-dash (escaped to keep this file ASCII).
    """
    # Coerce safely without bare str() - str() on non-ASCII unicode raises under Python 2.
    if contents is None:
        text = u""
    elif isinstance(contents, str):
        text = contents
    else:
        text = u"{0}".format(contents)

    split = text.find("\n\n")
    if split == -1:
        return None, text.strip()
    head = text[:split].strip()
    body = text[split + 2:].strip()
    # Header looks like "<author> \u2014 <ts>"; require the em-dash so a plain
    # multi-paragraph comment is not misread as having an author.
    sep = head.find(u" \u2014 ")
    if sep == -1:
        return None, text.strip()
    author = head[:sep].strip().strip("*").strip()
    return (author or None), body


def _render(entries, wanted):
    """Build newest-first markdown: uniform 'Author - timestamp - direction' + body."""
    comments = [e for e in entries if set(_entry_tags(e)) & set(wanted)]
    if not comments:
        return "_No comments yet._"

    comments.sort(key=lambda e: str(demisto.get(e, "Metadata.created") or ""), reverse=True)

    blocks = []
    for ent in comments:
        # Never let one malformed entry blank the whole section - degrade per comment.
        try:
            tags = _entry_tags(ent)
            meta = _meta_for(tags, wanted)
            when = _clean_timestamp(demisto.get(ent, "Metadata.created"))
            parsed_author, body = _split_author_body(demisto.get(ent, "Contents"))
            author = parsed_author or meta["default_author"]

            header = "**{0}**".format(author)
            if when:
                header += " &middot; {0}".format(when)
            if meta["direction"]:
                header += " &middot; _{0}_".format(meta["direction"])

            blocks.append(u"{0}\n\n{1}".format(header, body))
        except Exception as exc:
            raw = demisto.get(ent, "Contents")
            blocks.append(u"_(comment failed to render: {0})_\n\n{1}".format(exc, raw if raw else ""))

    return "\n\n---\n\n".join(blocks)


def main():
    args = demisto.args()
    tags_csv = (args.get("tags") or DEFAULT_TAGS).strip() or DEFAULT_TAGS
    wanted = [t.strip() for t in tags_csv.split(",") if t.strip()]
    debug = _is_truthy(args.get("debug"))

    entries = _fetch_entries()

    if debug:
        import json

        matched = [e for e in entries if set(_entry_tags(e)) & set(wanted)]
        dump = json.dumps(matched, indent=2, default=str)
        demisto.results(
            {
                "Type": ENTRY_TYPE_NOTE,
                "ContentsFormat": "markdown",
                "Contents": "### getEntries: {} total, {} match tags {}\n```json\n{}\n```".format(
                    len(entries), len(matched), wanted, dump
                ),
            }
        )
        return

    demisto.results(
        {
            "Type": ENTRY_TYPE_NOTE,
            "ContentsFormat": "markdown",
            "Contents": _render(entries, wanted),
        }
    )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
