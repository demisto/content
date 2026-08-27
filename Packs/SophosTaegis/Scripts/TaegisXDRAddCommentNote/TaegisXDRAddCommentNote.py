# -*- coding: utf-8 -*-
"""
Add a War Room note with tag 'xdrcomment' so it is mirrored to Taegis XDR as a comment.
The note is prefixed with the invoking XSOAR user as "User - ts" so the case-comments
display (and the Taegis XDR mirror) attribute who wrote it.
Use as an incident action button on the Taegis XDR Case layout.

Optional: select 'Yes' for 'Assign case back to Sophos MDR team' to also assign the Taegis
case to @secureworks (AWAITING_ACTION) immediately after submitting the comment.

Uses demisto.results() so no CommonServerPython import is required.
"""

# Tag must match Taegis XDR integration param comment_tag (default xdrcomment)
TAEGIS_COMMENT_TAG = "xdrcomment"
# Entry type: 1 = Note
ENTRY_TYPE_NOTE = 1


def _is_truthy(value):
    """Return True for 'true', '1', 'yes', True (case-insensitive). Also accepts 'Yes' from predefined dropdown."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def _current_user():
    """Display name of the user invoking this script, or '' if unavailable.

    callingContext carries the logged-in user for both button and CLI runs; the
    triggering war-room entry's user is a fallback for the command path.
    """
    try:
        user = (demisto.callingContext.get("context") or {}).get("User") or {}
        name = user.get("name") or user.get("username")
        if name:
            return name
    except Exception:
        pass
    try:
        return (demisto.parentEntry() or {}).get("user") or ""
    except Exception:
        return ""


def _format_comment(note, user):
    """Prefix the note with the author as 'User - ts' so the display can attribute it.

    Deliberately NOT '**User**': the Taegis mirror skips '**'-prefixed entries, and a
    plain prefix also reads cleanly on the Taegis side. The display parser strips any
    '*' and splits on the em-dash. With no user we send the note unchanged.
    \u2014 is the em-dash, written as an escape to keep this file ASCII.
    """
    if not user:
        return note
    import datetime

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return u"{0} \u2014 {1}\n\n{2}".format(user, ts, note)


def main():
    args = demisto.args()
    note = args.get("note") or ""
    note = note.strip() if isinstance(note, str) else u"{0}".format(note).strip()
    if not note:
        demisto.results(
            [
                {
                    "Type": ENTRY_TYPE_NOTE,
                    "ContentsFormat": "markdown",
                    "Contents": "No comment text provided. Enter text in the **Note** field and try again.",
                }
            ]
        )
        return

    # Add the comment note first so it is always mirrored even if the assign step fails.
    demisto.results(
        [
            {
                "Type": ENTRY_TYPE_NOTE,
                "ContentsFormat": "markdown",
                "Contents": _format_comment(note, _current_user()),
                "Tags": [TAEGIS_COMMENT_TAG],
            }
        ]
    )

    # Determine whether to assign to Secureworks.
    # The form always prompts the user ("No"/"Yes"); if somehow the arg arrives empty
    # (e.g. script called programmatically without the arg), default to not assigning.
    assign_arg = args.get("assign_case_to_sophos")
    if assign_arg is not None and str(assign_arg).strip() != "":
        do_assign = _is_truthy(assign_arg)
    else:
        do_assign = False

    if not do_assign:
        return

    # Get the Taegis investigation ID from the incident mirror ID.
    incident = demisto.incident() or {}
    inner = incident.get("incident") or incident.get("Incident") or incident
    custom = (inner.get("CustomFields") or inner.get("customFields") or {}) if isinstance(inner, dict) else {}
    investigation_id = (
        (inner.get("dbotMirrorId") if isinstance(inner, dict) else None)
        or custom.get("dbotMirrorId")
        or ""
    )
    investigation_id = str(investigation_id).strip() if investigation_id else ""

    if not investigation_id:
        demisto.results(
            [
                {
                    "Type": ENTRY_TYPE_NOTE,
                    "ContentsFormat": "markdown",
                    "Contents": "Comment added. Could not assign to Sophos MDR team: incident is not mirrored from Taegis (no investigation ID found).",
                }
            ]
        )
        return

    try:
        demisto.executeCommand(
            "taegis-push-assignee-status",
            {"id": investigation_id, "assignee_id": "@secureworks", "status": "AWAITING_ACTION"},
        )
        demisto.results(
            [
                {
                    "Type": ENTRY_TYPE_NOTE,
                    "ContentsFormat": "markdown",
                    "Contents": "Comment added and case assigned to Sophos MDR team (status: AWAITING_ACTION).",
                }
            ]
        )
    except Exception as e:
        demisto.results(
            [
                {
                    "Type": ENTRY_TYPE_NOTE,
                    "ContentsFormat": "markdown",
                    "Contents": "Comment added. Could not assign to Sophos MDR team: {}.".format(str(e)),
                }
            ]
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
