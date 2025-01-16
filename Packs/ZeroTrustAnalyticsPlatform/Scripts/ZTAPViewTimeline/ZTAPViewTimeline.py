from CommonServerPython import *

from typing import Any
import traceback

""" STANDALONE FUNCTION """


def view_timeline(notes, ztap_tags) -> str:
    table_name = "Timeline"
    headers = ["Time", "Message"]

    fields = []
    for note in notes:
        message = None
        occurred = ""
        # Filter out notes that do not relate to ZTAP
        tags = note.get("Tags") or []
        if all(tag not in ztap_tags for tag in tags):
            continue

        if note.get("ContentsFormat") == "text":
            message = note.get("Contents")
            occurred = note.get("Metadata").get("created")

        if note.get("ContentsFormat") == "markdown":
            message = note.get("Contents")
            occurred = note.get("Metadata").get("created")

        if message:
            fields.append({"Time": occurred, "Message": message})

    fields.sort(key=lambda f: f["Time"], reverse=True)

    if fields:
        output = tableToMarkdown(table_name, fields, headers=headers)
    else:
        output = "No ZTAP timeline"

    return output


""" COMMAND FUNCTION """


def view_timeline_command(args: dict[str, Any]) -> CommandResults:  # pragma: no cover
    incident = demisto.incident()
    input_tag = incident.get("CustomFields").get("ztapinputtag")
    output_tags = incident.get("dbotMirrorTags")

    ztap_tags = []
    if input_tag:
        ztap_tags.append(input_tag)
    ztap_tags.extend(output_tags)

    entries = demisto.executeCommand(
        "getEntries", {"filter": {"categories": ["notes"]}}
    )

    if not entries:
        entries = []

    # Call the standalone function and get the raw response
    result = view_timeline(entries, ztap_tags)

    return CommandResults(
        outputs_prefix="ZTAPviewTimeline",
        outputs_key_field="",
        outputs=[result],
        readable_output=result,
    )


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        return_results(view_timeline_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
