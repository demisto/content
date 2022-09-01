from CommonServerPython import *

from typing import Dict, Any
import traceback

""" STANDALONE FUNCTION """


def get_description(contents):
    """
    Gets the description of an ZTAP note.
    Type will be prefixed to the first line of the comment/log.
    """
    note = contents.get("contents")
    if not note:
        return ""

    first_line = note.split("\n")[0]

    typ = contents.get("type")
    if typ == "comment":
        description = "ZTAP Comment: " + first_line
    elif typ == "log":
        description = "ZTAP Log: " + first_line
    else:
        description = ""

    return description


def parse_note(note, filename_to_occurred):
    description = ""
    occurred = ""

    # Json contents log or comment
    if note.get("ContentsFormat") == "json":
        contents = note.get("Contents")
        description = get_description(contents)
        occurred = contents.get("occurred") or ""
    elif note.get("File"):
        filename = note.get("File")
        description = "ZTAP Uploaded File: " + filename
        occurred = filename_to_occurred.get(filename)

    return description, occurred


def get_occurred(note):
    if note.get("ContentsFormat") == "json":
        contents = note.get("Contents")
        return contents.get("occurred") or ""

    return ""


def get_filenames(note):
    if note.get("ContentsFormat") == "json":
        contents = note.get("Contents")
        return contents.get("files") or []

    return []


def build_timeline(entries):
    """
    Marks notes as evidence in the timeline
    :param entries: notes from the incident
    :return: Results
    """

    results = {}

    # Parse each comment for file names
    filename_to_occurred = {}
    for note in entries:
        occurred = get_occurred(note)
        for filename in get_filenames(note):
            filename_to_occurred[filename] = occurred

    for note in entries:
        if not note.get("Evidence", False):

            description, occurred = parse_note(note, filename_to_occurred)
            if all((description, occurred)):
                note_id = note["ID"]
                result = demisto.executeCommand(
                    "markAsEvidence",
                    {
                        "id": note_id,
                        "tags": note["Tags"],
                        "description": description,
                        "when": occurred,
                    },
                )
                if result[0].get("Contents") == "done":
                    results[note_id] = "Marked as evidence"
                else:
                    return_error("Unable to mark note {note_id} as evidence")

    if not results:
        results["Message"] = "No new notes to add to evidence timeline"

    return results


""" COMMAND FUNCTION """


def build_timeline_command(args: Dict[str, Any]) -> CommandResults:
    incident = demisto.incident()
    input_tag = incident.get("CustomFields").get("ztapinputtag")
    entries = demisto.executeCommand(
        "getEntries", {"filter": {"tags": [input_tag], "categories": ["notes"]}}
    )

    # Call the standalone function and get the raw response
    results = build_timeline(entries)

    return CommandResults(
        outputs_prefix="ZTAPBuildTimeline",
        outputs_key_field="",
        outputs=results,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(build_timeline_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
