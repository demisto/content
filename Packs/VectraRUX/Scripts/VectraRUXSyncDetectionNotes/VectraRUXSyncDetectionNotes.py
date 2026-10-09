import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any

# HELPER FUNCTIONS


def handle_error(command_results: list[dict[str, Any]]) -> None:
    """
    Handle the error entries after executing the commands.

    Args:
        command_results (List[Dict[str, Any]]): Command results object.
    Returns:
        Union[None, str]: Returns a string if there is an error, otherwise None.
    """
    if isError(command_results):
        return return_error(command_results[0]["Contents"])
    return None


""" MAIN FUNCTION """


def main():
    try:
        detection_id = demisto.incident().get("CustomFields", {}).get("vectraruxdetectionid", "")
        detection_notes = json.loads(demisto.incident().get("CustomFields", {}).get("vectraruxdetectionnotes") or "[]")

        command_args = {"detection_id": detection_id}
        command_result = demisto.executeCommand("vectra-detection-note-list", command_args)
        # Handle command error if there is any
        handle_error(command_result)
        result = command_result[0].get("Contents", [])

        new_notes = []
        for note in result:
            if note in detection_notes:
                continue
            elif "[Mirrored From XSOAR]" not in note.get("note"):
                new_notes.append(note)

        if not new_notes:
            return_results("Detection notes already synchronized.")
        else:
            for note in new_notes:
                return_results(
                    {
                        "ContentsFormat": EntryFormat.MARKDOWN,
                        "Type": EntryType.NOTE,
                        "Contents": "[Fetched From Vectra]\n"
                        + f"Added By: {note.get('created_by')}\n"
                        + f"Added At: {note.get('date_created')} UTC\n"
                        + f"Note: {note.get('note')}",
                        "Note": True,
                    }
                )
            demisto.executeCommand("setIncident", {"vectraruxdetectionnotes": json.dumps(result)})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute VectraRUXSyncDetectionNotes. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
