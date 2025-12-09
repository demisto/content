import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json

""" MAIN FUNCTION """


def main():
    try:
        notes = demisto.incident().get("CustomFields", {}).get("vectraxdrentitynotes", [])
        if not bool(notes):
            return_results({"ContentsFormat": EntryFormat.MARKDOWN, "Type": EntryType.NOTE, "Contents": "", "Note": False})
        else:
            for note in notes:
                note = json.loads(note)
                if note:
                    return_results(
                        {
                            "ContentsFormat": EntryFormat.MARKDOWN,
                            "Type": EntryType.NOTE,
                            "Contents": "[Fetched From Vectra]\n"
                            + f"Added By: {note.get('created_by')}\n"
                            + f"Added At: {note.get('date_created')} UTC\n"
                            + f"Note Content:{note.get('note')}",
                            "Note": True,
                        }
                    )
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute VectraXDRAddNotesInLayout. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
