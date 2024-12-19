import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

from typing import Any
import traceback

''' STANDALONE FUNCTION '''


def remove_id_and_version_from_entry(entry):
    entry.pop('ID', None)
    entry.pop('Version', None)


def copy_notes_to_target_incident(args: dict[str, Any]) -> CommandResults:

    target_incident = args.get('target_incident', None)
    if not target_incident:
        raise ValueError('Target Incident ID not specified')

    tags = argToList(args.get('tags'))
    auto_extract = argToBoolean(args.get('auto_extract', False))
    entries = demisto.executeCommand('getEntries', {'filter': {'tags': tags}})

    note_entries: list = []
    md: str = ''

    if isinstance(entries, list) and len(entries) > 0:
        for entry in entries:
            if entry.get('Note') is True:
                remove_id_and_version_from_entry(entry)
                if not auto_extract:
                    # indicators won't be extracted from the notes in the destination incident
                    entry['IgnoreAutoExtract'] = True
                note_entries.append(entry)

        if len(note_entries) > 0:
            demisto.executeCommand("addEntries", {"id": target_incident,
                                                  "entries": note_entries})
            md = f'## {len(note_entries)} notes copied'
        else:
            md = '## No notes found'
    else:
        md = '## No notes found'

    return CommandResults(readable_output=md)


''' MAIN FUNCTION '''


def main():
    try:
        return_results(copy_notes_to_target_incident(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CopyNotesToIncident. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
