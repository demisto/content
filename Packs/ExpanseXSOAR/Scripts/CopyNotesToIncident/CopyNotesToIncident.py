import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any, List
import traceback
import json

''' STANDALONE FUNCTION '''


def copy_notes_to_target_incident(args: Dict[str, Any]) -> CommandResults:

    target_incident = args.get('target_incident', None)
    if not target_incident:
        raise ValueError('Target Incident ID not specified')

    tags = argToList(args.get('tags'))

    entries = demisto.executeCommand('getEntries', {'filter': {'tags': tags}})

    note_entries: List = []
    md: str = ''

    if isinstance(entries, list) and len(entries) > 0:
        [note_entries.append(n) for n in entries if 'Note' in n and n['Note'] is True]
        if len(note_entries) > 0:
            out = demisto.executeCommand("addEntries", {"id": target_incident, "entries": note_entries})
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
