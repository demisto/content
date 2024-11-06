import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback

''' MAIN FUNCTION '''


def main():
    try:
        notes = []
        entity_type = demisto.incident().get('CustomFields', {}).get('vectraentitytype', '')
        if entity_type == 'account':
            account_id = demisto.incident().get('CustomFields', {}).get('accountid', '')
            response = demisto.executeCommand('vectra-account-note-list', args={'account_id': account_id})
            notes = response[0].get('Contents', [])
        elif entity_type == 'host':
            host_id = demisto.incident().get('CustomFields', {}).get('deviceid', '')
            response = demisto.executeCommand('vectra-host-note-list', args={'host_id': host_id})
            notes = response[0].get('Contents', [])
        if not bool(notes) or not isinstance(notes, list):
            return_results(
                {'ContentsFormat': EntryFormat.MARKDOWN, 'Type': EntryType.NOTE, 'Contents': '', 'Note': False})
        else:
            for note in notes:
                if note and isinstance(note, dict):
                    if '\n' in note.get('note', ''):
                        note_info = f"\n{note.get('note')}"
                    else:
                        note_info = note.get('note', '')
                    return_results(
                        {'ContentsFormat': EntryFormat.MARKDOWN, 'Type': EntryType.NOTE,
                         'Contents': "[Fetched From Vectra]\n"
                                     + f"Added By: {note.get('created_by')}\n"
                                     + f"Added At: {note.get('date_created')} UTC\n"
                                     + f"Note: {note_info}",
                         'Note': True})
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute VectraDetectAddNotesInLayout. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
