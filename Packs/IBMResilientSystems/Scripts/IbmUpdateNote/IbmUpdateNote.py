import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def update_note(args: Dict[str, Any]) -> CommandResults:
    note_id = args.get('note_id', '')
    note_body = args.get('note_body', '')
    tags = argToList(args.get('tags', ''))
    remote_incident_id = demisto.incident()['dbotMirrorId']
    demisto.debug(f'update_note {note_body=} | {remote_incident_id=}')
    response = demisto.executeCommand('rs-update-incident-note', args={
        'note_id': note_id,
        'note': note_body,
        'incident_id': remote_incident_id
    })
    demisto.debug(f"update_note {response=}")
    return CommandResults(
        readable_output=note_body, mark_as_note=True, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        res = update_note(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmUpdateNote. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
