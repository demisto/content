import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_note(args: Dict[str, Any]) -> CommandResults:
    note_body = args.get('note', '')
    tags = argToList(args.get('tags', ''))
    remote_incident_id = demisto.incident()['dbotMirrorId']
    demisto.debug(f'add_note {note_body=} | {remote_incident_id=}')
    response = demisto.executeCommand('rs-add-note', args={
        'note': note_body,
        'incident-id': remote_incident_id
    })
    demisto.debug(f"add_note {response=}")
    return CommandResults(
        readable_output=note_body, mark_as_note=True, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        res = add_note(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmAddNote. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
