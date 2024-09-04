import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_task(args: Dict[str, Any]) -> CommandResults:
    task_instructions = args.get('task', '')
    tags = argToList(args.get('tags', ''))
    remote_incident_id = demisto.incident()['dbotMirrorId']
    demisto.debug(f'add_task {task_instructions=} | {remote_incident_id}')
    response = demisto.executeCommand('rs-add-note', args={
        'note': task_instructions,
        'incident-id': remote_incident_id
    })
    demisto.debug(f"add_task {response=}")
    return CommandResults(
        readable_output=task_instructions, mark_as_note=False, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        res = add_task(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmAddNTask. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
