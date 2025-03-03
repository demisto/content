import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_task(args: Dict[str, Any]) -> CommandResults:
    remote_incident_id = demisto.incident()['dbotMirrorId']
    demisto.debug(f'add_task {args=} | {remote_incident_id=}')

    # Updating arguments according to expected command arguments.
    tags = argToList(args.pop('tags', ''))
    args["incident_id"] = remote_incident_id
    response = demisto.executeCommand('rs-add-custom-task', args)
    demisto.debug(f"add_task {response=}")

    table_name = response[0]["HumanReadable"]\
        if (isinstance(response, list)
            and len(response) > 0
            and response[0]["HumanReadable"])\
        else "New task created"

    readable_output = tableToMarkdown(table_name, {
        "Name": args.get('name'),
        "Phase": args.get('phase'),
        "Due date": args.get('due_date'),
        "Description": args.get('description'),
        "Instructions": args.get('instructions')
    })
    return CommandResults(
        readable_output=readable_output, mark_as_note=False, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        res = add_task(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmAddTask. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
