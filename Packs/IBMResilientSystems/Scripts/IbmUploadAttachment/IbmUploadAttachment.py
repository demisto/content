import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def upload_attachment(args: Dict[str, Any]) -> CommandResults:
    remote_incident_id = demisto.incident()['dbotMirrorId']
    demisto.debug(f'upload_attachment {args=} | {remote_incident_id=}')

    args["incident_id"] = remote_incident_id
    response = demisto.executeCommand('rs-upload-incident-attachment', args)
    demisto.debug(f"upload_attachment {response=}")

    human_readable = response[0]["HumanReadable"]\
        if (isinstance(response, list)
            and len(response) > 0
            and response[0]["HumanReadable"]) \
        else ''

    return CommandResults(
        readable_output=human_readable
    )


def main():  # pragma: no cover
    try:
        res = upload_attachment(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute IbmUploadAttachment. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
