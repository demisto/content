import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_to_table():
    incident = demisto.incident()
    attachment_entries = []
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")
    demisto.debug(f'ibm_convert_attachments_to_table {incident=}')
    fields = incident.get('CustomFields', [])

    if fields:
        attachments = fields.get('ibmsecurityqradarsoarattachments', [])
        for attachment_data in attachments:
            parsed_data = json.loads(attachment_data)
            attachment_entries.append(parsed_data)
    if not attachment_entries:
        return CommandResults(readable_output='No attachments were found for this incident')
    demisto.debug(f"ibm_convert_tasks_to_table {attachment_entries=}")
    markdown = tableToMarkdown("", attachment_entries, sort_headers=False)
    return CommandResults(
        readable_output=markdown
    )


def main():
    try:
        return_results(convert_to_table())
    except Exception as e:
        return_error(f'Got an error while parsing: {e}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
