import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def convert_to_table():
    incident = demisto.incident()
    artifact_entries = []
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident from context but returned None")
    demisto.debug(f'ibm_convert_artifacts_to_table {incident=}')
    fields = incident.get('CustomFields', [])

    if fields:
        artifacts = fields.get('ibmsecurityqradarsoarartifacts', [])
        for artifact in artifacts:
            artifact_entry = json.loads(artifact)
            artifact_entries.append(artifact_entry)
    if not artifact_entries:
        return CommandResults(readable_output='No artifacts were found for this incident')
    demisto.debug(f"ibm_convert_artifacts_to_table {artifact_entries=}")
    markdown = tableToMarkdown("", artifact_entries, sort_headers=False)
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
