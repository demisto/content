import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    incident = demisto.incident()
    splunkComments = []
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    fields = incident.get('CustomFields', [])
    if fields:
        splunkComments_str = fields.get('splunkcomments', [])
        for data in splunkComments_str:
            parsed_data = json.loads(data)
            splunkComments.append(parsed_data)
    if not splunkComments:
        return CommandResults(readable_output='No comments were found in the notable')

    markdown = tableToMarkdown("", splunkComments, headers=['Comment'])
    return CommandResults(
        readable_output=markdown
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
