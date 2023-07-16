import demistomock as demisto
from CommonServerPython import *


def main():
    incident = demisto.incident()
    splunkComments = []
    demisto.debug(f"incidens: {incident}")
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    fields = incident.get('CustomFields', [])
    if fields:
        splunkComments_str = fields.get('SplunkComments', [])
        for data in splunkComments_str:
            parsed_data = json.loads(data)
            splunkComments.append(parsed_data)
        demisto.debug(f"{fields} \n\n\n SplunkComments: {splunkComments} \n\n\n {type(splunkComments)}")

    if not splunkComments:
        return CommandResults(readable_output='No comments were found in the notable')

    markdown = tableToMarkdown("", splunkComments, headers=['Comment', 'Comment time', 'Reviwer'])
    demisto.debug(f"markdown {markdown}")

    return CommandResults(
        readable_output=markdown
    )
    # return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
