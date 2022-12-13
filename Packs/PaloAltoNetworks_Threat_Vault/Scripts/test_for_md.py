import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def read_context_from_threat_vault_incident():

    spyware = demisto.get(demisto.context(), 'incident.threatvaultbypaloaltonetworksspywarenew')
    vulnerability = demisto.get(demisto.context(), 'incident.testfortv')

    items = (x for x in (spyware, vulnerability))
    return items


def json_to_md(data_json: dict, type_: str):

    return tableToMarkdown(
        name=type_,
        t=data_json,
    )


def main():
    incident_context = read_context_from_threat_vault_incident()

    md = 'hello'
    for item in incident_context:
        md += json_to_md(item, 'Test')
        md += '\n\n\n'

    return_results(CommandResults(
        readable_output=md
    ))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
