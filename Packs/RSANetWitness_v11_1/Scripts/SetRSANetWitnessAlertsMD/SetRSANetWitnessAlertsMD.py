import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_INCIDENT_FIELDS = {
    'rsaalerts': 'RSA Alerts',
}


def read_context_from_rsa_netwitness_alerts() -> dict:

    incident = demisto.incident().get('CustomFields', {})

    data: dict = {}
    for key in KEYS_INCIDENT_FIELDS:
        if (field_content := incident.get(key)):
            data[KEYS_INCIDENT_FIELDS[key]] = field_content

    return data


def json_to_md(incident_fields: dict) -> str:
     return "\n\n\n".join(tableToMarkdown(name=incident_field, t=incident_fields[incident_field]) for incident_field in incident_fields)


def main():
    incident_fields = read_context_from_rsa_netwitness_alerts()
    return_results(
        CommandResults(
            readable_output=json_to_md(incident_fields) or "No data to present."
        )
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
