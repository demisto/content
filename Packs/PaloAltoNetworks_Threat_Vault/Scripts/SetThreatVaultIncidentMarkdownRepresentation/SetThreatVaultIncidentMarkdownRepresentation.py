import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

KEYS_INCIDENT_FIELDS = {
    'threatvaultbypaloaltonetworksspyware': 'Spyware',
    'threatvaultbypaloaltonetworksvulnerability': 'Vulnerability',
    'threatvaultbypaloaltonetworksfiletype': 'File type',
    'threatvaultbypaloaltonetworksdatacorrelation': 'Data correlation',
    'threatvaultbypaloaltonetworksdecoders': 'Decoders',
    'threatvaultbypaloaltonetworksapplications': 'Applications'
}


def read_context_from_threat_vault_incident():

    incident = demisto.incident().get('CustomFields', {})

    data: dict = {}
    for key in KEYS_INCIDENT_FIELDS.keys():
        if (field_content := incident.get(key)):
            data.update({KEYS_INCIDENT_FIELDS[key]: field_content})

    return data


def json_to_md(incident_fields: dict) -> str:

    md = ''

    for incident_field in incident_fields:
        md += tableToMarkdown(name=incident_field, t=incident_fields[incident_field])
        md += '\n\n\n'

    return md


def main():
    incident_fields = read_context_from_threat_vault_incident()
    md = json_to_md(incident_fields)

    return_results(
        CommandResults(
            readable_output=md or "No data to present"
        )
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
