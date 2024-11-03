from CommonServerPython import *

from typing import Any


def check_tags(args: dict[str, Any]) -> CommandResults:
    incident_id = args['incident_id']
    domain_tags = args['domain_tags']
    domain_tags_set = {domain_tag['label'] for domain_tag in domain_tags}

    malicious_tags = args['malicious_tags']
    malicious_tags_set = {tag.strip() for tag in malicious_tags.split(",")}

    tag_intersection = None
    human_readable_str = 'No matching tags found.'

    if len(domain_tags_set) and len(malicious_tags_set):
        tag_intersection = len(
            malicious_tags_set.intersection(domain_tags_set))
    if tag_intersection:
        # 3 is High severity level
        demisto.executeCommand(
            'setIncident', {'id': incident_id, 'severity': 3})
        human_readable_str = f'Incident {incident_id} has been updated to HIGH Severity.'

    return CommandResults(readable_output=human_readable_str)


def main():
    try:
        return_results(check_tags(demisto.args()))
    except Exception as ex:
        return_error(
            f"Failed to execute CheckTags. Error: {str(ex)}")


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
