from CommonServerPython import *


def main():
    incident_id = demisto.args().get('incident_id')
    domain_tags = demisto.args().get('domain_tags')
    malicious_tags = demisto.args().get('malicious_tags')

    malicious_tags_set = set(json.loads(malicious_tags))
    domain_tags_set = set([domain_tag['label'] for domain_tag in domain_tags])
    tag_intersection = None
    human_readable_str = 'No matching tags found.'

    if len(domain_tags_set) and len(malicious_tags_set):
        tag_intersection = len(malicious_tags_set.intersection(domain_tags_set))
    if tag_intersection:
        # 3 is High severity level
        demisto.executeCommand('setIncident', {'id': incident_id, 'severity': 3})
        human_readable_str = 'Incident {} has been updated to HIGH Severity.'.format(incident_id)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {},
        'HumanReadable': human_readable_str,
        'EntryContext': {}
    })


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
