from CommonServerPython import *

incident_id = demisto.args()['incident_id']
domain_tags = demisto.args()['domain_tags']
bad_tags = demisto.args()['bad_tags']


bad_tags_set = set(json.loads(bad_tags))
domain_tags_set = set([x['label'] for x in domain_tags])

tag_intersection = None
human_readable_str = "No matching tags found."
if len(domain_tags_set) and len(bad_tags_set):
    tag_intersection = len(bad_tags_set.intersection(domain_tags_set))
if tag_intersection:
    # 3 is High severity level
    demisto.executeCommand('setIncident', {'id': incident_id, 'severity': 3})
    human_readable_str = "Incident {} has been updated to HIGH Severity.".format(incident_id)

demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["json"],
    "Contents": {},
    "HumanReadable": human_readable_str,
    "EntryContext": {}
})