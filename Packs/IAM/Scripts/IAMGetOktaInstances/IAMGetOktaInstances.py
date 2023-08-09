import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
def to_cli_name(field_name):
    return field_name.lower().replace(' ', '')

OKTA_INSTANCE_FIELD = to_cli_name('Okta IAM Instance')

incident = demisto.incidents()[0]
instances = []
all_instances = demisto.getModules()
for instance_name, details in all_instances.items():
    if details.get('brand') == 'Okta IAM' and details.get('state') == 'active':
        instances.append(instance_name)

if len(instances) == 1:
    incident_data = {'id': incident.get('id'), 'customFields': {OKTA_INSTANCE_FIELD: instances[0]}}
    demisto.executeCommand('setIncident', incident_data)

demisto.results({"hidden": False, "options": sorted(instances)})
