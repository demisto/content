import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
available_instances = []
incident = demisto.incidents()[0]
custom_fields = incident.get('CustomFields', {})
okta_iam_instance = custom_fields.get('oktaiaminstance')
configuration = demisto.executeCommand('okta-iam-get-configuration', {'using': okta_iam_instance})[0]["Contents"]
if not configuration:
    configuration = []
unavailable_instances = [conf.get('Instance') for conf in configuration]


all_instances = demisto.getModules()
for instance_name, details in all_instances.items():
  if details.get('category') == 'Identity and Access Management' and details.get('state') == 'active':
      if instance_name not in unavailable_instances and details.get('brand') != 'Workday IAM':
        available_instances.append(instance_name)

demisto.results({"hidden": False, "options": sorted(available_instances)})
