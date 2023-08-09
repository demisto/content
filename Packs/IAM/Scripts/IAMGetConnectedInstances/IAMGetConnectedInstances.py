import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
incident = demisto.incidents()[0]
custom_fields = incident.get('CustomFields', {})
okta_iam_instance = custom_fields.get('oktaiaminstance')
configuration = demisto.executeCommand('okta-iam-get-configuration', {'using': okta_iam_instance})[0]["Contents"]
if not configuration:
    configuration = []
unavailable_instances = [conf.get('Instance') for conf in configuration]

demisto.results({"hidden": False, "options": sorted(unavailable_instances)})
