import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def to_cli_name(field_name):
    return field_name.lower().replace(" ", "")


OKTA_INSTANCE_FIELD = to_cli_name("Okta IAM Instance")
CONNECTED_INSTANCE_NAME_FIELD = to_cli_name("Connected integration instance in XSOAR")
CONNECTED_APP_ID_FIELD = to_cli_name("Connected application ID in Okta")

incident = demisto.incidents()[0]
custom_fields = incident.get("CustomFields", {})
okta_iam_instance = custom_fields.get(OKTA_INSTANCE_FIELD)
connected_instance = custom_fields.get(CONNECTED_INSTANCE_NAME_FIELD)

configuration = demisto.executeCommand(
    "okta-iam-get-configuration", {"using": okta_iam_instance}
)[0]["Contents"]
if not configuration:
    configuration = []

connected_application = ""
for conf in configuration:
    if conf.get("Instance") == connected_instance:
        connected_application = conf.get("ApplicationID")

incident_data = {
    "id": incident.get("id"),
    "customFields": {CONNECTED_APP_ID_FIELD: connected_application},
}
demisto.executeCommand("setIncident", incident_data)
