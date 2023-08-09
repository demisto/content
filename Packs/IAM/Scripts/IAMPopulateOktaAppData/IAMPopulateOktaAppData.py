import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
def to_cli_name(field_name):
    return field_name.lower().replace(' ', '')

OKTA_APPS_FIELD = to_cli_name('Available Okta applications')
OKTA_APPS_DATA_FIELD = to_cli_name('Available Okta applications data')
APP_NAME_FIELD = to_cli_name('Application name in Okta')
APP_ID_FIELD = to_cli_name('Application ID in Okta')

incident = demisto.incidents()[0]
custom_fields = incident.get('CustomFields', {})
okta_apps_data = safe_load_json(custom_fields.get(OKTA_APPS_DATA_FIELD))
selected_app_label = custom_fields.get(OKTA_APPS_FIELD)

app_id = okta_apps_data.get(selected_app_label, {}).get('ID')
app_name = okta_apps_data.get(selected_app_label, {}).get('Name')

if app_id or app_name:
    incident_data = {'id': incident.get('id'), 'customFields': {APP_NAME_FIELD: app_name, APP_ID_FIELD:app_id}}
    demisto.executeCommand('setIncident', incident_data)
