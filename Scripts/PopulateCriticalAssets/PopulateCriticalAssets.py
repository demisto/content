import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

field_cli_name = "criticalassets"
current_value = (demisto.incidents()[0].get("CustomFields").get(field_cli_name)
                 or demisto.incidents()[0].get(field_cli_name))
critical_assets = demisto.args().get('critical_assets')
lst = []
for key, value in critical_assets.items():
    if isinstance(value, list):
        lst += [{'assetname': asset_value, 'assettype': key} for asset_value in value]
    else:
        lst += [{'assetname': value, 'assettype': key}]

# If the field is empty, we will set an empty value. Else, we will append the new values and set it to the field.
if not current_value:
    current_value = lst
else:
    current_value += lst
val = json.dumps({ field_cli_name: current_value })

demisto.results(demisto.executeCommand("setIncident", { 'customFields': val }))