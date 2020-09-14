import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

mitre_id = demisto.get(demisto.args()['indicator'], 'CustomFields.mitreid')
err_msg = "MITRE ID was not found"

if not mitre_id:
    return_error(err_msg)

demisto.results(
    {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': f'# {mitre_id}'})
