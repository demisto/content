import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

mitre_name = demisto.get(demisto.args()['indicator'], 'CustomFields.mitrename')
err_msg = "MITRE Name was not found"

if not mitre_name:
    return_error(err_msg)

demisto.results(
    {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': f'# {mitre_name}'})
