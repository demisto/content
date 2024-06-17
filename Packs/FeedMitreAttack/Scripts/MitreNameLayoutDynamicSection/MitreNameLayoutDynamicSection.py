import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

mitre_name = demisto.get(demisto.args()['indicator'], 'CustomFields.mitrename') or ''

demisto.results(
    {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': f'# {mitre_name}'})
