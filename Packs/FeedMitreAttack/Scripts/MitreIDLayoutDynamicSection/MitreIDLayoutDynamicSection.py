import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

mitre_id = demisto.get(demisto.args()['indicator'], 'Name') or ''

demisto.results(
    {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': f'# {mitre_id}'})
