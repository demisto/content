import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

field = demisto.args().get('name')
new_step = demisto.args().get('new')
old_step = demisto.args().get('old')

incident = demisto.incidents()[0]
fields = incident['CustomFields']
phase_name = fields.get('usecasephase')
phase_status = fields.get('phasestatus')

config_list_raw = demisto.executeCommand("getList", {"listName": "UseCaseConfig"})
config_list = safe_load_json(config_list_raw[0]['Contents'])
phase = config_list[phase_name]
step = phase['steps'][new_step]

if phase_status == 'Complete':
    demisto.executeCommand("setIncident", {'usecasecompletion': step})
