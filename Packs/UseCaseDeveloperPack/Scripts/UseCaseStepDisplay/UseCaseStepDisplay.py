import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# #### Variables #####
field = demisto.args().get('name')
new_phase = demisto.args().get('new')
old_phase = demisto.args().get('old')

incident = demisto.incidents()[0]
fields = incident['CustomFields']
phase_name = fields.get('usecasephase')

# #### Logic #####
config_list_raw = demisto.executeCommand("getList", {"listName": "UseCaseConfig"})
config_list = safe_load_json(config_list_raw[0]['Contents'])
options = list(v for k, v in config_list.items() if k.lower() in phase_name.lower())
results = {'hidden': False, 'options': list(options[0]['steps'].keys())}

demisto.results(results)
