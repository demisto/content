import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# ##### Logic #####
field = demisto.args().get('name')
new_phase = demisto.args().get('new')
old_phase = demisto.args().get('old')

config_list_raw = demisto.executeCommand("getList", {"listName": "UseCaseConfig"})
config_list = safe_load_json(config_list_raw[0]['Contents'])

options = list(config_list.keys())
results = {'hidden': False, 'options': options}
demisto.results(results)
