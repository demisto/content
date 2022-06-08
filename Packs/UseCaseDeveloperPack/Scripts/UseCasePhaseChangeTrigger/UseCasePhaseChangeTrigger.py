import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

field = demisto.args().get('name')
new_phase = demisto.args().get('new')
old_phase = demisto.args().get('old')
field_name = "phasestep"

config_list_raw = demisto.executeCommand("getList", {"listName": "UseCaseConfig"})
config_list = safe_load_json(config_list_raw[0]['Contents'])

phase = config_list[new_phase]

# set step to first in phase
initial_step = list(phase['steps'].keys())[0]

demisto.executeCommand("setIncident", {field_name: initial_step})

# get each phase entry
for k, v in config_list.items():
    if k != new_phase:
        if v['timer']:
            demisto.executeCommand("pauseTimer", {"timerField": v['timer']})
            demisto.log(f"Timer paused - {v['timer']}")
# Commenting out as start timers handled in use case playbooks individually.
#    else:
#        if v['timer']:
#            demisto.executeCommand("startTimer", {"timerField": v['timer']})

playbook_command = "!setPlaybook name=\"{0}\"".format(phase['playbook'])
demisto.executeCommand("ScheduleCommand", {"command": playbook_command, "cron": "* * * * *", "times": 1})
