import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This automation sets the playbook on a given Incident based on a list of options in the playbook argument.

PLAYBOOK_MAP = {
    "Sub-Playbook Inputs & Outputs - AD User Lookup": "XSOAR Engineer Training - AD User Lookup (Parent)",
    "Loops - For Each": "XSOAR Engineer Training - For Each Loops (Parent)",
    "Loops - Builtin": "XSOAR Engineer Training - Builtin Loops (Parent)",
    "Loops - Loop on Array Data": "XSOAR Engineer Training - Loop on Array Data",
    "Extend Context - Set By Incident": "XSOAR Engineer Training - Extend Context - Set By Incident",
    "Extend Context - AD Get User": "XSOAR Engineer Training - Extend Context - AD Get User",
    "Lists - Internal IP": "XSOAR Engineer Training - Lists - Internal IPs",
    "Lists - Environment": "XSOAR Engineer Training - Lists - Environment List",
    "SLA Timer Breach": "XSOAR Engineer Training - SLA Timer Breach Example",
    "Data Collection Tasks": "XSOAR Engineer Training - Data Collection Tasks",
    "Set Grid Field": "XSOAR Engineer Training - Set Grid Field"
}

# get the argument for the playbook
playbook = demisto.args().get("playbook")
playbook = PLAYBOOK_MAP.get(playbook, "None")

# set new playbook
demisto.results(demisto.executeCommand("setPlaybook", {"name": playbook}))
