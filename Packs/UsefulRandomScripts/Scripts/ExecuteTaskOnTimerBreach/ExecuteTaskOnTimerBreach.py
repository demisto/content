import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# This script will complete tasks with the timerbreach tag value upon timer breach
# Add this as the script to run upon breach on the given timer field.
# Playbook tasks to complete need to be tagged timerbreach.

inc = demisto.incidents()[0].get('id')
demisto.executeCommand("taskComplete", {"id": "timerbreach", "incidentId": inc})
