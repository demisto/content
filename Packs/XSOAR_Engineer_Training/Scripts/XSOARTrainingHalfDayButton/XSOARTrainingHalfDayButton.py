import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# This automation sets the playbook on the current Incident to the XSOAR Engineer Training - BYOI Take a Half Day playbook.  Because we needed a button for half days.

demisto.results(demisto.executeCommand("setPlaybook", {"name": "XSOAR Engineer Training - BYOI Take a Half Day"}))
