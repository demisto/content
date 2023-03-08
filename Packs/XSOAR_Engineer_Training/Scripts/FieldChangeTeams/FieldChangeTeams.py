import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Field Change trigger script can take an "old" and "new" and then act accordingly.
# Can be used on fields like severity, or owner to do different actions such as escalation or notification.

old = demisto.args().get("old")
new = demisto.args().get("new")

if not old:
    old = "unassigned"

if not new:
    new = "unassigned"

demisto.results(f"Team was changed from {old} to {new}")
