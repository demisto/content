import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('caldera-get-planners', {})[0]['Contents']
planners = sorted([f"{x.get('name')} ({x.get('id')})" for x in res])
return_results(
    {
        "hidden": False,
        "options": planners
    }
)
