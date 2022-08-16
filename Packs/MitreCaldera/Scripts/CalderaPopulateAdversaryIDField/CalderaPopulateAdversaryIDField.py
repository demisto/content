import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('caldera-get-adversaries', {})[0]['Contents']
adversaries = sorted([f"{x.get('name')} ({x.get('adversary_id')})" for x in res])
return_results(
    {
        "hidden": False,
        "options": adversaries
    }
)
