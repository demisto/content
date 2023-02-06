import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('caldera-get-objectives', {})[0]['Contents']
objectives = sorted([f"{x.get('name')} ({x.get('id')})" for x in res])
return_results(
    {
        "hidden": False,
        "options": objectives
    }
)
