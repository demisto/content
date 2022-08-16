import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

res = demisto.executeCommand('caldera-get-sources', {})[0]['Contents']
sources = sorted([f"{x.get('name')} ({x.get('id')})" for x in res])
return_results(
    {
        "hidden": False,
        "options": sources
    }
)
