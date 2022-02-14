import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Counts the number of open FW Change requests for the platform, if the change management pack is in use.
"""
res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-status:closed -category:job type:\"FW change management\""
})
if is_error(res):
    return_error(get_error(res))

incidents = json.loads(res[0]['Contents'])


data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": len(incidents),
        "params": {
            "layout": "horizontal",
            "name": "Active Policy Change Requests",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {"value": -1},
                    "#FF9000": {"value": 0},
                    "#FF1744": {"value": 10},
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
