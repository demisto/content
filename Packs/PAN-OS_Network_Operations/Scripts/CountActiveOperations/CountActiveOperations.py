import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]
target = incident.get('CustomFields', {}).get('panosnetworkoperationstarget')
res = demisto.executeCommand("GetIncidentsByQuery", {
    "query": f"-status:closed -category:job target:{target} -type:\"PAN-OS Network Operations - Device\""
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
            "name": f"Active Operations for {target}",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {
                      "value": 5
                    },
                    "#FAC100": {
                        "value": 0
                    },
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
