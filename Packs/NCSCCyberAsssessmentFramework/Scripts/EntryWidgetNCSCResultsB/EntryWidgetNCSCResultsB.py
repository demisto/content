import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
cafbresult = incident[0].get("CustomFields", {}).get("cafbresultraw", {})
if type(cafbresult) is not dict:
    cafbresult = json.loads(cafbresult)
total = len(cafbresult)
non_compliant_count = (
    len([x for x in cafbresult if x["Result"] != "Achieved"]) if cafbresult else None
)
medium = int(round(total / 3, 0))
high = int(round(total / 3 * 2, 0))
data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": non_compliant_count,
        "params": {
            "layout": "horizontal",
            "name": "Unachieved items",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {"value": -1},
                    "#FF9000": {"value": medium},
                    "#FF1744": {"value": high},
                }
            },
            "type": "above",
        },
    },
}

demisto.results(data)
