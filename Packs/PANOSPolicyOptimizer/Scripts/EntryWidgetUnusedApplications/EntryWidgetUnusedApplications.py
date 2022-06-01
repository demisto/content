import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

no_apps = demisto.get(demisto.context(), 'PanOS.PolicyOptimizer.UnusedApps', [])

data = {
    "Type": 17,
    "ContentsFormat": "number",
    "Contents": {
        "stats": len(no_apps),
        "params": {
            "layout": "horizontal",
            "name": "Rules with Unused Apps",
            "sign": "",
            "colors": {
                "items": {
                    "#00CD33": {
                        "value": -1
                    },
                    "#FF9000": {
                        "value": 0
                    },
                    "#FF1744": {
                        "value": 3
                    }
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
