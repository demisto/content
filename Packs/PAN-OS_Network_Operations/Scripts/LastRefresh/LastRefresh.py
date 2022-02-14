import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Reports the duration since the occurred time, representing the last time this incident was refreshed."""
# -- This is a way to get around trimming commonserverpython on import
import datetime

try:
    demisto.args()
    pass
except:
    from CommonServerPython import *
    pass


incident = demisto.incidents()[0]

occurred_time = datetime.datetime.strptime(incident.get("occurred").split(".")[0], "%Y-%m-%dT%H:%M:%S")
current_time = datetime.datetime.now()
time_delta = current_time - occurred_time

data = {
    "Type": 17,
    "ContentsFormat": "duration",
    "Contents": {
        "stats": time_delta.seconds,
        "params": {
            "layout": "horizontal",
            "name": "Last run visibility incident",
            "sign": "@",
            "colors": {
                "items": {
                    "#00CD33": {
                        "value": 10
                    },
                    "#FAC100": {
                        "value": 20
                    },
                    "green": {
                        "value": 40
                    }
                }
            },
            "type": "above"
        }
    }
}

demisto.results(data)
