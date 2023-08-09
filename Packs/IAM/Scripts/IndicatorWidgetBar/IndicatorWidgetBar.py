import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Constants
HIGH = 3
SUSPICIOUS = 2
LOW = 1
NONE = 0

indicators = []
scores = {HIGH: 0, SUSPICIOUS: 0, LOW: 0, NONE: 0}
incident_id = demisto.incidents()[0].get('id')

foundIndicators = demisto.executeCommand("findIndicators", {"query":'type:"User Profile"', 'size':999999})[0]['Contents']

for indicator in foundIndicators:
    scores[indicator['score']] += 1

data = {
  "Type": 17,
  "ContentsFormat": "bar",
  "Contents": {
    "stats": [
      {
        "data": [
          scores[HIGH]
        ],
        "groups": None,
        "name": "high",
        "label": "incident.severity.high",
        "color": "rgb(255, 23, 68)"
      },
      {
        "data": [
          scores[SUSPICIOUS]
        ],
        "groups": None,
        "name": "medium",
        "label": "incident.severity.medium",
        "color": "rgb(255, 144, 0)"
      },
      {
        "data": [
          scores[LOW]
        ],
        "groups": None,
        "name": "low",
        "label": "incident.severity.low",
        "color": "rgb(0, 205, 51)"
      },
      {
        "data": [
          scores[NONE]
        ],
        "groups": None,
        "name": "normal activity",
        "label": "incident.severity.unknown",
        "color": "rgb(197, 197, 197)"
      }
    ],
    "params": {
        "layout": "horizontal"
    }
  }
}

demisto.results(data)
