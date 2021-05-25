from CommonServerPython import *
from CommonServerUserPython import *

import json
from itertools import cycle

# Executes confluera-fetch-detections command/script
detections_data = demisto.executeCommand('confluera-fetch-detections', {'hours': '72'})

if detections_data[1] and detections_data[1]['Contents']:
    detections = detections_data[1]['Contents']
else:
    detections = []

# Generating Chart data
data: List[dict] = []
colors = cycle([
    '#dc5e50',
    '#64bb18',
    '#8b639a',
    '#d8a747',
    '#528fb2',
    '#9cc5aa',
    '#f1934c',
    '#e25b4c',
    '#5bbe80',
    '#c0363f',
    '#cdb8a8',
    '#3cc861'])

for idx, ioc in enumerate(detections):
    element = [item for item in data if item['name'] == ioc['iocTactic']]
    if element and len(element) != 0:
        element[0]['data'][0] += 1
    else:
        chart_item = {
            "name": ioc['iocTactic'],
            "data": [1],
            "color": next(colors)
        }
        data.append(chart_item)

return_results(json.dumps(data))
