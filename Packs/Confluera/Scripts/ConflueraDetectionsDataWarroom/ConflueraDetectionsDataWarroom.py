from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-fetch-detections command/script
detections_data = demisto.executeCommand('confluera-fetch-detections', {'hours': '72'})

if detections_data[1] and detections_data[1]['Contents']:
    detections = detections_data[1]['Contents']
else:
    detections = []

# Generating Chart data
data = []

for idx, ioc in enumerate(detections):
    if ioc['scoreContribution'] == 0:
        ioc_color = "blue"
    elif ioc['scoreContribution'] < 10:
        ioc_color = "green"
    else:
        ioc_color = "red"

    chart_item = {
        "name": 'Detection-' + str(idx + 1),
        "data": [ioc['scoreContribution']],
        "color": ioc_color
    }

    data.append(chart_item)

return_results({
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": data,
        "params": {
            "layout": "horizontal"
        }
    }
})
