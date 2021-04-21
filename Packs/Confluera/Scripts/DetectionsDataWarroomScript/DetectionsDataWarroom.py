from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-login command/script
login_data = demisto.executeCommand('confluera-login', {})
token = login_data[0]['Contents']['access_token']


# Executes confluera-fetch-detections command/script
detections_data = demisto.executeCommand('confluera-fetch-detections', {'access_token': token, 'hours': '24'})
detections = detections_data[1]['Contents']

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

demisto.results({
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": data,
        "params": {
            "layout": "horizontal"
        }
    }
})
