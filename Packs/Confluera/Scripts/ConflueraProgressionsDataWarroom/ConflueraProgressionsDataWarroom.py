from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-fetch-progressions command/script
progressions_data = demisto.executeCommand('confluera-fetch-progressions', {'hours': '72'})

if progressions_data[1] and progressions_data[1]['Contents']:
    progressions = progressions_data[1]['Contents']
else:
    progressions = []

data = []

for _idx, progression in enumerate(progressions):
    if progression['riskScore'] == 0:
        color = "blue"
    elif progression['riskScore'] < 25:
        color = "green"
    else:
        color = "red"

    temp_dct = {
        "name": 'AP-' + str(progression['attackId']),
        "data": [progression['riskScore']],
        "color": color
    }

    data.append(temp_dct)

return_results({
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": data,
        "params": {
            "layout": "vertical"
        }
    }
})
