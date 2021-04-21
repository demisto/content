from CommonServerPython import *
from CommonServerUserPython import *

# Executes confluera-login command/script
login_data = demisto.executeCommand('confluera-login', {})
token = login_data[0]['Contents']['access_token']

# Executes confluera-fetch-progressions command/script
progressions_data = demisto.executeCommand('confluera-fetch-progressions', {'access_token': token, 'hours': '72'})
progressions = progressions_data[1]['Contents']

data = []

for idx, progression in enumerate(progressions):
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

demisto.results({
    "Type": 17,
    "ContentsFormat": "bar",
    "Contents": {
        "stats": data,
        "params": {
            "layout": "vertical"
        }
    }
})
