import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import date, timedelta
import json

current_date = date.today().isoformat()
date_before = (date.today()-timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')

username = demisto.get(demisto.args()['indicator'], "CustomFields.username")
searchString = "actor.alternateId eq \"{}\"".format(username)
searchQuery = {}
searchQuery['filter'] = searchString

searchQuery['since'] = date_before
#"2019-12-18T14:31:00Z"
err_msg = "No Activity Logs Were Found"

if not username:
    return_error(err_msg)
try:
    results = demisto.executeCommand('okta-get-logs', searchQuery)
except ValueError:
    return_error(err_msg)


content = results[0]['Contents']
total_count = int(len(content))
demisto.log(json.dumps(content))
sys.exit(1)

error_count = 0
warn_count = 0
debug_count = 0
info_count = 0

my_list = content[0]
for item in my_list:
    if item['severity'] == 'INFO':
        info_count += 1
    elif item['severity'] == 'DEBUG':
        debug_count +=1
    elif item['severity'] == 'WARN':
        warn_count += 1
    elif item['severity'] == 'ERROR':
        error_count += 1

if not content:
    return_error(err_msg)

data = {
    "Type": 17,
    "ContentsFormat": "pie",
    "Contents": {
        "stats": [
            {
                "data": [
                    int(warn_count)
                ],
                "groups": None,
                "name": "Suspicious",
                "label": "Suspicious",
                "color": "rgb(255, 23, 68)"
            },
            {
                "data": [
                    int(error_count)
                ],
                "groups": None,
                "name": "Error",
                "label": "Error",
                "color": "rgb(255, 144, 0)"
            },
            {
                "data": [
                    int(info_count)
                ],
                "groups": None,
                "name": "Info",
                "label": "Info",
                "color": "rgb(0, 205, 51)"
            },
            {
                "data": [
                    int(debug_count)
                ],
                "groups": None,
                "name": "Debug",
                "label": "Debug",
                "color": "rgb(220, 220, 220)"
            },
        ],
        "params": {
            "layout": "horizontal"
        }
    }
}

demisto.results(data)
#demisto.results(results)
#demisto.results(
#   {'ContentsFormat': formats['json'], 'Type': entryTypes['map'], 'Contents': {"lat": float(lat), "lng": float(lng)}})
