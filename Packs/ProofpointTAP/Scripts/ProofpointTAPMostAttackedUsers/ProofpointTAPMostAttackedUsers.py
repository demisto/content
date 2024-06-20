import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


users = []
users_res_for_chart = []
most_attacked_user_list = demisto.executeCommand('proofpoint-list-most-attacked-users', {'window': 14})
results = most_attacked_user_list[0].get('Contents', {})    # type: ignore

if isinstance(results, dict):
	# In the case the integration is not configured, this value will return as str.
	# Unsupported Command..
	users = results.get('users', [])

for user in users:
    users_res_for_chart.append({"name": user.get("identity").get("emails", [""])[0],
                  "data": [user.get("threatStatistics").get("attackIndex")]})

default_empty_chart_data = [
    {"name": "", "data": [], "color": ""},
]

final_res = users_res_for_chart if users_res_for_chart else default_empty_chart_data
return_results(json.dumps(final_res))