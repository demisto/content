import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

most_attacked_user_list = demisto.executeCommand('proofpoint-list-most-attacked-users', {'window': 14})
results = most_attacked_user_list[0].get('Contents', {})    # type: ignore

if isinstance(results, dict):
	# In the case the integration is not configured, this value will return as str.
	# Unsupported Command..
	users = results.get('users', [])

for user in users:
    users.append({"name": user.get("identity").get("emails", [""])[0],
                  "data": [user.get("threatStatistics").get("attackIndex")]})

data = [
    {"name": "", "data": [], "color": ""},
]

final = users if users else data
demisto.results(json.dumps(final))

return_results(json.dumps(users))
