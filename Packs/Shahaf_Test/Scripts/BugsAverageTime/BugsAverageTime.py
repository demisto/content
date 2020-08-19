import datetime

import demistomock as demisto
from CommonServerPython import *

github_context = demisto.executeCommand("getContext", {"id": demisto.executeCommand(
    "getIncidents", {'name': 'github-get'})[-1].get('Contents').get('data')[-2].get('id')})
issues_data = github_context[0].get('Contents').get('context').get('Github-GraphQL-data')

bugs_count = 0
total_time = 0

date_now = datetime.datetime.now().date()
start_time = datetime.datetime(2020, 5, 14).date()

for issue in issues_data:
    if 'bug' not in issue.get('labels'):
        continue

    if issue.get('state') == 'OPEN':
        created_at = datetime.datetime.strptime(issue.get('created_at'), '%Y-%m-%dT%H:%M:%SZ').date()
        total_time += (date_now - created_at).days
        bugs_count += 1
        continue

    closed_at = datetime.datetime.strptime(issue.get('closed_at'), '%Y-%m-%dT%H:%M:%SZ').date()
    if closed_at >= start_time:
        total_time += (date_now - closed_at).days
        bugs_count += 1

return_outputs(round(total_time / bugs_count))
