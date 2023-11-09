import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"

def get_audit_logs(api_token):
    url = "https://api.brandefense.io/api/v1/audit-logs"
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    auditlogs={'auditlogs':response.json()}
    result=CommandResults(outputs=auditlogs,outputs_prefix='branddefense_audit_logs')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token)
