import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"
audit_log_id=demisto.getArg('audit_log_id')
def get_audit_logs(api_token,audit_log_id):
    url = "https://api.brandefense.io/api/v1/audit-logs/"+str(audit_log_id)
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    requestedauditlog={'requestedauditlog':response.json()}
    result=CommandResults(outputs=requestedauditlog,outputs_prefix='branddefense_requested_audit_log')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token,audit_log_id)
