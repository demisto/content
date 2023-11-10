import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="api_token"
value=demisto.getArg('value')
value=str(value)
def get_audit_logs(api_token,value):
    url = "https://api.brandefense.io/api/v1/cti/threat-search"
    payload={"value": value}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.post(url, json=payload, headers=headers)
    search_start={'sarch_created':response.json()}
    result=CommandResults(outputs=search_start,outputs_prefix='search_start')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token,value)
