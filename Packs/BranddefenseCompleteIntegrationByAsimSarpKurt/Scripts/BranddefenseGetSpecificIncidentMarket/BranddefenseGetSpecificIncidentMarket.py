import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="<api_key>"
incident_code=demisto.getArg('incident_code')
incident_code=str(incident_code)
def get_audit_logs(api_token,incident_code):
    url = "https://api.brandefense.io/api/v1/incidents/"+incident_code
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    branddefense_requested_incident={'branddefense_requested_incident':response.json()}
    result=CommandResults(outputs=branddefense_requested_incident,outputs_prefix='branddefense_requested_incident')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token,incident_code)
