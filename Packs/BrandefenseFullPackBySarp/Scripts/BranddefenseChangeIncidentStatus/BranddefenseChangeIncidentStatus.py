import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"
incident_code=demisto.getArg('incident_code')
incident_code=str(incident_code)
incident_status=demisto.getArg('incident_status')
incident_status=str(incident_status)
def get_audit_logs(api_token,incident_code,incident_status):
    url = "https://api.brandefense.io/api/v1/incidents/"+incident_code+"/change-status"
    payload={"status":incident_status}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.patch(url,json=payload, headers=headers)
    incident_status_to_changed={'incident_status_to_changed':response.json()}
    result=CommandResults(outputs=incident_status_to_changed,outputs_prefix='incident_status_to_changed')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token,incident_code,incident_status)
