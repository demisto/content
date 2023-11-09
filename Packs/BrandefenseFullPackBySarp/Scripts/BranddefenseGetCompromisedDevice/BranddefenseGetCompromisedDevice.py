import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"

def get_audit_logs(api_token):
    botnet_id=demisto.getArg('botnet_id')
    url = "https://api.brandefense.io/api/v1/compromised-devices/"+str(botnet_id)
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    compromised_device={'compromised_devices':response.json()}
    result=CommandResults(outputs=compromised_device,outputs_prefix='compromised_devices')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token)
