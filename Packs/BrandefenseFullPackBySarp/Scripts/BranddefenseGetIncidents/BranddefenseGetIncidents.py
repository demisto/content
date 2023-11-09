import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"
created_at=demisto.getArg("created_at")
def get_incidents(api_token):
    url = "https://api.brandefense.io/api/v1/incidents"
    querystring={'created_at__range':str(created_at)}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers,params=querystring)
    branddefense_all_incidents={'branddefense_incidents':response.json()}
    result=CommandResults(outputs=branddefense_all_incidents,outputs_prefix='branddefense_all_incidents')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_incidents(api_token)
