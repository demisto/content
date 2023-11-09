import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"
ioc_type=demisto.getArg('ioc_type')
ioc_type=str(ioc_type)
def get_ioc(api_token,ioc_type):
    url = "https://api.brandefense.io/api/v1/threat-intelligence/iocs"
    querystring={'ioc_type':ioc_type}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers, params=querystring)
    branddefense_ioc={'branddefense_ioc':response.json()}
    result=CommandResults(outputs=branddefense_ioc,outputs_prefix='branddefense_ioc')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_ioc(api_token,ioc_type)
