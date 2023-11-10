import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="<api_key>"
indicator_type=demisto.getArg('indicator_type')
indicator_type=str(indicator_type)
def get_indicator(api_token,indicator_type):
    url = "https://api.brandefense.io/api/v1/indicators"
    querystring={'indicator_type':indicator_type}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers, params=querystring)
    branddefense_requested_indicator={'branddefense_requested_indicator':response.json()}
    result=CommandResults(outputs=branddefense_requested_indicator,outputs_prefix='branddefense_requested_indicator')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_indicator(api_token,indicator_type)
