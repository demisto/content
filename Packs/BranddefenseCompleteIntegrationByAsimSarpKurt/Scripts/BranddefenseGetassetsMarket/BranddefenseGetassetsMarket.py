import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="<api_key>"
def get_assets(api_token):
    url = "https://api.brandefense.io/api/v1/assets"
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    allassets={'assets':response.json()}
    result=CommandResults(outputs=allassets,outputs_prefix='branddefense_assets')
    return_results(result)
    return result

if __name__=='__main__':
    print("Directly executed!")
else:
    get_assets(api_token)
