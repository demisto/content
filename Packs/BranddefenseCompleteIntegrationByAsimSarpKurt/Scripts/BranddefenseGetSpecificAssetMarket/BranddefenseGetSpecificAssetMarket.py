import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="<api_key>"
asset_id=demisto.getArg('assetid')
def get_assets(api_token,asset_id):
    url = "https://api.brandefense.io/api/v1/assets/"+str(asset_id)
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    requestedasset={'assets':response.json()}
    result=CommandResults(outputs=requestedasset,outputs_prefix='branddefense_requested_asset')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_assets(api_token,asset_id)
