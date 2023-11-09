import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="vrYjCxBiBnbyoAAE4CAcztPcs9rjAAAsnuqbqXyc"
uuid=demisto.getArg('search_uuid')
uuid=str(uuid)
def get_audit_logs(api_token,uuid):
    url = "https://api.brandefense.io/api/v1/cti/threat-search/"+uuid
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    response = requests.get(url, headers=headers)
    search_result={'sarch_result':response.json()}
    result=CommandResults(outputs=search_result,outputs_prefix='search_result')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_audit_logs(api_token,uuid)
