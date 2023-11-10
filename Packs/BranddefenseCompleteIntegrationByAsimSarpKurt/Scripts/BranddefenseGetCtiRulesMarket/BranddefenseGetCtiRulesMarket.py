import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

api_token="<api_token>"
search=demisto.getArg('search')
search=str(search)
created_at__range=demisto.getArg('created_at__range')
created_at__range=str(created_at__range)
tag=demisto.getArg('tag')
tag=str(tag)
source__ilike=demisto.getArg('source__ilike')
source__ilike=str(source__ilike)
def get_cti_rules():
    url = "https://api.brandefense.io/api/v1/threat-intelligence/rules"
    querystring={'tag':tag,'search':search}
    headers = {
    "accept": "application/json",
    "content-type": "application/json",
    "authorization": "Bearer "+api_token}
    if len(search)>2 or len(created_at__range)>2 or len(search)>2 or len(tag)>2 or len(source__ilike)>2:
        response = requests.get(url, headers=headers,params=querystring)
    else:
        response = requests.get(url, headers=headers)
    branddefense_cti_rules={'branddefense_cti_rules':response.json()}
    result=CommandResults(outputs=branddefense_cti_rules,outputs_prefix='branddefense_cti_rules')
    return_results(result)
    return result

if __name__=='__main__':
    raise TypeError
else:
    get_cti_rules()
