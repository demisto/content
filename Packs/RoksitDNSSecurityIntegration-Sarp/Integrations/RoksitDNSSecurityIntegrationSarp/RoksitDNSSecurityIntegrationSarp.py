import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

url = demisto.params().get('url')
yourkey = demisto.params().get("token")

headers = {'Content-Type': 'application/json',
           'ApiKey': yourkey}
roksit_domain=(demisto.incident().get("CustomFields").get("roksitblockdomain"))
blacklist = {'items': [roksit_domain]}
x = requests.post(url, headers=headers, json=blacklist)

print(x.text)
