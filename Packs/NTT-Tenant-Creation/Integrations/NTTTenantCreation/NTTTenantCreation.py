import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Authored by Ashish Bansal from NTT Security


''' IMPORTS '''

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
URI = "/account"  # URL Param to be used.


headers = {
    'accept': 'application/json',
    'authorization': API_KEY,
    'content-type': 'application/json',
}


def create_tenant():
    cid = demisto.args()["Customer_Id"]
    cid = str(cid)
    cname = demisto.args()["Customer_Name"]
    hostzone = demisto.args()["XSOAR_Host"]
    payload = '{"name":"' + cid + "-" + cname + \
        '","accountRoles":["Administrator"],"propagationLabels":[],"syncOnCreation":false,"server":{"host":"' + \
        hostzone + '","hostPort":"443"}}'
    tcreate = requests.post(BASE_URL + URI, headers=headers, data=payload, verify=False)


if demisto.command() == 'NTT-Tenant-Creation':
    result = create_tenant()
