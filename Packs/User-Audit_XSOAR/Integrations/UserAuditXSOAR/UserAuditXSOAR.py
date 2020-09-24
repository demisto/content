import json
from datetime import date, timedelta

import demistomock as demisto
# Authored by Ashish Bansal
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from requests.exceptions import HTTPError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
today = date.today()
yesterday = today - timedelta(days=1)
runperiod = yesterday.strftime("%Y-%m-%dT00:00:00")  # change it if required.

BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
URI = "/settings/audits"
api_string = API_KEY


headers = {
    'accept': 'application/json',
    'authorization': API_KEY,
    'content-type': 'application/json',
}

data = '{"size" : 10000,"query": "modified:>' + runperiod + "\"}'"


def test_connection():
    "confirms url and api key are good, returns 404 on success"
    headers = {
        'Content-Type': 'text/json',
        'Authorization': api_string
    }
    r = requests.request(
        "GET",
        BASE_URL + URI,
        headers=headers,
        verify=False)
    return r.status_code


def audit_logs():
    auditlogs = requests.post(BASE_URL + URI, headers=headers, data=data, verify=False)
    TenantName = BASE_URL.split("/")
    TenantName = TenantName[3]
    auditlogs = (auditlogs.text)  # Added Later for data inputs.
    auditdate = str(yesterday)
    auditfile = ("User-Audit_" + TenantName + "_" + auditdate + ".log")
    demisto.results(fileResult(auditfile, auditlogs))


if demisto.command() == 'test-module':
    result = test_connection()
    if result == 200:
        return_results('ok')
    else:
        return_results('Status code: ' + str(result))

if demisto.command() == 'user-audit-demisto':
    result = audit_logs()
