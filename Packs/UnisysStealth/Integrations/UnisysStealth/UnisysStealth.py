import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

USERNAME = demisto.params().get("credentials")["identifier"]
PASSWORD = demisto.params().get("credentials")["password"]
SERVER_IP = demisto.params().get("server_ip")
PORT = demisto.params().get("port")
ISOLATION_ID = demisto.params()["isolation_id"]
BASE_URL = f"https://{SERVER_IP}:{PORT}/uisStealth/EcoApi/v1"
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}
VERIFY = demisto.params().get("insecure", False)
if not demisto.params().get("proxy", False):
    os.environ.pop("HTTP_PROXY", "")
    os.environ.pop("HTTPS_PROXY", "")
    os.environ.pop("http_proxy", "")
    os.environ.pop("https_proxy", "")
proxy = demisto.params().get("proxy", False)


def http_request(method, uri, data=None, **kwargs):
    try:
        requests.Request()
        res = requests.request(
            method=method,
            url=f"{BASE_URL}{uri}",
            verify=VERIFY,
            data=data,
            headers=HEADERS,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            **kwargs,
        )
    except requests.exceptions.Timeout:
        raise DemistoException("HTTP Request to Stealth has timed out. Please try again")
    except requests.exceptions.TooManyRedirects:
        raise DemistoException("Invalid API Endpoint")

    if res.status_code not in {200, 204}:
        raise DemistoException(f"Error received {res.status_code} in API response")

    # May need to change this to .content
    return res


def test_module():
    data = http_request(
        method="GET",
        uri="/role",
    )
    return data


def get_roles():
    data = http_request(
        method="GET",
        uri="/role",
    )
    return data.json()


def isolate_machine(endpoint):
    payload = {"role": [{"id": ISOLATION_ID, "endpoint": [{"name": endpoint}]}]}
    data = http_request(
        "PUT",
        uri="/role/isolate",
        data=json.dumps(payload),
    )
    return data


def unisolate_machine(endpoint):
    data = http_request(method="DELETE", uri=f"/role/isolate?hostname={endpoint}")
    return data


def isolate_user(user):
    payload = {"role": [{"id": ISOLATION_ID, "accounts": {"user": [{"name": user}]}}]}
    data = http_request(
        "PUT",
        "/role/isolate",
        data=json.dumps(payload),
    )
    return data


def unisolate_user(user):
    url_string = f"/role/isolate?username={user}"
    data = http_request(
        method="DELETE",
        uri=url_string,
    )
    return data


def isolate_machine_and_user(endpoint, user):
    payload = {"role": [{"id": ISOLATION_ID, "accounts": {"user": [{"name": user}]}, "endpoint": [{"name": endpoint}]}]}
    data = http_request(method="PUT", uri="/role/isolate", data=json.dumps(payload))
    return data


def unisolate_machine_and_user(endpoint, user):
    data = http_request(method="DELETE", uri=f"/role/isolate?username={user}&hostname={endpoint}")
    return data


if demisto.command() == "test-module":
    result = test_module()
    demisto.results("ok")
elif demisto.command() == "stealth-get-stealth-roles":
    result = get_roles()
    rows = [{"Name": role["name"], "ID": role["id"]} for role in result["role"]]
    table = tableToMarkdown("Stealth Roles", rows)
    return_outputs(readable_output=table, outputs={"Stealth": result}, raw_response=result)
elif demisto.command() == "stealth-isolate-machine":
    endpoint = demisto.args()["endpoint"]
    result = isolate_machine(endpoint)
    return_outputs(readable_output=f"{endpoint} successfully isolated", outputs={"Stealth": {"isolate": endpoint}})
    demisto.results(result)
elif demisto.command() == "stealth-unisolate-machine":
    endpoint = demisto.args()["endpoint"]
    result = unisolate_machine(endpoint)
    return_outputs(readable_output=f"{endpoint} successfully unisolated", outputs={"Stealth": {"unisolate": endpoint}})
elif demisto.command() == "stealth-isolate-user":
    user = demisto.args()["user"]
    result = isolate_user(user)
    return_outputs(readable_output=f"{user} successfully isolated", outputs={"Stealth": {"isolate": user}})
elif demisto.command() == "stealth-unisolate-user":
    user = demisto.args()["user"]
    result = unisolate_user(user)
    return_outputs(readable_output=f"{user} successfully unisolated", outputs={"Stealth": {"unisolate": user}})
elif demisto.command() == "stealth-isolate-machine-and-user":
    endpoint = demisto.args()["endpoint"]
    user = demisto.args()["user"]
    result = isolate_machine_and_user(endpoint, user)
    return_outputs(
        readable_output=f"{endpoint} and {user} successfully isolated", outputs={"Stealth": {"isolate": [endpoint, user]}}
    )
elif demisto.command() == "stealth-unisolate-machine-and-user":
    endpoint = demisto.args()["endpoint"]
    user = demisto.args()["user"]
    result = unisolate_machine_and_user(endpoint, user)
    return_outputs(
        readable_output=f"{endpoint} and {user} successfully unisolated", outputs={"Stealth": {"unisolate": [endpoint, user]}}
    )
else:
    demisto.results("Enter valid command")
