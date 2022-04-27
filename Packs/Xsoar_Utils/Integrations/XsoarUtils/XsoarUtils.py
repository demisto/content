import json
import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

from typing import Callable

# change the below to your default playground id while testing from your local machine
default_playground_id = "122c7bff-feae-4177-867e-37e2096cd7d9"


class Main_Object():
    def __init__(self) -> None:
        self.endpoint = demisto.params()['url']
        self.api_key = demisto.params().get('apikey')
        self.playground = demisto.params().get('playground-id')
        self.ssl_verify = not bool(demisto.params().get('insecure', False))
        self.log_response = log_response_demisto


def log_response_demisto(res: requests.Response):
    if (res.status_code == 200):
        return_results(f"Command seemed to have worked status-code:{res.status_code}")
    else:
        return_results(f"Command seemed to have failed status-code:{res.status_code}")
        return_results(res.text)


def send_request(obj: Main_Object, path: str, method="get", data="", test=False):
    endpoint = f'{obj.endpoint}{path}'
    headers = {'Authorization': obj.api_key, 'content-type': 'application/json'}
    if method == "get":
        res = requests.get(endpoint, headers=headers, verify=obj.ssl_verify)
    else:
        res = requests.post(endpoint, data=data, headers=headers, verify=obj.ssl_verify)

    if not test:
        obj.log_response(res)
    else:
        if (res.status_code == 200):
            demisto.results('ok')
        else:
            return_error(f"please validate your credentials.{res.text}")


def create_entry(obj: Main_Object, data: str, inv_id: str):
    req_args = {
        "id": "",
        "version": 0,
        "investigationId": inv_id,
        "data": data,
        "markdown": True
    }
    send_request(obj, path="/entry", method="Post", data=json.dumps(req_args))


def main():
    obj = Main_Object()
    commands_list: Dict[str, Callable] = {"xsoar-create-entry": create_entry}
    demisto.info("Executing Xsoar_Utils, detected demisto as environment")
    command = demisto.command()
    command_args = demisto.args()
    if "inv_id" not in command_args.keys():
        command_args["inv_id"] = obj.playground
    if command == "test-module":
        send_request(obj, path="/engines", method="get", test=True)
    else:
        commands_list[command](obj, **command_args)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
