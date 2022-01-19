import json
import os
import string
import sys

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# change the below to your default playground id while testing from your local machine
default_playground_id = "122c7bff-feae-4177-867e-37e2096cd7d9"


class Main_Object():
    def __init__(self) -> None:
        try:
            self.endpoint = demisto.params()['url']
            self.api_key = demisto.params().get('apikey')
            self.playground = demisto.params().get('playground-id')
            self.ssl_verify = not bool(demisto.params().get('insecure', False))
            self.run_env = "demisto"
            self.log_response = log_response_demisto
        except:
            self.endpoint = os.environ.get('DEMISTO_BASE_URL')
            self.api_key = os.environ.get('DEMISTO_API_KEY')
            if os.environ.get('DEMISTO_VERIFY_SSL') == "true":
                self.ssl_verify = True
            else:
                self.ssl_verify = False
            self.run_env = "terminal"
            self.log_response = log_response_terminal

    def ret_env(self):
        return self.run_env


def log_response_demisto(res: requests.Response):
    if (res.status_code == 200):
        return_results(f"Command seemed to have worked status-code:{res.status_code}")
    else:
        return_results(f"Command seemed to have failed status-code:{res.status_code}")
        return_results(res.text)


def log_response_terminal(res: requests.Response):
    print(res.status_code)
    print(res.text)


def send_request(obj: Main_Object, path: string, method="get", data=""):
    endpoint = f'{obj.endpoint}{path}'
    headers = {'Authorization': obj.api_key, 'content-type': 'application/json'}
    if method == "get":
        res = requests.get(endpoint, headers=headers, verify=obj.ssl_verify)
    else:
        res = requests.post(endpoint, data=data, headers=headers, verify=obj.ssl_verify)

    obj.log_response(res)


def create_entry(obj: Main_Object, data: string, inv_id: string):
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
    if obj.run_env == "terminal":
        print("detected terminal as environment")
        try:
            command = sys.argv[1]
            print(f"found command {command}")
            if sys.argv[2]:
                command_args = json.loads(sys.argv[2])
                commands_list[command](obj, **command_args)
            else:
                print("could not read command_args, creating entry in playground")
                create_entry(obj, data="**testapi**", inv_id=default_playground_id)
        except Exception as e:
            print(e)
            print("Creating default entry")
            create_entry(obj, data="**testapi**", inv_id=default_playground_id)

    else:
        demisto.info("Executing Xsoar_Utils, detected demisto as environment")
        command = demisto.command()
        command_args = demisto.args()
        if "inv_id" not in command_args.keys():
            command_args["inv_id"] = obj.playground
        commands_list[command](obj, **command_args)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
