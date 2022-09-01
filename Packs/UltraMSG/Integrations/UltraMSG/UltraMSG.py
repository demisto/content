import http.client
import json
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401


def send_whatapp(token, instance, t_id, text):

    try:
        conn = http.client.HTTPSConnection("api.ultramsg.com")
        payload = "token=" + token + "&to=" + t_id + "&body=" + text + "&priority=1"
        headers = {'content-type': "application/x-www-form-urlencoded"}
        result = conn.request("POST", "/" + instance + "/messages/chat", payload, headers)
        demisto.results(f'Task send_whatapp successfully added to project')
    except Exception:
        demisto.results('Task creation failed')


def main():
    params = demisto.params()
    token = params.get('token')
    instance = params.get('instance')
    try:
        if demisto.command() == 'send-whatapp':
            t_id = demisto.args()['id']
            text = demisto.args()['text']
            res = send_whatapp(token, instance, t_id, text)
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()

register_module_line('UltraMSG', 'start', __line__())
