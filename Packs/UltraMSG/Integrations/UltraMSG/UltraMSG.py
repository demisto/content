import http.client
import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def send_whatsapp(token, instance, t_id, text):
    try:
        conn = http.client.HTTPSConnection("api.ultramsg.com")
        payload = "token=" + token + "&to=" + t_id + "&body=" + text + "&priority=1"
        headers = {'content-type': "application/x-www-form-urlencoded"}
        conn.request("POST", "/" + instance + "/messages/chat", payload, headers)
        return_results('Task send_whatsapp successfully added to project')
    except Exception:
        return_results('Task creation failed')


def test_module(token, instance):
    try:
        conn = http.client.HTTPSConnection("api.ultramsg.com")
        headers = {'content-type': "application/x-www-form-urlencoded"}
        url_path = "/" + instance + "/instance/status?token=" + token
        conn.request("GET", url_path, headers=headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")
        data_json = json.loads(data)
        status = data_json['status']['accountStatus']['substatus']
        if status == "connected":
            return 'ok'
        else:
            return "Instance Status is: '" + status + "' Should be 'connected'.Please check your instance"
    except Exception:
        return "Please check you'r instance"


def main():
    params = demisto.params()
    token = params.get('token')
    instance = params.get('instance')
    try:
        if demisto.command() == 'send-whatsapp':
            t_id = demisto.args()['id']
            text = demisto.args()['text']
            send_whatsapp(token, instance, t_id, text)
        elif demisto.command() == 'test-module':
            return_results(test_module(token, instance))
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
