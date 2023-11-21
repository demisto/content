import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests


def send_whatsapp(token, instance, t_id, text):
    try:
        payload = 'token={token}&to={t_id}&body={text}&priority=1'
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        requests.post(f'api.ultramsg.com/{instance}/messages/chat?{payload}', headers=headers)
        return_results('Task send_whatsapp successfully added to project')
    except Exception:
        return_results('Task creation failed')


def test_module(token, instance):
    try:
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        url_path = f'api.ultramsg.com/{instance}/instance/status?token={token}'
        res = requests.get(url_path, headers=headers)
        data_json = res.json()
        status = data_json['status']['accountStatus']['substatus']
        if status == 'connected':
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
