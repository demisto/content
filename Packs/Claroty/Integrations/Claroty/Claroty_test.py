import demistomock as demisto
# from CommonServerPython import *
# from CommonServerUserPython import *
from .Claroty import Client


MOCK_AUTHENTICATION = {
    "first_name": "admin",
    "id": 1,
    "last_name": "admin",
    "mail": "admin",
    "password_expired": False,
    "token": "ok",
    "username": "admin"
}
RESOLVE_ALERT_RESPONSE = {
    "success": True
}
GET_ASSETS_RESPONSE = {

}
GET_ALERTS_RESPONSE = {"count_filtered": 0,
                       "count_in_page": 0,
                       "count_total": 0,
                       "objects": []
                       }


# def test_say_hello_over_http(requests_mock):
#     mock_response = {'result': 'Hello Dbot'}
#     requests_mock.get('https://test.com/hello/Dbot', json=mock_response)
#
#     client = Client(base_url='https://test.com', verify=False, auth=('test', 'test'))
#     args = {
#         'name': 'Dbot'
#     }
#     _, outputs, _ = say_hello_over_http_command(client, args)
#
#     assert outputs['hello'] == 'Hello Dbot'


def _create_client(mocker, requests_mock, request_url, response_json, request_type, **extra_params):
    mocker.patch.object(demisto, 'params', return_value={
        "credentials": {
            'identifier': 'user',
            'password': 'omgSecretsWow',
        },
        'url': 'https://website.com'
    })

    if request_type == "POST":
        requests_mock.post(request_url, json=response_json)
    elif request_type == "GET":
        requests_mock.get(request_url, json=response_json)

    mocker.patch.object(demisto, 'args', return_value={})
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    base_url = demisto.params()['url'].rstrip('/') + ':5000'
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    client = Client(
        base_url=base_url,
        verify=verify_certificate,
        credentials=(username, password),
        proxy=proxy,
        not_mock=False,
    )

    return client


def test_claroty_authentication(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, 'https://website.com:5000/auth/authenticate',
                            MOCK_AUTHENTICATION, "POST")

    token = client.get_token()
    assert token == 'ok'


def test_claroty_fetch_incidents(mocker, requests_mock):
    pass


def test_claroty_query_alerts(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, "https://website.com:5000/ranger/alerts", GET_ALERTS_RESPONSE, "GET")

    response = client.get_alerts([], {}, [])
    assert response


# def test_claroty_get_assets(mocker, requests_mock):
#     client = _create_client(mocker, requests_mock, "https://website.com:5000/ranger/assets", GET_ASSETS_RESPONSE, "GET")
#
#     response = client.get_assets([], {}, [])
#     assert response


def test_claroty_resolve_alerts(mocker, requests_mock):
    client = _create_client(mocker, requests_mock, 'https://website.com:5000/ranger/ranger_api/resolve_alerts',
                            RESOLVE_ALERT_RESPONSE, "POST")

    response = client.resolve_alert(True, [], [], {}, 1)
    assert response["success"]
