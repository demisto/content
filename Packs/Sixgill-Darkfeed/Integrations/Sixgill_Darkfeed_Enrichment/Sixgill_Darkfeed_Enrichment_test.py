import requests
import pytest
import json
import io

import demistomock as demisto

mock_response = ""
mocked_get_token_response = """{"access_token": "fababfafbh"}"""


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return f.read()


class MockedResponse(object):
    def __init__(self, status_code, text, reason=None, url=None, method=None):
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self.url = url
        self.request = requests.Request("GET")
        self.ok = True if self.status_code == 200 else False

    def json(self):
        return json.loads(self.text)


def init_params():
    return {
        "client_id": "WRONG_CLIENT_ID_TEST",
        "client_secret": "CLIENT_SECRET_TEST",
    }


def mocked_request(*args, **kwargs):
    global mock_response
    request = kwargs.get("request", {})
    end_point = request.path_url
    method = request.method
    body = request.body

    if end_point == '/ioc/enrich':
        result = json.loads(body)
        if 'ioc_type' in result:
            mock_response = util_load_json(f"test_data/{result.get('ioc_type')}.json")
        elif 'sixgill_field' in result:
            mock_response = util_load_json(f"test_data/{result.get('sixgill_field')}.json")

    response_dict = {
        "POST": {
            "/auth/token": MockedResponse(200, mocked_get_token_response),
            "/ioc/enrich": MockedResponse(200, mock_response)
        }
    }

    response_dict = response_dict.get(method)
    response = response_dict.get(end_point)

    return response


def test_test_module_command_raise_exception(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(400, "error"))

    from Sixgill_Darkfeed_Enrichment import test_module_command

    with pytest.raises(Exception):
        test_module_command()


def test_test_module_command(mocker):
    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", return_value=MockedResponse(200, "ok"))

    from Sixgill_Darkfeed_Enrichment import test_module_command

    test_module_command("client_id", "client_secret", "channel_code", requests.Session(), "verify")


def test_ip_reputation_command(mocker):
    """
    Given:
        - an IP

    When:
        - running ip command and validate whether the ip is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import ip_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = ip_reputation_command(client, {"ip": "<some ip>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")


def test_domain_reputation_command(mocker):
    """
    Given:
        - an Domain

    When:
        - running domain command and validate whether the domain is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import domain_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = domain_reputation_command(client, {"domain": "<some domain>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")


def test_url_reputation_command(mocker):
    """
    Given:
        - an URL

    When:
        - running url command and validate whether the url is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import url_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = url_reputation_command(client, {"url": "<some_url>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")


def test_file_reputation_command(mocker):
    """
    Given:
        - an File hash

    When:
        - running file command and validate whether the file hash is malicious

    Then:
        - return command results containing indicator and dbotscore

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import file_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = file_reputation_command(client, {"file": "<some hash>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")


def test_actor_reputation_command(mocker):
    """
    Given:
        - an Actor

    When:
        - running actor command and validate whether the actor is malicious

    Then:
        - return command results containing indicator

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import actor_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = actor_reputation_command(client, {"actor": "<some actor>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")


def test_postid_reputation_command(mocker):
    """
    Given:
        - an post_id

    When:
        - running sixgill-get-post-id command and validate whether the post_id is malicious

    Then:
        - return command results containing indicator

    """

    mocker.patch.object(demisto, "params", return_value=init_params())
    mocker.patch("requests.sessions.Session.send", new=mocked_request)

    from Sixgill_Darkfeed_Enrichment import postid_reputation_command
    from sixgill.sixgill_enrich_client import SixgillEnrichClient

    client = SixgillEnrichClient("client_id", "client_secret", "some_channel")

    output = postid_reputation_command(client, {"post_id": "<some postid>", "skip": 0})

    assert output[0].outputs == json.loads(mock_response).get("items")
