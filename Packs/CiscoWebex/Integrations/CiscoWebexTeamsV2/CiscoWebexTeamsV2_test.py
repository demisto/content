import pytest
from CommonServerPython import CommandResults, DemistoException

from CiscoWebexTeamsV2 import COMMANDS, Client, send_message_to_person, send_message_to_room, to_results
from CiscoWebexTeamsV2 import test_module as run_test_module

BASE = "https://webexapis.com/v1/"


@pytest.fixture
def client():
    return Client(base_url=BASE, headers={"Authorization": "Bearer token"})


def test_command_table_matches_yml():
    """The table covers every yml command except the two send-message helpers."""
    import yaml

    with open("CiscoWebexTeamsV2.yml") as f:
        yml = yaml.safe_load(f)
    names = {c["name"] for c in yml["script"]["commands"]}
    assert names - set(COMMANDS) == {"cisco-webex-teams-v2-send-message-to-person", "cisco-webex-teams-v2-send-message-to-room"}
    assert set(COMMANDS) <= names


@pytest.mark.parametrize("suffix", list(COMMANDS))
def test_call_routes_each_command(requests_mock, client, suffix):
    """Path args fill the template; the rest go to the query (GET) or JSON body."""
    method, template, _ = COMMANDS[suffix]
    args = {
        "personId": "p",
        "roomId": "r",
        "membershipId": "m",
        "messageId": "msg",
        "teamId": "t",
        "webhookId": "w",
        "orgId": "o",
        "licenseId": "l",
        "roleId": "rl",
        "extra": "x",
    }
    url = template.format(**args)
    mock = requests_mock.register_uri(method, BASE + url, json={"id": "1"})
    assert client.call(method, template, args) == {"id": "1"}
    sent = mock.last_request
    if method == "GET":
        assert sent.qs["extra"] == ["x"]
    else:
        assert sent.json()["extra"] == "x"
        assert all(key not in sent.json() for key in args if "{" + key + "}" in template)


def test_call_converts_array_and_bool_args(requests_mock, client):
    mock = requests_mock.post(BASE + "people", json={})
    client.call("POST", "people", {"emails": "a@x.com,b@x.com", "isModerator": "true"})
    assert mock.last_request.json() == {"emails": ["a@x.com", "b@x.com"], "isModerator": True}


def test_call_empty_response(requests_mock, client):
    requests_mock.delete(BASE + "rooms/r", status_code=204)
    assert client.call("DELETE", "rooms/{roomId}", {"roomId": "r"}) is None


def test_to_results_list_capitalizes_keys():
    res = to_results({"items": [{"id": "1", "displayName": "A"}]}, "People")
    assert isinstance(res, CommandResults)
    assert res.outputs_prefix == "CiscoSpark.People"
    assert res.outputs == [{"Id": "1", "DisplayName": "A"}]


def test_to_results_non_list_and_empty():
    assert to_results(None, None) == "Command successful."
    assert to_results({"items": []}, "Rooms") == "Response is empty."
    res = to_results({"id": "1"}, None)
    assert res.outputs is None
    assert res.raw_response == {"id": "1"}


def test_send_message_to_room_by_name(requests_mock, client):
    requests_mock.get(BASE + "rooms", json={"items": [{"id": "r1", "title": "SOC Alerts"}, {"id": "r2", "title": "Other"}]})
    post = requests_mock.post(BASE + "messages", json={"id": "m"})
    send_message_to_room(client, {"toRoomName": "SOC", "text": "hi"})
    assert post.last_request.json() == {"roomId": "r1", "text": "hi"}


@pytest.mark.parametrize(
    "rooms, error",
    [
        ([{"id": "1", "title": "SOC A"}, {"id": "2", "title": "SOC B"}], "More than one room"),
        ([{"id": "1", "title": "Other"}], "was not found"),
    ],
)
def test_send_message_to_room_errors(requests_mock, client, rooms, error):
    requests_mock.get(BASE + "rooms", json={"items": rooms})
    with pytest.raises(DemistoException, match=error):
        send_message_to_room(client, {"toRoomName": "SOC"})


def test_send_message_requires_target(client):
    with pytest.raises(DemistoException, match="room name or roomId"):
        send_message_to_room(client, {"text": "hi"})
    with pytest.raises(DemistoException, match="email or personId"):
        send_message_to_person(client, {"text": "hi"})


def test_test_module(requests_mock, client):
    requests_mock.get(BASE + "people/me", json={"id": "me"})
    assert run_test_module(client) == "ok"
    requests_mock.get(BASE + "people/me", status_code=401, json={})
    with pytest.raises(DemistoException, match=r"Invalid API token \(401\)"):
        run_test_module(client)
