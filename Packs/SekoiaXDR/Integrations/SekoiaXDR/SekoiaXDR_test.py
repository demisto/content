from CommonServerPython import *

import SekoiaXDR  # type: ignore
from freezegun import freeze_time


from datetime import datetime
import pytest
import json


MOCK_URL = "https://api.sekoia.io"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(scope="session")
def client():
    api_key = "test_api_key"
    headers = {"Authorization": f"Bearer {api_key}"}
    client = SekoiaXDR.Client(
        base_url=MOCK_URL,
        headers=headers,
    )
    return client


""" TEST HELPER FUNCTIONS """


@freeze_time("2024-09-24 11:25:31 UTC")
def test_arg_to_timestamp():
    assert (
        SekoiaXDR.arg_to_timestamp("2024-04-25T09:20:55", "lastupdate", True)
        == 1714036855
    )
    assert SekoiaXDR.arg_to_timestamp(1714036855.55, "lastupdate", True) == 1714036855

    three_days_ago = datetime.now() - timedelta(days=3)
    assert SekoiaXDR.arg_to_timestamp("3 days", "lastupdate", True) == int(
        three_days_ago.timestamp()
    )

    with pytest.raises(ValueError):
        assert SekoiaXDR.arg_to_timestamp(None, "lastupdate", True) == 1714036855


def test_timezone_format():
    assert SekoiaXDR.timezone_format(1714036855) == "2024-04-25T09:20:55"
    assert SekoiaXDR.timezone_format(1710494455) == "2024-03-15T09:20:55"
    assert SekoiaXDR.timezone_format(1678872055) == "2023-03-15T09:20:55"


def test_time_converter():
    assert (
        SekoiaXDR.time_converter("2024-04-20T15:30:00+00:00") == "2024-04-20T15:30:00"
    )
    assert SekoiaXDR.time_converter("1678872055") == "2023-03-15T09:20:55"
    with pytest.raises(ValueError):
        assert SekoiaXDR.time_converter("2024-04-20T15:30:00") == "2024-04-20T15:30:00"


def test_convert_to_demisto_severity():
    assert SekoiaXDR.convert_to_demisto_severity("Low") == 1
    assert SekoiaXDR.convert_to_demisto_severity("Moderate") == 2
    assert SekoiaXDR.convert_to_demisto_severity("High") == 3
    assert SekoiaXDR.convert_to_demisto_severity("Major") == 3
    assert SekoiaXDR.convert_to_demisto_severity("Urgent") == 4


def test_exclude_info_events():
    upload_test_data = util_load_json("test_data/SekoiaXDR_retrieve_events.json")

    result = SekoiaXDR.exclude_info_events(upload_test_data, "sekoiaio.any_asset.name")
    assert "sekoiaio.any_asset.name" not in result

    second_result = SekoiaXDR.exclude_info_events(
        upload_test_data, "sekoiaio.tags.related.ip,sekoiaio.tags.host.ip"
    )
    assert "sekoiaio.tags.related.ip" not in second_result
    assert "sekoiaio.tags.host.ip" not in second_result


def test_undot():
    upload_test_data = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    result = SekoiaXDR.undot(upload_test_data)

    assert "agent_id" in result
    assert "agent.id" not in result


def test_filter_list_by_keys():
    dicts_list = [
        {"key1": "value1", "key2": "value2", "key3": "value3"},
        {"key1": "value4", "key2": "value5", "key3": "value6"},
        {"key1": "value7", "key2": "value8", "key3": "value9"},
    ]
    keys_to_keep = ["key1", "key3"]
    expected_result = [
        {"key1": "value1", "key3": "value3"},
        {"key1": "value4", "key3": "value6"},
        {"key1": "value7", "key3": "value9"},
    ]
    assert SekoiaXDR.filter_list_by_keys(dicts_list, keys_to_keep) == expected_result


def test_filter_list_by_keys_with_empty_list():
    dicts_list = []
    keys_to_keep = ["key1", "key3"]
    expected_result = []
    assert SekoiaXDR.filter_list_by_keys(dicts_list, keys_to_keep) == expected_result


def test_filter_dict_by_keys():
    dict = {
        "key1": "value1",
        "key2": "value2",
        "key3": "value3",
    }
    keys_to_keep = ["key1", "key3"]
    expected_result = {
        "key1": "value1",
        "key3": "value3",
    }
    assert SekoiaXDR.filter_dict_by_keys(dict, keys_to_keep) == expected_result


def test_filter_dict_by_keys_with_empty_dict():
    dict = {}
    keys_to_keep = ["key1", "key3"]
    expected_result = {}
    assert SekoiaXDR.filter_dict_by_keys(dict, keys_to_keep) == expected_result


""" TEST COMMANDS FUNCTIONS """


def test_test_module_ok(client, requests_mock):
    response = {
        "csrf": "aaa",
        "fresh": False,
        "iat": 123456,
        "identity": "apikey:123456",
        "jti": "123456",
        "nbf": 123456,
        "type": "access",
        "user_claims": None,
    }

    requests_mock.get(MOCK_URL + "/v1/auth/validate", json=response)
    assert SekoiaXDR.test_module(client) == "ok"


@pytest.mark.parametrize(
    "api_response, expected",
    [
        ({"message": "The token is invalid", "code": "T300"}, "The token is invalid."),
        (
            {"message": "The token has expired", "code": "T301"},
            "The token has expired.",
        ),
        ({"message": "Token revoked", "code": "T302"}, "The token has been revoked."),
    ],
)
def test_test_module_nok(client, requests_mock, api_response, expected):
    requests_mock.get(
        MOCK_URL + "/v1/auth/validate", json=api_response, status_code=401
    )

    assert expected in SekoiaXDR.test_module(client)


@pytest.mark.parametrize(
    "method, url_suffix, params, json_test_file",
    [
        ("GET", "/v1/sic/alerts", {}, "test_data/SekoiaXDR_get_alerts.json"),
        (
            "GET",
            "/v1/asset-management/assets",
            {},
            "test_data/SekoiaXDR_get_assets.json",
        ),
    ],
)
def test_http_request_list(
    client, requests_mock, method, url_suffix, params, json_test_file
):
    mock_response = util_load_json(json_test_file)
    requests_mock.get(MOCK_URL + url_suffix, json=mock_response)

    args = {"url_sufix": url_suffix, "method": method, "params": params}
    result = SekoiaXDR.http_request_command(client=client, args=args)

    assert result.outputs["items"] == mock_response["items"]


def test_list_alerts(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    args = {}
    result = SekoiaXDR.list_alerts_command(client=client, args=args)

    assert result.outputs == mock_response["items"]


def test_get_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2", json=mock_response)

    args = {"id": "ALL1A4SKUiU2"}
    result = SekoiaXDR.get_alert_command(client=client, args=args)

    assert result.outputs == mock_response


def test_get_workflow_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert_workflow.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json=mock_response
    )

    args = {"id": "ALWVYiP2Msz4"}
    result = SekoiaXDR.get_workflow_alert_command(client=client, args=args)

    assert len(result.outputs) == len(mock_response["actions"])


def test_get_cases_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert_cases.json")
    requests_mock.get(
        MOCK_URL
        + "/v1/sic/cases?match[alert_uuid]=4fb686e0-ab0c-479c-9afe-856beef9d592&match[short_id]=CAs3AT1XeGCp",
        json=mock_response,
    )

    args = {
        "alert_id": "4fb686e0-ab0c-479c-9afe-856beef9d592",
        "case_id": "CAs3AT1XeGCp",
    }
    result = SekoiaXDR.get_cases_alert_command(client=client, args=args)

    assert len(result.outputs) > 0


def test_update_status_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert_workflow.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json=mock_response
    )
    requests_mock.patch(MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json={})

    args = {"id": "ALWVYiP2Msz4", "status": "Acknowledged", "comment": "test cortex"}
    result = SekoiaXDR.update_status_alert_command(client=client, args=args)

    assert result.outputs == {}


def test_comments_alert_command(client, requests_mock):
    mock_response_alert_comments = util_load_json(
        "test_data/SekoiaXDR_get_alert_comments.json"
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2/comments",
        json=mock_response_alert_comments,
    )

    args = {"id": "ALL1A4SKUiU2"}
    result = SekoiaXDR.get_comments_alert_command(client=client, args=args)

    for item in result.outputs:
        if item["author"].startswith("user"):
            assert item["user"] == "User with id 7114c307-d86c-4c55"
        if item["author"].startswith("apikey"):
            assert item["user"] == "Commented via API"
        if item["author"].startswith("application"):
            assert item["user"] == "Sekoia.io"


def test_post_comment_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_post_alert_comment.json")
    requests_mock.post(
        MOCK_URL + "/v1/sic/alerts/ALU9FpFZoApW/comments", json=mock_response
    )

    args = {
        "id": "ALU9FpFZoApW",
        "comment": "This alert is always on ongoing status",
        "author": "Joe",
    }
    result = SekoiaXDR.post_comment_alert_command(client=client, args=args)
    assert result.outputs["author"] == args["author"]
    assert result.outputs["content"] == args["comment"]


def kill_chain_command(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_killchain.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/kill-chains/73708d4f-419f-44aa", json=mock_response
    )

    args = {"kill_chain_uuid": "73708d4f-419f-44aa"}
    result = SekoiaXDR.get_kill_chain_command(client=client, args=args)
    assert result.outputs["uuid"] == args["73708d4f-419f-44aa"]


def test_query_events(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_query_events.json")
    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response)

    args = {
        "query": "sekoiaio.intake.uuid:834a2d7f-3623-4b26",
        "earliest_time": "2024-04-25T10:00:23",
        "lastest_time": "2024-04-25T15:00:23",
    }
    result = SekoiaXDR.query_events_command(client=client, args=args)

    assert result.outputs == mock_response


def test_query_events_status(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response,
    )

    args = {"uuid": "df904d2e-2c57-488f"}
    result = SekoiaXDR.query_events_status_command(client=client, args=args)

    assert result.outputs == mock_response


def test_retrieve_events(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response,
    )

    args = {"uuid": "df904d2e-2c57-488f"}
    result = SekoiaXDR.retrieve_events_command(client=client, args=args)

    assert result.outputs == mock_response


def test_search_events(client, requests_mock, mocker):
    mock_response_query_events = util_load_json("test_data/SekoiaXDR_query_events.json")
    mock_response_query_events_status = util_load_json(
        "test_data/SekoiaXDR_query_events_status.json"
    )
    mock_response_retrieve_events = util_load_json(
        "test_data/SekoiaXDR_retrieve_events.json"
    )
    requests_mock.post(
        MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query_events
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_query_events_status,
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response_retrieve_events,
    )

    params = {"exclude_info_events": "False", "replace_dots_event": "_"}
    mocker.patch.object(demisto, "params", return_value=params)
    args = {
        "earliest_time": "2024-04-25T10:00:23",
        "lastest_time": "2024-04-25T15:00:23",
        "query": "sekoiaio.intake.uuid:834a2d7f-3623-4b26",
        "max_last_events": "100",
        "timeout_in_seconds": "5",
        "exclude_info": "False",
        "interval_in_seconds": "3",
    }
    result: PollResult = SekoiaXDR.search_events_command(client=client, args=args)

    assert result.outputs[0]["action_id"]
    assert result.outputs[0]["action_outcome"]
    assert result.outputs[0]["action_name"]


def test_list_assets(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_list_assets.json")
    requests_mock.get(
        MOCK_URL + "/v1/asset-management/assets?limit=5&match[type_name]=computer",
        json=mock_response,
    )

    args = {"limit": "5", "assets_type": "computer"}
    result = SekoiaXDR.list_asset_command(client=client, args=args)

    assert len(result.outputs) == 2


def test_get_asset(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_asset.json")
    requests_mock.get(
        MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34", json=mock_response
    )

    args = {"asset_uuid": "015ea33b-a7a2-4e34"}
    result = SekoiaXDR.get_asset_command(client=client, args=args)

    assert result.outputs["uuid"] == args["asset_uuid"]


def test_add_keys_asset(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_post_asset_key.json")
    requests_mock.post(
        MOCK_URL
        + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/keys?name=host&value=computer1",
        json=mock_response,
    )

    args = {
        "asset_uuid": "015ea33b-a7a2-4e34-8beb-0197a93a1011",
        "name": "host",
        "value": "computer1",
    }
    result = SekoiaXDR.add_keys_asset_command(client=client, args=args)

    assert result.outputs["name"] == args["name"]
    assert result.outputs["value"] == args["value"]


def test_remove_keys_asset(client, requests_mock):
    requests_mock.delete(
        MOCK_URL
        + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/keys/8007222c-f135-4f5f",
        json={},
    )

    args = {
        "asset_uuid": "015ea33b-a7a2-4e34-8beb-0197a93a1011",
        "key_uuid": "8007222c-f135-4f5f",
    }
    result = SekoiaXDR.remove_key_asset_command(client=client, args=args)

    assert not result.outputs


def test_add_attr_asset(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_post_asset_attr.json")
    requests_mock.post(
        MOCK_URL
        + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/attr?name=attr_test_4&value=value4",
        json=mock_response,
    )

    args = {
        "asset_uuid": "015ea33b-a7a2-4e34-8beb-0197a93a1011",
        "name": "attr_test_4",
        "value": "value4",
    }
    result = SekoiaXDR.add_attributes_asset_command(client=client, args=args)

    assert result.outputs["name"] == args["name"]
    assert result.outputs["value"] == args["value"]


def test_remove_attr_asset(client, requests_mock):
    requests_mock.delete(
        MOCK_URL
        + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/attr/8007222c-f135-4f5f",
        json={},
    )

    args = {
        "asset_uuid": "015ea33b-a7a2-4e34-8beb-0197a93a1011",
        "attribute_uuid": "8007222c-f135-4f5f",
    }
    result = SekoiaXDR.remove_attribute_asset_command(client=client, args=args)

    assert not result.outputs


def test_get_user(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_user.json")
    requests_mock.get(MOCK_URL + "/v1/users/7114c307-d86c-4c55", json=mock_response)

    args = {"user_uuid": "7114c307-d86c-4c55"}
    result = SekoiaXDR.get_user_command(client=client, args=args)

    assert result.outputs["firstname"] == "Joe"
    assert result.outputs["lastname"] == "done"


def test_modified_remote_data(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    args = {"lastUpdate": "2023-06-28T13:21:45"}
    results = SekoiaXDR.get_modified_remote_data_command(client, args)

    assert len(results.modified_incident_ids) == 2


@pytest.mark.parametrize(
    "close_incident, close_note, mirror_events, mirror_kill_chain, reopen_incident",
    [
        (False, "Closed by Sekoia.", True, True, False),
        (False, "Closed by Sekoia.", False, False, False),
    ],
)
def test_get_remote_data(
    client,
    mocker,
    requests_mock,
    close_incident,
    close_note,
    mirror_events,
    mirror_kill_chain,
    reopen_incident,
):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert.json")
    mock_response_query_events = util_load_json("test_data/SekoiaXDR_query_events.json")
    mock_response_query_events_status = util_load_json(
        "test_data/SekoiaXDR_query_events_status.json"
    )
    mock_response_retrieve_events = util_load_json(
        "test_data/SekoiaXDR_retrieve_events.json"
    )
    mock_response_killchain = util_load_json(
        "test_data/SekoiaXDR_get_killchain_mirroring.json"
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/kill-chains/KCXKNfnJuUUU", json=mock_response_killchain
    )
    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2", json=mock_response)
    requests_mock.post(
        MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query_events
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_query_events_status,
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response_retrieve_events,
    )

    params = {"exclude_info_events": "False", "replace_dots_event": "_"}
    mocker.patch.object(demisto, "params", return_value=params)

    invistagation = {
        "cacheVersn": 0,
        "category": "",
        "closed": "0001-01-01T00:00:00Z",
        "created": "2024-04-09T15:58:41.908148032Z",
        "creatingUserId": "admin",
        "details": "",
        "entryUsers": ["admin"],
        "highPriority": False,
        "id": "5721bf3c-f9ef-4b9e-8942-712ac829e0b7",
        "isDebug": False,
        "lastOpen": "0001-01-01T00:00:00Z",
        "mirrorAutoClose": None,
        "mirrorTypes": None,
        "modified": "2024-04-10T09:10:14.357270528Z",
        "name": "Playground",
        "rawCategory": "",
        "reason": None,
        "runStatus": "",
        "sizeInBytes": 0,
        "slackMirrorAutoClose": False,
        "slackMirrorType": "",
        "status": 0,
        "systems": None,
        "tags": None,
        "type": 9,
        "users": ["admin"],
        "version": 2,
    }
    mocker.patch.object(demisto, "investigation", return_value=invistagation)

    args = {"lastUpdate": "2023-06-28T13:21:45", "id": "ALL1A4SKUiU2"}
    results = SekoiaXDR.get_remote_data_command(
        client,
        args,
        close_incident,
        close_note,
        mirror_events,
        mirror_kill_chain,
        reopen_incident,
    )

    assert len(results.mirrored_object) > 0
    if mirror_kill_chain:
        assert results.mirrored_object.get("kill_chain")
    if mirror_events:
        assert results.mirrored_object.get("events")


@pytest.mark.parametrize(
    "max_results, last_run, first_fetch_time, alert_status, alert_urgency, alert_type, fetch_mode, \
    mirror_direction, fetch_with_assets, fetch_with_kill_chain",
    [
        (
            100,
            {"last_fetch": 1574065501},
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            100,
            {"last_fetch": None},
            1574065501,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    ],
)
def test_fetch_incidents(
    client,
    requests_mock,
    max_results,
    last_run,
    first_fetch_time,
    alert_status,
    alert_urgency,
    alert_type,
    fetch_mode,
    mirror_direction,
    fetch_with_assets,
    fetch_with_kill_chain,
):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    results = SekoiaXDR.fetch_incidents(
        client,
        max_results,
        last_run,
        first_fetch_time,
        alert_status,
        alert_urgency,
        alert_type,
        fetch_mode,
        mirror_direction,
        fetch_with_assets,
        fetch_with_kill_chain,
    )

    assert results[0]["last_fetch"]
    assert len(results[1]) == 2
