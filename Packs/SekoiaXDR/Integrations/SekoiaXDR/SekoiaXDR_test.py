from CommonServerPython import *

import SekoiaXDR  # type: ignore
from freezegun import freeze_time


from datetime import datetime
import pytest
import json


MOCK_URL = "https://api.sekoia.io"


def util_load_json(path) -> dict:
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


@pytest.fixture()
def context_cache_with_mirroring():
    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")
    return {"mirroring_cache": [{"alert": alert, "entries": {}}]}


@pytest.fixture()
def context_cache_without_mirroring():
    return {}


""" TEST HELPER FUNCTIONS """


@freeze_time("2024-09-24 11:25:31 UTC")
def test_arg_to_timestamp():
    assert SekoiaXDR.arg_to_timestamp("2024-04-25T09:20:55", "lastupdate", True) == 1714036855
    assert SekoiaXDR.arg_to_timestamp(1714036855.55, "lastupdate", True) == 1714036855

    three_days_ago = datetime.now() - timedelta(days=3)
    assert SekoiaXDR.arg_to_timestamp("3 days", "lastupdate", True) == int(three_days_ago.timestamp())

    with pytest.raises(ValueError):
        assert SekoiaXDR.arg_to_timestamp(None, "lastupdate", True) == 1714036855


def test_timezone_format():
    assert SekoiaXDR.timezone_format(1714036855) == "2024-04-25T09:20:55"
    assert SekoiaXDR.timezone_format(1710494455) == "2024-03-15T09:20:55"
    assert SekoiaXDR.timezone_format(1678872055) == "2023-03-15T09:20:55"


def test_time_converter():
    assert SekoiaXDR.time_converter("2024-04-20T15:30:00+00:00") == "2024-04-20T15:30:00"
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

    second_result = SekoiaXDR.exclude_info_events(upload_test_data, "sekoiaio.tags.related.ip,sekoiaio.tags.host.ip")
    assert "sekoiaio.tags.related.ip" not in second_result
    assert "sekoiaio.tags.host.ip" not in second_result


def test_undot():
    upload_test_data = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    result = SekoiaXDR.undot(upload_test_data)

    assert type(result) is dict
    assert result["items"][0]["agent_id"]


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


def test_check_id_in_context_with_mirroring(context_cache_with_mirroring):
    assert SekoiaXDR.check_id_in_context("ALL1A4SKUiU2", context_cache_with_mirroring) == (
        context_cache_with_mirroring["mirroring_cache"][0],
        0,
    )


def test_fetch_alerts_asc_mode(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    args = {
        "client": client,
        "alert_status": None,
        "alert_urgency": None,
        "alert_type": None,
        "max_results": 100,
        "alerts_created_at": None,
        "alerts_updated_at": None,
        "sort_by": None,
    }

    result = SekoiaXDR.fetch_alerts_asc_mode(**args)
    assert len(result) == 2
    assert result[0]["created_at"] < result[1]["created_at"]


def test_handle_alert_events_query_finished_status(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_query_events.json")
    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response)

    mock_response_query_events_status = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_query_events_status,
    )

    mock_response_retrieve_events = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response_retrieve_events,
    )

    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")
    args = {
        "client": client,
        "alert": alert,
        "earliest_time": "2024-04-25T10:00:23",
        "latest_time": "2024-04-25T15:00:23",
        "events_term": "sekoiaio.intake.uuid:834a2d7f-3623-4b26",
    }

    result_alert, is_ready = SekoiaXDR.handle_alert_events_query(**args)

    assert "events" in result_alert
    assert is_ready is True


def test_handle_alert_events_query_in_progress_status(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_query_events.json")
    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response)

    mock_response_query_events_status = util_load_json("test_data/SekoiaXDR_query_events_status_in_progress.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_query_events_status,
    )

    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")
    args = {
        "client": client,
        "alert": alert,
        "earliest_time": "2024-04-25T10:00:23",
        "latest_time": "2024-04-25T15:00:23",
        "events_term": "sekoiaio.intake.uuid:834a2d7f-3623-4b26",
    }

    result_alert, is_ready = SekoiaXDR.handle_alert_events_query(**args)

    assert is_ready is False
    assert "job_uuid" in result_alert
    assert result_alert["job_uuid"] == "df904d2e-2c57-488f"
    assert "events" not in result_alert


def test_check_id_in_context_without_mirroring(context_cache_without_mirroring):
    assert not SekoiaXDR.check_id_in_context("ALL1A4SKUiU2", context_cache_without_mirroring)


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
    requests_mock.get(MOCK_URL + "/v1/auth/validate", json=api_response, status_code=401)

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
def test_http_request_list(client, requests_mock, method, url_suffix, params, json_test_file):
    mock_response = util_load_json(json_test_file)
    requests_mock.get(MOCK_URL + url_suffix, json=mock_response)

    args = {"url_suffix": url_suffix, "method": method, "params": params}
    result = SekoiaXDR.http_request_command(client=client, args=args)

    assert result.outputs == mock_response["items"]


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
    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json=mock_response)

    args = {"id": "ALWVYiP2Msz4"}
    result = SekoiaXDR.get_workflow_alert_command(client=client, args=args)

    assert len(result.outputs) == len(mock_response["actions"])


def test_get_cases_alert(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alert_cases.json")
    requests_mock.get(
        MOCK_URL + "/v1/sic/cases?match[alert_uuid]=4fb686e0-ab0c-479c-9afe-856beef9d592&match[short_id]=CAs3AT1XeGCp",
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
    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json=mock_response)
    requests_mock.patch(MOCK_URL + "/v1/sic/alerts/ALWVYiP2Msz4/workflow", json={})

    args = {"id": "ALWVYiP2Msz4", "status": "Acknowledged", "comment": "test cortex"}
    result = SekoiaXDR.update_status_alert_command(client=client, args=args)

    assert result.outputs == {}


def test_comments_alert_command(client, requests_mock):
    mock_response_alert_comments = util_load_json("test_data/SekoiaXDR_get_alert_comments.json")
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
    requests_mock.post(MOCK_URL + "/v1/sic/alerts/ALU9FpFZoApW/comments", json=mock_response)

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
    requests_mock.get(MOCK_URL + "/v1/sic/kill-chains/73708d4f-419f-44aa", json=mock_response)

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
    mock_response_query_events_status = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    mock_response_retrieve_events = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query_events)
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
    requests_mock.get(MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34", json=mock_response)

    args = {"asset_uuid": "015ea33b-a7a2-4e34"}
    result = SekoiaXDR.get_asset_command(client=client, args=args)

    assert result.outputs["uuid"] == args["asset_uuid"]


def test_add_keys_asset(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_post_asset_key.json")
    requests_mock.post(
        MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/keys?name=host&value=computer1",
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
        MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/keys/8007222c-f135-4f5f",
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
        MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/attr?name=attr_test_4&value=value4",
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
        MOCK_URL + "/v1/asset-management/assets/015ea33b-a7a2-4e34-8beb-0197a93a1011/attr/8007222c-f135-4f5f",
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
    mock_response_query_events_status = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    mock_response_retrieve_events = util_load_json("test_data/SekoiaXDR_retrieve_events.json")
    mock_response_killchain = util_load_json("test_data/SekoiaXDR_get_killchain_mirroring.json")
    requests_mock.get(MOCK_URL + "/v1/sic/kill-chains/KCXKNfnJuUUU", json=mock_response_killchain)
    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2", json=mock_response)
    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query_events)
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


def test_fetch_incidents_with_same_time(client, requests_mock):
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts_same_time.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    last_run = {"last_fetch": 1714036855}
    results = SekoiaXDR.fetch_incidents(client, 100, last_run, None, None, None, None, None, None, None, None)

    assert results[0]["last_fetch"] == 1747057948
    assert len(results[1]) == 2


""" TEST BACKWARD COMPATIBILITY - url_sufix vs url_suffix """


def test_http_request_with_url_suffix_new_param(client, requests_mock):
    """Test http_request_command with the NEW corrected parameter 'url_suffix'"""
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    args = {
        "method": "GET",
        "url_suffix": "/v1/sic/alerts",  # ← NEW parameter (correct spelling)
        "parameters": {},
    }
    result = SekoiaXDR.http_request_command(client=client, args=args)

    assert result.outputs == mock_response["items"]
    assert result.readable_output is not None


def test_http_request_with_url_sufix_old_param(client, requests_mock):
    """Test http_request_command with the OLD deprecated parameter 'url_sufix' (typo)"""
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    args = {
        "method": "GET",
        "url_sufix": "/v1/sic/alerts",  # ← OLD parameter (with typo - backward compatibility)
        "parameters": {},
    }
    result = SekoiaXDR.http_request_command(client=client, args=args)

    assert result.outputs == mock_response["items"]
    assert result.readable_output is not None


def test_http_request_missing_both_params():
    """Test http_request_command with BOTH parameters missing - should raise error"""
    client = SekoiaXDR.Client(base_url=MOCK_URL, headers={})

    args = {
        "method": "GET",
        # Neither url_suffix nor url_sufix provided
        "parameters": {},
    }

    with pytest.raises(DemistoException, match="Either 'url_suffix' or 'url_sufix' parameter must be provided"):
        SekoiaXDR.http_request_command(client=client, args=args)


def test_http_request_with_post_and_json_data(client, requests_mock):
    """Test http_request_command with POST method and JSON data"""
    mock_response = {"status": "created", "id": "12345"}
    requests_mock.post(MOCK_URL + "/v1/sic/alerts/test/comments", json=mock_response)

    args = {
        "method": "POST",
        "url_suffix": "/v1/sic/alerts/test/comments",
        "parameters": {},
        "data": '{"content": "Test comment", "author": "TestUser"}',
    }
    result = SekoiaXDR.http_request_command(client=client, args=args)

    assert result.outputs == mock_response


def test_http_request_with_invalid_json_data(client):
    """Test http_request_command with invalid JSON data - should raise error"""
    client = SekoiaXDR.Client(base_url=MOCK_URL, headers={})

    args = {
        "method": "POST",
        "url_suffix": "/v1/sic/alerts/test/comments",
        "parameters": {},
        "data": "{'invalid': json}",  # ← Invalid JSON format
    }

    with pytest.raises(DemistoException, match="Data argument is not a valid JSON"):
        SekoiaXDR.http_request_command(client=client, args=args)


""" TEST DUPLICATE HANDLING WITH processed_ids """


def test_fetch_incidents_duplicate_same_timestamp(client, requests_mock):
    """Test fetch_incidents correctly handles duplicate alerts with same created_at timestamp"""
    # Load alerts that have the SAME created_at timestamp
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts_same_time.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    # First fetch - should process all alerts with the same timestamp
    last_run = {"last_fetch": 1747057948, "processed_ids": []}
    next_run, incidents = SekoiaXDR.fetch_incidents(
        client=client,
        max_results=100,
        last_run=last_run,
        first_fetch_time=None,
        alert_status=None,
        alert_urgency=None,
        alert_type=None,
        fetch_mode=None,
        mirror_direction=None,
        fetch_with_assets=None,
        fetch_with_kill_chain=None,
    )

    # Verify processed_ids are tracked
    assert "processed_ids" in next_run

    processed_ids = next_run.get("processed_ids", [])
    assert isinstance(processed_ids, list), f"processed_ids should be a list, got {type(processed_ids)}"
    assert len(processed_ids) > 0, "processed_ids should not be empty"

    # Verify incidents
    assert len(incidents) == 2


def test_fetch_incidents_skip_already_processed(client, requests_mock):
    """Test fetch_incidents skips alerts that were already processed"""
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts_same_time.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    # Use actual alert ID from test data
    alert_to_skip = "ALL1A4SKUUUU"  # ✅ Correspond au fichier JSON

    last_run = {
        "last_fetch": 1747057948,
        "processed_ids": [alert_to_skip],
    }

    next_run, incidents = SekoiaXDR.fetch_incidents(
        client=client,
        max_results=100,
        last_run=last_run,
        first_fetch_time=None,
        alert_status=None,
        alert_urgency=None,
        alert_type=None,
        fetch_mode=None,
        mirror_direction=None,
        fetch_with_assets=None,
        fetch_with_kill_chain=None,
    )

    # Verify that the skipped alert is not in the results
    incident_ids = [json.loads(inc["rawJSON"]).get("short_id") for inc in incidents]
    assert alert_to_skip not in incident_ids, f"Alert '{alert_to_skip}' should have been skipped but was included"

    # Verify that the other alert is still processed
    assert len(incidents) == 1
    assert json.loads(incidents[0]["rawJSON"]).get("short_id") == "ALN1JwGVLxxx"


def test_fetch_incidents_reset_processed_ids_for_new_timestamp(client, requests_mock):
    """Test that processed_ids list is reset when timestamp changes to a newer one"""
    # Create two different mock responses for sequential calls
    old_alerts = util_load_json("test_data/SekoiaXDR_get_alerts_old_time.json")
    new_alerts = util_load_json("test_data/SekoiaXDR_get_alerts_new_time.json")

    requests_mock.get(
        MOCK_URL + "/v1/sic/alerts",
        [
            {"json": old_alerts},
            {"json": new_alerts},
        ],
    )

    # First fetch
    last_run_1 = {"last_fetch": 1714036855, "processed_ids": []}
    next_run_1, _ = SekoiaXDR.fetch_incidents(
        client=client,
        max_results=100,
        last_run=last_run_1,
        first_fetch_time=None,
        alert_status=None,
        alert_urgency=None,
        alert_type=None,
        fetch_mode=None,
        mirror_direction=None,
        fetch_with_assets=None,
        fetch_with_kill_chain=None,
    )

    # Second fetch with new timestamp
    last_run_2 = {
        "last_fetch": next_run_1["last_fetch"],
        "processed_ids": next_run_1.get("processed_ids", []),
    }
    next_run_2, _ = SekoiaXDR.fetch_incidents(
        client=client,
        max_results=100,
        last_run=last_run_2,
        first_fetch_time=None,
        alert_status=None,
        alert_urgency=None,
        alert_type=None,
        fetch_mode=None,
        mirror_direction=None,
        fetch_with_assets=None,
        fetch_with_kill_chain=None,
    )

    processed_ids_1 = next_run_1.get("processed_ids", [])
    processed_ids_2 = next_run_2.get("processed_ids", [])
    assert isinstance(processed_ids_1, list)
    assert isinstance(processed_ids_2, list)
    assert processed_ids_2 != processed_ids_1


def test_fetch_incidents_accumulate_processed_ids_same_timestamp(client, requests_mock):
    """Test that processed_ids accumulates for alerts with the same timestamp"""
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts_same_time.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    last_run = {"last_fetch": 1714036855, "processed_ids": []}
    next_run, incidents = SekoiaXDR.fetch_incidents(
        client=client,
        max_results=100,
        last_run=last_run,
        first_fetch_time=None,
        alert_status=None,
        alert_urgency=None,
        alert_type=None,
        fetch_mode=None,
        mirror_direction=None,
        fetch_with_assets=None,
        fetch_with_kill_chain=None,
    )

    # Both alerts have the same timestamp, so both should be in processed_ids
    processed_ids = next_run.get("processed_ids", [])
    assert isinstance(processed_ids, list), f"Expected list, got {type(processed_ids)}"
    assert len(processed_ids) == 2, f"Expected 2 processed IDs, got {len(processed_ids)}"
    assert len(incidents) == 2


""" TEST APPLY_TIME_BUFFER FUNCTION """


def test_apply_time_buffer_positive_delta():
    """Test apply_time_buffer with positive delta (future)"""
    iso_time = "2024-04-25T10:00:00Z"
    result = SekoiaXDR.apply_time_buffer(iso_time, 5)  # Add 5 minutes

    # Result should be 5 minutes later
    assert "10:05:00" in result


def test_apply_time_buffer_negative_delta():
    """Test apply_time_buffer with negative delta (past)"""
    iso_time = "2024-04-25T10:00:00Z"
    result = SekoiaXDR.apply_time_buffer(iso_time, -5)  # Subtract 5 minutes

    # Result should be 5 minutes earlier
    assert "09:55:00" in result


def test_apply_time_buffer_with_offset():
    """Test apply_time_buffer with timezone offset"""
    iso_time = "2024-04-25T10:00:00+02:00"
    result = SekoiaXDR.apply_time_buffer(iso_time, 1)

    # Should handle offset correctly
    assert "10:01:00" in result


def test_apply_time_buffer_preserves_format():
    """Test apply_time_buffer preserves ISO format"""
    iso_time = "2024-04-25T10:00:00Z"
    result = SekoiaXDR.apply_time_buffer(iso_time, 30)

    # Should return valid ISO format ending with Z
    assert result.endswith("Z")
    assert "T" in result


def test_apply_time_buffer_invalid_format():
    """Test apply_time_buffer with invalid format - should return original"""
    invalid_time = "invalid-time-format"
    result = SekoiaXDR.apply_time_buffer(invalid_time, 5)

    # Should return the original string if parsing fails
    assert result == invalid_time


""" TEST HANDLE_ALERT_EVENTS_QUERY WITH BUFFERING """


def test_handle_alert_events_query_with_buffer(client, requests_mock):
    """Test handle_alert_events_query applies time buffer correctly"""
    mock_response_query = util_load_json("test_data/SekoiaXDR_query_events.json")
    mock_response_status = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    mock_response_retrieve = util_load_json("test_data/SekoiaXDR_retrieve_events.json")

    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query)
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_status,
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response_retrieve,
    )

    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")

    result_alert, is_ready = SekoiaXDR.handle_alert_events_query(
        client=client,
        alert=alert,
        earliest_time="2024-04-25T10:00:00Z",
        latest_time="2024-04-25T15:00:00Z",
        events_term="test_term",
    )

    # Should have successfully retrieved events
    assert "events" in result_alert
    assert is_ready is True


def test_handle_alert_events_query_pending_status(client, requests_mock):
    """Test handle_alert_events_query when job is still pending"""
    mock_response_query = util_load_json("test_data/SekoiaXDR_query_events.json")
    mock_response_status_pending = util_load_json("test_data/SekoiaXDR_query_events_status_in_progress.json")

    requests_mock.post(MOCK_URL + "/v1/sic/conf/events/search/jobs", json=mock_response_query)
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_status_pending,
    )

    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")

    result_alert, is_ready = SekoiaXDR.handle_alert_events_query(
        client=client,
        alert=alert,
        earliest_time="2024-04-25T10:00:00Z",
        latest_time="2024-04-25T15:00:00Z",
        events_term="test_term",
    )

    assert "job_uuid" in result_alert
    assert result_alert["job_uuid"] == "df904d2e-2c57-488f"
    assert "events" not in result_alert
    assert is_ready is False


""" TEST MIRRORING WITH CACHE """


def test_get_remote_data_with_cached_alert(client, requests_mock, mocker):
    """Test get_remote_data when alert is in cache waiting for events"""
    alert_cached = util_load_json("test_data/SekoiaXDR_get_alert.json")
    alert_cached["job_uuid"] = "df904d2e-2c57-488f"

    mock_response_status = util_load_json("test_data/SekoiaXDR_query_events_status.json")
    mock_response_retrieve = util_load_json("test_data/SekoiaXDR_retrieve_events.json")

    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f",
        json=mock_response_status,
    )
    requests_mock.get(
        MOCK_URL + "/v1/sic/conf/events/search/jobs/df904d2e-2c57-488f/events",
        json=mock_response_retrieve,
    )

    # Mock the cache with the alert
    cache_with_alert = {
        "mirroring_cache": [
            {
                "alert": alert_cached,
                "entries": [],
            }
        ]
    }
    mocker.patch.object(SekoiaXDR, "get_integration_context", return_value=cache_with_alert)
    mocker.patch.object(SekoiaXDR, "set_integration_context")

    args = {"lastUpdate": "2023-06-28T13:21:45", "id": "ALL1A4SKUiU2"}

    result = SekoiaXDR.get_remote_data_command(
        client=client,
        args=args,
        close_incident=False,
        close_note="Closed by Sekoia",
        mirror_events=True,
        mirror_kill_chain=False,
        reopen_incident=False,
    )

    # Should return the alert with events
    assert result is not None
    assert "events" in result.mirrored_object


def test_get_remote_data_close_incident_when_closed(client, requests_mock, mocker):
    """Test get_remote_data closes XSOAR incident when Sekoia alert is closed"""
    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")
    alert["status"]["name"] = "Closed"  # Set status to Closed

    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2", json=alert)

    # Mock investigation as OPEN
    investigation = {
        "id": "5721bf3c-f9ef-4b9e-8942-712ac829e0b7",
        "status": 0,  # 0 = Open, 1 = Closed
    }
    mocker.patch.object(demisto, "investigation", return_value=investigation)

    args = {"lastUpdate": "2023-06-28T13:21:45", "id": "ALL1A4SKUiU2"}

    result = SekoiaXDR.get_remote_data_command(
        client=client,
        args=args,
        close_incident=True,  # ← Should close the incident
        close_note="Closed by Sekoia",
        mirror_events=False,
        mirror_kill_chain=False,
        reopen_incident=False,
    )

    # Should have entries requesting to close the incident
    assert len(result.entries) > 0
    assert result.entries[0]["Contents"]["dbotIncidentClose"] is True


def test_get_remote_data_reopen_incident_when_reopened(client, requests_mock, mocker):
    """Test get_remote_data reopens XSOAR incident when Sekoia alert is reopened"""
    alert = util_load_json("test_data/SekoiaXDR_get_alert.json")
    alert["status"]["name"] = "Ongoing"  # Set status to Ongoing (reopened)

    requests_mock.get(MOCK_URL + "/v1/sic/alerts/ALL1A4SKUiU2", json=alert)

    # Mock investigation as CLOSED
    investigation = {
        "id": "5721bf3c-f9ef-4b9e-8942-712ac829e0b7",
        "status": 1,  # 1 = Closed
    }
    mocker.patch.object(demisto, "investigation", return_value=investigation)

    args = {"lastUpdate": "2023-06-28T13:21:45", "id": "ALL1A4SKUiU2"}

    result = SekoiaXDR.get_remote_data_command(
        client=client,
        args=args,
        close_incident=False,
        close_note="",
        mirror_events=False,
        mirror_kill_chain=False,
        reopen_incident=True,  # ← Should reopen the incident
    )

    # Should have entries requesting to reopen the incident
    assert len(result.entries) > 0
    assert result.entries[0]["Contents"]["dbotIncidentReopen"] is True


def test_get_modified_remote_data_includes_cached(client, requests_mock, mocker):
    """Test get_modified_remote_data includes cached mirroring alerts"""
    mock_response = util_load_json("test_data/SekoiaXDR_get_alerts.json")
    requests_mock.get(MOCK_URL + "/v1/sic/alerts", json=mock_response)

    # Mock cache with a mirroring alert
    cached_alert_id = "CACHED_ALERT_ID"
    cache = {
        "mirroring_cache": [
            {
                "alert": {"short_id": cached_alert_id},
                "entries": [],
            }
        ]
    }
    mocker.patch.object(SekoiaXDR, "get_integration_context", return_value=cache)

    args = {"lastUpdate": "2023-06-28T13:21:45"}

    result = SekoiaXDR.get_modified_remote_data_command(client, args)

    # Should include the cached alert ID
    assert cached_alert_id in result.modified_incident_ids
    # Should also include the ones from API response
    assert len(result.modified_incident_ids) >= 3  # 1 cached + 2 from API
