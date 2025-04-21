import pytest
from Tanium_v2 import Client, get_question_result, get_action_result
import json


def get_fetch_data():
    with open("test_data/action_results.json") as f:
        return json.loads(f.read())


BASE_URL = "https://test.com/"

parse_question_res = {
    "data": [
        {
            "from_canonical_text": 0,
            "group": {
                "and_flag": True,
                "deleted_flag": True,
                "filters": [
                    {
                        "all_times_flag": False,
                        "all_values_flag": False,
                        "delimiter": "",
                        "delimiter_index": 0,
                        "ignore_case_flag": True,
                        "max_age_seconds": 0,
                        "not_flag": False,
                        "operator": "RegexMatch",
                        "sensor": {"hash": 3409330187, "id": 3, "name": "Computer Name"},
                        "substring_flag": False,
                        "substring_length": 0,
                        "substring_start": 0,
                        "utf8_flag": False,
                        "value": ".*equals.*",
                        "value_type": "String",
                    }
                ],
                "not_flag": False,
                "sub_groups": [],
            },
            "question_text": 'Get Computer Name from all machines with Computer Name contains "equals"',
            "selects": [{"sensor": {"hash": 3409330187, "name": "Computer Name"}}],
            "sensor_references": [
                {"name": "Computer Name", "real_ms_avg": 0, "start_char": "4"},
                {"name": "Computer Name", "real_ms_avg": 0, "start_char": "41"},
            ],
        }
    ]
}

parse_question_Folder_Contents_res = {
    "data": [
        {
            "from_canonical_text": 0,
            "question_text": "Get Folder-Contents from all machines",
            "selects": [{"sensor": {"hash": 3881863289, "name": "Folder-Contents"}}],
            "sensor_references": [{"name": "Folder-Contents", "real_ms_avg": 53, "start_char": "4"}],
        },
        {
            "from_canonical_text": 0,
            "question_text": "Get Tanium File Contents from all machines",
            "selects": [{"sensor": {"hash": 4070262781, "name": "Tanium File Contents"}}],
            "sensor_references": [{"name": "Folder-Contents", "real_ms_avg": 53, "start_char": "4"}],
        },
    ]
}

sensor_res = {"data": {"parameter_definition": '{"parameters":[{"key":"folderPath"}]}'}}

CREATE_ACTION_BY_TARGET_GROUP_RES = {
    "package_spec": {"source_id": 12345},
    "name": "action-name via Demisto API",
    "target_group": {"name": "target-group-name"},
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

CREATE_ACTION_BY_HOST_RES = {
    "package_spec": {"source_id": 20},
    "name": "action-name via Demisto API",
    "target_group": {
        "and_flag": True,
        "deleted_flag": True,
        "filters": [
            {
                "all_times_flag": False,
                "all_values_flag": False,
                "delimiter": "",
                "delimiter_index": 0,
                "ignore_case_flag": True,
                "max_age_seconds": 0,
                "not_flag": False,
                "operator": "RegexMatch",
                "sensor": {"hash": 3409330187, "id": 3, "name": "Computer Name"},
                "substring_flag": False,
                "substring_length": 0,
                "substring_start": 0,
                "utf8_flag": False,
                "value": ".*equals.*",
                "value_type": "String",
            }
        ],
        "not_flag": False,
        "sub_groups": [],
    },
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

CREATE_ACTION_WITH_PARAMETERS_RES = {
    "package_spec": {
        "source_id": 12345,
        "parameters": [{"key": "$1", "value": "true"}, {"key": "$2", "value": "value"}, {"key": "$3", "value": "otherValue"}],
    },
    "name": "action-name via Demisto API",
    "target_group": {"name": "target-group-name"},
    "action_group": {"id": 1},
    "expire_seconds": 360,
}

QUESTION_RESULTS_RAW = {
    "data": {
        "result_sets": [
            {
                "age": 0,
                "archived_question_id": 0,
                "cache_id": "3891494157",
                "columns": [
                    {"hash": 3409330187, "name": "Computer Name", "type": 1},
                    {"hash": 2801942354, "name": "IPv4 Address", "type": 5},
                    {"hash": 1092986182, "name": "Logged In Users", "type": 1},
                    {"hash": 0, "name": "Count", "type": 3},
                ],
                "estimated_total": 2,
                "mr_tested": 2,
                "rows": [
                    {
                        "cid": 2232836718,
                        "data": [[{"text": "host-name"}], [{"text": "127.0.0.1"}], [{"text": "[no results]"}], [{"text": "1"}]],
                        "id": 699534294,
                    }
                ],
            }
        ]
    }
}


QUESTION_RESULTS = [{"ComputerName": "host-name", "IPv4Address": "127.0.0.1", "Count": "1"}]


def test_create_action_body_by_target_group_name(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "SESSION-ID"}})
    requests_mock.get(BASE_URL + "packages/by-name/package-name", json={"data": {"id": 12345, "expire_seconds": 360}})

    body = client.build_create_action_body(
        False, "action-name", "", package_name="package-name", action_group_id=1, target_group_name="target-group-name"
    )

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_TARGET_GROUP_RES)

    assert res == body


def test_create_action_body_by_host(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.get(BASE_URL + "packages/20", json={"data": {"id": 12345, "expire_seconds": 360}})
    requests_mock.post(BASE_URL + "parse_question", json=parse_question_res)

    body = client.build_create_action_body(True, "action-name", "", package_id=20, action_group_id=1, hostname="host")

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_BY_HOST_RES)

    assert res == body


def test_create_action_body_with_parameters(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")

    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.get(BASE_URL + "packages/by-name/package-name", json={"data": {"id": 12345, "expire_seconds": 360}})

    body = client.build_create_action_body(
        False,
        "action-name",
        "$1=true;$2=value;$3=otherValue",
        package_name="package-name",
        action_group_id=1,
        target_group_name="target-group-name",
    )

    body = json.dumps(body)
    res = json.dumps(CREATE_ACTION_WITH_PARAMETERS_RES)

    assert res == body


def test_parse_question_results():
    client = Client(BASE_URL, "username", "password", "domain")
    results = client.parse_question_results(QUESTION_RESULTS_RAW, 95)
    assert results == QUESTION_RESULTS


def test_parse_question(requests_mock):
    client = Client(BASE_URL, "username", "password", "domain")
    requests_mock.post(BASE_URL + "session/login", json={"data": {"session": "session-id"}})
    requests_mock.post(BASE_URL + "parse_question", json=parse_question_Folder_Contents_res)
    requests_mock.get(BASE_URL + "sensors/by-name/Folder-Contents", json=sensor_res)

    results = client.parse_question(r"Get Folder-Contents[c:\] from all machines", "")
    assert results["selects"][0]["sensor"]["name"] == "Folder-Contents"
    assert results["selects"][0]["sensor"]["parameters"][0]["key"] == "||folderPath||"
    assert results["selects"][0]["sensor"]["parameters"][0]["value"] == "c:\\"


def test_get_question_result_invalid_input():
    client = Client(BASE_URL, "username", "password", "domain")
    data_args = {"completion-percentage": "0"}
    try:
        _, _, _ = get_question_result(client, data_args)
    except ValueError as e:
        assert str(e) == "completion-percentage argument is invalid, Please enter number between 1 to 100"


data_test_parse_action_parameters = [
    ("key1=value1", [{"key": "key1", "value": "value1"}]),
    ("key1=value1=value1", [{"key": "key1", "value": "value1=value1"}]),
    ("key1=value1=value1;key2=value2", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "value2"}]),
    ("key1=value1=value1;key2=valu;e2", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "valu;e2"}]),
    ("key1=value1=value1;key2=ab=;c", [{"key": "key1", "value": "value1=value1"}, {"key": "key2", "value": "ab=;c"}]),
]


@pytest.mark.parametrize("parameters, accepted_result", data_test_parse_action_parameters)
def test_parse_action_parameters(parameters, accepted_result):
    """Tests parse_action_parameters function
    Given
        A string representing a key=value list separated by ';'
        1. parameters = 'key1=value1'
        2. parameters = 'key1=value1=value1'
        3. parameters = 'key1=value1=value1;key2=value2'
        4. parameters = 'key1=value1=value1;key2=valu;e2'
        5. parameters = key1=value1=value1;key2=ab=;c'

    When
        When calling the "parse_action_parameters" function to extract it to a dictionary
    Then
        validate that everything is extracted properly even if there is within the value "=" or ";"
        1. Ensure result = [{'key': 'key1', 'value': 'value1'}]
        2. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}]
        3. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'value2'}]
        4. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'valu;e2'}]
        5. Ensure result = [{'key': 'key1', 'value': 'value1=value1'}, {'key': 'key2', 'value': 'ab=;c'}]
    """
    client = Client(BASE_URL, "username", "password", "domain")
    result = client.parse_action_parameters(parameters)
    assert result == accepted_result


def test_update_session(mocker):
    """
    Tests the authentication method, based on the instance configurations.
    Given:
        - A client created using username and password
        - A client created using an API token
    When:
        - calling the update_session() function of the client
    Then:
        - Verify that the session was created using basic authentication
        - Verify that the session was created using oauth authentication
    """
    client = Client(BASE_URL, username="abdc", password="1234", domain="domain", api_token="")
    mocker.patch.object(Client, "_http_request", return_value={"data": {"session": "basic authentication"}})
    client.update_session()
    assert client.session == "basic authentication"

    client = Client(BASE_URL, username="", password="", domain="domain", api_token="oauth authentication")
    client.update_session()
    assert client.session == "oauth authentication"


def test_get_action_result(mocker):
    """
    Tests the get action result method.
    Given:
        - Action ID to get information on.
    When:
        - calling the get_action_result() function.
    Then:
        - Verify that the human_readable was created as expected.
        - Verify that the outputs was created as expected.
        - Verify that the raw_response was created as expected.
    """
    client = Client(BASE_URL, "username", "password", "domain")
    data_args = {"id": "350385"}
    action_res = get_fetch_data()
    mocker.patch.object(Client, "do_request", return_value=action_res["action_raw_response"])
    human_readable, outputs, action_res_outputs = get_action_result(client, data_args)
    assert action_res_outputs == action_res["action_output"]
    assert outputs == action_res["action_output_res"]
    assert "### Device Statuses" in human_readable
