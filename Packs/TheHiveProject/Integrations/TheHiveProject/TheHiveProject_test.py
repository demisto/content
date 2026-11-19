import json

from freezegun import freeze_time


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_list_cases_command(requests_mock):
    from TheHiveProject import Client, list_cases_command

    mock_response = util_load_json("test_data/cases_list_new.json")

    requests_mock.post("https://test/api/v1/query?name=list-cases", json=mock_response)
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.post("https://test/api/case/task/_search", json=[])

    requests_mock.post("https://test/api/case/artifact/_search", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {}
    response = list_cases_command(client, args)

    assert len(response.outputs) == len(mock_response)
    assert response.outputs_prefix == "TheHive.Cases"
    assert response.outputs_key_field == "id"


def test_get_case_command(requests_mock):
    from TheHiveProject import Client, get_case_command

    mock_response = util_load_json("test_data/cases_list.json")

    requests_mock.get("https://test/api/case/1", json=mock_response[0])
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.post("https://test/api/case/task/_search", json=[])

    requests_mock.post("https://test/api/case/artifact/_search", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"id": "1"}
    response = get_case_command(client, args)

    assert response.outputs == mock_response[0]
    assert response.outputs_prefix == "TheHive.Cases"
    assert response.outputs_key_field == "id"


def test_update_case_command(requests_mock):
    from TheHiveProject import Client, update_case_command

    mock_original_response = util_load_json("test_data/cases_list.json")
    mock_response = mock_original_response.copy()
    mock_response[0]["title"] = "updated title"
    mock_response[0]["description"] = "updated description"

    requests_mock.get("https://test/api/case/1", json=mock_original_response[0])
    requests_mock.patch("https://test/api/case/1", json=mock_response[0])
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.post("https://test/api/case/task/_search", json=[])

    requests_mock.post("https://test/api/case/artifact/_search", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"id": "1", "title": "updated title", "description": "updated description"}
    response = update_case_command(client, args)

    assert response.outputs == mock_response[0]
    assert response.outputs_prefix == "TheHive.Cases"
    assert response.outputs_key_field == "id"


def test_create_case_command(requests_mock):
    from TheHiveProject import Client, create_case_command

    mock_response = {
        "_id": "4",
        "id": "4",
        "instance": "",
        "mirroring": "both",
        "observables": [],
        "caseId": "4",
        "createdBy": "example@example.com",
        "createdAt": "2021-07-22T09:15:09Z",
        "updatedAt": "2021-07-22T09:15:09Z",
        "_type": "case",
        "title": "added case title",
        "description": "added case description",
        "severity": 2,
        "status": "Open",
        "tasks": [],
        "owner": "example@example.com",
    }

    requests_mock.post("https://test/api/case", json=mock_response)
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"title": "added case title", "description": "added case description", "owner": "example@example.com"}
    response = create_case_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Cases"
    assert response.outputs_key_field == "id"


def test_merge_cases_command(requests_mock):
    from TheHiveProject import Client, merge_cases_command

    mock_response = util_load_json("test_data/merged_cases.json")

    requests_mock.post("https://test/api/case/1/_merge/2", json=mock_response)
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"firstCaseID": "1", "secondCaseID": "2"}
    response = merge_cases_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Cases"
    assert response.outputs_key_field == "id"


def test_get_case_tasks_command(requests_mock):
    from TheHiveProject import Client, get_case_tasks_command

    mock_response = util_load_json("test_data/cases_list.json")

    requests_mock.post("https://test/api/case/task/_search", json=mock_response[1]["tasks"])
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})
    requests_mock.get("https://test/api/case/2", json=mock_response[1])
    requests_mock.get("https://test/api/case/task/1/log", json=[])
    requests_mock.get("https://test/api/case/task/2/log", json=[])
    requests_mock.post("https://test/api/case/artifact/_search", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"id": "2"}
    response = get_case_tasks_command(client, args)

    assert response.outputs == mock_response[1]["tasks"]
    assert response.outputs_prefix == "TheHive.Tasks"
    assert response.outputs_key_field == "id"


def test_get_task_command(requests_mock):
    from TheHiveProject import Client, get_task_command

    mock_response = util_load_json("test_data/cases_list.json")[1]["tasks"][0]

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})
    requests_mock.get("https://test/api/task/1", json=mock_response)
    requests_mock.get("https://test/api/case/task/1", json=mock_response)
    requests_mock.get("https://test/api/case/task/1/log", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"id": "1"}
    response = get_task_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Tasks"
    assert response.outputs_key_field == "id"


def test_update_task_command(requests_mock):
    from TheHiveProject import Client, update_task_command

    mock_original_response = util_load_json("test_data/cases_list.json")[1]["tasks"][0]
    mock_response = mock_original_response.copy()
    mock_response["title"] = "updated title"

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})
    requests_mock.get("https://test/api/task/1", json=mock_original_response)
    requests_mock.get("https://test/api/case/task/1", json=mock_original_response)
    requests_mock.patch("https://test/api/case/task/1", json=mock_response)
    requests_mock.get("https://test/api/case/task/1/log", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    args = {"id": "1"}
    response = update_task_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Tasks"
    assert response.outputs_key_field == "id"


def test_get_users_list_command(requests_mock):
    from TheHiveProject import Client, get_users_list_command

    mock_response = util_load_json("test_data/users_list.json")

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.post("https://test/api/user/_search", json=mock_response)

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    response = get_users_list_command(client, {})

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Users"
    assert response.outputs_key_field == "id"


def test_get_user_command(requests_mock):
    from TheHiveProject import Client, get_user_command

    mock_response = util_load_json("test_data/users_list.json")[0]

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.get("https://test/api/user/1", json=mock_response)

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    response = get_user_command(client, {"id": "1"})

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Users"
    assert response.outputs_key_field == "id"


def test_create_local_user_command(requests_mock):
    from TheHiveProject import Client, create_local_user_command

    mock_response = util_load_json("test_data/added_user.json")

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.post("https://test/api/user", json=mock_response)

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )
    args = {"login": "example@example.com", "name": "Test User", "roles": ["read", "admin"], "password": "1234"}
    response = create_local_user_command(client, args)

    assert response.outputs == mock_response
    assert response.outputs_prefix == "TheHive.Users"
    assert response.outputs_key_field == "id"


def test_list_observables_command(requests_mock):
    from TheHiveProject import Client, list_observables_command

    mock_response = util_load_json("test_data/cases_list.json")[2]

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.get("https://test/api/case/3", json=mock_response)

    requests_mock.post("https://test/api/case/task/_search", json=[])

    requests_mock.post("https://test/api/case/artifact/_search", json=mock_response["observables"])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )
    args = {"id": "3"}
    response = list_observables_command(client, args)

    assert response.outputs == mock_response["observables"]
    assert response.outputs_prefix == "TheHive.Observables"
    assert response.outputs_key_field == "id"


def test_create_observable_command(requests_mock):
    from TheHiveProject import Client, create_observable_command

    mock_original_response = util_load_json("test_data/cases_list.json")[0]
    mock_response = mock_original_response.copy()
    mock_response["observables"].append(
        {
            "_id": "4",
            "id": "4",
            "createdBy": "example@example.com",
            "createdAt": 1627206318617,
            "_type": "case_artifact",
            "dataType": "domain",
            "data": "datas for test",
            "startDate": 1627206318617,
            "tlp": 2,
            "tags": [],
            "ioc": False,
            "sighted": False,
            "message": "messages for test",
            "reports": {},
            "stats": {},
        }
    )

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.get("https://test/api/case/1", json=mock_original_response)

    requests_mock.post("https://test/api/case/task/_search", json=[])

    requests_mock.post("https://test/api/case/artifact/_search", json=[])

    requests_mock.post("https://test/api/case/1/artifact", json=mock_response["observables"])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )
    args = {"id": "1"}
    response = create_observable_command(client, args)

    assert response.outputs == mock_response["observables"]
    assert response.outputs_prefix == "TheHive.Observables"
    assert response.outputs_key_field == "id"


def _mock_create_observable_case(requests_mock, artifact_status_code: int, artifact_response: dict):
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "4.1.9-1"}})
    requests_mock.get("https://test/api/case/1", json=util_load_json("test_data/cases_list.json")[0])
    requests_mock.post("https://test/api/v1/query?name=case-tasks", json=[])
    requests_mock.post("https://test/api/v1/query?name=observables", json=[])
    requests_mock.post("https://test/api/case/1/artifact", status_code=artifact_status_code, json=artifact_response)


def test_create_observable_command_already_exists(requests_mock):
    """
    Given:
        - TheHive returns 207 (Multi-Status) because the observable already exists in the case
          (for example, a playbook task retried after the first attempt already created it).
    When:
        - Running thehive-create-observable.
    Then:
        - No error is raised, no outputs are returned and the human readable says the observable already exists.
    """
    from TheHiveProject import Client, create_observable_command

    multi_status_response = {
        "success": [],
        "failure": [{"type": "CreateError", "message": "Observable already exists", "object": {"data": "example.com"}}],
    }
    _mock_create_observable_case(requests_mock, 207, multi_status_response)
    client = Client(base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"})

    response = create_observable_command(client, {"id": "1", "data": "example.com", "dataType": "domain"})

    assert response.outputs is None
    assert response.readable_output == "Observable already exists in case 1: example.com"


def test_create_observable_command_multi_status_partial_success(requests_mock):
    """
    Given:
        - TheHive returns 207 (Multi-Status) with one created observable and one that already exists.
    When:
        - Running thehive-create-observable.
    Then:
        - The created observable is returned in the outputs and the existing one is mentioned in the human readable.
    """
    from TheHiveProject import Client, create_observable_command

    created_observable = {"id": "~123", "data": "1.1.1.1", "dataType": "ip", "message": "test"}
    multi_status_response = {
        "success": [created_observable],
        "failure": [{"type": "CreateError", "message": "Observable already exists", "object": {"data": "example.com"}}],
    }
    _mock_create_observable_case(requests_mock, 207, multi_status_response)
    client = Client(base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"})

    response = create_observable_command(client, {"id": "1", "data": "1.1.1.1", "dataType": "ip"})

    assert response.outputs == [created_observable]
    assert "New Observable:" in response.readable_output
    assert "Observable already exists in case 1: example.com" in response.readable_output


def test_create_observable_command_multi_status_other_failure(requests_mock):
    """
    Given:
        - TheHive returns 207 (Multi-Status) with a failure other than "already exists".
    When:
        - Running thehive-create-observable.
    Then:
        - A DemistoException with the failure details is raised.
    """
    import pytest
    from CommonServerPython import DemistoException
    from TheHiveProject import Client, create_observable_command

    multi_status_response = {
        "success": [],
        "failure": [{"type": "AttributeCheckingError", "message": "Invalid dataType", "object": {"data": "example.com"}}],
    }
    _mock_create_observable_case(requests_mock, 207, multi_status_response)
    client = Client(base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"})

    with pytest.raises(DemistoException, match="Invalid dataType"):
        create_observable_command(client, {"id": "1", "data": "example.com", "dataType": "bad"})


def test_update_observable_command(requests_mock):
    from TheHiveProject import Client, update_observable_command

    mock_original_response = util_load_json("test_data/cases_list.json")[2]
    mock_response = mock_original_response.copy()
    mock_response["observables"][0]["message"] = "update message for test"

    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})

    requests_mock.patch("https://test/api/case/artifact/1", json=mock_response["observables"][0])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )
    args = {"id": "1", "message": "update message for test"}
    response = update_observable_command(client, args)

    assert response.outputs["message"] == "update message for test"
    assert "Updated Observable" in response.readable_output
    assert response.outputs_prefix == "TheHive.Observables"
    assert response.outputs_key_field == "id"


@freeze_time("2023-11-07T07:59:23Z")
def test_migrate_last_run(mocker, requests_mock):
    """
    Given:
        Old last run timestamp in milliseconds

    When:
        Running fetch-incidents after migrating to the new version

    Then:
        The last run timestamp is converted from milliseconds to ISO8601 format
    """
    from TheHiveProject import Client, demisto, fetch_incidents

    mocker.patch.object(demisto, "getLastRun", return_value={"timestamp": "1677728000000"})
    set_last_run_mock = mocker.patch.object(demisto, "setLastRun")
    get_cases_mock = mocker.patch.object(Client, "get_cases")
    requests_mock.get("https://test/api/status", json={"versions": {"TheHive": "version"}})
    requests_mock.post("https://test/api/v1/query?name=list-cases", json=[])

    client = Client(
        base_url="https://test/api", verify=False, headers={"Authorization": "Bearer APIKEY"}, proxy=False, mirroring="both"
    )

    fetch_incidents(client)
    assert set_last_run_mock.call_args_list[0][0][0]["time"] == "2023-11-07T07:59:23Z"
    mocker.patch.object(demisto, "getLastRun", return_value={"time": "2023-11-07T07:59:23Z"})
    assert get_cases_mock.call_args_list[0][1]["start_time"] == 1677728000000

    # now we want to test with updated last run to make sure it converts to milliseconds in the query
    get_cases_mock = mocker.patch.object(Client, "get_cases")
    fetch_incidents(client)
    assert get_cases_mock.call_args_list[0][1]["start_time"] == 1699343963000
