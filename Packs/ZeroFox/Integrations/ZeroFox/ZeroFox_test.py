import json
from dateparser import parse as parse_date
from datetime import timedelta
from ZeroFox import (
    ZFClient,
    fetch_incidents,
    get_modified_remote_data_command,
    get_remote_data_command,
    get_alert_command,
    alert_user_assignment_command,
    close_alert_command,
    open_alert_command,
    alert_request_takedown_command,
    alert_cancel_takedown_command,
    modify_alert_tags_command,
    create_entity_command,
    list_alerts_command,
    list_entities_command,
    get_entity_types_command,
    get_policy_types_command,
    modify_alert_notes_command,
    submit_threat_command,
    compromised_domain_command,
    compromised_email_command,
    malicious_ip_command,
    malicious_hash_command,
    search_exploits_command,
)

BASE_URL = "https://api.zerofox.com"
OK_CODES = (200, 201)
FETCH_LIMIT = 10
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def load_json(file: str):
    with open(file) as f:
        return json.load(f)


def build_zf_client() -> ZFClient:
    return ZFClient(
        base_url=BASE_URL,
        ok_codes=OK_CODES,
        username='',
        password='',
        fetch_limit=FETCH_LIMIT,
    )


def get_delayed_formatted_date(str_date: str, delay=timedelta(milliseconds=1)):
    formatted_date = parse_date(str_date, date_formats=(DATE_FORMAT,),)
    if formatted_date is None:
        raise ValueError("date must be a valid string date")
    delayed_date = formatted_date + delay
    return delayed_date.strftime(DATE_FORMAT)


def test_fetch_incidents_first_time_with_no_data(requests_mock, mocker):
    """
    Given
        There is 0 alerts
        And last_run is empty
    When
        Calling fetch_incidents
    Then
        It should list alerts with first_fetch_time as min_timestamp
        And offset equals to 0
        And return last_fetch equals to first_fetch_time
        And last last_offset equals to 0
        And 0 incidents
    """
    alerts_response = load_json("test_data/alerts/list_no_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    last_run: dict = {}
    first_fetch_time = "2023-06-01T00:00:00.000000"
    first_fetch_time_parsed = parse_date(
        first_fetch_time,
        date_formats=(DATE_FORMAT,),
    )
    expected_offset = 0
    spy = mocker.spy(client, "list_alerts")

    next_run, incidents = fetch_incidents(
        client,
        last_run,
        first_fetch_time,
    )

    spy.assert_called_once()
    list_alert_params = spy.call_args[0][0]
    assert list_alert_params.get("min_timestamp") == first_fetch_time_parsed
    assert list_alert_params.get("sort_direction") == "asc"
    assert list_alert_params.get("offset") == expected_offset
    assert next_run["last_fetched"] == first_fetch_time
    assert next_run["last_offset"] == str(expected_offset)
    assert len(incidents) == 0


def test_fetch_incidents_first_time(requests_mock, mocker):
    """
    Given
        There are alerts (less than the fetch limit)
        And there is no last_fetched in last_run
    When
        Calling fetch_incidents
    Then
        It should list alerts with first_fetch_time as min_timestamp
        And offset equals to 0
        And return last_fetch equals to last alert timestamp + 1 millisecond
        And last last_offset equals to 0
        And 10 incidents correctly formatted
    """
    alerts_response = load_json("test_data/alerts/list_10_records.json")
    last_alert_timestamp = alerts_response["alerts"][-1]["timestamp"]
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    last_run: dict = {}
    first_fetch_time = "2023-06-01T00:00:00.000000"
    first_fetch_time_parsed = parse_date(
        first_fetch_time,
        date_formats=(DATE_FORMAT,),
    )
    last_alert_timestamp_formatted = get_delayed_formatted_date(
        last_alert_timestamp,
    )
    expected_offset = 0
    spy = mocker.spy(client, "list_alerts")

    next_run, incidents = fetch_incidents(
        client,
        last_run,
        first_fetch_time,
    )

    spy.assert_called_once()
    list_alert_params = spy.call_args[0][0]
    assert list_alert_params.get("min_timestamp") == first_fetch_time_parsed
    assert list_alert_params.get("sort_direction") == "asc"
    assert list_alert_params.get("offset") == expected_offset
    assert next_run["last_fetched"] == last_alert_timestamp_formatted
    assert next_run["last_offset"] == str(expected_offset)
    assert len(incidents) == 10
    for incident in incidents:
        assert "mirror_instance" in incident["rawJSON"]
        assert "mirror_direction" in incident["rawJSON"]


def test_fetch_incidents_no_first_time(requests_mock, mocker):
    """
    Given
        There are alerts
        And there are more in the next page
        And last_fetched is set in last_run
        And last_offset is set in last_run
    When
        Calling fetch_incidents
    Then
        It should list alerts with the last_fetched set in last_run
        And with the last_offset set in last_run
        And return last_fetch equals to last_fetched set
        And last_offset equals to the offset set in the "next" link of the response
        And 10 incidents correctly formatted
    """
    alerts_response = load_json("test_data/alerts/list_10_records_and_more.json")
    alerts_response["alerts"][-1]["timestamp"]
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    last_offset_saved = 10
    last_run = {
        "last_fetched": "2023-07-01T12:34:56.000000",
        "last_offset": str(last_offset_saved),
    }
    first_fetch_time = "2023-06-01T00:00:00.000000"
    last_offset_expected = 20
    spy = mocker.spy(client, "list_alerts")

    next_run, incidents = fetch_incidents(
        client,
        last_run,
        first_fetch_time,
    )

    spy.assert_called_once()
    list_alert_params = spy.call_args[0][0]
    min_timestamp_called = list_alert_params.get(
        "min_timestamp"
    ).strftime(DATE_FORMAT)
    assert min_timestamp_called == last_run["last_fetched"]
    assert list_alert_params.get("sort_direction") == "asc"
    assert list_alert_params.get("offset") == last_offset_saved
    assert next_run["last_fetched"] == last_run["last_fetched"]
    assert next_run["last_offset"] == str(last_offset_expected)
    assert len(incidents) == 10
    for incident in incidents:
        assert "mirror_instance" in incident["rawJSON"]
        assert "mirror_direction" in incident["rawJSON"]


def test_get_modified_remote_data_command_with_no_data(requests_mock, mocker):
    """
    Given
        There are no modified alerts
    When
        Calling get_modified_remote_data_command
    Then
        It should list alerts with the last_fetched set in last_run
        And return an empty list
    """
    alerts_response = load_json("test_data/alerts/list_no_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_alerts")
    args = {"lastUpdate": "2023-07-01T12:34:56"}

    results = get_modified_remote_data_command(client, args)

    spy.assert_called_once()
    list_alerts_call_args = spy.call_args[0][0]
    assert list_alerts_call_args["last_modified_min_date"] == args["lastUpdate"]
    assert list_alerts_call_args["max_timestamp"] == args["lastUpdate"]
    assert len(results.modified_incident_ids) == 0


def test_get_modified_remote_data_command(requests_mock, mocker):
    """
    Given
        There are modified alerts
    When
        Calling get_modified_remote_data_command
    Then
        It should list alerts with the last_fetched set in last_run
        And return a list with the ids of the modified alerts as strings
    """
    alerts_response = load_json("test_data/alerts/list_10_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_alerts")
    args = {"lastUpdate": "2023-07-01T12:34:56"}

    results = get_modified_remote_data_command(client, args)

    spy.assert_called_once()
    list_alerts_call_args = spy.call_args[0][0]
    assert list_alerts_call_args["last_modified_min_date"] == args["lastUpdate"]
    assert list_alerts_call_args["max_timestamp"] == args["lastUpdate"]
    assert len(results.modified_incident_ids) == 10
    for modified_incident_id in results.modified_incident_ids:
        assert isinstance(modified_incident_id, str)


def test_get_remote_data_command_with_opened_alert(requests_mock, mocker):
    """
    Given
        There is an opened alert id
    When
        Calling get_remote_data_command
    Then
        It should call fetch alert with the given id
        And return the alert content
        And no entries in entries list
    """
    alert_id = 123
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_alert")
    args = {"id": alert_id, "lastUpdate": ""}

    results = get_remote_data_command(client, args)

    spy.assert_called_once()
    get_alert_call_arg = spy.call_args[0][0]
    assert get_alert_call_arg == args["id"]
    assert len(results.entries) == 0


def test_get_remote_data_command_with_closed_alert(requests_mock, mocker):
    """
    Given
        There is an opened alert id
    When
        Calling get_remote_data_command
    Then
        It should call fetch alert with the given id
        And return the alert content
        And one entry in the entries list
    """
    alert_id = "123"
    alert_response = load_json("test_data/alerts/closed_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_alert")
    args = {"id": alert_id, "lastUpdate": ""}

    results = get_remote_data_command(client, args)

    spy.assert_called_once()
    get_alert_call_arg = spy.call_args[0][0]
    assert get_alert_call_arg == args["id"]
    assert len(results.entries) == 1


def test_get_alert_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling get_alert_command
    Then
        It should call fetch alert with the given id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = 123
    alert_response = load_json("test_data/alerts/closed_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id}

    results = get_alert_command(client, args)

    spy.assert_called_once()
    get_alert_call_arg = spy.call_args[0][0]
    assert get_alert_call_arg == args["alert_id"]
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_alert_user_assignment_command(requests_mock, mocker):
    """
    Given
        There is a username
        And an alert id
    When
        Calling alert_user_assignment_command
    Then
        It should call the assign user to alert with correct data
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    username = "user123"
    alert_response = load_json("test_data/alerts/closed_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/assign/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_assignment = mocker.spy(client, "alert_user_assignment")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id, "username": username}

    results = alert_user_assignment_command(client, args)

    spy_assignment.assert_called_once()
    alert_id_called_in_assignment, username_called = spy_assignment.call_args[0]
    assert int(alert_id) == alert_id_called_in_assignment
    assert username == username_called
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_close_alert_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling close_alert_command
    Then
        It should call the close alert with the alert id
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    alert_response = load_json("test_data/alerts/closed_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/close/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_close = mocker.spy(client, "close_alert")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id}

    results = close_alert_command(client, args)

    spy_close.assert_called_once()
    alert_id_called_in_close, = spy_close.call_args[0]
    assert int(alert_id) == alert_id_called_in_close
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_open_alert_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling open_alert_command
    Then
        It should call the open alert with the alert id
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/open/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_open = mocker.spy(client, "open_alert")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id}

    results = open_alert_command(client, args)

    spy_open.assert_called_once()
    alert_id_called_in_open, = spy_open.call_args[0]
    assert int(alert_id) == alert_id_called_in_open
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_alert_request_takedown_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling alert_request_takedown_command
    Then
        It should call the request takedown alert with the alert id
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/request_takedown/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_request_takedown = mocker.spy(client, "alert_request_takedown")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id}

    results = alert_request_takedown_command(client, args)

    spy_request_takedown.assert_called_once()
    alert_id_called_in_request, = spy_request_takedown.call_args[0]
    assert int(alert_id) == alert_id_called_in_request
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_alert_cancel_takedown_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling alert_cancel_takedown_command
    Then
        It should call the cancel takedown alert with the alert id
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/cancel_takedown/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_cancel_takedown = mocker.spy(client, "alert_cancel_takedown")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id}

    results = alert_cancel_takedown_command(client, args)

    spy_cancel_takedown.assert_called_once()
    alert_id_called_in_cancel, = spy_cancel_takedown.call_args[0]
    assert int(alert_id) == alert_id_called_in_cancel
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_modify_alert_tags_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling modify_alert_tags_command
    Then
        It should call the modify alert tags with the alert id
        And the tags
        And the action
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    tags = "tag1,tag2,tag3"
    action = "add"
    action_in_request = "added"
    tags_in_request = tags.split(",")
    alert_response = load_json("test_data/alerts/opened_alert.json")
    change_tags_response = load_json("test_data/alerts/change_tags.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post("/1.0/alerttagchangeset/", json=change_tags_response)
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_modify = mocker.spy(client, "modify_alert_tags")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id, "tags": tags, "action": action}

    results = modify_alert_tags_command(client, args)

    spy_modify.assert_called_once()
    alert_id_called, action_called, tags_called = spy_modify.call_args[0]
    assert int(alert_id) == alert_id_called
    assert action_in_request == action_called
    assert tags_in_request == tags_called
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_create_entity_command_with_true_flag(requests_mock, mocker):
    """
    Given
        There is an entity name
        and its strict name matching flag
        and its tags
        and its policy id
        and its organization
        to create an entity
    When
        Calling create_entity_command
    Then
        It should call the create entity with the name
        And the strict_name_matching flag
        And the tags
        And the policy_id
        And the organization
        And return the entity as output
        And with the correct output prefix
    """
    entity_name = "name"
    strict_name_matching = "true"
    tags = "tag1,tag2,tag3"
    policy_id = 1
    organization = "org"
    strict_name_matching_request = True
    tags_request = tags.split(",")
    entity_response = load_json("test_data/entities/create_entity.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post("/1.0/entities/", json=entity_response)
    client = build_zf_client()
    spy_create_entity = mocker.spy(client, "create_entity")
    args = {
        "name": entity_name,
        "strict_name_matching": strict_name_matching,
        "tags": tags,
        "policy_id": policy_id,
        "organization": organization,
    }

    results = create_entity_command(client, args)

    spy_create_entity.assert_called_once()
    called_args = spy_create_entity.call_args[0]
    entity_name_called = called_args[0]
    strict_name_matching_called = called_args[1]
    tags_called = called_args[2]
    policy_id_called = called_args[3]
    organization_called = called_args[4]
    assert entity_name_called == entity_name
    assert strict_name_matching_called == strict_name_matching_request
    assert tags_called == tags_request
    assert policy_id_called == policy_id
    assert organization_called == organization

    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == 'ZeroFox.Entity'


def test_create_entity_command_with_false_flag(requests_mock, mocker):
    """
    Given
        There is an entity name
        and its strict name matching flag
        and its tags
        and its policy id
        and its organization
        to create an entity
    When
        Calling create_entity_command
    Then
        It should call the create entity with the name
        And the strict_name_matching flag
        And the tags
        And the policy_id
        And the organization
        And return the entity as output
        And with the correct output prefix
    """
    entity_name = "name"
    strict_name_matching = "false"
    tags = "tag1,tag2,tag3"
    policy_id = 1
    organization = "org"
    strict_name_matching_request = False
    tags_request = tags.split(",")
    entity_response = load_json("test_data/entities/create_entity.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post("/1.0/entities/", json=entity_response)
    client = build_zf_client()
    spy_create_entity = mocker.spy(client, "create_entity")
    args = {
        "name": entity_name,
        "strict_name_matching": strict_name_matching,
        "tags": tags,
        "policy_id": policy_id,
        "organization": organization,
    }

    results = create_entity_command(client, args)

    spy_create_entity.assert_called_once()
    called_args = spy_create_entity.call_args[0]
    entity_name_called = called_args[0]
    strict_name_matching_called = called_args[1]
    tags_called = called_args[2]
    policy_id_called = called_args[3]
    organization_called = called_args[4]
    assert entity_name_called == entity_name
    assert strict_name_matching_called == strict_name_matching_request
    assert tags_called == tags_request
    assert policy_id_called == policy_id
    assert organization_called == organization

    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == 'ZeroFox.Entity'


def test_list_alerts_command_with_no_records(requests_mock, mocker):
    """
    Given
        There is no alerts
    When
        Calling list_alerts_command
    Then
        It should call fetch alerts
        And return an empty list as output
        And with the correct output prefix
    """
    alerts_response = load_json("test_data/alerts/list_no_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_alerts")
    args: dict = {}

    results = list_alerts_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 0
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_list_alerts_command_with_records(requests_mock, mocker):
    """
    Given
        There are alerts
    When
        Calling list_alerts_command
    Then
        It should call fetch alerts
        And return a list with alerts as output
        And with the correct output prefix
    """
    alerts_response = load_json("test_data/alerts/list_10_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/alerts/", json=alerts_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_alerts")
    args: dict = {}

    results = list_alerts_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 10
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_list_entities_command_with_no_records(requests_mock, mocker):
    """
    Given
        There is no entities
    When
        Calling list_entities_command
    Then
        It should call fetch entities
        And return an empty list as output
        And with the correct output prefix
    """
    entities_response = load_json("test_data/entities/entities_no_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/entities/", json=entities_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_entities")
    args: dict = {}

    results = list_entities_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 0
    assert results.outputs_prefix == "ZeroFox.Entity"


def test_list_entities_command_with_records(requests_mock, mocker):
    """
    Given
        There are entities
    When
        Calling list_entities_command
    Then
        It should call fetch entities
        And return a list with entities as output
        And with the correct output prefix
    """
    entities_response = load_json("test_data/entities/entities_8_records.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/entities/", json=entities_response)
    client = build_zf_client()
    spy = mocker.spy(client, "list_entities")
    args: dict = {}

    results = list_entities_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 8
    assert results.outputs_prefix == "ZeroFox.Entity"


def test_get_entity_types_command_with_no_records(requests_mock, mocker):
    """
    Given
        There is no entity types
    When
        Calling get_entity_types_command
    Then
        It should call fetch entity types
        And return an empty list as output
        And with the correct output prefix
    """
    entity_types_response = load_json(
        "test_data/entities/entity_types_no_records.json",
    )
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/entities/types/", json=entity_types_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_entity_types")
    args: dict = {}

    results = get_entity_types_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 0
    assert results.outputs_prefix == "ZeroFox.EntityTypes"


def test_get_entity_types_command_with_records(requests_mock, mocker):
    """
    Given
        There are entity types
    When
        Calling get_entity_types_command
    Then
        It should call fetch entity types
        And return a list with entity types as output
        And with the correct output prefix
    """
    entity_types_response = load_json(
        "test_data/entities/entity_types_10_records.json",
    )
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/entities/types/", json=entity_types_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_entity_types")
    args: dict = {}

    results = get_entity_types_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 10
    assert results.outputs_prefix == "ZeroFox.EntityTypes"


def test_get_policy_types_command_with_no_records(requests_mock, mocker):
    """
    Given
        There is no policy types
    When
        Calling get_policy_types_command
    Then
        It should call fetch policy types
        And return an empty list as output
        And with the correct output prefix
    """
    policy_types_response = load_json(
        "test_data/policies/policy_types_no_records.json",
    )
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/policies/", json=policy_types_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_policy_types")
    args: dict = {}

    results = get_policy_types_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 0
    assert results.outputs_prefix == "ZeroFox.PolicyTypes"


def test_get_policy_types_command_with_records(requests_mock, mocker):
    """
    Given
        There are policy types
    When
        Calling get_policy_types_command
    Then
        It should call fetch policy types
        And return a list with policy types as output
        And with the correct output prefix
    """
    policy_types_response = load_json(
        "test_data/policies/policy_types_13_records.json",
    )
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.get("/1.0/policies/", json=policy_types_response)
    client = build_zf_client()
    spy = mocker.spy(client, "get_policy_types")
    args: dict = {}

    results = get_policy_types_command(client, args)

    spy.assert_called_once()
    assert len(results.outputs) == 13
    assert results.outputs_prefix == "ZeroFox.PolicyTypes"


def test_modify_alert_notes_command(requests_mock, mocker):
    """
    Given
        There is an alert id
    When
        Calling modify_alert_notes_command
    Then
        It should call the modify alert notes with the alert id
        And the notes
        And the action
        And call fetch alert with the alert id
        And return the alert as output
        And with the correct output prefix
    """
    alert_id = "123"
    notes = "some notes"
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post(f"/1.0/alerts/{alert_id}/")
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_modify = mocker.spy(client, "modify_alert_notes")
    spy_fetch = mocker.spy(client, "get_alert")
    args = {"alert_id": alert_id, "notes": notes}

    results = modify_alert_notes_command(client, args)

    spy_modify.assert_called_once()
    alert_id_called, notes_called, = spy_modify.call_args[0]
    assert int(alert_id) == alert_id_called
    assert notes_called == notes
    spy_fetch.assert_called_once()
    alert_id_called_in_fetch, = spy_fetch.call_args[0]
    assert int(alert_id) == alert_id_called_in_fetch
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_submit_threat_command(requests_mock, mocker):
    """
    Given
        There is a source
        And an alert type
        And a violation
        And an entity id
    When
        Calling submit_threat_command
    Then
        It should call the submit threat with the source
        And the alert type
        And the violation
        And the entity id
        And return the alert id as output
        And with the correct output prefix
    """
    source = "abc@test.com"
    alert_type = "email"
    violation = "phishing"
    entity_id = "123"
    alert_id = "123"
    submit_response = load_json("test_data/alerts/submit_threat.json")
    alert_response = load_json("test_data/alerts/opened_alert.json")
    requests_mock.post("/1.0/api-token-auth/", json={"token": ""})
    requests_mock.post("/2.0/threat_submit/", json=submit_response)
    requests_mock.get(f"/1.0/alerts/{alert_id}/", json=alert_response)
    client = build_zf_client()
    spy_submit = mocker.spy(client, "submit_threat")
    args = {
        "source": source,
        "alert_type": alert_type,
        "violation": violation,
        "entity_id": entity_id,
    }

    results = submit_threat_command(client, args)

    spy_submit.assert_called_once()
    submit_threat_args = spy_submit.call_args[0]
    source_called = submit_threat_args[0]
    alert_type_called = submit_threat_args[1]
    violation_called = submit_threat_args[2]
    entity_id_called = submit_threat_args[3]
    assert source == source_called
    assert alert_type == alert_type_called
    assert violation == violation_called
    assert entity_id == entity_id_called
    assert isinstance(results.outputs, dict)
    assert results.outputs_prefix == "ZeroFox.Alert"


def test_compromised_domain_command(requests_mock, mocker):
    """
    Given
        There is a domain
    When
        Calling compromised_domain_command
    Then
        It should call c2-domain endpoint
        And phishing endpoint
        And return a list with threats as output
        And with the correct output prefix
    """
    domain = "abc.xyz"
    c2_domains_response = load_json("test_data/cti/c2-domains.json")
    phishing_response = load_json("test_data/cti/phishing.json")
    requests_mock.post("/auth/token/verify/")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get("/cti/c2-domains/", json=c2_domains_response)
    requests_mock.get("/cti/phishing/", json=phishing_response)
    client = build_zf_client()
    spy_c2_domains = mocker.spy(client, "get_cti_c2_domains")
    spy_phishing = mocker.spy(client, "get_cti_phishing")
    args = {"domain": domain}

    results = compromised_domain_command(client, args)

    spy_c2_domains.assert_called_once()
    c2_domains_domain_arg, = spy_c2_domains.call_args[0]
    assert c2_domains_domain_arg == domain
    spy_phishing.assert_called_once()
    phishing_domain_arg = spy_phishing.call_args.kwargs.get("domain")
    assert phishing_domain_arg == domain
    assert len(results.outputs) == 5
    assert results.outputs_prefix == "ZeroFox.CompromisedDomains"


def test_compromised_email_command(requests_mock, mocker):
    """
    Given
        There is an email
    When
        Calling compromised_email_command
    Then
        It should call email-addresses endpoint
        And compromised-credentials endpoint
        And botnet-compromised-credentials endpoint
        And return a list with threats as output
        And with the correct output prefix
    """
    email = "abc@test.com"
    email_response = load_json("test_data/cti/email-addresses.json")
    credentials_response = load_json(
        "test_data/cti/compromised-credentials.json",
    )
    botnet_credentials_response = load_json(
        "test_data/cti/botnet-compromised-credentials.json",
    )
    requests_mock.post("/auth/token/verify/")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get("/cti/email-addresses/", json=email_response)
    requests_mock.get(
        "/cti/compromised-credentials/",
        json=credentials_response,
    )
    requests_mock.get(
        "/cti/botnet-compromised-credentials/",
        json=botnet_credentials_response,
    )
    client = build_zf_client()
    spy_email_addresses = mocker.spy(client, "get_cti_email_addresses")
    spy_compromised_credentials = mocker.spy(
        client,
        "get_cti_compromised_credentials",
    )
    spy_botnet_compromised_credentials = mocker.spy(
        client,
        "get_cti_botnet_compromised_credentials",
    )
    args = {"email": email}

    results = compromised_email_command(client, args)

    spy_email_addresses.assert_called_once()
    email_addresses_email_arg, = spy_email_addresses.call_args[0]
    assert email_addresses_email_arg == email

    spy_compromised_credentials.assert_called_once()
    compromised_credentials_email_arg, =\
        spy_compromised_credentials.call_args[0]
    assert compromised_credentials_email_arg == email

    spy_botnet_compromised_credentials.assert_called_once()
    botnet_compromised_credentials_email_arg, =\
        spy_botnet_compromised_credentials.call_args[0]
    assert botnet_compromised_credentials_email_arg == email

    assert len(results.outputs) == 3
    assert results.outputs_prefix == "ZeroFox.CompromisedEmails"


def test_malicious_ip_command(requests_mock, mocker):
    """
    Given
        There is an IP
    When
        Calling malicious_ip_command
    Then
        It should call botnet endpoint
        And phishing endpoint
        And return a list with threats as output
        And with the correct output prefix
    """
    ip = "127.0.0.1"
    botnet_response = load_json("test_data/cti/botnet.json")
    phishing_response = load_json("test_data/cti/phishing.json")
    requests_mock.post("/auth/token/verify/")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get("/cti/botnet/", json=botnet_response)
    requests_mock.get("/cti/phishing/", json=phishing_response)
    client = build_zf_client()
    spy_botnet = mocker.spy(client, "get_cti_botnet")
    spy_phishing = mocker.spy(client, "get_cti_phishing")
    args = {"ip": ip}

    results = malicious_ip_command(client, args)

    spy_botnet.assert_called_once()
    spy_botnet_ip_arg, = spy_botnet.call_args[0]
    assert spy_botnet_ip_arg == ip
    spy_phishing.assert_called_once()
    phishing_ip_arg = spy_phishing.call_args.kwargs.get("ip")
    assert phishing_ip_arg == ip
    assert len(results.outputs) == 7
    assert results.outputs_prefix == "ZeroFox.MaliciousIPs"


def test_malicious_hash_command(requests_mock, mocker):
    """
    Given
        There is a hash
    When
        Calling malicious_hash_command
    Then
        It should call malware endpoint with hash_type md5
        And with hash_type sha1
        And with hash_type sha256
        And with hash_type sha512
        And return a list with threats as output
        And with the correct output prefix
    """
    hash = "e89b43d57a67a3f4d705028cfbd7b6fb"
    hash_types = ["md5", "sha1", "sha256", "sha512"]
    malware_response = load_json("test_data/cti/malware.json")
    requests_mock.post("/auth/token/verify/")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get("/cti/malware/", json=malware_response)
    client = build_zf_client()
    spy_malware = mocker.spy(client, "get_cti_malware")
    args = {"hash": hash}

    results = malicious_hash_command(client, args)

    # assert spy_malware.call_args == 0

    assert spy_malware.call_count == 4
    for hash_type_index in range(len(hash_types)):
        hash_type = hash_types[hash_type_index]
        spy_malware_hash_type_arg, spy_malware_hash_arg = \
            spy_malware.call_args_list[hash_type_index][0]
        assert spy_malware_hash_type_arg == hash_type
        assert spy_malware_hash_arg == hash
    assert len(results.outputs) == 4
    assert results.outputs_prefix == "ZeroFox.MaliciousHashes"


def test_search_exploits_command(requests_mock, mocker):
    """
    Given
        There is a date
    When
        Calling search_exploits_command
    Then
        It should call exploits endpoint
        And with since param
        And return a list with threats as output
        And with the correct output prefix
    """
    since = "2023-06-27T00:00:00Z"
    exploits_response = load_json("test_data/cti/exploits.json")
    requests_mock.post("/auth/token/verify/")
    requests_mock.post("/auth/token/", json={"access": "token"})
    requests_mock.get("/cti/exploits/", json=exploits_response)
    client = build_zf_client()
    spy_exploits = mocker.spy(client, "get_cti_exploits")
    args = {"since": since}

    results = search_exploits_command(client, args)

    spy_exploits.assert_called_once()
    since_called_arg, = spy_exploits.call_args[0]
    assert since_called_arg == since
    assert len(results.outputs) == 10
    assert results.outputs_prefix == "ZeroFox.Exploits"
