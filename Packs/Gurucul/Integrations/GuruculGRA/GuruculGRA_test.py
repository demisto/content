import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_gra_fetch_users(requests_mock):
    """Unit test
    Given
    - fetch gra users
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-users.json")
    requests_mock.get("https://test.com/api/users", json=mock_response)
    api_url = "/users"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Users", "employeeId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Users"
    assert response.outputs_key_field == "employeeId"


def test_gra_fetch_accounts(requests_mock):
    """Unit test
    Given
    - fetch gra accounts
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-accounts.json")
    requests_mock.get("https://test.com/api/accounts", json=mock_response)
    api_url = "/accounts"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_fetch_active_resource_accounts(requests_mock):
    """Unit test
    Given
    - fetch gra active resource accounts
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-active-resource-accounts.json")
    requests_mock.get("https://test.com/api/resources/Linux/accounts", json=mock_response)
    api_url = "/resources/Linux/accounts"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Active.Resource.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Active.Resource.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_fetch_user_accounts(requests_mock):
    """Unit test
    Given
    - fetch gra users accounts
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-user-accounts.json")
    requests_mock.get("https://test.com/api/users/AB1234/accounts", json=mock_response)
    api_url = "/users/AB1234/accounts"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.User.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.User.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_fetch_resource_highrisk_accounts(requests_mock):
    """Unit test
    Given
    - fetch gra resource high risk accounts
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-resource-highrisk-accounts.json")
    requests_mock.get("https://test.com/api/resources/Linux/accounts/highrisk", json=mock_response)
    api_url = "/resources/Linux/accounts/highrisk"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Resource.Highrisk.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Resource.Highrisk.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_fetch_hpa(requests_mock):
    """Unit test
    Given
    - fetch high privileged accounts
    - command args page , max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-hpa.json")
    requests_mock.get("https://test.com/api/accounts/highprivileged", json=mock_response)
    api_url = "/accounts/highprivileged"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Hpa", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Hpa"
    assert response.outputs_key_field == "id"


def test_gra_fetch_resource_hpa(requests_mock):
    """Unit test
    Given
    - fetch high privileged accounts for resource
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-resource-hpa.json")
    requests_mock.get("https://test.com/api/resources/Linux/accounts/highprivileged", json=mock_response)
    api_url = "/resources/Linux/accounts/highprivileged"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Resource.Hpa", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Resource.Hpa"
    assert response.outputs_key_field == "id"


def test_gra_fetch_orphan_accounts(requests_mock):
    """Unit test
    Given
    - fetch orphan accounts
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-orphan-accounts.json")
    requests_mock.get("https://test.com/api/accounts/orphan", json=mock_response)
    api_url = "/accounts/orphan"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Orphan.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Orphan.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_fetch_resource_orphan_accounts(requests_mock):
    """Unit test
    Given
    - fetch orphan accounts for resource
    - command args page, max, resource
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-resource-orphan-accounts.json")
    requests_mock.get("https://test.com/api/resources/Linux/accounts/orphan", json=mock_response)
    api_url = "/resources/Linux/accounts/orphan"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Resource.Orphan.Accounts", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Resource.Orphan.Accounts"
    assert response.outputs_key_field == "id"


def test_gra_user_activities(requests_mock):
    """Unit test
    Given
    - fetch gra user activities
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-user-activities.json")
    requests_mock.get("https://test.com/api/user/AB1234/activity", json=mock_response)
    api_url = "/user/AB1234/activity"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.User.Activity", "id", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.User.Activity"
    assert response.outputs_key_field == "id"


def test_fetch_gra_users_details(requests_mock):
    """Unit test
    Given
    - fetch gra user details
    - command args page, max, employeeId
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-fetch-users-details.json")
    requests_mock.get("https://test.com/api/users/AB1234", json=mock_response)
    api_url = "/users/AB1234"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.User", "employeeId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.User"
    assert response.outputs_key_field == "employeeId"


def test_gra_highRisk_users(requests_mock):
    """Unit test
    Given
    - fetch gra high risk users
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-highRisk-users.json")
    requests_mock.get("https://test.com/api/users/highrisk", json=mock_response)
    api_url = "/users/highrisk"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Highrisk.Users", "employeeId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Highrisk.Users"
    assert response.outputs_key_field == "employeeId"


def test_gra_cases(requests_mock):
    """Unit test
    Given
    - fetch gra cases as per status
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-cases.json")
    requests_mock.get("https://test.com/api/cases/OPEN", json=mock_response)
    api_url = "/cases/OPEN"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, api_url, "Gra.Cases", "caseId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Cases"
    assert response.outputs_key_field == "caseId"


def test_fetch_user_anomalies(requests_mock):
    """Unit test
    Given
    - fetch gra user anomalies
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra fetch users command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-user-anomalies.json")
    requests_mock.get("https://test.com/api/users/AB1234/anomalies/", json=mock_response)
    anomaly_url = "/users/AB1234/anomalies/"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, anomaly_url, "Gra.User.Anomalies", "anomaly_name", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.User.Anomalies"
    assert response.outputs_key_field == "anomaly_name"


def test_module(mocker):
    """
    Given
    - Gurucul GRA test application
    When
    - mock the demisto params.
    - mock the Client's generate_token
    Then
    - run the test_module command using the Client
    Validate The response is ok.
    """
    from GuruculGRA import Client, test_module_command

    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    mocker.patch.object(client, "validate_api_key")
    result = test_module_command(client)
    assert result == "ok"


def test_gra_case_action(requests_mock):
    """Unit test
    Given
    - gra case action
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra case action command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-case-action.json")
    requests_mock.get("https://test.com/api/cases/closeCase", json=mock_response)
    cases_url = "/cases/closeCase"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, cases_url, "Gra.Case.Action", "caseId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Case.Action"
    assert response.outputs_key_field == "caseId"


def test_gra_case_action_anomaly(requests_mock):
    """Unit test
    Given
    - gra case action
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra case action anomaly command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-case-action-anomaly.json")
    requests_mock.get("https://test.com/api/cases/closeCaseAnomaly", json=mock_response)
    cases_url = "/cases/closeCaseAnomaly"
    params = {"page": 1, "max": 10}
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, cases_url, "Gra.Cases.Action.Anomaly", "caseId", params)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Cases.Action.Anomaly"
    assert response.outputs_key_field == "caseId"


def test_gra_investigate_anomaly_summary(requests_mock):
    """Unit test
    Given
    - gra investigate anomaly summary
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra investigate anomaly summary command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-investigate-anomaly-summary.json")
    requests_mock.get("https://test.com/api/investigateAnomaly/anomalySummary/ModelName", json=mock_response)
    investigateAnomaly_url = "/investigateAnomaly/anomalySummary/ModelName"
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, investigateAnomaly_url, "Gra.Investigate.Anomaly.Summary", "modelId", None)
    mock_response_array = []
    mock_response_array.append(mock_response)
    assert response.outputs == mock_response_array
    assert response.outputs_prefix == "Gra.Investigate.Anomaly.Summary"
    assert response.outputs_key_field == "modelId"


def test_gra_analytical_features_entity_value(requests_mock):
    """Unit test
    Given
    - gra analytical features entity value
    - command args page, max
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the gra investigate anomaly summary command using the Client
    Validate the output with mock response
    Validate the output prefix
    Validate key field
    """
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-analytical-features-entity-value.json")
    requests_mock.get("https://test.com/api/profile/analyticalFeatures/entityValue", json=mock_response)
    investigateAnomaly_url = "/profile/analyticalFeatures/entityValue"
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, investigateAnomaly_url, "Gra.Analytical.Features.Entity.Value", "entityID", None)
    mock_response_array = []
    mock_response_array.append(mock_response)
    assert response.outputs == mock_response_array
    assert response.outputs_prefix == "Gra.Analytical.Features.Entity.Value"
    assert response.outputs_key_field == "entityID"


def test_fetch_gra_incidents_bootstrap_uses_dates(requests_mock):
    """First incident fetch uses date window and stores maxIncidentId."""
    from GuruculGRA import Client, fetch_gra_incidents

    mock_response = util_load_json("test_data/gra-incidents.json")
    requests_mock.get("https://test.com/api/incidents/opendate", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    first_fetch_time = 1600000000

    next_run, incidents = fetch_gra_incidents(client, max_results=25, last_run={}, first_fetch_time=first_fetch_time)

    assert len(incidents) == 2
    assert next_run == {"maxIncidentId": 34}
    assert "last_fetch" not in next_run
    request = requests_mock.request_history[0]
    assert "startdate" in request.qs
    assert "enddate" in request.qs
    assert "maxincidentid" not in request.qs


def test_fetch_gra_incidents_later_run_uses_max_id_only(requests_mock):
    """Subsequent incident fetch sends maxIncidentId without dates."""
    from GuruculGRA import Client, fetch_gra_incidents

    mock_response = util_load_json("test_data/gra-incidents.json")
    requests_mock.get("https://test.com/api/incidents/opendate", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_incidents(client, max_results=25, last_run={"maxIncidentId": 30}, first_fetch_time=1600000000)

    assert len(incidents) == 2
    assert next_run == {"maxIncidentId": 34}
    request = requests_mock.request_history[0]
    assert request.qs["maxincidentid"] == ["30"]
    assert "startdate" not in request.qs
    assert "enddate" not in request.qs


def test_fetch_gra_incidents_migrates_max_case_id(requests_mock):
    """Upgrade path: maxCaseId is reused as maxIncidentId when Incident cursor is missing."""
    from GuruculGRA import Client, fetch_gra_incidents

    mock_response = util_load_json("test_data/gra-incidents.json")
    requests_mock.get("https://test.com/api/incidents/opendate", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_incidents(
        client, max_results=25, last_run={"maxCaseId": 30, "last_fetch": 1600000000}, first_fetch_time=1600000000
    )

    assert len(incidents) == 2
    assert next_run == {"maxIncidentId": 34}
    request = requests_mock.request_history[0]
    assert request.qs["maxincidentid"] == ["30"]
    assert "startdate" not in request.qs
    assert "enddate" not in request.qs


def test_fetch_gra_incidents_empty_preserves_max_id(requests_mock):
    """Empty page keeps the previous maxIncidentId cursor."""
    from GuruculGRA import Client, fetch_gra_incidents

    requests_mock.get("https://test.com/api/incidents/opendate", json=[])
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_incidents(client, max_results=25, last_run={"maxIncidentId": 50}, first_fetch_time=1600000000)

    assert incidents == []
    assert next_run == {"maxIncidentId": 50}


def test_fetch_gra_alerts_bootstrap_uses_dates(requests_mock):
    """First alert fetch uses date window and stores maxAlertId."""
    from GuruculGRA import Client, fetch_gra_alerts

    mock_response = util_load_json("test_data/gra-alerts.json")
    requests_mock.get("https://test.com/api/alerts/OPEN", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_alerts(client, max_results=25, last_run={}, first_fetch_time=1600000000)

    assert len(incidents) == 1
    assert next_run == {"maxAlertId": 101}
    assert "last_fetch_alert" not in next_run
    request = requests_mock.request_history[0]
    assert "startdate" in request.qs
    assert "enddate" in request.qs
    assert "maxalertid" not in request.qs


def test_fetch_gra_alerts_later_run_uses_max_id_only(requests_mock):
    """Subsequent alert fetch sends maxAlertId without dates."""
    from GuruculGRA import Client, fetch_gra_alerts

    mock_response = util_load_json("test_data/gra-alerts.json")
    requests_mock.get("https://test.com/api/alerts/OPEN", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_alerts(client, max_results=25, last_run={"maxAlertId": 100}, first_fetch_time=1600000000)

    assert len(incidents) == 1
    assert next_run == {"maxAlertId": 101}
    request = requests_mock.request_history[0]
    assert request.qs["maxalertid"] == ["100"]
    assert "startdate" not in request.qs
    assert "enddate" not in request.qs


def test_gra_incidents(requests_mock):
    """Unit test for gra-incidents list command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-incidents.json")
    requests_mock.get("https://test.com/api/incidents/OPEN", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, "/incidents/OPEN", "Gra.Incidents", "incidentId", {"page": 1, "max": 10})
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Incidents"
    assert response.outputs_key_field == "incidentId"


def test_gra_incident_action(requests_mock):
    """Unit test for gra-incident-action POST command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-incident-action.json")
    requests_mock.post("https://test.com/api/incidents/closeIncident", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps({"incidentId": 33, "subOption": "True Incident", "incidentComment": "closed"})
    response = fetch_record_command(
        client, "/incidents/closeIncident", "Gra.Incident.Action", "incidentId", {"page": 1, "max": 10}, post_url
    )
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Incident.Action"
    assert response.outputs_key_field == "incidentId"


def test_gra_incident_action_anomaly(requests_mock):
    """Unit test for gra-incident-action-anomaly POST command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-incident-action-anomaly.json")
    requests_mock.post("https://test.com/api/incidents/closeIncidentAnomaly", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps(
        {
            "incidentId": 33,
            "anomalyNames": "anomalyName1",
            "subOption": "True Incident",
            "incidentComment": "closed",
        }
    )
    response = fetch_record_command(
        client,
        "/incidents/closeIncidentAnomaly",
        "Gra.Incident.Action.Anomaly",
        "incidentId",
        {"page": 1, "max": 10},
        post_url,
    )
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Incident.Action.Anomaly"
    assert response.outputs_key_field == "incidentId"


def test_gra_incidents_anomaly(requests_mock):
    """Unit test for gra-incidents-anomaly list command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-incidents-anomaly.json")
    requests_mock.get("https://test.com/api/anomalies/33", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, "/anomalies/33", "Gra.Incidents.anomalies", "incidentId", {"page": 1, "max": 10})
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Incidents.anomalies"
    assert response.outputs_key_field == "incidentId"


def test_gra_alerts(requests_mock):
    """Unit test for gra-alerts list command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alerts.json")
    requests_mock.get("https://test.com/api/alerts/OPEN", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, "/alerts/OPEN", "Gra.Alerts", "alertId", {"page": 1, "max": 10})
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alerts"
    assert response.outputs_key_field == "alertId"


def test_gra_alert_get(requests_mock):
    """Unit test for gra-alert-get command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alert-get.json")
    requests_mock.get("https://test.com/api/alerts/getAlert", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, "/alerts/getAlert", "Gra.Alert", "alertId", {"id": 101})
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert"
    assert response.outputs_key_field == "alertId"


def test_gra_alert_action(requests_mock):
    """Unit test for gra-alert-action POST command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alert-action.json")
    requests_mock.post("https://test.com/api/alerts/closeAlert", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps(
        {
            "alertId": 101,
            "alertComment": "closed",
            "incidentType": "Incident",
            "subStatus": "True Positive",
        }
    )
    response = fetch_record_command(client, "/alerts/closeAlert", "Gra.Alert.Action", "alertId", {"page": 1, "max": 10}, post_url)
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert.Action"
    assert response.outputs_key_field == "alertId"


def test_gra_alert_comment(requests_mock):
    """Unit test for gra-alert-comment thin wrapper POST path."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alert-action.json")
    requests_mock.post("https://test.com/api/alerts/addCommentOnAlert", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps({"alertId": 101, "alertComment": "note"})
    response = fetch_record_command(
        client, "/alerts/addCommentOnAlert", "Gra.Alert.Action", "alertId", {"page": 1, "max": 10}, post_url
    )
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert.Action"
    assert response.outputs_key_field == "alertId"


def test_fetch_gra_alerts_empty_preserves_max_id(requests_mock):
    """Empty alert page keeps the previous maxAlertId cursor."""
    from GuruculGRA import Client, fetch_gra_alerts

    requests_mock.get("https://test.com/api/alerts/OPEN", json=[])
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_gra_alerts(client, max_results=25, last_run={"maxAlertId": 100}, first_fetch_time=1600000000)

    assert incidents == []
    assert next_run == {"maxAlertId": 100}


def test_fetch_incidents_routes_to_alerts(requests_mock):
    """fetch_incidents with fetch_type=Alerts uses the alert fetch path."""
    from GuruculGRA import Client, fetch_incidents

    mock_response = util_load_json("test_data/gra-alerts.json")
    requests_mock.get("https://test.com/api/alerts/OPEN", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=25,
        last_run={},
        first_fetch_time=1600000000,
        fetch_type="Alerts",
    )

    assert len(incidents) == 1
    assert next_run == {"maxAlertId": 101}


def test_gra_alert_assign(requests_mock):
    """Unit test for gra-alert-assign POST command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alert-action.json")
    requests_mock.post("https://test.com/api/alerts/assignAlert", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps(
        {
            "alertId": 101,
            "alertComment": "assigned",
            "assigneeType": "GRA_USER",
            "assigneeName": "analyst1",
        }
    )
    response = fetch_record_command(
        client, "/alerts/assignAlert", "Gra.Alert.Action", "alertId", {"page": 1, "max": 10}, post_url
    )
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert.Action"
    assert response.outputs_key_field == "alertId"


def test_gra_alert_in_progress(requests_mock):
    """Unit test for gra-alert-in-progress POST command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = util_load_json("test_data/gra-alert-action.json")
    requests_mock.post("https://test.com/api/alerts/inProgressAlert", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    post_url = json.dumps({"alertId": 101, "alertComment": "working"})
    response = fetch_record_command(
        client, "/alerts/inProgressAlert", "Gra.Alert.Action", "alertId", {"page": 1, "max": 10}, post_url
    )
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert.Action"
    assert response.outputs_key_field == "alertId"


def test_gra_alert_update_history(requests_mock):
    """Unit test for gra-alert-update-history command."""
    from GuruculGRA import Client, fetch_record_command

    mock_response = [{"alertDetails": [{"actionName": "Comment", "comment": "note", "addedDate": "2026-07-12T08:15:00"}]}]
    requests_mock.get("https://test.com/api/alerts/getAlertUpdateHistory", json=mock_response)
    client = Client(base_url="https://test.com/api", verify=False, headers={"Authentication": "Bearer some_api_key"})
    response = fetch_record_command(client, "/alerts/getAlertUpdateHistory", "Gra.Alert.History", "alertId", {"alertId": 101})
    assert response.outputs == mock_response
    assert response.outputs_prefix == "Gra.Alert.History"
    assert response.outputs_key_field == "alertId"
