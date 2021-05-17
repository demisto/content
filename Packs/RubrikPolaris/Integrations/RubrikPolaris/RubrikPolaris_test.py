import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_test_module(requests_mock):
    """Tests the test_module validation command.

    Checks the mock_response for a "access_key" token which
    will result in the return value of "ok"
    """
    from RubrikPolaris import Client, test_module

    client = Client(
        base_url="http://xsoar.my.rubrik.com",
        headers={},
        verify=False
    )

    mock_response = {
        "access_token": "xsoar",
        "password": "password",
    }
    requests_mock.post('http://xsoar.my.rubrik.com/session', json=mock_response)

    response = test_module(client)

    assert response == 'ok'


def test_test_module_incorrect_polaris_account(requests_mock):
    """Tests the test_module validation command error messages.

    Checks the error message returned when Xsoar can not connect to the
    provided Rubrik Polaris account and verifies the expected human friendly
    error message is returned.
    """
    from RubrikPolaris import Client, test_module, DemistoException

    client = Client(
        base_url="http://xsoar.my.rubrik.com",
        headers={},
        verify=False
    )

    requests_mock.post('http://xsoar.my.rubrik.com/session', exc=DemistoException(
        "Verify that the server URL parameter is correct and that you have\
         access to the server from your host.", None))

    assert test_module(
        client) == """We were unable to connect to the provided Polaris Account. Verify it has been entered correctly."""


def test_test_module_incorrect_polaris_credentials(requests_mock):
    """Tests the test_module validation command error messages.

    Checks the error message returned when an incorrect username or password
    for Rubrik Polaris has been provided and verifies the expected human
    friendly error message is returned.
    """
    from RubrikPolaris import Client, test_module, DemistoException

    client = Client(
        base_url="http://xsoar.my.rubrik.com",
        headers={},
        verify=False
    )

    requests_mock.post('http://xsoar.my.rubrik.com/session', exc=DemistoException("Error in API call [401] - Unauthorized", None))

    assert test_module(client) == "Incorrect email address or password."


def test_fetch_incidents(mocker, requests_mock):
    """Tests the fetch_incidents command.

    Checks the mock_response for a "access_key" token which
    will result in the return value of "ok"
    """
    from RubrikPolaris import Client, fetch_incidents
    import demistomock as demisto
    from datetime import datetime, timedelta

    client = Client(
        base_url="http://xsoar.my.rubrik.com",
        headers={},
        verify=False
    )
    date_time_format = "%Y-%m-%dT%H:%M:%S.000Z"

    last_fetch = (datetime.now() - timedelta(minutes=6)).strftime(date_time_format)

    mocker.patch.object(demisto, 'getLastRun', return_value={'last_fetch': last_fetch})
    # Mock the get_api_token() helper function
    requests_mock.post('http://xsoar.my.rubrik.com/session', json={"access_token": "xsoar"})
    # Mock the GraphQL call
    # radar_event.json is example out from the API
    requests_mock.post('http://xsoar.my.rubrik.com/graphql', json=util_load_json("test_data/radar_event.json"))
    # The fetch_incidents function processing the data returned by the API and
    # returns a simplied version
    mock_incident = util_load_json("test_data/processed_radar_event.json")

    current_time, response = fetch_incidents(client, 200)
    mock_response = [{
        "name": f'Rubrik Radar Anomaly - {mock_incident["objectName"]}',
        "occurred": current_time,
        "rawJSON": json.dumps(mock_incident)
    }]

    assert response == mock_response
