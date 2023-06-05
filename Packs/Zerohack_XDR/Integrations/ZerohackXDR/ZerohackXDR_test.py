# Tests verified with pytest -vv as demisto-sdk didnt work.
# Test records are present in the test_data directory.
# Kept here for future reference.

# Coverage
# --------
# There should be at least one unit test per command function. In each unit
# test, the target command function is executed with specific parameters and the
# output of the command function is checked against an expected output.
# Unit tests should be self contained and should not interact with external
# resources like (API, devices, ...). To isolate the code from external resources
# you need to mock the API of the external resource using pytest-mock:
# https://github.com/pytest-dev/pytest-mock/
# In the following code we configure requests-mock (a mock of Python requests)
# before each test to simulate the API calls to the HelloWorld API. This way we
# can have full control of the API behavior and focus only on testing the logic
# inside the integration code.
# We recommend to use outputs from the API calls and use them to compare the
# results when possible. See the ``test_data`` directory that contains the data
# we use for comparison, in order to reduce the complexity of the unit tests and
# avoding to manually mock all the fields.
# NOTE: we do not have to import or build a requests-mock instance explicitly.
# requests-mock library uses a pytest specific mechanism to provide a
# requests_mock instance to any function with an argument named requests_mock.

# Note: The test module function has not been added to these set of tests as it is only used for checking if the
#       connection with Zerohack XDR is working correctly.
import json


def util_load_json(path):
    with open(path, "r") as file:
        text = file.read()
        return json.loads(text)


def test_get_latest_incident(requests_mock):
    from ZerohackXDR import Client, get_latest_incident
    from ZerohackXDR import ZEROHACK_XDR_API_BASE_URL

    # Initialising the client.
    client = Client(
        base_url=ZEROHACK_XDR_API_BASE_URL,
        verify=False,
        api_key="Some Random Key",
        proxy=False,
    )

    mock_response = util_load_json("test_data/get_latest_incident.json")

    requests_mock.register_uri(
        "GET", f"{ZEROHACK_XDR_API_BASE_URL}/xdr-api", json=mock_response
    )
    incident = get_latest_incident(client, severity_level=4)
    assert isinstance(incident, dict)


def test_fetch_incidents(requests_mock):
    from ZerohackXDR import Client, fetch_incidents
    from ZerohackXDR import ZEROHACK_XDR_API_BASE_URL
    from ZerohackXDR import ZEROHACK_SEVERITIES

    # Initialising the client.
    client = Client(
        base_url=ZEROHACK_XDR_API_BASE_URL,
        verify=False,
        api_key="Some Random Key",
        proxy=False,
    )
    min_severity = "4"
    severity_levels = ZEROHACK_SEVERITIES[ZEROHACK_SEVERITIES.index(min_severity):]
    max_results_per_severity = 10
    mock_responses = util_load_json("test_data/fetch_incidents.json")

    responses_list = []
    for response in mock_responses:
        responses_list.append({"text": json.dumps(response)})

    last_run = {"last_fetch": 1662120898}

    requests_mock.register_uri(
        "GET", f"{ZEROHACK_XDR_API_BASE_URL}/xdr-api", responses_list
    )

    next_run, incidents = fetch_incidents(
        client=client,
        max_results=max_results_per_severity,
        min_severity=min_severity,
        last_run=last_run,
        first_fetch="1 day",
    )
    # Type checks.
    assert isinstance(next_run, dict)
    assert isinstance(incidents, list)
    # Bound checks.
    assert len(incidents) <= max_results_per_severity * len(severity_levels)


def test_convert_to_demisto_severity():
    from ZerohackXDR import convert_to_demisto_severity
    severity_level = convert_to_demisto_severity("3.0")
    assert isinstance(severity_level, int)
    assert severity_level == 2

    severity_level = convert_to_demisto_severity("4.0")
    assert isinstance(severity_level, float)
    assert severity_level == 0.5

    severity_level = convert_to_demisto_severity("2.0")
    assert isinstance(severity_level, int)
    assert severity_level == 3

    severity_level = convert_to_demisto_severity("1.0")
    assert isinstance(severity_level, int)
    assert severity_level == 4


def test_main():
    from ZerohackXDR import main

    output = main()

    assert isinstance(output, type(None))


def test_test_module(requests_mock):
    from ZerohackXDR import Client, test_module
    from ZerohackXDR import ZEROHACK_XDR_API_BASE_URL

    # Initialising the client.
    client = Client(
        base_url=ZEROHACK_XDR_API_BASE_URL,
        verify=False,
        api_key="Some Random Key",
        proxy=False,
    )

    mock_response = util_load_json("test_data/get_latest_incident.json")

    requests_mock.register_uri(
        "GET", f"{ZEROHACK_XDR_API_BASE_URL}/xdr-api", json=mock_response
    )
    assert test_module(client) == 'ok'
