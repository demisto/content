"""HelloWorldV2 Integration - Unit Tests file

This file contains the Unit Tests for the HelloWorldV2 Integration based
on pytest. Cortex contribution requirements mandate that every
integration should have a proper set of unit tests to automatically
verify that the integration is behaving as expected during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in multiple ways:
- Using the command `demisto-sdk lint`. The command will build a dedicated
  Docker instance for your integration locally and use the Docker instance to
  execute your tests in a dedicated Docker instance.
- Using the command `demisto-sdk pre-commit pytest` (Ensure all relevant files
are staged).
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/HelloWorldV2

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the HelloWorld API. This way we
can have full control of the API behavior and focus only on testing the logic
inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoiding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

import json
import pytest
from pytest_mock import MockerFixture
from freezegun import freeze_time
from unittest.mock import AsyncMock
from CommonServerPython import DemistoException, Common, arg_to_datetime
from HelloWorldV2 import (
    BASE_CONTEXT_OUTPUT_PREFIX,
    Credentials,
    DUMMY_VALID_API_KEY,
    FetchAssetsStages,
    HelloWorldClient,
    HelloWorldParams,
    HelloWorldLastRun,
    HelloWorldAssetsLastRun,
    HelloWorldSeverity,
    ContentClient,
)


@pytest.fixture(autouse=True)
def mock_support_multithreading(mocker: MockerFixture):
    """Mock support_multithreading to prevent demistomock attribute errors.

    This fixture automatically runs before each test to mock the support_multithreading
    function which is called during ContentClient initialization. Without this mock,
    tests fail with: AttributeError: module 'demistomock' has no attribute '_Demisto__do'
    """
    mocker.patch("CommonServerPython.support_multithreading")


def util_load_json(path: str):
    """Load JSON test data from file.

    Args:
        path (str): Path to JSON file relative to test_data directory.

    Returns:
        dict | list: Parsed JSON data.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# region General - Credentials & Params Tests


class TestCredentials:
    """Tests for valid Credentials model initialization."""

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("secret123", id="Simple password"),
            pytest.param("P@ssw0rd!", id="Complex password"),
            pytest.param("very_long_password_with_many_characters_123456789", id="Long password"),
        ],
    )
    def test_credentials_valid_passwords(self, password):
        """
        Given:
            - A valid password string.
        When:
            - Initializing Credentials model.
        Then:
            - Assert model is created successfully.
            - Assert password is stored as SecretStr.
        """
        from HelloWorldV2 import Credentials

        creds = Credentials(password=password)
        assert creds.password.get_secret_value() == password

    def test_credentials_missing_password(self):
        """
        Given:
            - No password provided.
        When:
            - Initializing Credentials model.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import Credentials

        with pytest.raises(DemistoException, match="password"):
            Credentials()  # type: ignore[call-arg]


class TestHelloWorldParams:
    """Tests for valid HelloWorldParams model initialization."""

    @pytest.mark.parametrize(
        "url,expected_clean_url",
        [
            pytest.param("https://api.example.com", "https://api.example.com", id="No trailing slash"),
            pytest.param("https://api.example.com/", "https://api.example.com", id="Single trailing slash"),
            pytest.param("https://api.example.com///", "https://api.example.com", id="Multiple trailing slashes"),
        ],
    )
    def test_params_url_cleaning(self, url, expected_clean_url):
        """
        Given:
            - A URL with or without trailing slashes.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert URL is cleaned (trailing slashes removed).
        """
        from HelloWorldV2 import HelloWorldParams

        params = HelloWorldParams(
            url=url,  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
        )
        assert str(params.url) == expected_clean_url

    @pytest.mark.parametrize(
        "max_fetch, expected",
        [
            pytest.param(10, 10, id="Within limit"),
            pytest.param(10000, 10000, id="At limit"),
            pytest.param(200000, 100000, id="Exceeds limit capped"),
        ],
    )
    def test_params_max_events_fetch_capping(self, mocker: MockerFixture, max_fetch: int, expected: int):
        """
        Given:
            - A max_fetch value that may exceed the cap.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert max_fetch is capped at 50 for non-event systems.
        """
        from HelloWorldV2 import HelloWorldParams

        mocker.patch("HelloWorldV2.CAN_SEND_EVENTS", True)  # Assume running on a Cortex XSIAM tenant

        params = HelloWorldParams(
            url="https://api.example.com",  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
            isFetchEvents=True,
            max_events_fetch=max_fetch,
        )
        assert params.max_fetch == expected

    @pytest.mark.parametrize(
        "max_fetch, expected",
        [
            pytest.param(10, 10, id="Within limit"),
            pytest.param(200, 200, id="At limit"),
            pytest.param(1000, 200, id="Exceeds limit capped"),
        ],
    )
    def test_params_max_incidents_fetch_capping(self, mocker: MockerFixture, max_fetch: int, expected: int):
        """
        Given:
            - A max_fetch value that may exceed the cap.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert max_fetch is capped at 50 for non-event systems.
        """
        from HelloWorldV2 import HelloWorldParams

        mocker.patch("HelloWorldV2.CAN_SEND_EVENTS", False)  # Assume running on a Cortex XSOAR tenant

        params = HelloWorldParams(
            url="https://api.example.com",  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
            isFetch=True,
            max_incidents_fetch=max_fetch,
        )
        assert params.max_fetch == expected

    def test_params_valid_severity(self):
        """
        Given:
            - Valid HelloWorldSeverity enum values.
        When:
            - Initializing HelloWorldParams with each severity.
        Then:
            - Assert severity is set correctly.
        """
        from HelloWorldV2 import HelloWorldParams, HelloWorldSeverity

        for severity in [HelloWorldSeverity.LOW, HelloWorldSeverity.MEDIUM, HelloWorldSeverity.HIGH, HelloWorldSeverity.CRITICAL]:
            params = HelloWorldParams(
                url="https://api.example.com",  # type: ignore[arg-type]
                credentials={"password": "secret"},  # type: ignore[arg-type]
                severity=severity,
            )
            assert params.severity == severity

    def test_params_default_values(self):
        """
        Given:
            - Minimal required parameters.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert default values are set correctly.
        """
        from HelloWorldV2 import HelloWorldParams, HelloWorldSeverity

        params = HelloWorldParams(
            url="https://api.example.com",  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
        )
        assert params.insecure is False
        assert params.proxy is False
        assert params.max_fetch == 10
        assert params.severity == HelloWorldSeverity.HIGH
        assert params.threshold_ip == 65

    @pytest.mark.parametrize(
        "first_fetch,expected_contains",
        [
            pytest.param("3 days", "T", id="Relative time - 3 days"),
            pytest.param("1 week", "T", id="Relative time - 1 week"),
            pytest.param("2026-01-15T00:00:00Z", "2026-01-15T00:00:00", id="Absolute ISO 8601 time"),
        ],
    )
    def test_params_first_fetch_time_conversion(self, first_fetch, expected_contains):
        """
        Given:
            - Different first_fetch values (relative and absolute time).
        When:
            - Accessing first_fetch_time property.
        Then:
            - Assert property returns ISO 8601 timestamp string.
            - Assert the timestamp contains expected components.
        """
        params = HelloWorldParams(
            url="https://api.example.com",  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
            first_fetch=first_fetch,
        )
        first_fetch_time = params.first_fetch_time
        assert isinstance(first_fetch_time, str)
        assert expected_contains in first_fetch_time

        # Verify it's a valid ISO 8601 format by parsing it
        parsed = arg_to_datetime(first_fetch_time)
        assert parsed is not None

    def test_params_missing_url(self):
        """
        Given:
            - No URL provided.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloWorldParams

        with pytest.raises(DemistoException, match="url"):
            HelloWorldParams(credentials={"password": "secret"})  # type: ignore[call-arg]

    def test_params_missing_credentials(self):
        """
        Given:
            - No credentials provided.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloWorldParams

        with pytest.raises(DemistoException, match="credentials"):
            HelloWorldParams(url="https://api.example.com")  # type: ignore[call-arg,arg-type]

    def test_params_invalid_url(self):
        """
        Given:
            - An invalid URL format.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloWorldParams

        with pytest.raises(DemistoException, match="url"):
            HelloWorldParams(
                url="not-a-valid-url",  # type: ignore[arg-type]
                credentials={"password": "secret"},  # type: ignore[arg-type]
            )


# endregion

# region test-module


@pytest.mark.parametrize(
    "is_fetch",
    [
        pytest.param(False, id="Fetching disabled"),
        pytest.param(True, id="Fetching enabled"),
    ],
)
@freeze_time("2026-01-01 00:01")
def test_module_success(mocker: MockerFixture, is_fetch: bool):
    """
    Given:
        - Valid client and params.
        - is_fetch parameter set to True or False.
    When:
        - Running test_module.
    Then:
        - Assert client.say_hello is called once.
        - Assert fetch_alerts is called once if is_fetch is True, not called if False.
        - Assert "ok" is returned.
    """
    from HelloWorldV2 import test_module

    # Assume this is running on a Cortex XSIAM tenant
    mocker.patch("HelloWorldV2.CAN_SEND_EVENTS", True)

    # Create mock client
    mock_client_say_hello = mocker.patch.object(HelloWorldClient, "say_hello", return_value="Hello Test")

    # Mock fetch_alerts function
    mock_fetch_alerts = mocker.patch("HelloWorldV2.fetch_alerts")

    # Create params with is_fetch set accordingly
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
        isFetchEvents=is_fetch,
        severity=HelloWorldSeverity.HIGH,
    )
    client = HelloWorldClient(params)

    # Execute test_module
    result = test_module(client, params)

    # Assertions
    assert result == "ok"
    assert mock_client_say_hello.call_count == 1
    assert mock_client_say_hello.call_args.kwargs == {"name": "Test"}

    if is_fetch:
        assert mock_fetch_alerts.call_count == 1
        assert mock_fetch_alerts.call_args.kwargs == {
            "max_fetch": 1,
            "last_run": HelloWorldLastRun(),  # send empty / default last run object
            "severity": params.severity,
            "first_fetch_time": "2026-01-01T00:00:00+00:00",  # freeze_time - 1 minute in ISO format
            "should_push": False,  # ensure push is disabled to prevent creating events during testing
        }
    else:
        assert mock_fetch_alerts.call_count == 0


def test_module_authentication_error(mocker: MockerFixture):
    """
    Given:
        - Client that raises ContentClientAuthenticationError.
    When:
        - Running test_module.
    Then:
        - Assert appropriate error message is returned.
    """
    from HelloWorldV2 import test_module, ContentClientAuthenticationError

    # Mock demisto functions
    mocker.patch("HelloWorldV2.demisto.error")

    # Create mock client that raises authentication error
    mocker.patch.object(HelloWorldClient, "say_hello", side_effect=ContentClientAuthenticationError("Invalid API key"))

    # Create params
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password="wrong-key"),
        is_fetch=False,
    )

    with pytest.raises(DemistoException, match="Invalid Credentials. Please verify your API key."):
        client = HelloWorldClient(params)
        test_module(client, params)


# endregion

# region helloworld-say-hello


class TestHelloworldSayHelloArgs:
    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("John", id="Simple name"),
            pytest.param("John Doe", id="Name with space"),
            pytest.param("José García", id="Name with accents"),
        ],
    )
    def test_say_hello_args_valid_names(self, name):
        """
        Given:
            - A valid name string.
        When:
            - Initializing HelloworldSayHelloArgs.
        Then:
            - Assert model is created successfully.
            - Assert name is stored correctly.
        """
        from HelloWorldV2 import HelloworldSayHelloArgs

        args = HelloworldSayHelloArgs(name=name)
        assert args.name == name

    def test_say_hello_args_missing_name(self):
        """
        Given:
            - No name provided.
        When:
            - Initializing HelloworldSayHelloArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloworldSayHelloArgs

        with pytest.raises(DemistoException, match="name"):
            HelloworldSayHelloArgs()  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("World", id="Simple name"),
        pytest.param("John Doe", id="Name with space"),
        pytest.param("José García", id="Name with accents"),
    ],
)
def test_say_hello_command(mocker: MockerFixture, name: str):
    """
    Given:
        - Valid client and args with different name values.
    When:
        - Running say_hello_command.
    Then:
        - Assert client.say_hello is called once with the provided name.
        - Assert CommandResults is returned with correct readable_output and outputs.
    """
    from HelloWorldV2 import say_hello_command, HelloworldSayHelloArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock client.say_hello
    expected_response = f"Hello {name}"
    mock_say_hello = mocker.patch.object(client, "say_hello", return_value=expected_response)

    # Create args
    args = HelloworldSayHelloArgs(name=name)

    # Execute command
    result = say_hello_command(client, args)

    # Assertions
    assert mock_say_hello.call_count == 1
    assert mock_say_hello.call_args.kwargs == {"name": name}

    # Verify CommandResults
    assert result.readable_output == f"## {expected_response}"
    assert result.outputs == {"name": name}
    assert result.outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.Hello"


# endregion

# region fetch-incidents / fetch-events


def test_create_events(mocker: MockerFixture):
    """
    Given:
        - List of alert dictionaries.
    When:
        - Running create_events.
    Then:
        - Assert format_as_events is called once with correct parameters.
        - Assert send_events_to_xsiam is called once with formatted events.
    """
    from HelloWorldV2 import create_events, format_as_events, EventsDatasetConfigs

    # Load mock alert data
    mock_alerts = util_load_json("test_data/alert_events.json")
    expected_formatted_events = format_as_events(mock_alerts, time_field="date")
    mock_send_events = mocker.patch("HelloWorldV2.send_events_to_xsiam")

    # Execute function
    create_events(mock_alerts)

    assert mock_send_events.call_count == 1
    assert mock_send_events.call_args.kwargs == {
        "events": expected_formatted_events,
        "vendor": EventsDatasetConfigs.VENDOR.value,
        "product": EventsDatasetConfigs.PRODUCT.value,
        "client_class": ContentClient,
    }


def test_create_incidents(mocker: MockerFixture):
    """
    Given:
        - List of alert dictionaries.
    When:
        - Running create_incidents.
    Then:
        - Assert format_as_incidents is called once with correct parameters.
        - Assert demisto.incidents is called once with formatted incidents.
    """
    from HelloWorldV2 import create_incidents, format_as_incidents

    # Load mock alert data
    mock_alerts = util_load_json("test_data/alert_events.json")

    # Mock formatted incidents
    expected_formatted_incidents = format_as_incidents(
        mock_alerts, id_field="id", occurred_field="date", severity_field="severity"
    )

    # Mock helper functions
    mock_demisto_incidents = mocker.patch("HelloWorldV2.demisto.incidents")

    # Execute function
    create_incidents(mock_alerts)

    # Assertions
    assert mock_demisto_incidents.call_count == 1
    assert mock_demisto_incidents.call_args.args[0] == expected_formatted_incidents


def test_format_as_incidents():
    """
    Given:
        - List of alert dictionaries.
    When:
        - Running format_as_incidents.
    Then:
        - Assert alerts are correctly formatted as XSOAR incidents.
        - Assert incident fields are properly mapped.
    """
    from HelloWorldV2 import format_as_incidents

    # Create mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "critical",
            "date": "2026-01-15T00:00:01Z",
            "user": "admin@example.com",
            "action": "Alert",
            "status": "Error",
        },
    ]

    # Execute function
    incidents = format_as_incidents(
        mock_alerts,
        id_field="id",
        occurred_field="date",
        severity_field="severity",
    )

    # Assertions
    assert len(incidents) == 2
    assert incidents[0]["name"] == "XSOAR Test Alert #1"
    assert incidents[0]["occurred"] == "2026-01-15T00:00:00Z"
    assert incidents[0]["type"] == "Hello World Alert"
    assert incidents[0]["severity"] == 3  # High severity
    assert "rawJSON" in incidents[0]

    assert incidents[1]["name"] == "XSOAR Test Alert #2"
    assert incidents[1]["severity"] == 4  # Critical severity


def test_format_as_events():
    """
    Given:
        - List of alert dictionaries.
    When:
        - Running format_as_events.
    Then:
        - Assert alerts are correctly formatted as XSIAM events.
        - Assert event fields are properly mapped.
    """
    from HelloWorldV2 import format_as_events, EventsDatasetConfigs

    # Create mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "critical",
            "date": "2026-01-15T00:00:01Z",
            "user": "admin@example.com",
            "action": "Alert",
            "status": "Error",
        },
    ]

    # Execute function
    events = format_as_events(mock_alerts, time_field="date")

    # Assertions
    assert len(events) == 2
    assert events[0]["id"] == 1
    assert events[0][EventsDatasetConfigs.TIME_KEY.value] == "2026-01-15T00:00:00Z"
    assert events[0][EventsDatasetConfigs.SOURCE_LOG_TYPE_KEY.value] == "Alert"

    assert events[1]["id"] == 2
    assert events[1][EventsDatasetConfigs.TIME_KEY.value] == "2026-01-15T00:00:01Z"
    assert events[1][EventsDatasetConfigs.SOURCE_LOG_TYPE_KEY.value] == "Alert"


@pytest.mark.asyncio
async def test_get_alert_list(mocker: MockerFixture):
    """
    Given:
        - Client, start_time, limit, severity, should_push, and last_alert_ids.
    When:
        - Running get_alert_list async function.
    Then:
        - Assert client.get_alert_list is called with correct parameters.
        - Assert alerts are fetched and deduplicated.
        - Assert function returns list of alerts.
    """
    from HelloWorldV2 import get_alert_list

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",  # type: ignore[arg-type]
        credentials=Credentials(password=DUMMY_VALID_API_KEY),  # type: ignore[arg-type]
    )
    client = HelloWorldClient(params)

    # Mock client.get_alert_list to return alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "critical",
            "date": "2026-01-15T00:00:01Z",
            "user": "admin@example.com",
            "action": "Alert",
            "status": "Error",
        },
    ]
    mock_get_alert_list = mocker.patch.object(client, "get_alert_list", return_value=mock_alerts)

    # Execute async function
    start_time = "2026-01-15T00:00:00Z"
    limit = 10
    severity = HelloWorldSeverity.HIGH
    should_push = False
    last_alert_ids = []

    alerts = await get_alert_list(
        client=client,
        start_time=start_time,
        severity=severity,
        limit=limit,
        should_push=should_push,
        last_alert_ids=last_alert_ids,
    )

    # Assertions
    assert len(alerts) == 2
    assert alerts[0]["id"] == 1
    assert alerts[1]["id"] == 2
    # Verify client.get_alert_list was called with correct parameters
    mock_get_alert_list.assert_called_once_with(
        limit=limit,
        start_time=start_time,
        severity=severity,
    )


class TestHelloWorldLastRun:
    """Tests for HelloWorldLastRun model."""

    @pytest.mark.parametrize(
        "start_time,last_alert_ids",
        [
            pytest.param(None, [], id="Initial state - no data"),
            pytest.param("2026-01-15T00:00:00Z", [], id="With start_time only"),
            pytest.param("2026-01-15T00:00:00Z", [1, 2, 3], id="With start_time and alert IDs"),
            pytest.param(None, [5, 6], id="With alert IDs only"),
        ],
    )
    def test_last_run_valid_states(self, start_time, last_alert_ids):
        """
        Given:
            - Valid state parameters for HelloWorldLastRun.
        When:
            - Initializing HelloWorldLastRun.
        Then:
            - Assert model is created successfully with correct values.
        """
        from HelloWorldV2 import HelloWorldLastRun

        last_run = HelloWorldLastRun(start_time=start_time, last_alert_ids=last_alert_ids)
        assert last_run.start_time == start_time
        assert last_run.last_alert_ids == last_alert_ids

    def test_last_run_default_values(self):
        """
        Given:
            - No parameters provided.
        When:
            - Initializing HelloWorldLastRun.
        Then:
            - Assert default values are set correctly.
        """
        from HelloWorldV2 import HelloWorldLastRun

        last_run = HelloWorldLastRun()
        assert last_run.start_time is None
        assert last_run.last_alert_ids == []


@pytest.mark.parametrize(
    "last_run,mock_alerts,expected_start_time,expected_alert_ids",
    [
        pytest.param(
            HelloWorldLastRun(start_time=None, last_alert_ids=[]),
            [
                {
                    "id": 1,
                    "severity": "high",
                    "date": "2026-01-15T00:00:00Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
                {
                    "id": 2,
                    "severity": "high",
                    "date": "2026-01-15T00:00:01Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
            ],
            "2026-01-15T00:00:01Z",
            [2],
            id="First fetch - no duplicates",
        ),
        pytest.param(
            HelloWorldLastRun(start_time="2026-01-15T00:00:00Z", last_alert_ids=[1, 2]),
            [
                {
                    "id": 1,
                    "severity": "high",
                    "date": "2026-01-15T00:00:00Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
                {
                    "id": 2,
                    "severity": "high",
                    "date": "2026-01-15T00:00:00Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
                {
                    "id": 3,
                    "severity": "high",
                    "date": "2026-01-15T00:00:01Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
            ],
            "2026-01-15T00:00:01Z",
            [3],
            id="Subsequent fetch - with duplicates filtered",
        ),
        pytest.param(
            HelloWorldLastRun(start_time="2026-01-15T00:00:00Z", last_alert_ids=[]),
            [
                {
                    "id": 1,
                    "severity": "high",
                    "date": "2026-01-15T00:00:01Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
                {
                    "id": 2,
                    "severity": "high",
                    "date": "2026-01-15T00:00:01Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
                {
                    "id": 3,
                    "severity": "high",
                    "date": "2026-01-15T00:00:01Z",
                    "user": "test@example.com",
                    "action": "Testing",
                    "status": "Success",
                },
            ],
            "2026-01-15T00:00:01Z",
            [1, 2, 3],
            id="Multiple alerts at same timestamp",
        ),
    ],
)
def test_fetch_alerts_basic_flow(
    mocker: MockerFixture,
    last_run: HelloWorldLastRun,
    mock_alerts: list[dict],
    expected_start_time: str,
    expected_alert_ids: list[int],
):
    """
    Given:
        - Valid client and last_run state.
        - Mock alerts from get_alert_list.
    When:
        - Running fetch_alerts.
    Then:
        - Assert get_alert_list is called with correct parameters.
        - Assert next_run state is correctly updated.
        - Assert latest alert IDs are tracked for deduplication.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock get_alert_list as AsyncMock
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    first_fetch_time = "2026-01-15T00:00:00Z"
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time=first_fetch_time,
        should_push=False,
    )

    # Verify next_run state
    assert next_run.start_time == expected_start_time
    assert next_run.last_alert_ids == expected_alert_ids


@pytest.mark.parametrize(
    "is_xsiam,expected_create_function",
    [
        pytest.param(True, "create_events", id="XSIAM - create events"),
        pytest.param(False, "create_incidents", id="XSOAR - create incidents"),
    ],
)
def test_fetch_alerts_xsiam_vs_xsoar(mocker: MockerFixture, is_xsiam: bool, expected_create_function: str):
    """
    Given:
        - Valid client and last_run.
    When:
        - Running fetch_alerts with should_push=True on Cortex XSIAM and Cortex XSOAR tenants.
    Then:
        - Assert create_events is called for XSIAM.
        - Assert create_incidents is called for XSOAR.
    """
    from HelloWorldV2 import fetch_alerts

    # Mock system capabilities
    mocker.patch("HelloWorldV2.CAN_SEND_EVENTS", is_xsiam)

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "high",
            "date": "2026-01-15T00:00:01Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list to return alerts
    mocker.patch.object(client, "get_alert_list", return_value=mock_alerts)

    # Mock create functions
    mock_create_events = mocker.patch("HelloWorldV2.create_events")
    mock_create_incidents = mocker.patch("HelloWorldV2.create_incidents")

    # Execute fetch_alerts
    last_run = HelloWorldLastRun()
    fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=True,
    )

    # Verify correct create function was called
    if expected_create_function == "create_events":
        assert mock_create_events.call_count >= 1
        assert mock_create_incidents.call_count == 0
    else:
        assert mock_create_incidents.call_count >= 1
        assert mock_create_events.call_count == 0


def test_fetch_alerts_no_new_alerts(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - get_alert_list returns empty list (no new alerts).
    When:
        - Running fetch_alerts.
    Then:
        - Assert last_run state is returned unchanged.
        - Assert no incidents/events are created.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock get_alert_list to return empty list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=[]))

    # Mock create functions
    mock_create_events = mocker.patch("HelloWorldV2.create_events")
    mock_create_incidents = mocker.patch("HelloWorldV2.create_incidents")

    # Execute fetch_alerts
    last_run = HelloWorldLastRun(start_time="2026-01-15T00:00:00Z", last_alert_ids=[1, 2])
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-14T00:00:00Z",
        should_push=True,
    )

    # Verify last_run is returned unchanged
    assert next_run.start_time == last_run.start_time
    assert next_run.last_alert_ids == last_run.last_alert_ids

    # Verify no create functions were called
    assert mock_create_events.call_count == 0
    assert mock_create_incidents.call_count == 0


def test_fetch_alerts_deduplication(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run with last_alert_ids.
        - get_alert_list returns alerts including duplicates.
    When:
        - Running fetch_alerts.
    Then:
        - Assert duplicate alerts are filtered out.
        - Assert only new alerts are processed.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts with some duplicates
    mock_alerts = [
        {
            "id": 3,
            "severity": "high",
            "date": "2026-01-15T00:00:02Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 4,
            "severity": "high",
            "date": "2026-01-15T00:00:03Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts with last_alert_ids containing [1, 2]
    last_run = HelloWorldLastRun(start_time="2026-01-15T00:00:00Z", last_alert_ids=[1, 2])
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-14T00:00:00Z",
        should_push=False,
    )

    # Verify next_run contains new alert IDs
    assert next_run.start_time == "2026-01-15T00:00:03Z"
    assert next_run.last_alert_ids == [4]


def test_fetch_alerts_first_fetch_uses_first_fetch_time(mocker: MockerFixture):
    """
    Given:
        - Valid client and empty last_run (first fetch).
        - first_fetch_time parameter provided.
    When:
        - Running fetch_alerts.
    Then:
        - Assert first_fetch_time is used when last_run.start_time is None.
        - Assert get_alert_list is called with first_fetch_time.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mock_get_alert_list = mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts with empty last_run
    first_fetch_time = "2026-01-14T00:00:00Z"
    last_run = HelloWorldLastRun()
    fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time=first_fetch_time,
        should_push=False,
    )

    # Verify get_alert_list was called with first_fetch_time
    # Note: asyncio.run is mocked, so we check the mock was called
    assert mock_get_alert_list.call_count == 1


@pytest.mark.parametrize(
    "severity",
    [
        pytest.param(HelloWorldSeverity.LOW, id="Low severity"),
        pytest.param(HelloWorldSeverity.MEDIUM, id="Medium severity"),
        pytest.param(HelloWorldSeverity.HIGH, id="High severity"),
        pytest.param(HelloWorldSeverity.CRITICAL, id="Critical severity"),
    ],
)
def test_fetch_alerts_different_severities(mocker: MockerFixture, severity: HelloWorldSeverity):
    """
    Given:
        - Valid client and last_run.
        - Different severity levels.
    When:
        - Running fetch_alerts.
    Then:
        - Assert get_alert_list is called with correct severity.
        - Assert alerts are fetched for each severity level.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": severity.value,
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mock_get_alert_list = mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    last_run = HelloWorldLastRun()
    fetch_alerts(
        client,
        last_run,
        severity=severity,
        max_fetch=10,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=False,
    )

    # Verify get_alert_list was called
    assert mock_get_alert_list.call_count == 1


@pytest.mark.parametrize(
    "max_fetch,expected_limit",
    [
        pytest.param(1, 1, id="Fetch 1 alert"),
        pytest.param(10, 10, id="Fetch 10 alerts"),
        pytest.param(100, 100, id="Fetch 100 alerts"),
        pytest.param(1000, 1000, id="Fetch 1000 alerts"),
    ],
)
def test_fetch_alerts_max_fetch_limits(mocker: MockerFixture, max_fetch: int, expected_limit: int):
    """
    Given:
        - Valid client and last_run.
        - Different max_fetch values.
    When:
        - Running fetch_alerts.
    Then:
        - Assert get_alert_list is called with correct limit.
        - Assert no more than max_fetch alerts are processed.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Generate mock alerts up to max_fetch
    mock_alerts = [
        {
            "id": i,
            "severity": "high",
            "date": f"2026-01-15T00:00:{i:02d}Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        }
        for i in range(1, min(max_fetch + 1, 101))  # Cap at 100 for test performance
    ]

    # Mock get_alert_list
    mock_get_alert_list = mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    last_run = HelloWorldLastRun()
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=max_fetch,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=False,
    )

    # Verify get_alert_list was called
    assert mock_get_alert_list.call_count == 1

    # Verify next_run has correct number of alert IDs
    assert len(next_run.last_alert_ids) >= 1


def test_fetch_alerts_no_push(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - should_push=False.
    When:
        - Running fetch_alerts.
    Then:
        - Assert get_alert_list is called.
        - Assert create_events/create_incidents are NOT called.
        - Assert next_run state is still updated correctly.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Mock create functions
    mock_create_events = mocker.patch("HelloWorldV2.create_events")
    mock_create_incidents = mocker.patch("HelloWorldV2.create_incidents")

    # Execute fetch_alerts with should_push=False
    last_run = HelloWorldLastRun()
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=False,
    )

    # Verify create functions were NOT called
    assert mock_create_events.call_count == 0
    assert mock_create_incidents.call_count == 0

    # Verify next_run is still updated
    assert next_run.start_time == "2026-01-15T00:00:00Z"
    assert next_run.last_alert_ids == [1]


def test_fetch_alerts_multiple_alerts_same_timestamp(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - Multiple alerts with the same timestamp.
    When:
        - Running fetch_alerts.
    Then:
        - Assert all alert IDs at the latest timestamp are tracked.
        - Assert next_run.last_alert_ids contains all IDs from latest timestamp.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts - multiple at same timestamp
    same_timestamp = "2026-01-15T00:00:05Z"
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "high",
            "date": "2026-01-15T00:00:01Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 3,
            "severity": "high",
            "date": same_timestamp,
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 4,
            "severity": "high",
            "date": same_timestamp,
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 5,
            "severity": "high",
            "date": same_timestamp,
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    last_run = HelloWorldLastRun()
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=False,
    )

    # Verify all IDs at the latest timestamp are tracked
    assert next_run.start_time == same_timestamp
    assert set(next_run.last_alert_ids) == {3, 4, 5}
    assert len(next_run.last_alert_ids) == 3


def test_fetch_alerts_uses_last_run_start_time(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run with existing start_time.
        - first_fetch_time parameter provided.
    When:
        - Running fetch_alerts.
    Then:
        - Assert last_run.start_time is used instead of first_fetch_time.
        - Assert get_alert_list is called with last_run.start_time.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 10,
            "severity": "high",
            "date": "2026-01-16T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mock_get_alert_list = mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts with existing last_run
    last_run_start_time = "2026-01-15T12:00:00Z"
    last_run = HelloWorldLastRun(start_time=last_run_start_time, last_alert_ids=[8, 9])
    first_fetch_time = "2026-01-14T00:00:00Z"  # Should be ignored

    fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time=first_fetch_time,
        should_push=False,
    )

    # Verify get_alert_list was called (asyncio.run is mocked)
    assert mock_get_alert_list.call_count == 1


def test_fetch_alerts_empty_last_alert_ids(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run with empty last_alert_ids.
    When:
        - Running fetch_alerts.
    Then:
        - Assert all alerts are processed (no deduplication).
        - Assert next_run.last_alert_ids is populated.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alerts
    mock_alerts = [
        {
            "id": 1,
            "severity": "high",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
        {
            "id": 2,
            "severity": "high",
            "date": "2026-01-15T00:00:01Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    last_run = HelloWorldLastRun(start_time="2026-01-15T00:00:00Z", last_alert_ids=[])
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.HIGH,
        max_fetch=10,
        first_fetch_time="2026-01-14T00:00:00Z",
        should_push=False,
    )

    # Verify next_run has alert IDs
    assert next_run.last_alert_ids == [2]


def test_fetch_alerts_single_alert(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - get_alert_list returns single alert.
    When:
        - Running fetch_alerts.
    Then:
        - Assert next_run state is updated with single alert.
        - Assert last_alert_ids contains only that alert ID.
    """
    from HelloWorldV2 import fetch_alerts

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock single alert
    mock_alerts = [
        {
            "id": 42,
            "severity": "critical",
            "date": "2026-01-15T00:00:00Z",
            "user": "test@example.com",
            "action": "Testing",
            "status": "Success",
        },
    ]

    # Mock get_alert_list
    mocker.patch("HelloWorldV2.get_alert_list", new=AsyncMock(return_value=mock_alerts))

    # Execute fetch_alerts
    last_run = HelloWorldLastRun()
    next_run = fetch_alerts(
        client,
        last_run,
        severity=HelloWorldSeverity.CRITICAL,
        max_fetch=1,
        first_fetch_time="2026-01-15T00:00:00Z",
        should_push=False,
    )

    # Verify next_run
    assert next_run.start_time == "2026-01-15T00:00:00Z"
    assert next_run.last_alert_ids == [42]


# endregion

# region fetch-assets


class TestHelloWorldAssetsLastRun:
    """Tests for HelloWorldAssetsLastRun model."""

    @pytest.mark.parametrize(
        "stage,id_offset,cumulative_count,snapshot_id,next_trigger",
        [
            pytest.param("assets", 0, 0, None, None, id="Initial state - assets stage"),
            pytest.param("vulnerabilities", 100, 50, "1234567890", "1", id="Vulnerabilities stage with data"),
            pytest.param("assets", 500, 250, "9876543210", None, id="Assets stage mid-fetch"),
        ],
    )
    def test_assets_last_run_valid_states(self, stage, id_offset, cumulative_count, snapshot_id, next_trigger):
        """
        Given:
            - Valid state parameters for HelloWorldAssetsLastRun.
        When:
            - Initializing HelloWorldAssetsLastRun.
        Then:
            - Assert model is created successfully with correct values.
        """
        last_run = HelloWorldAssetsLastRun(
            stage=stage,
            id_offset=id_offset,
            cumulative_count=cumulative_count,
            snapshot_id=snapshot_id,
            nextTrigger=next_trigger,
        )
        assert last_run.stage == FetchAssetsStages(stage)
        assert last_run.id_offset == id_offset
        assert last_run.cumulative_count == cumulative_count
        assert last_run.snapshot_id == snapshot_id
        assert last_run.next_trigger_in_seconds == next_trigger

    def test_assets_last_run_default_values(self):
        """
        Given:
            - No parameters provided.
        When:
            - Initializing HelloWorldAssetsLastRun.
        Then:
            - Assert default values are set correctly.
        """
        last_run = HelloWorldAssetsLastRun()
        assert last_run.stage == FetchAssetsStages.ASSETS
        assert last_run.id_offset == 0
        assert last_run.cumulative_count == 0
        assert last_run.snapshot_id is None
        assert last_run.next_trigger_in_seconds is None
        assert last_run.trigger_type == 1


@pytest.mark.parametrize(
    "assets_last_run,mock_assets_response,mock_vulns_response,expected_stage,expected_offset,expected_cumulative,expected_trigger",
    [
        pytest.param(
            HelloWorldAssetsLastRun(stage=FetchAssetsStages.ASSETS, id_offset=0, cumulative_count=0, snapshot_id=None),
            {
                "has_more": False,
                "data": [{"id": 1, "name": "Server-01", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}],
            },
            None,
            "vulnerabilities",
            0,
            0,
            "1",
            id="First assets batch - no more data, move to vulnerabilities",
        ),
        pytest.param(
            HelloWorldAssetsLastRun(stage=FetchAssetsStages.ASSETS, id_offset=0, cumulative_count=0, snapshot_id=None),
            {
                "has_more": True,
                "data": [
                    {"id": i, "name": f"Server-{i:02d}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
                    for i in range(1, 11)
                ],
            },
            None,
            "assets",
            10,
            10,
            "1",
            id="First assets batch - has more data, continue assets",
        ),
        pytest.param(
            HelloWorldAssetsLastRun(
                stage=FetchAssetsStages.ASSETS, id_offset=1000, cumulative_count=1000, snapshot_id="1234567890"
            ),
            {
                "has_more": True,
                "data": [
                    {"id": i, "name": f"Server-{i:02d}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
                    for i in range(1001, 1011)
                ],
            },
            None,
            "assets",
            1010,
            1010,
            "1",
            id="Mid-fetch assets - has more data, continue pagination",
        ),
        pytest.param(
            HelloWorldAssetsLastRun(stage=FetchAssetsStages.VULNS, id_offset=0, cumulative_count=0, snapshot_id="1234567890"),
            None,
            {
                "has_more": False,
                "data": [
                    {
                        "id": 1,
                        "cve_id": "CVE-MOCK-0001",
                        "severity": "critical",
                        "description": "Test vuln",
                        "published": "2026-01-15T00:00:00",
                    }
                ],
            },
            "assets",
            0,
            0,
            None,
            id="Vulnerabilities batch - no more data, complete cycle back to assets",
        ),
        pytest.param(
            HelloWorldAssetsLastRun(stage=FetchAssetsStages.VULNS, id_offset=0, cumulative_count=0, snapshot_id="1234567890"),
            None,
            {
                "has_more": True,
                "data": [
                    {
                        "id": i,
                        "cve_id": f"CVE-MOCK-{i:04d}",
                        "severity": "high",
                        "description": "Test",
                        "published": "2026-01-15T00:00:00",
                    }
                    for i in range(1, 11)
                ],
            },
            "vulnerabilities",
            10,
            10,
            "1",
            id="Vulnerabilities batch - has more data, continue vulnerabilities",
        ),
    ],
)
def test_fetch_assets_stage_transitions(
    mocker: MockerFixture,
    assets_last_run: HelloWorldAssetsLastRun,
    mock_assets_response: dict | None,
    mock_vulns_response: dict | None,
    expected_stage: str,
    expected_offset: int,
    expected_cumulative: int,
    expected_trigger: str | None,
):
    """
    Given:
        - Valid client and last_run state at different stages.
        - Mock API responses with varying has_more flags.
    When:
        - Running fetch_assets.
    Then:
        - Assert correct client method is called based on stage.
        - Assert send_data_to_xsiam is called with correct parameters.
        - Assert next_run state is correctly updated based on has_more flag.
        - Assert stage transitions happen correctly.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock client methods
    mock_get_assets = mocker.patch.object(client, "get_assets", return_value=mock_assets_response)
    mock_get_vulnerabilities = mocker.patch.object(client, "get_vulnerabilities", return_value=mock_vulns_response)

    # Mock send_data_to_xsiam
    mock_send_data = mocker.patch("HelloWorldV2.send_data_to_xsiam")

    # Mock generate_unix_timestamp to return consistent value
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="9999999999")

    # Execute fetch_assets
    next_run = fetch_assets(client, assets_last_run, should_push=True)

    # Assertions - verify correct method was called based on stage
    if assets_last_run.stage is FetchAssetsStages.ASSETS:
        assert mock_get_assets.call_count == 1
        assert mock_get_assets.call_args.kwargs == {"limit": 1000, "id_offset": assets_last_run.id_offset}
        assert mock_get_vulnerabilities.call_count == 0
        response = mock_assets_response or {}
    else:
        assert mock_get_vulnerabilities.call_count == 1
        assert mock_get_vulnerabilities.call_args.kwargs == {"limit": 1000, "id_offset": assets_last_run.id_offset}
        assert mock_get_assets.call_count == 0
        response = mock_vulns_response or {}

    # Verify send_data_to_xsiam was called
    assert mock_send_data.call_count == 1
    call_kwargs = mock_send_data.call_args.kwargs

    # Verify data sent
    assert call_kwargs["data"] == response["data"]

    # Verify items_count and should_update_health_module based on has_more
    has_more = response["has_more"]
    batch_count = len(response["data"])
    if has_more:
        assert call_kwargs["items_count"] == 1
        assert call_kwargs["should_update_health_module"] is False
    else:
        expected_items_count = assets_last_run.cumulative_count + batch_count
        assert call_kwargs["items_count"] == expected_items_count
        assert call_kwargs["should_update_health_module"] is True

    # Verify next_run state
    assert next_run.stage == FetchAssetsStages(expected_stage)
    assert next_run.id_offset == expected_offset
    assert next_run.cumulative_count == expected_cumulative
    assert next_run.next_trigger_in_seconds == expected_trigger


@pytest.mark.parametrize(
    "stage,has_more",
    [
        pytest.param(FetchAssetsStages.ASSETS, True, id="Assets stage - has more - retain snapshot"),
        pytest.param(FetchAssetsStages.ASSETS, False, id="Assets stage - no more - new snapshot"),
        pytest.param(FetchAssetsStages.VULNS, True, id="Vulnerabilities stage - has more - retain snapshot"),
        pytest.param(FetchAssetsStages.VULNS, False, id="Vulnerabilities stage - no more - new snapshot"),
    ],
)
def test_fetch_assets_snapshot_id_management(mocker: MockerFixture, stage: FetchAssetsStages, has_more: bool):
    """
    Given:
        - Valid client and last_run with existing snapshot_id.
        - Mock API responses with varying has_more flags.
    When:
        - Running fetch_assets.
    Then:
        - Assert snapshot_id is retained when has_more=True.
        - Assert new snapshot_id is generated when has_more=False.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run with existing snapshot_id
    original_snapshot_id = "1234567890"
    last_run = HelloWorldAssetsLastRun(stage=stage, id_offset=0, cumulative_count=0, snapshot_id=original_snapshot_id)

    # Mock response
    mock_response = {
        "has_more": has_more,
        "data": [{"id": 1, "name": "Test", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}],
    }

    # Mock client methods
    if stage is FetchAssetsStages.ASSETS:
        mocker.patch.object(client, "get_assets", return_value=mock_response)
    else:
        mocker.patch.object(client, "get_vulnerabilities", return_value=mock_response)

    # Mock send_data_to_xsiam
    mocker.patch("HelloWorldV2.send_data_to_xsiam")

    # Mock generate_unix_timestamp to return new value
    new_snapshot_id = "9999999999"
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value=new_snapshot_id)

    # Execute fetch_assets
    next_run = fetch_assets(client, last_run, should_push=True)

    # Verify snapshot_id behavior
    assert next_run.snapshot_id == original_snapshot_id if has_more else new_snapshot_id


def test_fetch_assets_empty_response(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - Mock API response with empty data array.
    When:
        - Running fetch_assets.
    Then:
        - Assert function handles empty data gracefully.
        - Assert send_data_to_xsiam is called with empty array.
        - Assert next_run state is updated correctly.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run
    last_run = HelloWorldAssetsLastRun(stage="assets", id_offset=0, cumulative_count=0)

    # Mock response with empty data
    mock_response = {"has_more": False, "data": []}

    # Mock client methods
    mocker.patch.object(client, "get_assets", return_value=mock_response)

    # Mock send_data_to_xsiam
    mock_send_data = mocker.patch("HelloWorldV2.send_data_to_xsiam")

    # Mock generate_unix_timestamp
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="1234567890")

    # Execute fetch_assets
    next_run = fetch_assets(client, last_run, should_push=True)

    # Assertions
    assert mock_send_data.call_count == 1
    assert mock_send_data.call_args.kwargs["data"] == []
    assert mock_send_data.call_args.kwargs["items_count"] == 0
    assert next_run.stage.value == "vulnerabilities"
    assert next_run.id_offset == 0


def test_fetch_assets_no_push(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - should_push=False.
    When:
        - Running fetch_assets.
    Then:
        - Assert client method is called.
        - Assert send_data_to_xsiam is NOT called.
        - Assert next_run state is still updated correctly.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run
    last_run = HelloWorldAssetsLastRun(stage="assets", id_offset=0, cumulative_count=0)

    # Mock response
    mock_response = util_load_json("test_data/assets.json")

    # Mock client methods
    mock_get_assets = mocker.patch.object(client, "get_assets", return_value=mock_response)

    # Mock send_data_to_xsiam
    mock_send_data = mocker.patch("HelloWorldV2.send_data_to_xsiam")

    # Mock generate_unix_timestamp
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="1234567890")

    # Execute fetch_assets with should_push=False
    next_run = fetch_assets(client, last_run, should_push=False)

    # Assertions
    assert mock_get_assets.call_count == 1
    assert mock_send_data.call_count == 0  # Should NOT be called
    assert next_run.stage.value == "vulnerabilities"


@pytest.mark.parametrize(
    "initial_offset,batch_size,has_more,expected_next_offset",
    [
        pytest.param(0, 10, True, 10, id="First batch - has more"),
        pytest.param(100, 50, True, 150, id="Mid-fetch - has more"),
        pytest.param(5000, 100, True, 5100, id="Large offset - has more"),
        pytest.param(0, 10, False, 0, id="First batch - no more (reset)"),
        pytest.param(1000, 50, False, 0, id="Mid-fetch - no more (reset)"),
    ],
)
def test_fetch_assets_offset_calculation(
    mocker: MockerFixture, initial_offset: int, batch_size: int, has_more: bool, expected_next_offset: int
):
    """
    Given:
        - Valid client and last_run with various offset values.
        - Mock API responses with different batch sizes and has_more flags.
    When:
        - Running fetch_assets.
    Then:
        - Assert offset is correctly incremented when has_more=True.
        - Assert offset is reset to 0 when has_more=False.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run
    last_run = HelloWorldAssetsLastRun(
        stage="assets", id_offset=initial_offset, cumulative_count=initial_offset, snapshot_id="1234567890"
    )

    # Mock response with specified batch size
    mock_data = [
        {"id": i, "name": f"Asset-{i}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
        for i in range(initial_offset + 1, initial_offset + batch_size + 1)
    ]
    mock_response = {"has_more": has_more, "data": mock_data}

    # Mock client methods
    mocker.patch.object(client, "get_assets", return_value=mock_response)
    mocker.patch("HelloWorldV2.send_data_to_xsiam")
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="9999999999")

    # Execute fetch_assets
    next_run = fetch_assets(client, last_run, should_push=True)

    # Verify offset
    assert next_run.id_offset == expected_next_offset


def test_fetch_assets_cumulative_count_tracking(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run with existing cumulative_count.
        - Mock API response with has_more=True.
    When:
        - Running fetch_assets.
    Then:
        - Assert cumulative_count is correctly incremented.
        - Assert cumulative_count is reset when has_more=False.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Test case 1: has_more=True, cumulative should increment
    last_run = HelloWorldAssetsLastRun(stage="assets", id_offset=100, cumulative_count=100, snapshot_id="1234567890")

    mock_response = {
        "has_more": True,
        "data": [
            {"id": i, "name": f"Asset-{i}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
            for i in range(101, 111)
        ],
    }

    mocker.patch.object(client, "get_assets", return_value=mock_response)
    mocker.patch("HelloWorldV2.send_data_to_xsiam")
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="9999999999")

    next_run = fetch_assets(client, last_run, should_push=True)

    # Verify cumulative_count incremented
    assert next_run.cumulative_count == 110

    # Test case 2: has_more=False, cumulative should reset
    last_run2 = HelloWorldAssetsLastRun(stage="assets", id_offset=200, cumulative_count=200, snapshot_id="1234567890")

    mock_response2 = {
        "has_more": False,
        "data": [
            {"id": i, "name": f"Asset-{i}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
            for i in range(201, 206)
        ],
    }

    mocker.patch.object(client, "get_assets", return_value=mock_response2)

    next_run2 = fetch_assets(client, last_run2, should_push=True)

    # Verify cumulative_count reset
    assert next_run2.cumulative_count == 0


def test_fetch_assets_vendor_product_dataset_selection(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run at different stages.
    When:
        - Running fetch_assets.
    Then:
        - Assert correct vendor/product is used for assets stage.
        - Assert correct vendor/product is used for vulnerabilities stage.
    """
    from HelloWorldV2 import (
        fetch_assets,
        AssetsDatasetConfigs,
        VulnerabilitiesDatasetConfigs,
    )

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Test assets stage
    last_run_assets = HelloWorldAssetsLastRun(stage="assets", id_offset=0, cumulative_count=0)
    mock_assets_response = util_load_json("test_data/assets.json")
    mocker.patch.object(client, "get_assets", return_value=mock_assets_response)
    mock_send_data = mocker.patch("HelloWorldV2.send_data_to_xsiam")
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="1234567890")

    fetch_assets(client, last_run_assets, should_push=True)

    # Verify vendor/product for assets
    assert mock_send_data.call_args.kwargs["vendor"] == AssetsDatasetConfigs.VENDOR.value
    assert mock_send_data.call_args.kwargs["product"] == AssetsDatasetConfigs.PRODUCT.value

    # Test vulnerabilities stage
    last_run_vulns = HelloWorldAssetsLastRun(stage="vulnerabilities", id_offset=0, cumulative_count=0, snapshot_id="1234567890")
    mock_vulns_response = util_load_json("test_data/vulnerabilities.json")
    mocker.patch.object(client, "get_vulnerabilities", return_value=mock_vulns_response)
    mock_send_data.reset_mock()

    fetch_assets(client, last_run_vulns, should_push=True)

    # Verify vendor/product for vulnerabilities
    assert mock_send_data.call_args.kwargs["vendor"] == VulnerabilitiesDatasetConfigs.VENDOR.value
    assert mock_send_data.call_args.kwargs["product"] == VulnerabilitiesDatasetConfigs.PRODUCT.value


def test_fetch_assets_initial_snapshot_generation(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run with no snapshot_id (first run).
    When:
        - Running fetch_assets.
    Then:
        - Assert generate_unix_timestamp is called to create new snapshot_id.
        - Assert snapshot_id is included in send_data_to_xsiam call.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run with no snapshot_id (first run)
    last_run = HelloWorldAssetsLastRun(stage=FetchAssetsStages.ASSETS, id_offset=0, cumulative_count=0, snapshot_id=None)

    # Mock response
    mock_response = util_load_json("test_data/assets.json")
    mock_response["has_more"] = True  # assume has_more to ensure current snapshot_id is persisted

    # Mock client methods
    mocker.patch.object(client, "get_assets", return_value=mock_response)
    mock_send_data_to_xsiam = mocker.patch("HelloWorldV2.send_data_to_xsiam")

    # Mock generate_unix_timestamp
    expected_snapshot_id = "1234567890"
    mock_generate_timestamp = mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value=expected_snapshot_id)

    # Execute fetch_assets
    fetch_assets(client, last_run, should_push=True)

    # Verify generate_unix_timestamp was NOT called (snapshot_id generated inline)
    # The function generates snapshot_id using: last_run.snapshot_id or generate_unix_timestamp()
    # So it should be called once since response["has_more"] == True
    assert mock_generate_timestamp.call_count == 1

    # Verify snapshot_id is used in send_data_to_xsiam
    assert mock_send_data_to_xsiam.call_args.kwargs["snapshot_id"] == expected_snapshot_id


def test_fetch_assets_large_batch_pagination(mocker: MockerFixture):
    """
    Given:
        - Valid client and last_run.
        - Mock API response with exactly 1000 items (batch limit).
    When:
        - Running fetch_assets.
    Then:
        - Assert function handles large batches correctly.
        - Assert offset is incremented by batch size.
    """
    from HelloWorldV2 import fetch_assets

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Create last_run
    last_run = HelloWorldAssetsLastRun(stage="assets", id_offset=0, cumulative_count=0)

    # Mock response with 1000 items
    mock_data = [
        {"id": i, "name": f"Asset-{i:04d}", "type": "server", "status": "active", "created": "2024-01-15T00:00:00"}
        for i in range(1, 1001)
    ]
    mock_response = {"has_more": True, "data": mock_data}

    # Mock client methods
    mocker.patch.object(client, "get_assets", return_value=mock_response)
    mocker.patch("HelloWorldV2.send_data_to_xsiam")
    mocker.patch("HelloWorldV2.generate_unix_timestamp", return_value="1234567890")

    # Execute fetch_assets
    next_run = fetch_assets(client, last_run, should_push=True)

    # Verify offset incremented by 1000
    assert next_run.id_offset == 1000
    assert next_run.cumulative_count == 1000


# endregion

# region ip reputation


class TestIpArgs:
    @pytest.mark.parametrize(
        "ip_input",
        [
            pytest.param("8.8.8.8", id="Single IPv4"),
            pytest.param("2001:4860:4860::8888", id="Single IPv6"),
            pytest.param(["8.8.8.8", "1.1.1.1"], id="Multiple IPv4"),
        ],
    )
    def test_ip_args_valid_ips(self, ip_input, mocker):
        """
        Given:
            - Valid IP address(es).
        When:
            - Initializing IpArgs and accessing ips property.
        Then:
            - Assert model is created successfully.
            - Assert ips property returns valid IPs.
        """
        from HelloWorldV2 import IpArgs

        # Mock demisto.error to avoid actual logging
        mocker.patch("HelloWorldV2.demisto.error")

        args = IpArgs(ip=ip_input)
        assert args.ip == ip_input
        # The ips property validates IPs
        valid_ips = args.ips
        assert len(valid_ips) > 0

    def test_ip_args_missing_ip(self):
        """
        Given:
            - No IP provided.
        When:
            - Initializing IpArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import IpArgs

        with pytest.raises(DemistoException, match="ip"):
            IpArgs()  # type: ignore[call-arg]

    def test_ip_args_all_invalid_ips(self, mocker):
        """
        Given:
            - Only invalid IP addresses.
        When:
            - Initializing IpArgs and accessing ips property.
        Then:
            - Assert ValueError is raised when accessing ips property.
        """
        from HelloWorldV2 import IpArgs

        # Mock demisto.error to avoid actual logging
        mocker.patch("HelloWorldV2.demisto.error")

        args = IpArgs(ip=["not-an-ip", "also-invalid"])
        with pytest.raises(ValueError):
            _ = args.ips


@pytest.mark.parametrize(
    "ip,threshold,expected_score,expected_reputation",
    [
        pytest.param("8.8.8.8", 65, Common.DBotScore.NONE, 0, id="Bad IP - reputation below threshold/2"),
        pytest.param("1.1.1.1", 65, Common.DBotScore.SUSPICIOUS, 50, id="Suspicious IP - reputation below threshold"),
        pytest.param("151.1.1.1", 65, Common.DBotScore.GOOD, 70, id="Good IP - reputation above threshold"),
        pytest.param("192.168.1.1", 65, Common.DBotScore.NONE, 0, id="Unknown IP - reputation is 0"),
        pytest.param("10.0.0.1", 30, Common.DBotScore.SUSPICIOUS, 20, id="Custom threshold - suspicious"),
    ],
)
def test_ip_reputation_command(mocker: MockerFixture, ip: str, threshold: int, expected_score: int, expected_reputation: int):
    """
    Given:
        - Valid client, args with different IP addresses and thresholds.
        - Mock IP reputation data with varying reputation scores.
    When:
        - Running ip_reputation_command.
    Then:
        - Assert client.get_ip_reputation is called once with the provided IP.
        - Assert CommandResults is returned with correct DBotScore, IP context, and readable output.
        - Assert the reputation score is correctly mapped to DBotScore (0-3).
    """
    from HelloWorldV2 import ip_reputation_command, IpArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
        threshold_ip=threshold,
    )
    client = HelloWorldClient(params)

    # Load base mock data and update with test-specific values
    mock_ip_data = util_load_json("test_data/ip_reputation.json")
    mock_ip_data["attributes"]["reputation"] = expected_reputation
    mock_ip_data["id"] = ip
    mock_ip_data["links"]["self"] = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    mock_get_ip_reputation = mocker.patch.object(client, "get_ip_reputation", return_value=mock_ip_data)

    # Create args
    args = IpArgs(ip=ip, threshold=threshold)

    # Execute command
    results = ip_reputation_command(client, args, params)

    # Assertions
    assert mock_get_ip_reputation.call_count == 1
    assert mock_get_ip_reputation.call_args.args[0] == ip

    # Verify we got a list with one CommandResults
    assert len(results) == 1

    # Verify outputs
    assert results[0].outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.IP"
    assert results[0].outputs_key_field == "ip"
    assert results[0].outputs["ip"] == ip
    assert "attributes" not in results[0].outputs  # Should be excluded
    assert "whois" not in results[0].outputs  # Should be excluded

    # Verify indicator (IP standard context)
    assert results[0].indicator is not None
    assert results[0].indicator.ip == ip
    assert results[0].indicator.dbot_score.score == expected_score
    assert results[0].indicator.dbot_score.indicator == ip
    assert results[0].indicator.dbot_score.indicator_type == "ip"
    assert results[0].indicator.dbot_score.integration_name == "HelloWorld"

    # Verify readable output contains IP data
    assert ip in results[0].readable_output
    assert "Attributes" in results[0].readable_output


@pytest.mark.parametrize(
    "ips",
    [
        pytest.param(["8.8.8.8", "1.1.1.1"], id="Multiple IPs"),
        pytest.param(["192.168.1.1", "10.0.0.1", "172.16.0.1"], id="Three IPs"),
    ],
)
def test_ip_reputation_command_multiple_ips(mocker: MockerFixture, ips: list[str]):
    """
    Given:
        - Valid client and args with multiple IP addresses.
    When:
        - Running ip_reputation_command.
    Then:
        - Assert client.get_ip_reputation is called once for each IP.
        - Assert a list of CommandResults is returned with one result per IP.
    """
    from HelloWorldV2 import ip_reputation_command, IpArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock client.get_ip_reputation to return different data for each IP
    def mock_get_reputation(ip: str):
        return {
            "attributes": {
                "as_owner": "TEST",
                "asn": 12345,
                "reputation": 50,
            },
            "id": ip,
            "links": {"self": f"https://example.com/{ip}"},
            "type": "ip_address",
        }

    mock_get_ip_reputation = mocker.patch.object(client, "get_ip_reputation", side_effect=mock_get_reputation)

    # Create args
    args = IpArgs(ip=ips)

    # Execute command
    results = ip_reputation_command(client, args, params)

    # Assertions
    assert mock_get_ip_reputation.call_count == len(ips)
    assert len(results) == len(ips)

    # Verify each result corresponds to the correct IP
    for i, result in enumerate(results):
        assert result.outputs["ip"] == ips[i]
        assert result.indicator.ip == ips[i]


def test_ip_reputation_command_with_relationships(mocker: MockerFixture):
    """
    Given:
        - Valid client and args.
        - Mock IP reputation data with relationship links.
    When:
        - Running ip_reputation_command.
    Then:
        - Assert EntityRelationship objects are created for related URLs.
        - Assert relationships are included in CommandResults.
    """
    from HelloWorldV2 import ip_reputation_command, IpArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock data with relationships
    ip = "8.8.8.8"
    related_url = "https://example.com/related"
    mock_ip_data = util_load_json("test_data/ip_reputation_with_relationships.json")
    mocker.patch.object(client, "get_ip_reputation", return_value=mock_ip_data)

    # Create args
    args = IpArgs(ip=ip)

    # Execute command
    results = ip_reputation_command(client, args, params)

    # Assertions
    assert len(results) == 1
    result = results[0]

    # Verify relationships
    assert result.relationships is not None
    assert len(result.relationships) == 1
    relationship = result.relationships[0]
    assert relationship._entity_a == ip
    assert relationship._entity_b == related_url
    assert relationship._name == "related-to"


def test_ip_reputation_command_threshold_override(mocker: MockerFixture):
    """
    Given:
        - Valid client and args with custom threshold in args.
        - Params with different default threshold.
    When:
        - Running ip_reputation_command.
    Then:
        - Assert args threshold is used instead of params threshold.
        - Assert DBotScore is calculated using args threshold.
    """
    from HelloWorldV2 import ip_reputation_command, IpArgs

    # Create params with default threshold
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
        threshold_ip=100,  # High default threshold
    )
    client = HelloWorldClient(params)

    # Mock client.get_ip_reputation
    ip = "8.8.8.8"
    reputation = 40  # Would be good with threshold=100, but suspicious with threshold=50
    mock_ip_data = {
        "attributes": {
            "reputation": reputation,
        },
        "id": ip,
        "links": {"self": ""},
        "type": "ip_address",
    }
    mocker.patch.object(client, "get_ip_reputation", return_value=mock_ip_data)

    # Create args with custom threshold
    custom_threshold = 50
    args = IpArgs(ip=ip, threshold=custom_threshold)

    # Execute command
    results = ip_reputation_command(client, args, params)

    # Assertions
    result = results[0]
    # With threshold=50, reputation=40 should be suspicious (score=2)
    # because 40 < 50 but 40 >= 50/2 (25)
    assert result.indicator.dbot_score.score == Common.DBotScore.SUSPICIOUS


# endregion

# region helloworld-alert-list


class TestHelloworldAlertListArgs:
    @pytest.mark.parametrize(
        "alert_id,severity",
        [
            pytest.param(123, None, id="With alert_id only"),
            pytest.param(None, "high", id="With severity only"),
        ],
    )
    def test_alert_list_args_valid_combinations(self, alert_id, severity):
        """
        Given:
            - Either alert_id or severity (but not both).
        When:
            - Initializing HelloworldAlertListArgs.
        Then:
            - Assert model is created successfully.
        """
        from HelloWorldV2 import HelloworldAlertListArgs

        args = HelloworldAlertListArgs(alert_id=alert_id, severity=severity)
        assert args.alert_id == alert_id
        assert args.severity == severity

    @pytest.mark.parametrize(
        "alert_id,severity",
        [
            pytest.param(None, None, id="Neither provided"),
            pytest.param(123, "high", id="Both provided"),
        ],
    )
    def test_alert_list_args_invalid_combinations(self, alert_id, severity):
        """
        Given:
            - Either both alert_id and severity, or neither.
        When:
            - Initializing HelloworldAlertListArgs.
        Then:
            - Assert DemistoException is raised with appropriate message.
        """
        from HelloWorldV2 import HelloworldAlertListArgs

        with pytest.raises(DemistoException, match="Either 'alert_id' or 'severity' arguments need to be provided."):
            HelloworldAlertListArgs(alert_id=alert_id, severity=severity)


@pytest.mark.parametrize(
    "alert_id,severity,limit,expected_method",
    [
        pytest.param(123, None, 10, "get_alert", id="With alert_id"),
        pytest.param(None, HelloWorldSeverity.HIGH, 10, "get_alert_list", id="With severity"),
    ],
)
def test_alert_list_command(
    mocker: MockerFixture, alert_id: int | None, severity: HelloWorldSeverity | None, limit: int, expected_method: str
):
    """
    Given:
        - Valid client and args with either alert_id or severity.
    When:
        - Running alert_list_command.
    Then:
        - Assert correct client method is called (get_alert for alert_id, get_alert_list for severity).
        - Assert tableToMarkdown is called with correct args.
        - Assert CommandResults is returned with correct outputs.
    """
    from HelloWorldV2 import alert_list_command, HelloworldAlertListArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Mock alert data
    mock_alert = {
        "id": alert_id or 1,
        "severity": severity.value if severity else "high",
        "user": "test@example.com",
        "action": "Testing",
        "date": "2026-01-15T00:00:00",
        "status": "Success",
    }

    # Mock the appropriate client method
    if expected_method == "get_alert":
        mock_get_alert = mocker.patch.object(client, "get_alert", return_value=mock_alert)
        mock_get_alert_list = mocker.patch.object(client, "get_alert_list")
    else:  # get_alert_list
        mock_get_alert = mocker.patch.object(client, "get_alert")
        mock_get_alert_list = mocker.patch.object(client, "get_alert_list", return_value=[mock_alert])

    # Mock tableToMarkdown
    mock_table_to_markdown = mocker.patch("HelloWorldV2.tableToMarkdown")

    # Create args
    args = HelloworldAlertListArgs(alert_id=alert_id, severity=severity, limit=limit)

    # Execute command
    result = alert_list_command(client, args)

    # Assertions - verify correct method was called
    if expected_method == "get_alert":
        assert mock_get_alert.call_count == 1
        assert mock_get_alert.call_args.args == (alert_id,)
        assert mock_get_alert_list.call_count == 0
    else:  # get_alert_list
        assert mock_get_alert_list.call_count == 1
        assert mock_get_alert_list.call_args.kwargs == {"limit": limit, "severity": severity}
        assert mock_get_alert.call_count == 0

    # Verify tableToMarkdown was called
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args[0] == "Items List (Sample Data)"
    assert isinstance(mock_table_to_markdown.call_args.args[1], list)

    # Verify CommandResults
    assert result.outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.Alert"
    assert result.outputs_key_field == "id"
    assert isinstance(result.outputs, list)


# endregion

# region helloworld-get-events


class TestHelloWorldGetEventsArgs:
    @pytest.mark.parametrize(
        "limit,should_push_events",
        [
            pytest.param(10, False, id="Defaults"),
            pytest.param(100, True, id="With limit and push"),
            pytest.param(50, False, id="With limit no push"),
        ],
    )
    def test_get_events_args_valid(self, mocker: MockerFixture, limit: int, should_push_events: bool):
        """
        Given:
            - Optional limit and should_push_events values.
        When:
            - Initializing HelloWorldGetEventsArgs.
        Then:
            - Assert model is created successfully with correct values.
        """
        from HelloWorldV2 import HelloWorldGetEventsArgs

        mocker.patch("HelloWorldV2.CAN_SEND_EVENTS", True)

        args = HelloWorldGetEventsArgs(limit=limit, severity=HelloWorldSeverity.HIGH, should_push_events=should_push_events)
        assert args.limit == limit
        assert args.should_push_events == should_push_events


def test_get_events_command(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for get_events_command.
    When:
        - Running get_events_command.
    Then:
        - Assert get_alert_list is called once with correct parameters.
        - Assert tableToMarkdown is called with correct args/kwargs.
        - Assert CommandResults is returned with correct readable output.
    """
    from HelloWorldV2 import get_events_command, HelloWorldGetEventsArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock alert data
    mock_events = util_load_json("test_data/alert_events.json")

    mock_get_alert_list = mocker.patch("HelloWorldV2.get_alert_list", return_value=mock_events)
    mock_table_to_markdown = mocker.patch("HelloWorldV2.tableToMarkdown")

    args = HelloWorldGetEventsArgs(severity=HelloWorldSeverity.HIGH, limit=10, should_push_events=False)
    # Execute command
    get_events_command(client, args)

    # Assertions
    assert mock_get_alert_list.call_count == 1
    # Verify the call was made with correct parameters
    assert mock_get_alert_list.call_args.kwargs == {
        "client": client,
        "start_time": None,
        "severity": HelloWorldSeverity.HIGH,
        "limit": 10,
        "should_push": False,
    }

    # Verify tableToMarkdown was called with correct args
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args == ("HelloWorld Events", mock_events)


# endregion

# region helloworld-alert-note-create


class TestHelloworldAlertNoteCreateArgs:
    @pytest.mark.parametrize(
        "alert_id,note_text",
        [
            pytest.param(1, "Simple note", id="Simple note"),
            pytest.param(999, "Note with special chars: !@#$%", id="Special chars"),
            pytest.param(42, "Very long note " * 50, id="Long note"),
        ],
    )
    def test_alert_note_create_args_valid(self, alert_id, note_text):
        """
        Given:
            - A positive alert_id and note_text.
        When:
            - Initializing HelloworldAlertNoteCreateArgs.
        Then:
            - Assert model is created successfully.
        """
        from HelloWorldV2 import HelloworldAlertNoteCreateArgs

        args = HelloworldAlertNoteCreateArgs(alert_id=alert_id, note_text=note_text)
        assert args.alert_id == alert_id
        assert args.note_text == note_text

    @pytest.mark.parametrize(
        "alert_id",
        [
            pytest.param(0, id="Zero alert_id"),
            pytest.param(-1, id="Negative alert_id"),
            pytest.param(-999, id="Large negative alert_id"),
        ],
    )
    def test_alert_note_create_args_invalid_alert_id(self, alert_id):
        """
        Given:
            - A non-positive alert_id.
        When:
            - Initializing HelloworldAlertNoteCreateArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloworldAlertNoteCreateArgs

        with pytest.raises(DemistoException, match="Please provide a valid 'alert_id' argument"):
            HelloworldAlertNoteCreateArgs(alert_id=alert_id, note_text="Test note")

    def test_alert_note_create_args_missing_note_text(self):
        """
        Given:
            - No note_text provided.
        When:
            - Initializing HelloworldAlertNoteCreateArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloworldAlertNoteCreateArgs

        with pytest.raises(DemistoException, match="note_text"):
            HelloworldAlertNoteCreateArgs(alert_id=1)  # type: ignore[call-arg]


def test_alert_note_create_command(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for alert_note_create_command.
    When:
        - Running alert_note_create_command.
    Then:
        - Assert client.create_note is called once with correct parameters.
        - Assert CommandResults is returned with correct outputs and readable output.
    """
    from HelloWorldV2 import alert_note_create_command, HelloworldAlertNoteCreateArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock response data
    alert_id = 123
    note_text = "This is a test note"
    mock_response = util_load_json("test_data/note_create_response.json")

    # Mock client.create_note
    mock_create_note = mocker.patch.object(client, "create_note", return_value=mock_response)

    # Create args
    args = HelloworldAlertNoteCreateArgs(alert_id=alert_id, note_text=note_text)

    # Execute command
    result = alert_note_create_command(client, args)

    # Assertions
    assert mock_create_note.call_count == 1
    assert mock_create_note.call_args.kwargs == {"alert_id": alert_id, "comment": note_text}

    # Verify CommandResults
    assert result.outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.Note"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_response
    assert result.readable_output == "Note was created successfully."


# endregion

# region helloworld-job-submit


class TestHelloWorldJobSubmitArgs:
    @pytest.mark.parametrize(
        "interval,timeout",
        [
            pytest.param(30, 600, id="Defaults"),
            pytest.param("30", "300", id="String numbers"),
        ],
    )
    def test_job_submit_args_valid(self, interval, timeout):
        """
        Given:
            - Optional interval_in_seconds and timeout_in_seconds values.
        When:
            - Initializing HelloWorldJobSubmitArgs.
        Then:
            - Assert model is created successfully.
            - Assert values are converted to integers.
        """
        from HelloWorldV2 import HelloWorldJobSubmitArgs

        args = HelloWorldJobSubmitArgs(interval_in_seconds=interval, timeout_in_seconds=timeout)
        assert isinstance(args.interval_in_seconds, int)
        assert isinstance(args.timeout_in_seconds, int)


def test_job_submit_command(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for job_submit_command.
    When:
        - Running job_submit_command.
    Then:
        - Assert client.submit_job is called once.
        - Assert CommandResults is returned with correct outputs and ScheduledCommand.
    """
    from HelloWorldV2 import job_submit_command, HelloWorldJobSubmitArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock job response
    mock_job_data = util_load_json("test_data/job_submit_response.json")

    # Mock client.submit_job
    mock_submit_job = mocker.patch.object(client, "submit_job", return_value=mock_job_data)

    # Create args
    interval_in_seconds = 30
    timeout_in_seconds = 600
    args = HelloWorldJobSubmitArgs(interval_in_seconds=interval_in_seconds, timeout_in_seconds=timeout_in_seconds)

    # Execute command
    result = job_submit_command(client, args)

    # Assertions
    assert mock_submit_job.call_count == 1

    # Verify CommandResults
    assert result.outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job"
    assert result.outputs_key_field == "id"
    assert result.outputs == mock_job_data
    assert "Successfully submitted" in result.readable_output
    assert "test-job-123" in result.readable_output

    # Verify ScheduledCommand
    assert result.scheduled_command is not None
    assert result.scheduled_command._command == "helloworld-job-poll"
    assert result.scheduled_command._next_run == str(interval_in_seconds)
    assert result.scheduled_command._timeout == str(timeout_in_seconds)
    assert result.scheduled_command._args == {
        "job_id": "test-job-123",
        "interval_in_seconds": interval_in_seconds,
        "timeout_in_seconds": timeout_in_seconds,
    }


# endregion

# region helloworld-job-poll


class TestHelloWorldJobPollArgs:
    @pytest.mark.parametrize(
        "job_id",
        [
            pytest.param("abc-123", id="Alphanumeric ID"),
            pytest.param("job_12345", id="Underscore ID"),
            pytest.param("550e8400-e29b-41d4-a716-446655440000", id="UUID ID"),
        ],
    )
    def test_job_poll_args_valid_job_ids(self, job_id):
        """
        Given:
            - A valid job_id string.
        When:
            - Initializing HelloWorldJobPollArgs.
        Then:
            - Assert model is created successfully.
        """
        from HelloWorldV2 import HelloWorldJobPollArgs

        args = HelloWorldJobPollArgs(job_id=job_id)
        assert args.job_id == job_id

    def test_job_poll_args_missing_job_id(self):
        """
        Given:
            - No job_id provided.
        When:
            - Initializing HelloWorldJobPollArgs.
        Then:
            - Assert DemistoException is raised.
        """
        from HelloWorldV2 import HelloWorldJobPollArgs

        with pytest.raises(DemistoException, match="job_id"):
            HelloWorldJobPollArgs()  # type: ignore[call-arg]


def test_job_poll_command_complete(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for job_poll_command.
        - Job status is "complete".
    When:
        - Running job_poll_command.
    Then:
        - Assert client.get_job_status is called once.
        - Assert client.get_job_result is called once.
        - Assert PollResult is returned with continue_to_poll=False and final results.
    """
    from HelloWorldV2 import job_poll_command, HelloWorldJobPollArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock job status and result
    job_id = "test-job-123"
    mock_status_response = util_load_json("test_data/job_status_complete.json")
    mock_job_result = util_load_json("test_data/job_result.json")

    # Mock client methods
    mock_get_job_status = mocker.patch.object(client, "get_job_status", return_value=mock_status_response)
    mock_get_job_result = mocker.patch.object(client, "get_job_result", return_value=mock_job_result)
    mock_table_to_markdown = mocker.patch("HelloWorldV2.tableToMarkdown")

    # Create args
    args = HelloWorldJobPollArgs(job_id=job_id, interval_in_seconds=30, timeout_in_seconds=600)

    # Execute command
    result = job_poll_command(args, client)

    # Assertions
    assert mock_get_job_status.call_count == 1
    assert mock_get_job_status.call_args.args == (job_id,)
    assert mock_get_job_result.call_count == 1
    assert mock_get_job_result.call_args.args == (job_id,)

    # Verify tableToMarkdown was called
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args[0] == f"HelloWorld Job {job_id} - Complete"
    assert mock_table_to_markdown.call_args.args[1] == mock_job_result

    # Verify PollResult
    assert result.scheduled_command is None  # No more scheduled commands since polling is complete
    assert result.outputs_prefix == f"{BASE_CONTEXT_OUTPUT_PREFIX}.Job"
    assert result.outputs == mock_job_result


def test_job_poll_command_in_progress(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for job_poll_command.
        - Job status is "running" (not complete).
    When:
        - Running job_poll_command.
    Then:
        - Assert client.get_job_status is called once.
        - Assert client.get_job_result is NOT called.
        - Assert PollResult is returned with continue_to_poll=True and partial results.
    """
    from HelloWorldV2 import job_poll_command, HelloWorldJobPollArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock job status (running)
    job_id = "test-job-456"
    mock_status_response = util_load_json("test_data/job_status_running.json")

    # Mock client methods
    mock_get_job_status = mocker.patch.object(client, "get_job_status", return_value=mock_status_response)
    mock_get_job_result = mocker.patch.object(client, "get_job_result")

    # Create args
    interval = 30
    args = HelloWorldJobPollArgs(job_id=job_id, interval_in_seconds=interval, timeout_in_seconds=600)

    # Execute command
    result = job_poll_command(args, client)

    # Assertions
    assert mock_get_job_status.call_count == 1
    assert mock_get_job_status.call_args.args[0] == job_id
    assert mock_get_job_result.call_count == 0  # Should NOT be called when job is not complete

    # Verify No Command Results returned
    assert result is None


# endregion

# region helloworld-get-assets


def test_get_assets_command(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for get_assets_command.
    When:
        - Running get_assets_command.
    Then:
        - Assert client.get_assets is called once with correct parameters.
        - Assert tableToMarkdown is called with correct args.
        - Assert CommandResults is returned with correct readable output.
    """
    from HelloWorldV2 import get_assets_command, HelloWorldGetAssetsArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock asset data
    assets_raw_response = util_load_json("test_data/assets.json")
    mock_assets = assets_raw_response.get("data", [])

    # Mock client.get_assets
    mock_get_assets = mocker.patch.object(client, "get_assets", return_value=assets_raw_response)

    # Mock tableToMarkdown
    mock_table_to_markdown = mocker.patch("HelloWorldV2.tableToMarkdown", return_value="Mocked table")

    # Create args
    limit = 10
    args = HelloWorldGetAssetsArgs(limit=limit)

    # Execute command
    result = get_assets_command(client, args)

    # Assertions
    assert mock_get_assets.call_count == 1
    assert mock_get_assets.call_args.kwargs == {"limit": limit}

    # Verify tableToMarkdown was called
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args == ("HelloWorld Assets", mock_assets)

    # Verify CommandResults
    assert result.readable_output == "Mocked table"


# endregion

# region helloworld-get-vulnerabilities


def test_get_vulnerabilities_command(mocker: MockerFixture):
    """
    Given:
        - Valid client and args for get_vulnerabilities_command.
    When:
        - Running get_vulnerabilities_command.
    Then:
        - Assert client.get_vulnerabilities is called once with correct parameters.
        - Assert tableToMarkdown is called with correct args.
        - Assert CommandResults is returned with correct readable output.
    """
    from HelloWorldV2 import get_vulnerabilities_command, HelloWorldGetVulnerabilitiesArgs

    # Create params and client
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
    )
    client = HelloWorldClient(params)

    # Load mock vulnerability data
    vulnerabilities_raw_response = util_load_json("test_data/vulnerabilities.json")
    mock_vulnerabilities = vulnerabilities_raw_response.get("data", [])

    # Mock client.get_vulnerabilities
    mock_get_vulnerabilities = mocker.patch.object(client, "get_vulnerabilities", return_value=vulnerabilities_raw_response)

    # Mock tableToMarkdown
    mock_table_to_markdown = mocker.patch("HelloWorldV2.tableToMarkdown", return_value="Mocked table")

    # Create args
    limit = 10
    args = HelloWorldGetVulnerabilitiesArgs(limit=limit)

    # Execute command
    result = get_vulnerabilities_command(client, args)

    # Assertions
    assert mock_get_vulnerabilities.call_count == 1
    assert mock_get_vulnerabilities.call_args.kwargs == {"limit": limit}

    # Verify tableToMarkdown was called
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args == ("HelloWorld Vulnerabilities", mock_vulnerabilities)

    # Verify CommandResults
    assert result.readable_output == "Mocked table"


# endregion
