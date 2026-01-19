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
from CommonServerPython import DemistoException, Common
from HelloWorldV2 import (
    BASE_CONTEXT_OUTPUT_PREFIX,
    HelloWorldParams,
    HelloWorldClient,
    HelloWorldLastRun,
    HelloWorldSeverity,
    Credentials,
    DUMMY_VALID_API_KEY,
    ContentClient,
)


def util_load_json(path):
    """Load JSON test data from file.
    
    Args:
        path (str): Path to JSON file relative to test_data directory.
        
    Returns:
        dict | list: Parsed JSON data.
    """
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# ========== Credentials Model Tests ==========


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


# ========== HelloWorldParams Model Tests ==========


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
        "max_fetch,expected",
        [
            pytest.param(10, 10, id="Within limit"),
            pytest.param(50, 50, id="At limit"),
            pytest.param(300, 200, id="Exceeds limit capped"),
        ],
    )
    def test_params_max_fetch_capping(self, max_fetch, expected):
        """
        Given:
            - A max_fetch value that may exceed the cap.
        When:
            - Initializing HelloWorldParams.
        Then:
            - Assert max_fetch is capped at 50 for non-event systems.
        """
        from HelloWorldV2 import HelloWorldParams

        params = HelloWorldParams(
            url="https://api.example.com",  # type: ignore[arg-type]
            credentials={"password": "secret"},  # type: ignore[arg-type]
            max_fetch=max_fetch,
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


# ========== HelloworldSayHelloArgs Model Tests ==========


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


# ========== HelloworldAlertListArgs Model Tests ==========


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


# ========== HelloworldAlertNoteCreateArgs Model Tests ==========


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


# ========== HelloWorldGetEventsArgs Model Tests ==========


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
        mocker.patch("HelloWorldV2.SYSTEM.is_xsiam", True)

        args = HelloWorldGetEventsArgs(limit=limit, severity=HelloWorldSeverity.HIGH, should_push_events=should_push_events)
        assert args.limit == limit
        assert args.should_push_events == should_push_events


# ========== HelloWorldJobSubmitArgs Model Tests ==========


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


# ========== HelloWorldJobPollArgs Model Tests ==========


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


# ========== IpArgs Model Tests ==========


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
    "is_fetch",
    [
        pytest.param(False, id="Fetching disabled"),
        pytest.param(True, id="Fetching enabled"),
    ],
)
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

    # Create mock client
    mock_client_say_hello = mocker.patch.object(HelloWorldClient, "say_hello", return_value="Hello Test")

    # Mock fetch_alerts function
    mock_fetch_alerts = mocker.patch("HelloWorldV2.fetch_alerts")

    # Create params with is_fetch set accordingly
    params = HelloWorldParams(
        url="https://api.example.com",
        credentials=Credentials(password=DUMMY_VALID_API_KEY),
        is_fetch=is_fetch,
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
            "client": client,
            "max_fetch": 1,
            "last_run": HelloWorldLastRun(),
            "severity": params.severity,
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

    args = HelloWorldGetEventsArgs(severity=HelloWorldSeverity.HIGH, offset=0, limit=10, should_push_events=False)
    # Execute command
    get_events_command(client, args)

    # Assertions
    assert mock_get_alert_list.call_count == 1
    # Verify the call was made with correct parameters
    assert mock_get_alert_list.call_args.kwargs == {
        "client": client,
        "start_offset": 0,
        "severity": HelloWorldSeverity.HIGH,
        "limit": 10,
        "should_push": False,
    }

    # Verify tableToMarkdown was called with correct args
    assert mock_table_to_markdown.call_count == 1
    assert mock_table_to_markdown.call_args.args == ("HelloWorld Events", mock_events)


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




@pytest.mark.parametrize(
    "alert_id,severity,limit,expected_method",
    [
        pytest.param(123, None, 10, "get_alert", id="With alert_id"),
        pytest.param(None, HelloWorldSeverity.HIGH, 10, "get_alert_list", id="With severity"),
    ],
)
def test_alert_list_command(mocker: MockerFixture, alert_id: int | None, severity: HelloWorldSeverity | None, limit: int, expected_method: str):
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
    expected_formatted_incidents = format_as_incidents(mock_alerts, id_field="id", occurred_field="date", severity_field="severity")

    # Mock helper functions
    mock_demisto_incidents = mocker.patch("HelloWorldV2.demisto.incidents")

    # Execute function
    create_incidents(mock_alerts)

    # Assertions
    assert mock_demisto_incidents.call_count == 1
    assert mock_demisto_incidents.call_args.args[0] ==  expected_formatted_incidents
