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

import pytest
from CommonServerPython import DemistoException


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

        with pytest.raises(DemistoException) as exc_info:
            Credentials()  # type: ignore[call-arg]
        assert "password" in str(exc_info.value).lower()


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
            pytest.param(100, 50, id="Exceeds limit capped"),
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
        assert params.severity == HelloWorldSeverity.LOW
        assert params.first_fetch == "3 days"
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

        with pytest.raises(DemistoException) as exc_info:
            HelloWorldParams(credentials={"password": "secret"})  # type: ignore[call-arg]
        assert "url" in str(exc_info.value).lower()

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

        with pytest.raises(DemistoException) as exc_info:
            HelloWorldParams(url="https://api.example.com")  # type: ignore[call-arg,arg-type]
        assert "credentials" in str(exc_info.value).lower()

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

        with pytest.raises(DemistoException) as exc_info:
            HelloWorldParams(
                url="not-a-valid-url",  # type: ignore[arg-type]
                credentials={"password": "secret"},  # type: ignore[arg-type]
            )
        assert "url" in str(exc_info.value).lower()


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

        with pytest.raises(DemistoException) as exc_info:
            HelloworldSayHelloArgs()  # type: ignore[call-arg]
        assert "name" in str(exc_info.value).lower()


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

        with pytest.raises(DemistoException) as exc_info:
            HelloworldAlertListArgs(alert_id=alert_id, severity=severity)
        assert "either" in str(exc_info.value).lower()


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

        with pytest.raises(DemistoException) as exc_info:
            HelloworldAlertNoteCreateArgs(alert_id=alert_id, note_text="Test note")
        assert "positive" in str(exc_info.value).lower()

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

        with pytest.raises(DemistoException) as exc_info:
            HelloworldAlertNoteCreateArgs(alert_id=1)  # type: ignore[call-arg]
        assert "note_text" in str(exc_info.value).lower()


# ========== HelloWorldGetEventsArgs Model Tests ==========


class TestHelloWorldGetEventsArgs:
    @pytest.mark.parametrize(
        "limit,should_push_events",
        [
            pytest.param(None, False, id="Defaults"),
            pytest.param(100, True, id="With limit and push"),
            pytest.param(50, False, id="With limit no push"),
        ],
    )
    def test_get_events_args_valid(self, limit, should_push_events):
        """
        Given:
            - Optional limit and should_push_events values.
        When:
            - Initializing HelloWorldGetEventsArgs.
        Then:
            - Assert model is created successfully with correct values.
        """
        from HelloWorldV2 import HelloWorldGetEventsArgs

        args = HelloWorldGetEventsArgs(limit=limit, should_push_events=should_push_events)
        assert args.limit == limit
        assert args.should_push_events == should_push_events


# ========== HelloWorldJobSubmitArgs Model Tests ==========


class TestHelloWorldJobSubmitArgs:
    @pytest.mark.parametrize(
        "interval,timeout",
        [
            pytest.param(None, None, id="Defaults"),
            pytest.param(60, 600, id="Custom values"),
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

        with pytest.raises(DemistoException) as exc_info:
            HelloWorldJobPollArgs()  # type: ignore[call-arg]
        assert "job_id" in str(exc_info.value).lower()


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

        with pytest.raises(DemistoException) as exc_info:
            IpArgs()  # type: ignore[call-arg]
        assert "ip" in str(exc_info.value).lower()

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
        with pytest.raises(ValueError) as exc_info:
            _ = args.ips
        assert "no valid ip" in str(exc_info.value).lower()
