# bandit: skip-file
"""
IPQualityScore Integration - Comprehensive Test Suite

This module provides comprehensive tests for the IPQualityScore XSOAR integration,
covering reputation lookups (IP, email, URL, phone), leak detection, and malware scanning.
Tests are organized into logical sections for better maintainability.
"""

import importlib
import json
import sys
import types
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


def _install_fake_demisto_modules() -> None:
    """
    Install lightweight fake XSOAR modules before importing the integration.

    This function sets up mock implementations of demistomock, urllib3,
    CommonServerPython, and CommonServerUserPython modules to allow testing
    without a full XSOAR environment.
    """
    # Setup demistomock module
    demisto_module = types.ModuleType("demistomock")
    demisto_module.getFilePath = MagicMock()
    demisto_module.params = MagicMock(return_value={})
    demisto_module.args = MagicMock(return_value={})
    demisto_module.command = MagicMock(return_value="")
    demisto_module.results = MagicMock()
    demisto_module.debug = MagicMock()
    demisto_module.error = MagicMock()
    demisto_module.getIntegrationContext = MagicMock(return_value={})
    demisto_module.setIntegrationContext = MagicMock()

    # Setup urllib3 module
    urllib3_module = types.ModuleType("urllib3")

    class InsecureRequestWarning(Warning):
        """Mock warning class for insecure requests."""

    urllib3_module.disable_warnings = MagicMock()
    urllib3_module.exceptions = types.SimpleNamespace(
        InsecureRequestWarning=InsecureRequestWarning,
    )

    # Setup CommonServerPython module
    csp_module = types.ModuleType("CommonServerPython")

    class DemistoException(Exception):
        """Mock exception from XSOAR."""

    class ContentClient:
        """Mock ContentClient base class for API interactions."""

        def __init__(
            self,
            base_url: str | None = None,
            headers: dict[str, str] | None = None,
            verify: bool = True,
            proxy: bool = False,
            ok_codes: list[int] | None = None,
        ) -> None:
            self.base_url = base_url
            self.headers = headers
            self._verify = verify
            self.proxy = proxy
            self.ok_codes = ok_codes

        def _http_request(self, method: str, url_suffix: str | None = None, **kwargs: Any) -> Any:
            """Raise NotImplementedError to be mocked in tests."""
            raise NotImplementedError("_http_request should be mocked in tests")

    class BaseClient:
        """Mock BaseClient for backward compatibility."""

        def __init__(
            self,
            base_url: str | None = None,
            headers: dict[str, str] | None = None,
            verify: bool = True,
            proxy: bool = False,
            ok_codes: list[int] | None = None,
        ) -> None:
            self.base_url = base_url
            self.headers = headers
            self._verify = verify
            self.proxy = proxy
            self.ok_codes = ok_codes

        def _http_request(self, method: str, url_suffix: str | None = None, **kwargs: Any) -> Any:
            """Raise NotImplementedError to be mocked in tests."""
            raise NotImplementedError("_http_request should be mocked in tests")

    def argToList(value: Any, separator: str = ",") -> list[str]:
        """Convert various types to list."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(separator) if item.strip()]
        return [value]

    def arg_to_number(value: Any) -> int | None:
        """Convert value to integer."""
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def tableToMarkdown(title: str, data: Any, headers: list[str] | None = None) -> str:
        """Convert table data to markdown format."""
        return f"{title}: {data}"

    class CommandResults:
        """Mock CommandResults for test assertions."""

        def __init__(
            self,
            readable_output: str | None = None,
            outputs_prefix: str | None = None,
            outputs_key_field: str | None = None,
            outputs: Any = None,
            indicator: Any = None,
            raw_response: Any = None,
            scheduled_command: Any = None,
        ) -> None:
            self.readable_output = readable_output
            self.outputs_prefix = outputs_prefix
            self.outputs_key_field = outputs_key_field
            self.outputs = outputs
            self.indicator = indicator
            self.raw_response = raw_response
            self.scheduled_command = scheduled_command

    class ScheduledCommand:
        """Mock ScheduledCommand for polling operations."""

        def __init__(
            self,
            command: str | None = None,
            next_run_in_seconds: int | None = None,
            args: dict[str, Any] | None = None,
        ) -> None:
            self.command = command
            self.next_run_in_seconds = next_run_in_seconds
            self.args = args or {}

    def return_results(value: Any) -> Any:
        """Return results mock."""
        return value

    def return_error(message: str) -> None:
        """Raise exception on error."""
        raise Exception(message)

    def LOG(message: str) -> str:
        """Log message mock."""
        return message

    class DBotScoreReliability:
        """Mock DBotScore reliability constants."""

        A_PLUS = "A+"
        A = "A"
        B = "B"
        C = "C"
        D = "D"
        E = "E"
        F = "F"

    class DBotScoreType:
        """Mock DBotScore type constants."""

        IP = "IP"
        EMAIL = "Email"
        URL = "URL"
        FILE = "File"
        PHONE = "Phone"
        ACCOUNT = "Account"
        GENERIC = "Generic"
        CUSTOM = "Custom"

    class Common:
        """Mock Common namespace for indicators."""

        class DBotScore:
            """Mock DBotScore indicator."""

            BAD = 3
            SUSPICIOUS = 2
            NONE = 0

            def __init__(
                self,
                indicator: str,
                indicator_type: str,
                score: int,
                integration_name: str,
                reliability: str,
            ) -> None:
                self.indicator = indicator
                self.indicator_type = indicator_type
                self.score = score
                self.integration_name = integration_name
                self.reliability = reliability

        class IP:
            """Mock IP indicator."""

            def __init__(self, **kwargs: Any) -> None:
                self.__dict__.update(kwargs)

        class EMAIL:
            """Mock EMAIL indicator."""

            def __init__(self, **kwargs: Any) -> None:
                self.__dict__.update(kwargs)

        class URL:
            """Mock URL indicator."""

            def __init__(self, **kwargs: Any) -> None:
                self.__dict__.update(kwargs)

        class File:
            """Mock File indicator."""

            def __init__(self, **kwargs: Any) -> None:
                self.__dict__.update(kwargs)

    # Register all mock modules
    csp_module.BaseClient = BaseClient
    csp_module.ContentClient = ContentClient
    csp_module.DemistoException = DemistoException
    csp_module.argToList = argToList
    csp_module.arg_to_number = arg_to_number
    csp_module.tableToMarkdown = tableToMarkdown
    csp_module.CommandResults = CommandResults
    csp_module.ScheduledCommand = ScheduledCommand
    csp_module.return_results = return_results
    csp_module.return_error = return_error
    csp_module.LOG = LOG
    csp_module.DBotScoreReliability = DBotScoreReliability
    csp_module.DBotScoreType = DBotScoreType
    csp_module.Common = Common

    csu_module = types.ModuleType("CommonServerUserPython")

    sys.modules["demistomock"] = demisto_module
    sys.modules["urllib3"] = urllib3_module
    sys.modules["CommonServerPython"] = csp_module
    sys.modules["CommonServerUserPython"] = csu_module


@pytest.fixture(scope="module")
def integration_module() -> types.ModuleType:
    """
    Fixture to load the IPQualityScore integration module.

    Sets up mock XSOAR modules before importing, ensuring the integration
    can be tested without a full XSOAR environment. Module-scoped to
    optimize performance across multiple tests.

    Returns:
        types.ModuleType: The loaded IPQualityScore module.
    """
    _install_fake_demisto_modules()

    if "IPQualityScore" in sys.modules:
        del sys.modules["IPQualityScore"]

    module = importlib.import_module("IPQualityScore")
    return module


@pytest.fixture
def client(integration_module: types.ModuleType) -> Any:
    """
    Fixture to create a test Client instance.

    Creates an IPQualityScore Client with test configuration and disabled
    SSL verification for testing purposes.

    Args:
        integration_module: The loaded IPQualityScore integration module.

    Returns:
        Any: An initialized Client instance ready for testing.
    """
    return integration_module.Client(
        base_url="https://ipqualityscore.com/api/json",
        headers={"IPQS-KEY": "test-key"},
        verify=False,
        proxy=False,
    )


@pytest.fixture
def sample_password() -> str:
    """
    Fixture to generate a random password for testing.

    Generates a unique UUID-based password string for password leak tests.
    This ensures test isolation and prevents hardcoded test values.

    Returns:
        str: A randomly generated password string.
    """
    return uuid.uuid4().hex


def load_test_data(filename: str) -> dict[str, Any]:
    """
    Load JSON test data from the test_data directory.

    Reads and parses JSON test data files stored alongside the test module.
    This allows for realistic API response testing without network calls.

    Args:
        filename: Name of the JSON file to load from test_data directory.

    Returns:
        dict[str, Any]: Parsed JSON content from the test data file.

    Raises:
        FileNotFoundError: If the specified test data file doesn't exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    test_data_dir = Path(__file__).parent / "test_data"
    with open(test_data_dir / filename, encoding="utf-8") as fh:
        return json.load(fh)


# ============================================================================
# Test Module Validation Tests
# ============================================================================


def test_test_module_success(integration_module: types.ModuleType, client: Any) -> None:
    """Test that test_module succeeds with valid API response."""
    with patch.object(client, "reputation_request", return_value={"success": True}):
        assert integration_module.test_module(client) == "ok"


def test_test_module_failure(integration_module: types.ModuleType, client: Any) -> None:
    """Test that test_module raises exception when API response indicates failure."""
    with (
        patch.object(
            client,
            "reputation_request",
            return_value={"success": False, "message": "Invalid API key"},
        ),
        pytest.raises(integration_module.DemistoException, match="Invalid API key"),
    ):
        integration_module.test_module(client)


# ============================================================================
# Response Validation Tests
# ============================================================================


def test_ensure_dict_response_valid(integration_module: types.ModuleType) -> None:
    """Test that ensure_dict_response accepts valid dictionary responses."""
    response = {"success": True}
    assert integration_module.ensure_dict_response(response, "test") == response


def test_ensure_dict_response_invalid(integration_module: types.ModuleType) -> None:
    """Test that ensure_dict_response rejects non-dictionary responses."""
    with pytest.raises(integration_module.DemistoException, match="expected dict"):
        integration_module.ensure_dict_response(["bad"], "test")


# ============================================================================
# Score Calculation Tests
# ============================================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (10, 0),  # Below suspicious threshold
        (75, 2),  # At suspicious threshold
        (90, 3),  # At malicious threshold
    ],
)
def test_calculate_score(integration_module: types.ModuleType, value: int, expected: int) -> None:
    """Test score calculation against various thresholds."""
    assert integration_module.calculate_score(value, 75, 90) == expected


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"leaked": True}, True),
        ({"exposed": True}, True),
        ({"leaked": False, "exposed": False}, False),
        ({}, False),
    ],
)
def test_was_leaked(integration_module: types.ModuleType, result: dict[str, Any], expected: bool) -> None:
    """Test leak detection from API response fields."""
    assert integration_module.was_leaked(result) is expected


# ============================================================================
# Threshold Configuration Tests
# ============================================================================


def test_get_thresholds_default(integration_module: types.ModuleType) -> None:
    """Test that get_thresholds returns default values when not configured."""
    assert integration_module.get_thresholds({}, "ip") == (75, 90)


def test_get_thresholds_from_params(integration_module: types.ModuleType) -> None:
    """Test that get_thresholds properly retrieves custom parameters."""
    params = {
        "ip_suspicious_score_threshold": "60",
        "ip_malicious_score_threshold": "95",
    }
    assert integration_module.get_thresholds(params, "ip") == (60, 95)


def test_get_file_thresholds_default(integration_module: types.ModuleType) -> None:
    """Test that get_file_thresholds returns correct default values."""
    assert integration_module.get_file_thresholds({}) == (1, 4)


# ============================================================================
# Input Validation Tests
# ============================================================================


def test_validate_ip_valid(integration_module: types.ModuleType) -> None:
    """Test that valid IP addresses pass validation."""
    assert integration_module.validate_ip("8.8.8.8") == "8.8.8.8"


def test_validate_ip_invalid(integration_module: types.ModuleType) -> None:
    """Test that invalid IP addresses raise DemistoException."""
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_ip("999.999.999.999")


def test_validate_email_valid(integration_module: types.ModuleType) -> None:
    """Test that valid email addresses pass validation."""
    assert integration_module.validate_email("test@example.com") == "test@example.com"


def test_validate_email_invalid(integration_module: types.ModuleType) -> None:
    """Test that invalid email addresses raise DemistoException."""
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_email("bad-email")


def test_validate_phone_valid(integration_module: types.ModuleType) -> None:
    """Test that valid phone numbers pass validation."""
    assert integration_module.validate_phone("+14155552671") == "+14155552671"


def test_validate_phone_invalid(integration_module: types.ModuleType) -> None:
    """Test that invalid phone numbers raise DemistoException."""
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_phone("bad-phone")


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path",
        "example.com",
    ],
)
def test_validate_url_or_domain_valid(integration_module: types.ModuleType, value: str) -> None:
    """Test that valid URLs and domains pass validation."""
    assert integration_module.validate_url_or_domain(value) == value


def test_validate_url_or_domain_invalid(integration_module: types.ModuleType) -> None:
    """Test that invalid URLs and domains raise DemistoException."""
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_url_or_domain("not valid url")


def test_validate_non_empty(integration_module: types.ModuleType) -> None:
    """Test that validate_non_empty strips whitespace and validates content."""
    assert integration_module.validate_non_empty(" user ", "Username") == "user"

    with pytest.raises(integration_module.DemistoException, match="Username cannot be empty"):
        integration_module.validate_non_empty(" ", "Username")


# ============================================================================
# IP Reputation Command Tests
# ============================================================================


def test_ip_command_with_test_data(integration_module: types.ModuleType, client: Any) -> None:
    """Test IP reputation lookup with realistic API response."""
    response = load_test_data("ip_response.json")

    with patch.object(client, "reputation_request", return_value=response):
        result = integration_module.ip_command(
            client,
            {"ip": "15.99.160.255"},
            75,
            85,
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.IP"
    assert result[0].outputs["address"] == "15.99.160.255"
    assert result[0].indicator.dbot_score.score == 3
    assert result[0].indicator.geo_country == "US"


# ============================================================================
# Email Reputation Command Tests
# ============================================================================


def test_email_command_with_test_data(integration_module: types.ModuleType, client: Any) -> None:
    """Test email reputation lookup with realistic API response."""
    response = load_test_data("email_response.json")

    with patch.object(client, "reputation_request", return_value=response):
        result = integration_module.email_command(
            client,
            {"email": "example@gmail.com"},
            75,
            85,
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.Email"
    assert result[0].outputs["address"] == "example@gmail.com"
    assert result[0].indicator.dbot_score.score == 3


# ============================================================================
# URL Reputation Command Tests
# ============================================================================


def test_url_command_with_test_data(integration_module: types.ModuleType, client: Any) -> None:
    """Test URL reputation lookup with realistic API response."""
    response = load_test_data("url_response.json")

    with patch.object(client, "reputation_request", return_value=response):
        result = integration_module.url_command(
            client,
            {"url": "https://www.example.com"},
            75,
            85,
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.Url"
    assert result[0].outputs["url"] == "https://www.example.com"
    assert result[0].indicator.dbot_score.score in (0, 2, 3)


# ============================================================================
# Phone Reputation Command Tests
# ============================================================================


def test_phone_command_with_test_data(integration_module: types.ModuleType, client: Any) -> None:
    """Test phone reputation lookup with realistic API response."""
    response = load_test_data("phone_response.json")

    with patch.object(client, "reputation_request", return_value=response):
        result = integration_module.phone_command(
            client,
            {"phone": "+14155552671"},
            75,
            85,
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.Phone"
    assert result[0].outputs["phone"] == "+14155552671"
    assert result[0].indicator.score in (0, 2, 3)


# ============================================================================
# Leak Detection Command Tests
# ============================================================================


def test_leaked_username_command(integration_module: types.ModuleType, client: Any) -> None:
    """Test username leak detection."""
    with patch.object(client, "leaked_request", return_value={"success": True, "leaked": True}):
        result = integration_module.leaked_username_command(
            client,
            {"username": "admin"},
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.Username"
    assert result[0].outputs["username"] == "admin"
    assert result[0].indicator.score == 3


def test_leaked_password_command(integration_module: types.ModuleType, client: Any, sample_password: str) -> None:
    """Test password leak detection returns no score when password is not exposed."""
    with patch.object(client, "leaked_request", return_value={"success": True, "exposed": False}):
        result = integration_module.leaked_password_command(
            client,
            {"password": sample_password},
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.Password"
    assert result[0].outputs["password"] == sample_password
    assert result[0].indicator.score == 0


def test_leaked_email_command(integration_module: types.ModuleType, client: Any) -> None:
    """Test email leak detection."""
    with patch.object(client, "leaked_request", return_value={"success": True, "exposed": True}):
        result = integration_module.leaked_email_command(
            client,
            {"email": "user@example.com"},
            "A - Completely reliable",
        )

    assert len(result) == 1
    assert result[0].outputs_prefix == "IPQualityScore.LeakedEmail"
    assert result[0].outputs["email"] == "user@example.com"
    assert result[0].indicator.dbot_score.score == 3


# ============================================================================
# Malware Scan Engine Result Processing Tests
# ============================================================================


def test_flatten_engine_results_with_valid_result(integration_module: types.ModuleType) -> None:
    """Test that engine results are properly flattened for display."""
    scan_result = {
        "status": "cached",
        "result": [
            {"name": "EngineA", "detected": True, "error": False},
            {"name": "EngineB", "detected": False, "error": False},
        ],
    }

    flattened = integration_module.flatten_engine_results(scan_result)

    assert "result" not in flattened
    assert flattened["EngineA"] == {"detected": True, "error": False}
    assert flattened["EngineB"] == {"detected": False, "error": False}


def test_flatten_engine_results_with_non_list_result(integration_module: types.ModuleType) -> None:
    """Test that flatten_engine_results handles non-list result fields."""
    scan_result = {"status": "cached", "result": {"bad": "format"}}

    flattened = integration_module.flatten_engine_results(scan_result)

    assert flattened == {"status": "cached"}


@pytest.mark.parametrize(
    ("scan_result", "expected"),
    [
        (
            {
                "result": [
                    {"name": "A", "detected": True},
                    {"name": "B", "detected": False},
                ],
            },
            1,
        ),
        ({"detected_scans": "3"}, 3),
        ({}, 0),
    ],
)
def test_extract_detected_scans_variants(
    integration_module: types.ModuleType,
    scan_result: dict[str, Any],
    expected: int,
) -> None:
    """Test detection count extraction from various result formats."""
    assert integration_module.extract_detected_scans(scan_result) == expected


def test_normalize_scan_result(integration_module: types.ModuleType) -> None:
    """Test that scan results are properly normalized for XSOAR."""
    normalized = integration_module.normalize_scan_result(
        {
            "file_size": "123",
            "update_url": "https://example.com/update",
            "result": [
                {"name": "EngineA", "detected": True},
                {"name": "EngineB", "detected": False},
            ],
        }
    )

    assert "update_url" not in normalized
    assert normalized["file_size"] == 123
    assert normalized["detected_scans"] == 1


# ============================================================================
# File Scan Command Result Building Tests
# ============================================================================


def test_build_file_scan_command_result(integration_module: types.ModuleType) -> None:
    """Test file scan command result construction."""
    result = integration_module.build_file_scan_command_result(
        scan_result={
            "status": "cached",
            "file_hash": "abc123",
            "file_size": 10,
            "detected_scans": 4,
            "result": [{"name": "EngineA", "detected": True, "error": False}],
        },
        file_name="sample.exe",
        suspicious_threshold=1,
        malicious_threshold=4,
        parsed_reliability="F",
    )

    assert result.outputs_prefix == "IPQualityScore.FileScan"
    assert result.outputs_key_field == "file_name"
    assert result.outputs["file_name"] == "sample.exe"
    assert result.indicator.name == "sample.exe"
    assert result.indicator.dbot_score.score == 3


def test_build_url_file_scan_command_result(integration_module: types.ModuleType) -> None:
    """Test URL file scan command result construction."""
    result = integration_module.build_url_file_scan_command_result(
        scan_result={
            "status": "cached",
            "detected_scans": 1,
            "url": "https://evil.example",
        },
        url_value="https://evil.example",
        suspicious_threshold=1,
        malicious_threshold=4,
        parsed_reliability="F",
    )

    assert result.outputs_prefix == "IPQualityScore.URLFileScan"
    assert result.outputs_key_field == "url"
    assert result.indicator.url == "https://evil.example"
    assert result.indicator.dbot_score.score == 2


# ============================================================================
# File Scanning Command Tests
# ============================================================================


def test_file_command_cached_lookup(integration_module: types.ModuleType, client: Any) -> None:
    """Test file command with cached scan result."""
    integration_module.demisto.getFilePath.return_value = {
        "path": "/tmp/sample.exe",
        "name": "sample.exe",
    }

    with patch.object(
        client,
        "malware_file_request",
        return_value={
            "status": "cached",
            "file_hash": "hash123",
            "file_size": "50",
            "detected_scans": "0",
            "result": [],
        },
    ) as mocked_request:
        result = integration_module.file_command(
            client,
            {"entry_id": "123"},
            1,
            4,
            "A - Completely reliable",
        )

    # file_command returns a single CommandResults when cached
    assert result.outputs_prefix == "IPQualityScore.FileScan"
    assert result.outputs["file_name"] == "sample.exe"
    mocked_request.assert_called_once_with(is_lookup=True, file_path="/tmp/sample.exe")


def test_file_command_missing_entry_id(integration_module: types.ModuleType, client: Any) -> None:
    """Test file command raises error when entry_id is missing."""
    with pytest.raises(integration_module.DemistoException, match="entry_id is required"):
        integration_module.file_command(
            client,
            {},
            1,
            4,
            "A - Completely reliable",
        )


def test_file_command_pending_returns_scheduled_command(integration_module: types.ModuleType, client: Any) -> None:
    """Test file command returns scheduled command when scan is pending."""
    context = {}

    integration_module.demisto.getFilePath.return_value = {
        "path": "/tmp/sample.exe",
        "name": "sample.exe",
    }
    integration_module.demisto.command.return_value = "ipqs-file-scan"
    integration_module.demisto.getIntegrationContext.side_effect = lambda: context
    integration_module.demisto.setIntegrationContext.side_effect = lambda updated: context.update(updated)

    with patch.object(
        client,
        "malware_file_request",
        side_effect=[
            {"status": "not_found"},
            {"status": "pending", "request_id": "req-123"},
        ],
    ):
        result = integration_module.file_command(
            client,
            {"entry_id": "123"},
            1,
            4,
            "A - Completely reliable",
        )

    assert result.scheduled_command.command == "ipqs-file-scan"
    assert result.scheduled_command.args["request_id"] == "req-123"
    assert context["ipqs_retry_count_req-123"] == 1


def test_file_command_poll_completed(integration_module: types.ModuleType, client: Any) -> None:
    """Test file command polling returns results when scan completes."""
    context = {"ipqs_retry_count_req-123": 2}
    integration_module.demisto.getIntegrationContext.side_effect = lambda: context
    integration_module.demisto.setIntegrationContext.side_effect = lambda updated: context.clear() or context.update(updated)

    with patch.object(
        client,
        "poll_result",
        return_value={
            "status": "complete",
            "request_id": "req-123",
            "file_name": "sample.exe",
            "file_hash": "hash123",
            "file_size": "100",
            "detected_scans": "0",
            "result": [],
        },
    ):
        result = integration_module.file_command(
            client,
            {"request_id": "req-123"},
            1,
            4,
            "A - Completely reliable",
        )

    assert result.outputs_prefix == "IPQualityScore.FileScan"
    assert result.outputs["file_name"] == "sample.exe"
    assert "ipqs_retry_count_req-123" not in context


# ============================================================================
# URL File Scanning Command Tests
# ============================================================================


def test_url_file_command_cached_lookup(integration_module: types.ModuleType, client: Any) -> None:
    """Test URL file command with cached scan result."""
    with patch.object(
        client,
        "malware_url_request",
        return_value={
            "status": "cached",
            "file_size": "20",
            "detected_scans": "0",
            "result": [],
        },
    ):
        result = integration_module.url_file_command(
            client,
            {"url": "https://example.com"},
            1,
            4,
            "A - Completely reliable",
        )

    # url_file_command returns a single CommandResults when cached
    assert result.outputs_prefix == "IPQualityScore.URLFileScan"
    assert result.indicator.url == "https://example.com"


def test_url_file_command_missing_url(integration_module: types.ModuleType, client: Any) -> None:
    """Test URL file command raises error when URL is missing."""
    with pytest.raises(integration_module.DemistoException, match="url is required"):
        integration_module.url_file_command(
            client,
            {},
            1,
            4,
            "A - Completely reliable",
        )


def test_url_file_command_pending_returns_scheduled_command(integration_module: types.ModuleType, client: Any) -> None:
    """Test URL file command returns scheduled command when scan is pending."""
    context = {}

    integration_module.demisto.command.return_value = "ipqs-url-file-scan"
    integration_module.demisto.getIntegrationContext.side_effect = lambda: context
    integration_module.demisto.setIntegrationContext.side_effect = lambda updated: context.update(updated)

    with patch.object(
        client,
        "malware_url_request",
        side_effect=[
            {"status": "not_found"},
            {"status": "pending", "request_id": "req-url-123"},
        ],
    ):
        result = integration_module.url_file_command(
            client,
            {"url": "https://example.com"},
            1,
            4,
            "A - Completely reliable",
        )

    assert result.scheduled_command.command == "ipqs-url-file-scan"
    assert result.scheduled_command.args["request_id"] == "req-url-123"
    assert context["ipqs_retry_count_req-url-123"] == 1


def test_url_file_command_poll_completed(integration_module: types.ModuleType, client: Any) -> None:
    """Test URL file command polling returns results when scan completes."""
    context = {"ipqs_retry_count_req-url-123": 2}
    integration_module.demisto.getIntegrationContext.side_effect = lambda: context
    integration_module.demisto.setIntegrationContext.side_effect = lambda updated: context.clear() or context.update(updated)

    with patch.object(
        client,
        "poll_result",
        return_value={
            "status": "complete",
            "request_id": "req-url-123",
            "url": "https://example.com",
            "file_size": "100",
            "detected_scans": "0",
            "result": [],
        },
    ):
        result = integration_module.url_file_command(
            client,
            {"request_id": "req-url-123", "url": "https://example.com"},
            1,
            4,
            "A - Completely reliable",
        )

    assert result.outputs_prefix == "IPQualityScore.URLFileScan"
    assert result.indicator.url == "https://example.com"
    assert "ipqs_retry_count_req-url-123" not in context


# ============================================================================
# Retry Count Management Tests
# ============================================================================


def test_get_retry_count_accepts_string(integration_module: types.ModuleType) -> None:
    """Test get_retry_count correctly handles string-formatted retry counts."""
    integration_module.demisto.getIntegrationContext.side_effect = None
    integration_module.demisto.getIntegrationContext.return_value = {
        "ipqs_retry_count_req-1": "2",
    }

    assert integration_module.get_retry_count("req-1") == 2


def test_get_retry_count_rejects_bad_string(integration_module: types.ModuleType) -> None:
    """Test get_retry_count raises error for invalid string values."""
    integration_module.demisto.getIntegrationContext.side_effect = None
    integration_module.demisto.getIntegrationContext.return_value = {
        "ipqs_retry_count_req-1": "bad",
    }

    with pytest.raises(integration_module.DemistoException, match="Invalid retry count"):
        integration_module.get_retry_count("req-1")
