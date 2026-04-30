# bandit: skip-file

import importlib
import json
import sys
import types
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _install_fake_demisto_modules() -> None:
    """Install lightweight fake XSOAR modules before importing the integration."""
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

    urllib3_module = types.ModuleType("urllib3")

    class InsecureRequestWarning(Warning):
        pass

    urllib3_module.disable_warnings = MagicMock()
    urllib3_module.exceptions = types.SimpleNamespace(
        InsecureRequestWarning=InsecureRequestWarning,
    )

    csp_module = types.ModuleType("CommonServerPython")

    class DemistoException(Exception):
        pass

    class BaseClient:
        def __init__(
            self,
            base_url=None,
            headers=None,
            verify=True,
            proxy=False,
            ok_codes=None,
        ):
            self.base_url = base_url
            self.headers = headers
            self._verify = verify
            self.proxy = proxy
            self.ok_codes = ok_codes

        def _http_request(self, method, url_suffix=None, **kwargs):
            raise NotImplementedError("_http_request should be mocked in tests")

    def argToList(value, separator=","):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            return [item.strip() for item in value.split(separator) if item.strip()]
        return [value]

    def arg_to_number(value):
        if value is None or isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def tableToMarkdown(title, data, headers=None):
        return f"{title}: {data}"

    class CommandResults:
        def __init__(
            self,
            readable_output=None,
            outputs_prefix=None,
            outputs_key_field=None,
            outputs=None,
            indicator=None,
            raw_response=None,
            scheduled_command=None,
        ):
            self.readable_output = readable_output
            self.outputs_prefix = outputs_prefix
            self.outputs_key_field = outputs_key_field
            self.outputs = outputs
            self.indicator = indicator
            self.raw_response = raw_response
            self.scheduled_command = scheduled_command

    class ScheduledCommand:
        def __init__(self, command=None, next_run_in_seconds=None, args=None):
            self.command = command
            self.next_run_in_seconds = next_run_in_seconds
            self.args = args or {}

    def return_results(value):
        return value

    def return_error(message):
        raise Exception(message)

    def LOG(message):
        return message

    class DBotScoreReliability:
        A_PLUS = "A+"
        A = "A"
        B = "B"
        C = "C"
        D = "D"
        E = "E"
        F = "F"

    class DBotScoreType:
        IP = "IP"
        EMAIL = "Email"
        URL = "URL"
        FILE = "File"
        PHONE = "Phone"
        ACCOUNT = "Account"
        GENERIC = "Generic"
        CUSTOM = "Custom"

    class Common:
        class DBotScore:
            BAD = 3
            SUSPICIOUS = 2
            NONE = 0

            def __init__(
                self,
                indicator,
                indicator_type,
                score,
                integration_name,
                reliability,
            ):
                self.indicator = indicator
                self.indicator_type = indicator_type
                self.score = score
                self.integration_name = integration_name
                self.reliability = reliability

        class IP:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class EMAIL:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class URL:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        class File:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

    csp_module.BaseClient = BaseClient
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
def integration_module():
    _install_fake_demisto_modules()

    if "IPQualityScore" in sys.modules:
        del sys.modules["IPQualityScore"]

    module = importlib.import_module("IPQualityScore")

    return module


@pytest.fixture
def client(integration_module):
    return integration_module.Client(
        base_url="https://ipqualityscore.com/api/json",
        headers={"IPQS-KEY": "test-key"},
        verify=False,
        proxy=False,
    )


@pytest.fixture
def sample_password():
    return uuid.uuid4().hex


def load_test_data(filename):
    test_data_dir = Path(__file__).parent / "test_data"
    with open(test_data_dir / filename, encoding="utf-8") as fh:
        return json.load(fh)


def test_test_module_success(integration_module, client):
    with patch.object(client, "reputation_request", return_value={"success": True}):
        assert integration_module.test_module(client) == "ok"


def test_test_module_failure(integration_module, client):
    with (
        patch.object(
            client,
            "reputation_request",
            return_value={"success": False, "message": "Invalid API key"},
        ),
        pytest.raises(integration_module.DemistoException, match="Invalid API key"),
    ):
        integration_module.test_module(client)


def test_ensure_dict_response_valid(integration_module):
    response = {"success": True}
    assert integration_module.ensure_dict_response(response, "test") == response


def test_ensure_dict_response_invalid(integration_module):
    with pytest.raises(integration_module.DemistoException, match="expected dict"):
        integration_module.ensure_dict_response(["bad"], "test")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (10, 0),
        (75, 2),
        (90, 3),
    ],
)
def test_calculate_score(integration_module, value, expected):
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
def test_was_leaked(integration_module, result, expected):
    assert integration_module.was_leaked(result) is expected


def test_get_thresholds_default(integration_module):
    assert integration_module.get_thresholds({}, "ip") == (75, 90)


def test_get_thresholds_from_params(integration_module):
    params = {
        "ip_suspicious_score_threshold": "60",
        "ip_malicious_score_threshold": "95",
    }
    assert integration_module.get_thresholds(params, "ip") == (60, 95)


def test_get_file_thresholds_default(integration_module):
    assert integration_module.get_file_thresholds({}) == (1, 4)


def test_validate_ip_valid(integration_module):
    assert integration_module.validate_ip("8.8.8.8") == "8.8.8.8"


def test_validate_ip_invalid(integration_module):
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_ip("999.999.999.999")


def test_validate_email_valid(integration_module):
    assert integration_module.validate_email("test@example.com") == "test@example.com"


def test_validate_email_invalid(integration_module):
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_email("bad-email")


def test_validate_phone_valid(integration_module):
    assert integration_module.validate_phone("+14155552671") == "+14155552671"


def test_validate_phone_invalid(integration_module):
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_phone("bad-phone")


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path",
        "example.com",
    ],
)
def test_validate_url_or_domain_valid(integration_module, value):
    assert integration_module.validate_url_or_domain(value) == value


def test_validate_url_or_domain_invalid(integration_module):
    with pytest.raises(integration_module.DemistoException):
        integration_module.validate_url_or_domain("not valid url")


def test_validate_non_empty(integration_module):
    assert integration_module.validate_non_empty(" user ", "Username") == "user"

    with pytest.raises(integration_module.DemistoException, match="Username cannot be empty"):
        integration_module.validate_non_empty(" ", "Username")


def test_ip_command_with_test_data(integration_module, client):
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


def test_email_command_with_test_data(integration_module, client):
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


def test_url_command_with_test_data(integration_module, client):
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


def test_phone_command_with_test_data(integration_module, client):
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


def test_leaked_username_command(integration_module, client):
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


def test_leaked_password_command(integration_module, client, sample_password):
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


def test_leaked_email_command(integration_module, client):
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


def test_flatten_engine_results_with_valid_result(integration_module):
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


def test_flatten_engine_results_with_non_list_result(integration_module):
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
def test_extract_detected_scans_variants(integration_module, scan_result, expected):
    assert integration_module.extract_detected_scans(scan_result) == expected


def test_normalize_scan_result(integration_module):
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


def test_build_file_scan_command_result(integration_module):
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


def test_build_url_file_scan_command_result(integration_module):
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


def test_file_command_cached_lookup(integration_module, client):
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
        results = integration_module.file_command(
            client,
            {"entry_id": "123"},
            1,
            4,
            "A - Completely reliable",
        )

    assert len(results) == 1
    assert results[0].outputs_prefix == "IPQualityScore.FileScan"
    assert results[0].outputs["file_name"] == "sample.exe"
    mocked_request.assert_called_once_with(is_lookup=True, file_path="/tmp/sample.exe")


def test_file_command_missing_entry_id(integration_module, client):
    with pytest.raises(integration_module.DemistoException, match="entry_id is required"):
        integration_module.file_command(
            client,
            {},
            1,
            4,
            "A - Completely reliable",
        )


def test_file_command_pending_returns_scheduled_command(integration_module, client):
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


def test_file_command_poll_completed(integration_module, client):
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


def test_url_file_command_cached_lookup(integration_module, client):
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
        results = integration_module.url_file_command(
            client,
            {"url": "https://example.com"},
            1,
            4,
            "A - Completely reliable",
        )

    assert len(results) == 1
    assert results[0].outputs_prefix == "IPQualityScore.URLFileScan"
    assert results[0].indicator.url == "https://example.com"


def test_url_file_command_missing_url(integration_module, client):
    with pytest.raises(integration_module.DemistoException, match="url is required"):
        integration_module.url_file_command(
            client,
            {},
            1,
            4,
            "A - Completely reliable",
        )


def test_url_file_command_pending_returns_scheduled_command(integration_module, client):
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


def test_url_file_command_poll_completed(integration_module, client):
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


def test_get_retry_count_accepts_string(integration_module):
    integration_module.demisto.getIntegrationContext.side_effect = None
    integration_module.demisto.getIntegrationContext.return_value = {
        "ipqs_retry_count_req-1": "2",
    }

    assert integration_module.get_retry_count("req-1") == 2


def test_get_retry_count_rejects_bad_string(integration_module):
    integration_module.demisto.getIntegrationContext.side_effect = None
    integration_module.demisto.getIntegrationContext.return_value = {
        "ipqs_retry_count_req-1": "bad",
    }

    with pytest.raises(integration_module.DemistoException, match="Invalid retry count"):
        integration_module.get_retry_count("req-1")
