"""Unit tests for the SDK-backed ThreatZone integration.

The integration delegates all HTTP work to the official `threatzone` Python
SDK, so these tests mock the SDK client methods returning pydantic models
straight from the SDK's own type system.
"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, mock_open, patch

import pytest
import ThreatZone as integration
from CommonServerPython import DemistoException
from threatzone import (
    AnalysisTimeoutError,
    APIError,
    AuthenticationError,
    NotFoundError,
    ReportUnavailableError,
    YaraRulePendingError,
)
from threatzone import ThreatZone as ThreatZoneSDK
from threatzone.testing import FakeThreatZoneAPI, scenarios
from threatzone.types import (
    Artifact,
    ArtifactsResponse,
    ExtractedConfigsResponse,
    Indicator,
    IndicatorsResponse,
    IoC,
    IoCsResponse,
    SubmissionCreated,
    UserInfo,
    YaraRule,
    YaraRulesResponse,
)
from threatzone.types.indicators import ArtifactHashes, IndicatorLevels
from threatzone.types.config import MetafieldOption


def _user_info(api_used: int = 5, daily_used: int = 5, concurrent_used: int = 1) -> UserInfo:
    return UserInfo.model_validate(
        {
            "userInfo": {
                "email": "name@company.com",
                "fullName": "Test User",
                "workspace": {
                    "id": "ws-1",
                    "name": "ACME Lab",
                    "alias": "acme",
                    "private": True,
                    "type": "organization",
                },
                "limitsCount": {
                    "apiRequestCount": api_used,
                    "dailySubmissionCount": daily_used,
                    "concurrentSubmissionCount": concurrent_used,
                },
            },
            "plan": {
                "planName": "Enterprise",
                "startTime": "2025-01-01",
                "endTime": "2026-01-01",
                "subsTime": "yearly",
                "fileLimits": {"extensions": ["exe", "dll"], "fileSize": "256 MiB"},
                "submissionLimits": {
                    "apiLimit": 9999,
                    "dailyLimit": 999,
                    "concurrentLimit": 2,
                },
            },
            "modules": [
                {
                    "moduleId": "m1",
                    "moduleName": "Sandbox",
                    "startTime": "2025-01-01",
                    "endTime": "2026-01-01",
                },
                {
                    "moduleId": "m2",
                    "moduleName": "CDR",
                    "startTime": "2025-01-01",
                    "endTime": "2026-01-01",
                },
            ],
        }
    )


def _submission(level: str = "malicious", status: str = "completed", report_type: str = "dynamic"):
    """Build a minimal Submission via SDK model validation."""
    from threatzone.types.submissions import Submission

    payload = {
        "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
        "type": "file",
        "filename": "sample.exe",
        "hashes": {
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha256": "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0",
        },
        "level": level,
        "private": True,
        "tags": [],
        "reports": [{"type": report_type, "status": status, "level": level}],
        "overview": {"status": "completed"},
        "indicators": {
            "levels": {"malicious": 1, "suspicious": 0, "benign": 0},
            "artifactCount": 0,
        },
        "mitreTechniques": [],
        "createdAt": "2025-01-01T00:00:00Z",
        "updatedAt": "2025-01-01T00:00:00Z",
    }
    return Submission.model_validate(payload)


def _make_client() -> integration.Client:
    """Build a Client without spinning up the real httpx session."""
    with (
        patch.object(integration, "httpx") as mock_httpx,
        patch.object(integration, "ThreatZoneSDK") as mock_sdk,
    ):
        mock_httpx.Client.return_value = MagicMock()
        mock_sdk.return_value = MagicMock()
        return integration.Client(base_url="https://app.threat.zone", api_key="key", verify=True, proxy=False)


def _metafield(
    key: str,
    default: bool | int | str,
    *,
    active: bool = True,
    accessible: bool = True,
) -> MetafieldOption:
    return MetafieldOption.model_validate(
        {
            "key": key,
            "label": key,
            "description": key,
            "type": "select",
            "default": default,
            "active": active,
            "accessible": accessible,
            "options": None,
        }
    )


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestPureHelpers(unittest.TestCase):
    def test_normalize_sdk_base_url(self):
        assert integration.normalize_sdk_base_url("https://app.threat.zone") == "https://app.threat.zone/public-api"
        assert integration.normalize_sdk_base_url("https://app.threat.zone/public-api/") == "https://app.threat.zone/public-api"

    def test_normalize_sdk_base_url_rejects_missing_url(self):
        with pytest.raises(DemistoException, match="Server URL is required"):
            integration.normalize_sdk_base_url("  ")

    def test_parse_json_object_argument(self):
        assert integration.parse_json_object_argument('{"networkConfig":"id"}', "configurations") == {"networkConfig": "id"}
        with pytest.raises(DemistoException, match="JSON object"):
            integration.parse_json_object_argument("[]", "configurations")

    def test_parse_csv_and_bounded_integer_arguments(self):
        assert integration.parse_csv_list_argument(" malicious, suspicious, ") == [
            "malicious",
            "suspicious",
        ]
        assert integration.parse_bounded_int_argument("500", "limit", minimum=1, maximum=500) == 500
        with pytest.raises(DemistoException, match="between 1 and 500"):
            integration.parse_bounded_int_argument("501", "limit", minimum=1, maximum=500)

    def test_translate_score_levels(self):
        assert integration.translate_score(None) == 0
        assert integration.translate_score(0) == 0
        assert integration.translate_score(1) == 1
        assert integration.translate_score(2) == 2
        assert integration.translate_score(3) == 3
        assert integration.translate_score(99) == 3

    def test_get_reputation_reliability_known(self):
        assert integration.get_reputation_reliability("A - Completely reliable") == "A - Completely reliable"

    def test_get_reputation_reliability_unknown(self):
        assert integration.get_reputation_reliability("not-a-real-value") is None

    def test_parse_modules_argument_csv(self):
        assert integration.parse_modules_argument("a, b, ,c") == ["a", "b", "c"]

    def test_parse_modules_argument_json_array(self):
        assert integration.parse_modules_argument('["a","b"]') == ["a", "b"]

    def test_parse_modules_argument_empty(self):
        assert integration.parse_modules_argument(None) is None
        assert integration.parse_modules_argument("") is None

    def test_parse_analyze_config_valid(self):
        result = integration.parse_analyze_config_argument('[{"metafieldId":"x","value":1}]')
        assert result == [{"metafieldId": "x", "value": 1}]

    def test_parse_analyze_config_invalid_json(self):
        with pytest.raises(DemistoException):
            integration.parse_analyze_config_argument("not-json")

    def test_metafields_from_legacy_args_merges(self):
        fields = integration.metafields_from_legacy_args(
            {
                "timeout": "120",
                "work_path": "desktop",
                "mouse_simulation": "true",
                "raw_logs": "true",
                "modules": '["cdr"]',
                "analyze_config": '[{"metafieldId":"timeout","value":300}]',
            }
        )
        assert fields["timeout"] == 300  # user override wins
        assert fields["work_path"] == "desktop"
        assert fields["mouse_simulation"] is True
        assert "raw_logs" not in fields
        assert "modules" not in fields

    def test_metafields_from_legacy_args_uses_api_defaults(self):
        assert integration.metafields_from_legacy_args({}, {"snapshot": True}) == {"snapshot": True}

    def test_metafields_from_legacy_args_forwards_explicit_false(self):
        assert integration.metafields_from_legacy_args({"snapshot": "false"}, {"snapshot": True}) == {"snapshot": False}

    def test_sandbox_api_defaults_filters_unavailable_definitions(self):
        client = _make_client()
        client.sdk.get_metafields.return_value = [
            _metafield("snapshot", True),
            _metafield("inactive", True, active=False),
            _metafield("inaccessible", True, accessible=False),
        ]

        assert integration.sandbox_api_defaults(client) == {"snapshot": True}
        client.sdk.get_metafields.assert_called_once_with("sandbox")

    def test_submission_level_int(self):
        assert integration.submission_level_int("malicious") == 3
        assert integration.submission_level_int("suspicious") == 2
        assert integration.submission_level_int("benign") == 1
        assert integration.submission_level_int("unknown") == 0
        assert integration.submission_level_int(None) is None

    def test_report_status_int(self):
        assert integration.report_status_int("completed") == 5
        assert integration.report_status_int("in_progress") == 3
        assert integration.report_status_int(None) is None

    def test_parse_file_size_mib(self):
        assert integration.parse_file_size_mib("256 MiB") == 256
        assert integration.parse_file_size_mib(128) == 128
        assert integration.parse_file_size_mib("1.5 MiB") == 1.5
        assert integration.parse_file_size_mib("unknown") is None


class TestClient(unittest.TestCase):
    @patch.object(integration, "ThreatZoneSDK")
    @patch.object(integration.httpx, "Client")
    def test_supplied_http_client_matches_sdk_transport_defaults(self, http_client_mock, sdk_mock):
        client = integration.Client(
            base_url="https://app.threat.zone",
            api_key="key",
            verify=False,
            proxy=True,
        )

        http_client_kwargs = http_client_mock.call_args.kwargs
        assert http_client_kwargs["verify"] is False
        assert http_client_kwargs["trust_env"] is True
        assert http_client_kwargs["follow_redirects"] is True
        timeout = http_client_kwargs["timeout"]
        assert timeout.connect == integration.SDK_REQUEST_TIMEOUT_SECONDS
        assert timeout.read == integration.SDK_REQUEST_TIMEOUT_SECONDS
        assert timeout.write == integration.SDK_REQUEST_TIMEOUT_SECONDS
        assert timeout.pool == integration.SDK_REQUEST_TIMEOUT_SECONDS
        assert sdk_mock.call_args.kwargs["http_client"] is http_client_mock.return_value

        client.close()


# ---------------------------------------------------------------------------
# Command-handler tests
# ---------------------------------------------------------------------------


class TestCheckLimits(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_basic(self):
        self.client.sdk.get_user_info.return_value = _user_info()
        results = integration.threatzone_check_limits(self.client, {})
        assert len(results) == 1
        outputs = results[0].outputs
        assert outputs["E_Mail"] == "name@company.com"
        assert outputs["API_Limit"] == "5/9999"

    def test_detailed_adds_plan_and_metadata(self):
        self.client.sdk.get_user_info.return_value = _user_info()
        results = integration.threatzone_check_limits(self.client, {"detailed": "true"})
        prefixes = [r.outputs_prefix for r in results]
        assert "ThreatZone.Plan" in prefixes
        assert "ThreatZone.Metadata" in prefixes
        plan_result = next(result for result in results if result.outputs_prefix == "ThreatZone.Plan")
        assert plan_result.outputs["File_Size_Limit_MiB"] == 256


class TestPlanCapacity(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_concurrent_limit_blocks_sandbox(self):
        self.client.sdk.get_user_info.return_value = _user_info(concurrent_used=2)
        with pytest.raises(DemistoException) as excinfo:
            integration._verify_plan_capacity(self.client, requires_concurrent=True)
        assert "Concurrent" in str(excinfo.value)

    def test_concurrent_limit_does_not_block_url(self):
        self.client.sdk.get_user_info.return_value = _user_info(concurrent_used=2)
        integration._verify_plan_capacity(self.client, requires_concurrent=False)

    def test_api_limit_blocks(self):
        self.client.sdk.get_user_info.return_value = _user_info(api_used=9999)
        with pytest.raises(DemistoException) as excinfo:
            integration._verify_plan_capacity(self.client, requires_concurrent=False)
        assert "API request limit" in str(excinfo.value)


class TestUrlSubmission(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()
        self.client.sdk.get_user_info.return_value = _user_info()

    def test_url_submission_returns_uuid(self):
        self.client.sdk.create_url_submission.return_value = SubmissionCreated(uuid="abc", message="ok")
        results = integration.threatzone_submit_url_analysis(self.client, {"url": "https://example.com", "private": "true"})
        primary = results[0]
        assert primary.outputs["UUID"] == "abc"
        assert primary.outputs["URL"] == "https://example.com"
        self.client.sdk.create_url_submission.assert_called_once_with("https://example.com", private=True, safe_browsing=False)

    def test_url_submission_forwards_safe_browsing(self):
        self.client.sdk.create_url_submission.return_value = SubmissionCreated(uuid="abc", message="ok")
        integration.threatzone_submit_url_analysis(
            self.client,
            {"url": "https://example.com", "safe_browsing": "true"},
        )
        assert self.client.sdk.create_url_submission.call_args.kwargs["safe_browsing"] is True

    def test_url_submission_requires_url(self):
        with pytest.raises(DemistoException):
            integration.threatzone_submit_url_analysis(self.client, {})


class TestSandboxUpload(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()
        self.client.sdk.get_user_info.return_value = _user_info()
        self.client.sdk.get_metafields.return_value = []
        self.client.sdk.create_sandbox_submission.return_value = SubmissionCreated(uuid="sb-uuid", message="ok")

    @patch.object(integration, "demisto")
    def test_sandbox_upload(self, mock_demisto):
        mock_demisto.getFilePath.return_value = {
            "path": "/tmp/generated-entry-id",
            "name": "original sample.exe",
        }
        with patch.object(integration.Path, "open", mock_open(read_data=b"sample")):
            results = integration.threatzone_sandbox_upload_sample(
                self.client,
                {
                    "entry_id": "1",
                    "environment": "w10_x64",
                    "private": "true",
                    "timeout": "120",
                    "configurations": '{"startArguments":"--safe"}',
                },
            )
        assert results[0].outputs["UUID"] == "sb-uuid"
        assert results[0].outputs["FileName"] == "original sample.exe"
        upload_file = self.client.sdk.create_sandbox_submission.call_args.args[0]
        assert upload_file.name == "original sample.exe"
        call_kwargs = self.client.sdk.create_sandbox_submission.call_args.kwargs
        assert call_kwargs["environment"] == "w10_x64"
        assert call_kwargs["auto_select_environment"] is False
        assert call_kwargs["private"] is True
        assert call_kwargs["metafields"]["timeout"] == 120
        assert call_kwargs["configurations"] == {"startArguments": "--safe"}

    @patch.object(integration, "demisto")
    def test_sandbox_auto_environment_ignores_explicit_default(self, mock_demisto):
        mock_demisto.getFilePath.return_value = {
            "path": "/tmp/sample.exe",
            "name": "sample.exe",
        }
        with patch.object(integration.Path, "open", mock_open(read_data=b"sample")):
            integration.threatzone_sandbox_upload_sample(
                self.client,
                {"entry_id": "1", "environment": "w7_x64", "auto": "true"},
            )
        call_kwargs = self.client.sdk.create_sandbox_submission.call_args.kwargs
        assert call_kwargs["environment"] is None
        assert call_kwargs["auto_select_environment"] is True

    @patch.object(integration, "demisto")
    def test_bat_sandbox_uses_sdk_with_api_defaults(self, mock_demisto):
        mock_demisto.getFilePath.return_value = {
            "path": "/tmp/sample.bat",
            "name": "sample.bat",
        }
        self.client.sdk.get_metafields.return_value = [
            _metafield("private", True),
            _metafield("snapshot", True),
            _metafield("timeout", 120),
        ]

        with patch.object(integration.Path, "open", mock_open(read_data=b"sample")):
            results = integration.threatzone_sandbox_upload_sample(
                self.client,
                {"entry_id": "1", "environment": "w10_x64", "private": "true"},
            )

        assert results[0].outputs["UUID"] == "sb-uuid"
        self.client.sdk.create_sandbox_submission.assert_called_once()
        call_kwargs = self.client.sdk.create_sandbox_submission.call_args.kwargs
        assert call_kwargs["environment"] == "w10_x64"
        assert call_kwargs["private"] is True
        assert call_kwargs["metafields"] == {"snapshot": True, "timeout": 120}


class TestStaticAndCdrUpload(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()
        self.client.sdk.get_user_info.return_value = _user_info()
        self.client.sdk.create_static_submission.return_value = SubmissionCreated(uuid="static-uuid", message="ok")
        self.client.sdk.create_cdr_submission.return_value = SubmissionCreated(uuid="cdr-uuid", message="ok")

    @patch.object(integration, "demisto")
    def test_static_upload(self, mock_demisto):
        mock_demisto.getFilePath.return_value = {
            "path": "/tmp/generated-entry-id",
            "name": "original-static.exe",
        }
        with patch.object(integration.Path, "open", mock_open(read_data=b"sample")):
            results = integration.threatzone_static_or_cdr_upload(
                self.client,
                {"entry_id": "1", "private": "false", "extension_check": "false"},
                "static",
            )
        assert results[0].outputs["UUID"] == "static-uuid"
        upload_file = self.client.sdk.create_static_submission.call_args.args[0]
        assert upload_file.name == "original-static.exe"
        call_kwargs = self.client.sdk.create_static_submission.call_args.kwargs
        assert call_kwargs["private"] is False
        assert call_kwargs["dynamic_mimetype_check"] is False

    @patch.object(integration, "demisto")
    def test_cdr_upload(self, mock_demisto):
        mock_demisto.getFilePath.return_value = {
            "path": "/tmp/generated-entry-id",
            "name": "original-document.docx",
        }
        with patch.object(integration.Path, "open", mock_open(read_data=b"sample")):
            results = integration.threatzone_static_or_cdr_upload(
                self.client,
                {"entry_id": "1", "private": "true", "extension_check": "true"},
                "cdr",
            )
        assert results[0].outputs["UUID"] == "cdr-uuid"
        upload_file = self.client.sdk.create_cdr_submission.call_args.args[0]
        assert upload_file.name == "original-document.docx"
        call_kwargs = self.client.sdk.create_cdr_submission.call_args.kwargs
        assert call_kwargs["private"] is True
        assert call_kwargs["dynamic_mimetype_check"] is True


class TestSectionHandlers(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_get_indicator_result(self):
        self.client.sdk.get_indicators.return_value = IndicatorsResponse(
            items=[
                Indicator(
                    id="ind-1",
                    name="Suspicious behavior",
                    description="desc",
                    category=["cat"],
                    level="suspicious",
                    score=50,
                    pids=[],
                    attackCodes=[],
                    eventIds=[],
                    syscallLineNumbers=[],
                    author="system",
                )
            ],
            total=1,
            levels=IndicatorLevels(malicious=0, suspicious=1, benign=0),
        )
        result = integration.threatzone_get_indicator_result(
            self.client,
            {
                "uuid": "u",
                "level": "suspicious",
                "category": "cat",
                "pid": "7",
                "attack_code": "T1055",
            },
        )[0]
        assert result.outputs["UUID"] == "u"
        assert result.outputs["Data"][0]["name"] == "Suspicious behavior"
        self.client.sdk.get_indicators.assert_called_once_with(
            "u",
            page=1,
            limit=integration.REPORT_FINDINGS_PAGE_SIZE,
            level="suspicious",
            category="cat",
            pid=7,
            attack_code="T1055",
        )

    def test_get_ioc_result_fetches_every_page(self):
        self.client.sdk.get_iocs.side_effect = [
            IoCsResponse(
                items=[IoC(type="domain", value="evil.example", artifacts=[])],
                total=2,
            ),
            IoCsResponse(
                items=[IoC(type="ip", value="192.0.2.1", artifacts=[])],
                total=2,
            ),
        ]
        result = integration.threatzone_get_ioc_result(self.client, {"uuid": "u", "type": "domain"})[0]
        assert result.outputs["Data"][0]["value"] == "evil.example"
        assert result.outputs["Data"][1]["value"] == "192.0.2.1"
        assert self.client.sdk.get_iocs.call_args_list == [
            call("u", page=1, limit=integration.REPORT_FINDINGS_PAGE_SIZE, type="domain"),
            call("u", page=2, limit=integration.REPORT_FINDINGS_PAGE_SIZE, type="domain"),
        ]

    def test_get_yara_result(self):
        self.client.sdk.get_yara_rules.return_value = YaraRulesResponse(
            items=[YaraRule(rule="EvilRule", category="malicious", artifacts=[])],
            total=1,
        )
        result = integration.threatzone_get_yara_result(self.client, {"uuid": "u", "category": "malicious"})[0]
        assert result.outputs["Data"][0]["rule"] == "EvilRule"
        self.client.sdk.get_yara_rules.assert_called_once_with(
            "u",
            page=1,
            limit=integration.REPORT_FINDINGS_PAGE_SIZE,
            category="malicious",
        )

    def test_get_artifact_result(self):
        self.client.sdk.get_artifacts.return_value = ArtifactsResponse(
            items=[
                Artifact(
                    id="art-1",
                    filename="dropped.bin",
                    size=10,
                    type="dropped_file",
                    source="dropped",
                    hashes=ArtifactHashes(md5="m", sha1="s", sha256="x"),
                    tags=[],
                )
            ],
            total=1,
        )
        result = integration.threatzone_get_artifact_result(self.client, {"uuid": "u"})[0]
        assert result.outputs["Data"][0]["filename"] == "dropped.bin"

    def test_get_config_empty(self):
        self.client.sdk.get_extracted_configs.return_value = ExtractedConfigsResponse(items=[], total=0)
        result = integration.threatzone_get_config_result(self.client, {"uuid": "u"})[0]
        assert result.outputs is None

    def test_requires_uuid(self):
        for handler in (
            integration.threatzone_get_indicator_result,
            integration.threatzone_get_ioc_result,
            integration.threatzone_get_yara_result,
            integration.threatzone_get_artifact_result,
            integration.threatzone_get_config_result,
        ):
            with pytest.raises(DemistoException):
                handler(self.client, {})


class TestConfigurationAndSubmissionCommands(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_configuration_commands(self):
        metafield = _metafield("timeout", 120)
        self.client.sdk.get_metafields.return_value = [metafield]
        self.client.sdk.get_environments.return_value = []
        self.client.sdk.list_network_configs.return_value = []

        metafields = integration.threatzone_get_metafields(self.client, {"scan_type": "sandbox"})[0]
        environments = integration.threatzone_get_environments(self.client, {})[0]
        network_configs = integration.threatzone_list_network_configs(self.client, {})[0]

        assert metafields.outputs == {
            "Data": [metafield.model_dump(by_alias=True, exclude_none=True, mode="json")],
            "ScanType": "sandbox",
        }
        assert environments.outputs == {"Data": []}
        assert network_configs.outputs == {"Data": []}
        self.client.sdk.get_metafields.assert_called_once_with("sandbox")
        self.client.sdk.get_environments.assert_called_once_with()
        self.client.sdk.list_network_configs.assert_called_once_with()

    def test_get_all_metafields_omits_filter(self):
        self.client.sdk.get_metafields.return_value = MagicMock()
        integration.threatzone_get_metafields(self.client, {})
        self.client.sdk.get_metafields.assert_called_once_with()

    def test_get_metafields_rejects_unknown_scan_type(self):
        with pytest.raises(DemistoException, match="scan_type"):
            integration.threatzone_get_metafields(self.client, {"scan_type": "unknown"})

    def test_open_in_browser_maps_sdk_arguments(self):
        self.client.sdk.get_user_info.return_value = _user_info()
        self.client.sdk.create_open_in_browser_submission.return_value = SubmissionCreated(uuid="browser-u", message="ok")

        result = integration.threatzone_open_in_browser(
            self.client,
            {
                "url": "https://example.com",
                "environment": "w11_x64",
                "auto": "false",
                "metafields": '{"timeout":120}',
                "private": "false",
                "configurations": '{"networkConfig":"config-id"}',
            },
        )[0]

        assert result.outputs["UUID"] == "browser-u"
        self.client.sdk.create_open_in_browser_submission.assert_called_once_with(
            "https://example.com",
            environment="w11_x64",
            auto_select_environment=False,
            metafields={"timeout": 120},
            private=False,
            configurations={"networkConfig": "config-id"},
        )

    def test_list_submissions_maps_filters(self):
        response = MagicMock()
        response.model_dump.return_value = {
            "items": [],
            "total": 0,
            "page": 2,
            "limit": 50,
            "totalPages": 0,
        }
        self.client.sdk.list_submissions.return_value = response

        result = integration.threatzone_list_submissions(
            self.client,
            {
                "page": "2",
                "limit": "50",
                "level": "malicious,suspicious",
                "tags": "tag-1,tag-2",
                "private": "true",
                "type": "file",
            },
        )[0]

        assert result.outputs["page"] == 2
        call_kwargs = self.client.sdk.list_submissions.call_args.kwargs
        assert call_kwargs["level"] == ["malicious", "suspicious"]
        assert call_kwargs["tags"] == ["tag-1", "tag-2"]
        assert call_kwargs["private"] is True
        assert call_kwargs["type"] == "file"

    def test_search_submissions_serializes_empty_result(self):
        self.client.sdk.search_by_sha256.return_value = []
        result = integration.threatzone_search_submissions(self.client, {"sha256": "a" * 64})[0]
        assert result.outputs == {"Data": []}
        self.client.sdk.search_by_sha256.assert_called_once_with("a" * 64)


@pytest.mark.parametrize(
    ("sdk_method", "section"),
    [
        ("get_overview_summary", "OverviewSummary"),
        ("get_eml_analysis", "EMLAnalysis"),
        ("get_mitre_techniques", "MITRE"),
        ("get_static_scan_results", "StaticScan"),
        ("get_cdr_results", "CDRResult"),
        ("get_signature_check_results", "SignatureCheck"),
        ("get_processes", "Processes"),
        ("get_process_tree", "ProcessTree"),
        ("get_url_analysis", "URLAnalysis"),
        ("get_network_summary", "NetworkSummary"),
    ],
)
def test_uuid_section_sdk_mappings(sdk_method, section):
    client = _make_client()
    getattr(client.sdk, sdk_method).return_value = {"value": sdk_method}

    result = integration.threatzone_get_uuid_section(client, {"uuid": "u"}, sdk_method, section, "Title")[0]

    assert result.outputs == {"UUID": "u", "Data": {"value": sdk_method}}
    getattr(client.sdk, sdk_method).assert_called_once_with("u")


class TestTelemetryCommands(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_behaviours_defaults_and_filters(self):
        self.client.sdk.get_behaviours.return_value = {"items": [], "total": 0}
        result = integration.threatzone_get_behaviours(
            self.client,
            {"uuid": "u", "pid": "42", "process_name": "sample.exe"},
        )[0]
        assert result.outputs["UUID"] == "u"
        self.client.sdk.get_behaviours.assert_called_once_with(
            "u",
            type=None,
            pid=42,
            operation=None,
            process_name="sample.exe",
            page=1,
            limit=100,
        )

    def test_behaviours_bounds_limit(self):
        with pytest.raises(DemistoException, match="between 1 and 500"):
            integration.threatzone_get_behaviours(self.client, {"uuid": "u", "limit": "501"})

    def test_syscalls_defaults_and_limit_bound(self):
        self.client.sdk.get_syscalls.return_value = {"items": [], "total": 0}
        integration.threatzone_get_syscalls(self.client, {"uuid": "u"})
        self.client.sdk.get_syscalls.assert_called_once_with("u", page=1, limit=500)
        with pytest.raises(DemistoException, match="between 1 and 2000"):
            integration.threatzone_get_syscalls(self.client, {"uuid": "u", "limit": "2001"})

    def test_network_window_mappings(self):
        for sdk_method in (
            "get_dns_queries",
            "get_http_requests",
            "get_tcp_connections",
            "get_udp_connections",
            "get_network_threats",
        ):
            sdk_mock = getattr(self.client.sdk, sdk_method)
            sdk_mock.return_value = []
            result = integration.threatzone_get_network_data(
                self.client,
                {"uuid": "u", "limit": "1000", "skip": "0"},
                sdk_method,
                "Section",
                "Title",
            )[0]
            assert result.outputs == {"UUID": "u", "Data": []}
            sdk_mock.assert_called_once_with("u", limit=1000, skip=0)

    def test_network_window_rejects_out_of_range(self):
        with pytest.raises(DemistoException, match="between 0 and 1000"):
            integration.threatzone_get_network_data(
                self.client,
                {"uuid": "u", "skip": "1001"},
                "get_dns_queries",
                "DNSQueries",
                "DNS Queries",
            )


class TestGetResult(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()
        self.client.sdk.get_submission.return_value = _submission()
        # By default, the legacy IOC query returns no items.
        self.client.sdk.get_iocs.return_value = IoCsResponse(items=[], total=0)

    def test_basic_result(self):
        results = integration.threatzone_get_result(self.client, {"uuid": "u"})
        prefixes = [r.outputs_prefix for r in results if hasattr(r, "outputs_prefix")]
        assert "ThreatZone.Submission" in prefixes
        assert "ThreatZone.Analysis" in prefixes
        assert "ThreatZone.IOC" in prefixes
        analysis = next(r for r in results if r.outputs_prefix == "ThreatZone.Analysis")
        submission = next(r for r in results if r.outputs_prefix == "ThreatZone.Submission")
        assert analysis.outputs["LEVEL"] == 3
        assert analysis.outputs["STATUS"] == 5
        assert analysis.outputs["REPORT"]["status"] == 5
        assert submission.outputs["Summary"]["REPORT"]["status"] == 5
        assert submission.outputs["reports"][0]["status"] == "completed"
        assert analysis.outputs["SHA256"].startswith("6e899ff7")

    def test_legacy_iocs_include_every_page(self):
        self.client.sdk.get_iocs.side_effect = [
            IoCsResponse(items=[IoC(type="domain", value="one.example", artifacts=[])], total=2),
            IoCsResponse(items=[IoC(type="domain", value="two.example", artifacts=[])], total=2),
        ]

        results = integration.threatzone_get_result(self.client, {"uuid": "u"})

        legacy_iocs = next(result for result in results if result.outputs_prefix == "ThreatZone.IOC")
        assert legacy_iocs.outputs["DOMAIN"] == ["one.example", "two.example"]

    def test_details_use_paginated_finding_endpoints(self):
        self.client.sdk.get_indicators.return_value = IndicatorsResponse(
            items=[],
            total=0,
            levels=IndicatorLevels(malicious=0, suspicious=0, benign=0),
        )
        self.client.sdk.get_yara_rules.return_value = YaraRulesResponse(items=[], total=0)
        self.client.sdk.get_artifacts.return_value = ArtifactsResponse(items=[], total=0)
        self.client.sdk.get_extracted_configs.return_value = ExtractedConfigsResponse(items=[], total=0)

        integration.threatzone_get_result(self.client, {"uuid": "u", "details": "true"})

        expected_page_call = call("c89d310b-7862-4534-998a-3eb39d9a9d42", page=1, limit=100)
        assert self.client.sdk.get_indicators.call_args == expected_page_call
        assert self.client.sdk.get_yara_rules.call_args == expected_page_call
        assert self.client.sdk.get_iocs.call_args_list == [expected_page_call]

    def test_url_analysis_preserves_legacy_type_label(self):
        self.client.sdk.get_submission.return_value = _submission(report_type="url_analysis")

        results = integration.threatzone_get_result(self.client, {"uuid": "u"})

        analysis = next(result for result in results if result.outputs_prefix == "ThreatZone.Analysis")
        assert analysis.outputs["TYPE"] == "urlAnalysis"

    def test_declined_status_raises(self):
        self.client.sdk.get_submission.return_value = _submission(status="error")
        with pytest.raises(DemistoException) as excinfo:
            integration.threatzone_get_result(self.client, {"uuid": "u"})
        assert "declined" in str(excinfo.value).lower()


class TestDownloads(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    @patch.object(integration, "_save_download", return_value={"EntryID": "entry-1"})
    def test_download_html_report(self, save_download_mock):
        download = MagicMock()
        self.client.sdk.download_html_report.return_value = download
        result = integration.threatzone_get_html_report_file(self.client, {"uuid": "u"})
        assert result["EntryID"] == "entry-1"
        save_download_mock.assert_called_once_with(download, "threatzone-report-u.html")

    @patch.object(integration, "_save_download", return_value={"EntryID": "entry-2"})
    def test_download_cdr_result(self, save_download_mock):
        download = MagicMock()
        self.client.sdk.download_cdr_result.return_value = download
        result = integration.threatzone_get_sanitized_file(self.client, {"uuid": "u"})
        assert result["EntryID"] == "entry-2"
        save_download_mock.assert_called_once_with(download, "sanitized-u.zip")

    @patch.object(integration, "file_result_existing_file", return_value={"EntryID": "entry-3"})
    def test_save_download_streams_to_existing_file(self, existing_file_result_mock):
        download = MagicMock()
        download.filename = "report.html"
        download.save.return_value = Path("report.html")

        result = integration._save_download(download, "fallback.html")

        assert result["EntryID"] == "entry-3"
        download.save.assert_called_once_with("report.html")
        download.read.assert_not_called()
        download.close.assert_called_once_with()
        existing_file_result_mock.assert_called_once_with("report.html", "report.html")

    @patch.object(integration, "file_result_existing_file", return_value={"EntryID": "entry-4"})
    def test_save_download_uses_fallback_for_unnamed_response(self, existing_file_result_mock):
        download = MagicMock()
        download.filename = "download"
        download.save.return_value = Path("fallback.html")

        result = integration._save_download(download, "fallback.html")

        assert result["EntryID"] == "entry-4"
        download.save.assert_called_once_with("fallback.html")
        download.close.assert_called_once_with()
        existing_file_result_mock.assert_called_once_with("fallback.html", "fallback.html")

    @patch.object(integration, "_save_download", return_value={"EntryID": "entry"})
    def test_sdk_stream_download_mappings(self, save_download_mock):
        mappings = (
            ("get_static_scan_strings", "{uuid}_strings.json", None),
            ("download_sample", "sample-{uuid}", None),
            ("download_artifact", "artifact-{uuid}", "artifact_id"),
            ("download_pcap", "threatzone-{uuid}.pcap", None),
        )
        for sdk_method, fallback, id_argument in mappings:
            save_download_mock.reset_mock()
            download = MagicMock()
            getattr(self.client.sdk, sdk_method).return_value = download
            args = {"uuid": "u", "artifact_id": "artifact-1"}

            integration.threatzone_download_sdk_file(
                self.client,
                args,
                sdk_method,
                fallback,
                id_argument=id_argument,
            )

            expected_args = ("u", "artifact-1") if id_argument else ("u",)
            getattr(self.client.sdk, sdk_method).assert_called_once_with(*expected_args)
            save_download_mock.assert_called_once_with(download, fallback.format(uuid="u"))

    @patch.object(integration, "_save_download", return_value={"EntryID": "yara-entry"})
    def test_generated_yara_immediate_success(self, save_download_mock):
        download = MagicMock()
        self.client.sdk.download_yara_rule.return_value = download

        result = integration.threatzone_download_yara_rule(self.client, {"uuid": "u"})

        assert result == {"EntryID": "yara-entry"}
        save_download_mock.assert_called_once_with(download, "u.yar")

    @patch.object(integration, "_save_download", return_value={"EntryID": "yara-entry"})
    @patch.object(integration.demisto, "executeCommand")
    @patch.object(integration.time, "monotonic", side_effect=[0.0, 1.0, 4.0])
    def test_generated_yara_polls_with_server_retry(self, monotonic_mock, execute_command_mock, save_download_mock):
        download = MagicMock()
        self.client.sdk.download_yara_rule.side_effect = [
            YaraRulePendingError("pending", retry_after=2.5),
            YaraRulePendingError("pending"),
            download,
        ]

        integration.threatzone_download_yara_rule(self.client, {"uuid": "u", "timeout": "120"})

        assert execute_command_mock.call_args_list == [
            call("Sleep", {"seconds": "2.5"}),
            call("Sleep", {"seconds": str(integration.YARA_POLL_INTERVAL_SECONDS)}),
        ]
        save_download_mock.assert_called_once_with(download, "u.yar")

    @patch.object(integration.demisto, "executeCommand")
    @patch.object(integration.time, "monotonic", side_effect=[0.0, 119.0])
    def test_generated_yara_timeout(self, monotonic_mock, execute_command_mock):
        self.client.sdk.download_yara_rule.side_effect = YaraRulePendingError("pending", retry_after=2.0)

        with pytest.raises(DemistoException, match="Timed out after 120 seconds"):
            integration.threatzone_download_yara_rule(self.client, {"uuid": "u"})

        execute_command_mock.assert_not_called()

    @patch.object(integration, "fileResult", return_value={"EntryID": "screenshot"})
    def test_screenshot_bytes_become_war_room_file(self, file_result_mock):
        self.client.sdk.get_screenshot.return_value = b"png"
        result = integration.threatzone_download_url_screenshot(self.client, {"uuid": "u"})
        assert result == {"EntryID": "screenshot"}
        file_result_mock.assert_called_once_with("threatzone-url-screenshot-u.png", b"png")

    @patch.object(integration, "fileResult", return_value={"EntryID": "media"})
    def test_media_file_uses_validated_server_filename(self, file_result_mock):
        media = MagicMock()
        media.id = "media-1"
        media.name = "screen.png"
        self.client.sdk.list_media_files.return_value = [media]
        self.client.sdk.get_media_file.return_value = b"png"

        result = integration.threatzone_download_media_file(
            self.client,
            {"uuid": "u", "file_id": "media-1"},
        )

        assert result == {"EntryID": "media"}
        file_result_mock.assert_called_once_with("screen.png", b"png")

    def test_media_file_rejects_unsafe_server_filename(self):
        media = MagicMock()
        media.id = "media-1"
        media.name = "../screen.png"
        self.client.sdk.list_media_files.return_value = [media]
        with pytest.raises(DemistoException, match="unsafe media filename"):
            integration.threatzone_download_media_file(
                self.client,
                {"uuid": "u", "file_id": "media-1"},
            )


class TestSdkExceptionFormatting(unittest.TestCase):
    def test_known_exceptions(self):
        assert "Authorization" in integration._format_sdk_exception(AuthenticationError("nope", status_code=401))
        assert "not found" in integration._format_sdk_exception(NotFoundError("nope", status_code=404)).lower()
        assert "API error" in integration._format_sdk_exception(APIError("boom", status_code=500))
        assert "timed out" in integration._format_sdk_exception(AnalysisTimeoutError("late", uuid="u", elapsed=1.0))
        assert "not yet available" in integration._format_sdk_exception(ReportUnavailableError("wait"))


class TestTestModule(unittest.TestCase):
    def test_ok(self):
        client = _make_client()
        client.sdk.get_user_info.return_value = _user_info()
        assert integration.test_module(client) == "ok"

    def test_auth_failure(self):
        client = _make_client()
        client.sdk.get_user_info.side_effect = AuthenticationError("bad", status_code=401)
        result = integration.test_module(client)
        assert "Authorization" in result


class TestSdkConsumerContract(unittest.TestCase):
    def test_completed_submission_through_fake_api(self):
        sample_bytes = b"threatzone-sdk-contract-sample"
        sample_sha256 = hashlib.sha256(sample_bytes).hexdigest()
        fake_api = FakeThreatZoneAPI()
        scenarios.seed_malicious_pe(fake_api, sha256=sample_sha256)
        sdk = ThreatZoneSDK(
            api_key="test-key",
            base_url="https://fake.threat.zone/public-api",
            http_client=fake_api.as_httpx_client(),
        )
        created = sdk.create_sandbox_submission(sample_bytes, private=True)
        sdk.get_submission(created.uuid)
        sdk.get_submission(created.uuid)

        client = _make_client()
        client.sdk = sdk
        results = integration.threatzone_get_result(client, {"uuid": created.uuid})
        analysis = next(result for result in results if result.outputs_prefix == "ThreatZone.Analysis")
        assert analysis.outputs["STATUS"] == 5
        assert analysis.outputs["LEVEL"] == 3
        assert analysis.outputs["REPORT"]["status"] == 5

    @patch.object(integration, "_save_download", return_value={"EntryID": "fake-download"})
    def test_extended_commands_through_fake_api(self, save_download_mock):
        fake_api = FakeThreatZoneAPI()
        scenarios.seed_malicious_pe(fake_api)
        sdk = ThreatZoneSDK(
            api_key="test-key",
            base_url="https://fake.threat.zone/public-api",
            http_client=fake_api.as_httpx_client(),
        )
        created = sdk.create_sandbox_submission(b"sample", private=True)
        sdk.get_submission(created.uuid)
        sdk.get_submission(created.uuid)
        client = _make_client()
        client.sdk = sdk

        assert integration.threatzone_get_metafields(client, {"scan_type": "sandbox"})[0].outputs["Data"]
        assert integration.threatzone_list_submissions(client, {})[0].outputs["items"]
        assert integration.threatzone_get_uuid_section(
            client,
            {"uuid": created.uuid},
            "get_overview_summary",
            "OverviewSummary",
            "Overview",
        )[0].outputs["Data"]
        assert integration.threatzone_get_network_data(
            client,
            {"uuid": created.uuid},
            "get_network_threats",
            "NetworkThreats",
            "Network Threats",
        )[0].outputs["Data"]

        integration.threatzone_download_sdk_file(
            client,
            {"uuid": created.uuid},
            "download_sample",
            "sample-{uuid}",
        )
        integration.threatzone_download_yara_rule(client, {"uuid": created.uuid})
        assert save_download_mock.call_count == 2
        for download_call in save_download_mock.call_args_list:
            download_call.args[0].close()


if __name__ == "__main__":
    unittest.main()
