import unittest
from unittest.mock import ANY, MagicMock, patch

from CommonServerPython import *
from ThreatZone import Client as tz_client
from ThreatZone import (
    encode_file_name,
    generate_dbotscore,
    generate_indicator,
    get_reputation_reliability,
    parse_analyze_config_argument,
    parse_modules_argument,
    threatzone_check_limits,
    threatzone_get_result,
    threatzone_get_html_report_file,
    threatzone_get_indicator_result,
    threatzone_get_ioc_result,
    threatzone_get_yara_result,
    threatzone_get_artifact_result,
    threatzone_get_config_result,
    threatzone_get_sanitized_file,
    threatzone_return_results,
    threatzone_sandbox_upload_sample,
    threatzone_submit_url_analysis,
    threatzone_static_cdr_upload_sample,
    translate_score,
)

DBOT_SCORES = {
    "Reliability": "A - Completely reliable",
    "Vendor": "ThreatZone",
    "Indicator": "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0",
    "Score": 3,
    "Type": DBotScoreType.FILE,
}


class MockClient:
    def threatzone_me(self):
        return {
            "userInfo": {
                "email": "name@company.com",
                "fullName": "Test User",
                "workspaceName": "ACME Lab",
                "limitsCount": {"apiRequestCount": 5, "dailySubmissionCount": 5, "concurrentSubmissionCount": 2},
            },
            "plan": {
                "submissionLimits": {"apiLimit": 9999, "dailyLimit": 999, "concurrentLimit": 2},
                "fileLimits": {"fileSize": 256, "extensions": ["exe", "dll"]},
                "name": "Enterprise",
                "status": "active",
            },
            "modules": [{"name": "Sandbox"}, {"name": "CDR"}],
        }

    def threatzone_check_limits(self, _):
        api_me = self.threatzone_me()
        acc_email = api_me["userInfo"]["email"]
        limits_count = api_me["userInfo"]["limitsCount"]
        submission_limits = api_me["plan"]["submissionLimits"]
        limits = {
            "E_Mail": f"{acc_email}",
            "Daily_Submission_Limit": f"{limits_count['dailySubmissionCount']}/{submission_limits['dailyLimit']}",
            "Concurrent_Limit": f"{limits_count['concurrentSubmissionCount']}/{submission_limits['concurrentLimit']}",
            "API_Limit": f"{limits_count['apiRequestCount']}/{submission_limits['apiLimit']}",
        }
        return {
            "available": True,
            "Limits": limits,
            "PlanDetails": {
                "File_Size_Limit_MiB": api_me["plan"]["fileLimits"]["fileSize"],
                "Allowed_Extensions": api_me["plan"]["fileLimits"]["extensions"],
                "Modules": [module["name"] for module in api_me["modules"]],
            },
            "Metadata": {
                "Full_Name": api_me["userInfo"]["fullName"],
                "Workspace": api_me["userInfo"]["workspaceName"],
                "Plan_Name": api_me["plan"]["name"],
                "Plan_Status": api_me["plan"]["status"],
            },
        }

    def threatzone_add(self, *, scan_type, data, files, params=None):
        return {"uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42", "message": "You have successfully submitted a submission."}

    def threatzone_submit_url(self, payload):
        return {
            "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
            "message": "You have successfully submitted a submission.",
            "payload": payload,
        }

    def threatzone_get_html_report(self, submission_uuid: str):
        raise NotImplementedError


class Test_ThreatZone_Helper_Functions(unittest.TestCase):
    def setUp(self):
        self.client = MockClient()

    def test_threatzone_return_results(self):
        uuid = "12345"
        readable_output = "Some readable output"
        availability = {"Limits": {"SomeLimit": "SomeValue"}}
        scan_type = "cdr"
        results = threatzone_return_results(scan_type, uuid, readable_output, availability)

        assert len(results) == 2

        first_result, second_result = results

        assert first_result.outputs_prefix == "ThreatZone.Submission.CDR"
        assert first_result.outputs_key_field == "UUID"
        assert first_result.outputs == {"UUID": uuid}
        assert first_result.readable_output == "Some readable output"

        assert second_result.outputs_prefix == "ThreatZone.Limits"
        assert second_result.outputs_key_field == "E_Mail"
        assert second_result.outputs == availability["Limits"]

    def test_encode_file_name(self):
        file_name = "Sample_File_名字.png"
        encoded_name = encode_file_name(file_name)

        assert encoded_name == "Sample_File_.png"

    def test_threatzone_check_limits_default(self):
        results = threatzone_check_limits(self.client, {})
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0].outputs_prefix == "ThreatZone.Limits"

    def test_threatzone_check_limits_detailed(self):
        results = threatzone_check_limits(self.client, {"detailed": "true"})
        assert isinstance(results, list)
        assert results[0].outputs_prefix == "ThreatZone.Limits"
        assert results[1].outputs_prefix == "ThreatZone.Plan"
        assert results[1].outputs["Modules"] == ["Sandbox", "CDR"]
        assert results[2].outputs_prefix == "ThreatZone.Metadata"
        assert results[2].outputs["Workspace"] == "ACME Lab"

    def test_generate_dbotscore(self):
        with patch("ThreatZone.get_reputation_reliability", return_value=DBotScoreReliability.A):
            dbot_score = generate_dbotscore(
                "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0", 3, type_of_indicator="file"
            )
        assert len(list(dbot_score.to_context().values())) == 1
        assert isinstance(dbot_score, Common.DBotScore)
        for k, v in list(dbot_score.to_context().values())[0].items():
            assert v == DBOT_SCORES[k]

    def test_parse_modules_argument_json(self):
        modules = parse_modules_argument('["cdr", "static"]')
        assert modules == ["cdr", "static"]

    def test_parse_modules_argument_csv(self):
        modules = parse_modules_argument("cdr, static")
        assert modules == ["cdr", "static"]

    def test_parse_modules_argument_invalid(self):
        with self.assertRaises(DemistoException):
            parse_modules_argument('{"invalid": true}')

    def test_parse_analyze_config_argument_valid(self):
        config = parse_analyze_config_argument('[{"metafieldId": "timeout", "value": 120}]')
        assert config == [{"metafieldId": "timeout", "value": 120}]

    def test_parse_analyze_config_argument_invalid(self):
        with self.assertRaises(DemistoException):
            parse_analyze_config_argument('[{"value": 1}]')


class TestTranslateScore(unittest.TestCase):
    def test_translate_score_zero(self):
        score = 0
        result = translate_score(score)
        assert result == Common.DBotScore.NONE

    def test_translate_score_one(self):
        score = 1
        result = translate_score(score)
        assert result == Common.DBotScore.GOOD

    def test_translate_score_two(self):
        score = 2
        result = translate_score(score)
        assert result == Common.DBotScore.SUSPICIOUS

    def test_translate_score_three(self):
        score = 3
        result = translate_score(score)
        assert result == Common.DBotScore.BAD

    def test_translate_score_none(self):
        assert translate_score(None) == Common.DBotScore.NONE


class TestGetReputationReliability(unittest.TestCase):
    def test_get_reputation_reliability_A_PLUS(self):
        reliability = "A+ - 3rd party enrichment"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.A_PLUS

    def test_get_reputation_reliability_A(self):
        reliability = "A - Completely reliable"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.A

    def test_get_reputation_reliability_B(self):
        reliability = "B - Usually reliable"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.B

    def test_get_reputation_reliability_C(self):
        reliability = "C - Fairly reliable"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.C

    def test_get_reputation_reliability_D(self):
        reliability = "D - Not usually reliable"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.D

    def test_get_reputation_reliability_E(self):
        reliability = "E - Unreliable"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.E

    def test_get_reputation_reliability_F(self):
        reliability = "F - Reliability cannot be judged"
        result = get_reputation_reliability(reliability)
        assert result == DBotScoreReliability.F


class TestGenerateIndicator(unittest.TestCase):
    def setUp(self):
        self.report = {"THREAT_LEVEL": 3}

    def test_generate_file_indicator(self):
        indicator = ("6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0",)
        indicator_type = "file"
        result = generate_indicator(indicator, self.report, indicator_type)
        assert isinstance(result, Common.File)

    def test_generate_ip_indicator(self):
        indicator = "0.0.0.0"
        indicator_type = "ip"
        result = generate_indicator(indicator, self.report, indicator_type)
        assert isinstance(result, Common.IP)

    def test_generate_url_indicator(self):
        indicator = "http://www.sample.com/index.php"
        indicator_type = "url"
        result = generate_indicator(indicator, self.report, indicator_type)
        assert isinstance(result, Common.URL)

    def test_generate_domain_indicator(self):
        indicator = ("google.com",)
        indicator_type = "domain"
        result = generate_indicator(indicator, self.report, indicator_type)
        assert isinstance(result, Common.Domain)

    def test_generate_email_indicator(self):
        indicator = "test@test"
        indicator_type = "email"
        result = generate_indicator(indicator, self.report, indicator_type)
        assert isinstance(result, Common.EMAIL)


class TestClient(unittest.TestCase):
    def setUp(self):
        self._base_url = "https://example.com"
        self._headers = None
        self._verify = False
        self.client = tz_client(base_url="https://example.com", verify=False)

    @patch("ThreatZone.BaseClient._http_request")
    def test_threatzone_add(self, mock_http_request):
        files = [("file", ("test.txt", b"test file data", "application/octet-stream"))]
        payload = {"analyzeConfig": json.dumps([{"metafieldId": "environment", "value": "some_environment"}])}
        mock_http_request.return_value = {
            "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
            "message": "You have successfully submitted a submission.",
        }
        result = self.client.threatzone_add(scan_type="sandbox", data=payload, files=files)
        mock_http_request.assert_called_with(
            method="POST",
            url_suffix="/public-api/scan/sandbox",
            data=payload,
            files=files,
        )
        assert result == {
            "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
            "message": "You have successfully submitted a submission.",
        }

    @patch("ThreatZone.BaseClient._http_request")
    def test_threatzone_add_with_params(self, mock_http_request):
        files = [("file", ("test.txt", b"test file data", "application/octet-stream"))]
        payload = {"modules": json.dumps(["cdr"])}
        params = {"auto": "true"}
        self.client.threatzone_add(scan_type="sandbox", data=payload, files=files, params=params)
        mock_http_request.assert_called_with(
            method="POST",
            url_suffix="/public-api/scan/sandbox",
            data=payload,
            files=files,
            params=params,
        )

    @patch("ThreatZone.BaseClient._http_request")
    def test_threatzone_get(self, mock_http_request):
        param = {"uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42"}
        mock_http_request.return_value = {"result": "sample result data"}
        result = self.client.threatzone_get(param)
        mock_http_request.assert_called_with(
            method="GET", url_suffix="/public-api/get/submission/c89d310b-7862-4534-998a-3eb39d9a9d42"
        )
        assert result == {"result": "sample result data"}

    @patch("ThreatZone.BaseClient._http_request")
    def test_threatzone_me(self, mock_http_request):
        mock_http_request.return_value = {"userInfo": {"email": "test@example.com"}}
        result = self.client.threatzone_me()
        mock_http_request.assert_called_with(method="GET", url_suffix="/public-api/me")
        assert result == {"userInfo": {"email": "test@example.com"}}

    @patch("ThreatZone.BaseClient._http_request")
    def test_threatzone_check_limits(self, mock_http_request):
        expected_response = {
            "userInfo": {
                "email": "name@company.com",
                "fullName": "Test User",
                "workspaceName": "ACME Lab",
                "limitsCount": {"apiRequestCount": 5, "dailySubmissionCount": 5, "concurrentSubmissionCount": 0},
            },
            "plan": {
                "submissionLimits": {"apiLimit": 9999, "dailyLimit": 999, "concurrentLimit": 2},
                "fileLimits": {"fileSize": 512, "extensions": ["exe", "dll"]},
                "name": "Enterprise",
                "status": "active",
            },
            "modules": [{"name": "Sandbox"}, {"name": "CDR"}],
        }
        mock_http_request.return_value = expected_response

        result = self.client.threatzone_check_limits("sandbox")

        assert result == {
            "available": True,
            "Limits": {
                "E_Mail": "name@company.com",
                "Daily_Submission_Limit": "5/999",
                "Concurrent_Limit": "0/2",
                "API_Limit": "5/9999",
            },
            "PlanDetails": {
                "File_Size_Limit_MiB": 512,
                "Allowed_Extensions": ["exe", "dll"],
                "Modules": ["Sandbox", "CDR"],
            },
            "Metadata": {
                "Full_Name": "Test User",
                "Workspace": "ACME Lab",
                "Plan_Name": "Enterprise",
                "Plan_Status": "active",
            },
        }

    @patch("ThreatZone.Client._download_submission_asset")
    def test_threatzone_get_html_report(self, mock_download):
        mock_download.return_value = {"Name": "report"}
        result = self.client.threatzone_get_html_report("test-uuid")
        mock_download.assert_called_with(
            "/public-api/download/html-report/test-uuid",
            "threatzone-report-test-uuid.html",
        )
        assert result == {"Name": "report"}

    @patch("ThreatZone.shutil.copyfileobj")
    @patch("ThreatZone.file_result_existing_file")
    def test_threatzone_get_sanitized(self, mock_file_result_existing_file, mock_copyfileobj):
        submission_uuid = "test_uuid"
        response_mock = MagicMock()
        response_mock.ok = True
        response_mock.raw = MagicMock()
        result = None
        with patch("ThreatZone.Client._http_request", return_value=response_mock) as mock_http_request:
            result = self.client.threatzone_get_sanitized(submission_uuid)
        mock_http_request.assert_called_once_with(
            method="GET",
            url_suffix=f"/public-api/download/cdr/{submission_uuid}",
            resp_type="response",
            stream=True,
        )
        mock_copyfileobj.assert_called_once_with(response_mock.raw, ANY)  # Use ANY here
        mock_file_result_existing_file.assert_called_once_with(ANY)  # Use ANY here
        response_mock.close.assert_called_once()
        assert result == mock_file_result_existing_file.return_value


@patch("ThreatZone.Client.threatzone_me", return_value=MockClient.threatzone_me)
@patch.object(demisto, "getFilePath", return_value={"id": "id", "path": "README.md", "name": "README.md"})
class Test_ThreatZone_Main_Functions(unittest.TestCase):
    def setUp(self):
        self.client = MockClient()
        self.args = {
            "private": True,
            "environment": "some_environment",
            "work_path": "some_work_path",
            "timeout": 3600,
            "mouse_simulation": False,
            "https_inspection": False,
            "internet_connection": False,
            "raw_logs": True,
            "snapshot": False,
            "entry_id": "file_entry_id",
        }

    def test_threatzone_sandbox_upload_sample(self, _, __):
        results = threatzone_sandbox_upload_sample(self.client, self.args)

        assert len(results) == 2

        first_result, second_result = results
        assert first_result.outputs_prefix == "ThreatZone.Submission.Sandbox"
        assert first_result.outputs_key_field == "UUID"

        assert second_result.outputs_prefix == "ThreatZone.Limits"
        assert second_result.outputs_key_field == "E_Mail"

    def test_fail_threatzone_sandbox_upload_sample(self, _, __):
        return_value = {"available": False, "Limits": "", "Reason": "", "Suggestion": ""}
        with patch.object(self.client, "threatzone_check_limits", return_value=return_value), self.assertRaises(DemistoException):
            threatzone_sandbox_upload_sample(self.client, self.args)

    def test_threatzone_static_upload_sample(self, _, __):
        args = {}
        args["entry_id"] = self.args["entry_id"]
        args["scan_type"] = "static-scan"
        args["private"] = "false"
        args["extension_check"] = "false"
        results = threatzone_static_cdr_upload_sample(self.client, args)

        assert len(results) == 2

        first_result, second_result = results

        assert first_result.outputs_prefix == "ThreatZone.Submission.Static"
        assert first_result.outputs_key_field == "UUID"

        assert second_result.outputs_prefix == "ThreatZone.Limits"
        assert second_result.outputs_key_field == "E_Mail"

    def test_threatzone_cdr_upload_sample(self, _, __):
        args = {}
        args["entry_id"] = self.args["entry_id"]
        args["scan_type"] = "cdr"
        args["private"] = "false"
        args["extension_check"] = "false"
        results = threatzone_static_cdr_upload_sample(self.client, args)

        assert len(results) == 2

        first_result, second_result = results

        assert first_result.outputs_prefix == "ThreatZone.Submission.CDR"
        assert first_result.outputs_key_field == "UUID"

        assert second_result.outputs_prefix == "ThreatZone.Limits"
        assert second_result.outputs_key_field == "E_Mail"

    def test_threatzone_submit_url_analysis(self, _, __):
        args = {"url": "https://malicious.example", "private": "true"}
        with patch.object(
            self.client,
            "threatzone_submit_url",
            return_value={"uuid": "mock-uuid", "message": "You have successfully submitted a submission."},
        ) as submit_mock:
            results = threatzone_submit_url_analysis(self.client, args)

        submit_mock.assert_called_with({"url": "https://malicious.example", "private": True})
        assert len(results) == 2
        assert results[0].outputs_prefix == "ThreatZone.Submission.URL"

    def test_threatzone_get_html_report_file(self, _, __):
        args = {"uuid": "test-uuid"}
        with patch.object(self.client, "threatzone_get_html_report", return_value={"Name": "report"}) as html_mock:
            result = threatzone_get_html_report_file(self.client, args)
        html_mock.assert_called_with("test-uuid")
        assert result == {"Name": "report"}

    @patch("ThreatZone.Client")
    def test_threatzone_get_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value

        expected_response = {
            "reports": {
                "dynamic": {
                    "enabled": True,
                    "status": 5,
                    "indicators": [{"name": "Create mutex"}],
                },
                "cdr": {"enabled": False, "status": 1},
                "static": {"enabled": False, "status": 1},
            },
            "fileInfo": {"hashes": {"md5": "mock-md5", "sha1": "mock-sha1", "sha256": "mock-sha256"}, "name": "mock-file-name"},
            "private": True,
            "uuid": "mock-uuid",
            "level": 2,
            "indicators": [{"name": "Create mutex"}],
            "iocs": {"url": ["https://indicator.example"]},
            "matchedYARARules": [{"rule": "rule_name"}],
            "artifacts": [{"path": "artifact.bin"}],
            "extractedConfigs": [{"key": "value"}],
        }
        mock_client_instance.threatzone_get.return_value = expected_response

        args = {"uuid": "mock-uuid"}

        results = threatzone_get_result(mock_client_instance, args)

        assert len(results) == 3
        submission_result, analysis_result, ioc_result = results
        assert submission_result.outputs_prefix == "ThreatZone.Submission"
        assert submission_result.outputs == expected_response
        assert submission_result.raw_response == expected_response
        assert analysis_result.outputs_prefix == "ThreatZone.Analysis"
        assert analysis_result.outputs["UUID"] == "mock-uuid"
        assert analysis_result.outputs["SHA256"] == "mock-sha256"
        assert analysis_result.outputs["STATUS"] == 5
        assert ioc_result.outputs_prefix == "ThreatZone.IOC"
        assert ioc_result.outputs["URL"] == ["https://indicator.example"]

        detail_args = {"uuid": "mock-uuid", "details": "true"}
        detail_results = threatzone_get_result(mock_client_instance, detail_args)
        assert len(detail_results) == 3
        detail_output = detail_results[0].readable_output
        assert "### Indicators" not in detail_output
        assert "| INDICATORS | Create mutex" in detail_output
        assert "| INDICATORS OF COMPROMISE | url: https://indicator.example" in detail_output
        assert "| MATCHED YARA RULES | rule_name" in detail_output
        assert "| ANALYSIS ARTIFACTS | artifact.bin" in detail_output
        assert "| EXTRACTED CONFIGURATIONS | key: value" in detail_output

        cdr_expected_response = {
            "reports": {
                "cdr": {"enabled": True, "status": 5},
                "dynamic": {"enabled": False, "status": 1},
                "static": {"enabled": False, "status": 1},
            },
            "fileInfo": {"hashes": {"md5": "mock-md5", "sha1": "mock-sha1", "sha256": "mock-sha256"}, "name": "mock-file-name"},
            "private": True,
            "uuid": "mock-uuid",
            "level": 2,
        }
        mock_client_instance.threatzone_get.return_value = cdr_expected_response

        args = {"uuid": "mock-uuid"}

        results = threatzone_get_result(mock_client_instance, args)

        assert len(results) == 3
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission"
        assert result.outputs == cdr_expected_response

        url_expected_response = {
            "reports": {
                "urlAnalysis": {
                    "enabled": True,
                    "status": 5,
                    "generalInfo": {
                        "url": "https://example.com",
                        "domain": "example.com",
                        "websiteTitle": "Example Domain",
                    },
                }
            },
            "private": False,
            "uuid": "url-uuid",
            "level": 1,
        }
        mock_client_instance.threatzone_get.return_value = url_expected_response

        url_results = threatzone_get_result(mock_client_instance, {"uuid": "url-uuid"})

        assert len(url_results) == 3
        url_result = url_results[0]
        assert "https://example.com" in url_result.readable_output
        assert isinstance(url_result.indicator, Common.URL)

    @patch("ThreatZone.Client")
    def test_threatzone_get_ioc_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value
        mock_client_instance.threatzone_get_section.return_value = {"iocs": {"url": ["https://indicator.example"], "domain": []}}

        args = {"uuid": "mock-uuid"}
        results = threatzone_get_ioc_result(mock_client_instance, args)

        assert len(results) == 1
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission.IOCs"
        assert result.outputs["UUID"] == "mock-uuid"
        assert result.outputs["Data"]["url"] == ["https://indicator.example"]

    @patch("ThreatZone.Client")
    def test_threatzone_get_indicator_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value
        mock_client_instance.threatzone_get_section.return_value = {"indicators": [{"name": "Create mutex"}]}

        args = {"uuid": "mock-uuid"}
        results = threatzone_get_indicator_result(mock_client_instance, args)

        assert len(results) == 1
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission.Indicators"
        assert result.outputs["UUID"] == "mock-uuid"
        assert result.outputs["Data"][0]["name"] == "Create mutex"

    @patch("ThreatZone.Client")
    def test_threatzone_get_yara_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value
        mock_client_instance.threatzone_get_section.return_value = {"yaraRules": [{"rule": "rule_name"}]}

        args = {"uuid": "mock-uuid"}
        results = threatzone_get_yara_result(mock_client_instance, args)

        assert len(results) == 1
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission.YaraMatches"
        assert result.outputs["UUID"] == "mock-uuid"
        assert result.outputs["Data"][0]["rule"] == "rule_name"

    @patch("ThreatZone.Client")
    def test_threatzone_get_artifact_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value
        mock_client_instance.threatzone_get_section.return_value = {"artifacts": [{"path": "sample.bin"}]}

        args = {"uuid": "mock-uuid"}
        results = threatzone_get_artifact_result(mock_client_instance, args)

        assert len(results) == 1
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission.Artifacts"
        assert result.outputs["UUID"] == "mock-uuid"
        assert result.outputs["Data"][0]["path"] == "sample.bin"

    @patch("ThreatZone.Client")
    def test_threatzone_get_config_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value
        mock_client_instance.threatzone_get_section.return_value = {"configExtractorResults": [{"key": "value"}]}

        args = {"uuid": "mock-uuid"}
        results = threatzone_get_config_result(mock_client_instance, args)

        assert len(results) == 1
        result = results[0]
        assert result.outputs_prefix == "ThreatZone.Submission.Config"
        assert result.outputs["UUID"] == "mock-uuid"
        assert result.outputs["Data"][0]["key"] == "value"

    @patch("ThreatZone.Client.threatzone_get_sanitized")
    def test_threatzone_get_sanitized_file(self, mock_threatzone_get_sanitized, _, __):
        # Arrange
        submission_uuid = "test_uuid"
        args = {"uuid": submission_uuid}
        sanitized_file_data = {"filename": "sanitized_file.zip", "contents": "file contents"}
        mock_threatzone_get_sanitized.return_value = sanitized_file_data
        client_mock = MagicMock()
        client_mock.threatzone_get_sanitized.return_value = sanitized_file_data

        # Act
        result = threatzone_get_sanitized_file(client_mock, args)

        # Assert
        assert result == sanitized_file_data


if __name__ == "__main__":
    unittest.main()
