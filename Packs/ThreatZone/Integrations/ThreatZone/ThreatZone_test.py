from CommonServerPython import *
import unittest
from unittest.mock import patch, MagicMock, ANY
from ThreatZone import (
    generate_dbotscore,
    threatzone_return_results,
    encode_file_name,
    threatzone_static_cdr_upload_sample,
    threatzone_sandbox_upload_sample,
    threatzone_check_limits,
    generate_indicator,
    get_reputation_reliability,
    translate_score,
    threatzone_get_result,
    threatzone_get_sanitized_file,
)
from ThreatZone import Client as tz_client

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
                "limitsCount": {"apiRequestCount": 5, "dailySubmissionCount": 5, "concurrentSubmissionCount": 2},
            },
            "plan": {"submissionLimits": {"apiLimit": 9999, "dailyLimit": 999, "concurrentLimit": 2}},
            "modules": [],
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
        }

    def threatzone_add(self, param=None):
        return {"uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42", "message": "You have successfully submitted a submission."}


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

        assert encoded_name == b"Sample_File_.png"

    def test_threatzone_check_limits(self):
        results = threatzone_check_limits(self.client)
        assert results.outputs_prefix == "ThreatZone.Limits"

    def test_generate_dbotscore(self):
        with patch("ThreatZone.get_reputation_reliability", return_value=DBotScoreReliability.A):
            dbot_score = generate_dbotscore(
                "6e899ff7ef160d96787f505b7a9e17b789695bf3206a130c462b3820898257d0", {"THREAT_LEVEL": 3}, type_of_indicator="file"
            )
        assert len(list(dbot_score.to_context().values())) == 1
        assert isinstance(dbot_score, Common.DBotScore)
        for k, v in list(dbot_score.to_context().values())[0].items():
            assert v == DBOT_SCORES[k]


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

    def test_translate_score_other(self):
        score = 3
        result = translate_score(score)
        assert result == Common.DBotScore.BAD


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
        param = {
            "scan_type": "sandbox",
            "environment": "some_environment",
            "private": "true",
            "timeout": 3600,
            "work_path": "some_work_path",
            "mouse_simulation": "false",
            "https_inspection": "false",
            "internet_connection": "false",
            "raw_logs": "true",
            "snapshot": "false",
            "files": [("file", ("test.txt", b"test file data", "application/octet-stream"))],
        }
        mock_http_request.return_value = {
            "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
            "message": "You have successfully submitted a submission.",
        }
        result = self.client.threatzone_add(param)
        expected_data = [
            {"metafieldId": "environment", "value": "some_environment"},
            {"metafieldId": "private", "value": True},
            {"metafieldId": "timeout", "value": 3600},
            {"metafieldId": "work_path", "value": "some_work_path"},
            {"metafieldId": "mouse_simulation", "value": False},
            {"metafieldId": "https_inspection", "value": False},
            {"metafieldId": "internet_connection", "value": False},
            {"metafieldId": "raw_logs", "value": True},
            {"metafieldId": "snapshot", "value": False},
        ]
        expected_data_as_str = json.dumps(expected_data)
        payload = {"analyzeConfig": expected_data_as_str}
        mock_http_request.assert_called_with(
            method="POST",
            url_suffix="/public-api/scan/sandbox",
            data=payload,
            files=[("file", ("test.txt", b"test file data", "application/octet-stream"))],
        )
        assert result == {
            "uuid": "c89d310b-7862-4534-998a-3eb39d9a9d42",
            "message": "You have successfully submitted a submission.",
        }

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
                "limitsCount": {"apiRequestCount": 5, "dailySubmissionCount": 5, "concurrentSubmissionCount": 0},
            },
            "plan": {"submissionLimits": {"apiLimit": 9999, "dailyLimit": 999, "concurrentLimit": 2}},
            "modules": [],
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
        }

    @patch("ThreatZone.requests.get")
    @patch("ThreatZone.shutil.copyfileobj")
    @patch("ThreatZone.file_result_existing_file")
    def test_threatzone_get_sanitized(self, mock_file_result_existing_file, mock_copyfileobj, mock_requests_get):
        submission_uuid = "test_uuid"
        response_mock = MagicMock()
        response_mock.status_code = 200
        response_mock.raw.decode_content = True
        mock_requests_get.return_value = response_mock
        result = self.client.threatzone_get_sanitized(submission_uuid)
        mock_requests_get.assert_called_once_with(
            url=f"{self._base_url}/public-api/download/cdr/{submission_uuid}",
            headers=self._headers,
            stream=True,
            verify=self._verify,
        )
        mock_copyfileobj.assert_called_once_with(response_mock.raw, ANY)  # Use ANY here
        mock_file_result_existing_file.assert_called_once_with(ANY)  # Use ANY here
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
        args["extensionCheck"] = "false"
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
        args["extensionCheck"] = "false"
        results = threatzone_static_cdr_upload_sample(self.client, args)

        assert len(results) == 2

        first_result, second_result = results

        assert first_result.outputs_prefix == "ThreatZone.Submission.CDR"
        assert first_result.outputs_key_field == "UUID"

        assert second_result.outputs_prefix == "ThreatZone.Limits"
        assert second_result.outputs_key_field == "E_Mail"

    @patch("ThreatZone.Client")
    def test_threatzone_get_result(self, mock_client, _, __):
        mock_client_instance = mock_client.return_value

        expected_response = {
            "reports": {
                "dynamic": {"enabled": True, "status": 5},
                "cdr": {"enabled": False, "status": 1},
                "static": {"enabled": False, "status": 1},
            },
            "fileInfo": {"hashes": {"md5": "mock-md5", "sha1": "mock-sha1", "sha256": "mock-sha256"}, "name": "mock-file-name"},
            "private": True,
            "uuid": "mock-uuid",
            "level": 2,
        }
        mock_client_instance.threatzone_get.return_value = expected_response

        args = {"uuid": "mock-uuid"}

        results = threatzone_get_result(mock_client_instance, args)

        assert len(results) == 2
        assert isinstance(results[0], CommandResults)

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

        assert len(results) == 2
        assert isinstance(results[0], CommandResults)

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
