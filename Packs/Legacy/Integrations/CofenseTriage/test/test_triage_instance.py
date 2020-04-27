import pytest

from .. import triage_instance


class TestTriageInstance:
    def test_init(self, set_demisto_arg):
        set_demisto_arg("host", "https://triage.whatever")
        set_demisto_arg("token", "top-secret-token-value")
        set_demisto_arg("user", "triage-user")

        triage_instance.init()

        assert triage_instance.TRIAGE_INSTANCE.host == "https://triage.whatever"
        assert triage_instance.TRIAGE_INSTANCE.token == "top-secret-token-value"
        assert triage_instance.TRIAGE_INSTANCE.user == "triage-user"

    def test_request(self, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        requests = triage_instance.TRIAGE_INSTANCE.request("processed_reports")

        assert len(requests) == 3
        assert requests[0]["subject"] == "my great subject"

    def test_request_unsuccessful(self, mocker, requests_mock):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            status_code=403,
            text="a bad error",
        )
        return_error = mocker.patch("CofenseTriage.triage_instance.return_error")

        triage_instance.TRIAGE_INSTANCE.request("processed_reports")

        return_error.assert_called_once_with(
            "Call to Cofense Triage failed (403): a bad error"
        )

    def test_request_raw(self, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        response = triage_instance.TRIAGE_INSTANCE.request(
            "processed_reports", raw_response=True
        )

        assert response.__class__.__name__ == "Response"

    def test_request_empty(self, requests_mock):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports", text="[]"
        )

        assert triage_instance.TRIAGE_INSTANCE.request("processed_reports") == {}

    def test_request_malformed_json(self, mocker, requests_mock, fixture_from_file):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("malformed_json.json"),
        )
        return_error = mocker.patch("CofenseTriage.triage_instance.return_error")

        triage_instance.TRIAGE_INSTANCE.request("processed_reports")

        return_error.assert_called_once_with(
            "Could not parse result from Cofense Triage (200)"
        )

    def test_api_url(self):
        assert (
            triage_instance.TRIAGE_INSTANCE.api_url("endpoint")
            == "https://triage.whatever/api/public/v1/endpoint"
        )
        assert (
            triage_instance.TRIAGE_INSTANCE.api_url("/endpoint")
            == "https://triage.whatever/api/public/v1/endpoint"
        )
        assert (
            triage_instance.TRIAGE_INSTANCE.api_url("///endpoint/edit?query_string&")
            == "https://triage.whatever/api/public/v1/endpoint/edit?query_string&"
        )
