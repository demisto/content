import pytest

from CofenseTriage.CofenseTriage import TriageInstance


@pytest.fixture
def triage_instance():
    return TriageInstance(
        host="https://triage.whatever",
        token="top-secret-token-value",
        user="triage-user",
    )


class TestTriageInstance:
    def test_request(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        requests = triage_instance.request("processed_reports")

        assert len(requests) == 2
        assert requests[0]["report_subject"] == "suspicious subject"

    def test_request_unsuccessful(self, mocker, requests_mock, triage_instance):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            status_code=403,
            text="a bad error",
        )
        return_error = mocker.patch("CofenseTriage.CofenseTriage.return_error")

        triage_instance.request("processed_reports")

        return_error.assert_called_once_with(
            "Call to Cofense Triage failed (403): a bad error"
        )

    def test_request_raw(self, requests_mock, triage_instance, fixture_from_file):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("processed_reports.json"),
        )

        response = triage_instance.request("processed_reports", raw_response=True)

        assert response.__class__.__name__ == "Response"

    def test_request_empty(self, requests_mock, triage_instance):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports", text="[]"
        )

        assert triage_instance.request("processed_reports") == {}

    def test_request_malformed_json(
        self, mocker, requests_mock, triage_instance, fixture_from_file
    ):
        requests_mock.get(
            "https://triage.whatever/api/public/v1/processed_reports",
            text=fixture_from_file("malformed_json.json"),
        )
        return_error = mocker.patch("CofenseTriage.CofenseTriage.return_error")

        triage_instance.request("processed_reports")

        return_error.assert_called_once_with(
            "Could not parse result from Cofense Triage (200)"
        )

    def test_api_url(self, triage_instance):
        assert (
            triage_instance.api_url("endpoint")
            == "https://triage.whatever/api/public/v1/endpoint"
        )
        assert (
            triage_instance.api_url("/endpoint")
            == "https://triage.whatever/api/public/v1/endpoint"
        )
        assert (
            triage_instance.api_url("///endpoint/edit?query_string&")
            == "https://triage.whatever/api/public/v1/endpoint/edit?query_string&"
        )
