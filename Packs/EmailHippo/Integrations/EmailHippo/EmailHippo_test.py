import pytest
import json
import EmailHippo
from EmailHippo import Client, DemistoException


@pytest.fixture
def client():
    return Client(
        more_api_key="test", whois_api_key="test", more_server_url="https://test.com", whois_server_url="https://test.com"
    )


def load_test_data(path):
    with open(path) as f:
        return json.load(f)


class TestHappyPath:
    def test_get_email_reputation_success(self, requests_mock, client: Client):
        """
        Given:
            a Client instance and a mocked API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            - result returned as expected
            - execution metrics success is raised by 1
        """
        requests_mock.get(
            "https://test.com/v3/more/json/test/test@example.com",
            json=load_test_data("test_data/get_email_output.json")["api_result"],
        )
        expected_entry_context = load_test_data("test_data/get_email_output.json")["expected_context"]

        command_res = EmailHippo.email_reputation_command(client, {"email": "test@example.com"}, 0)

        hr_keys = ["Result", "Hippo Trust Score", "Inbox quality score", "Spam risk score"]

        assert command_res
        actual_entry_context = command_res[0].to_context()["EntryContext"]
        assert expected_entry_context == actual_entry_context
        assert all(key in command_res[0].readable_output for key in hr_keys)
        assert client.execution_metrics.success == 1

    def test_domain_reputation_command_success(self, requests_mock, client: Client):
        """
        Given:
            - a Client instance and a mocked API response
        When:
            - domain_reputation_command is called with a valid domain
        Then:
            - result returned as expected
            - execution metrics success is raised by 1
        """
        requests_mock.get(
            "https://test.com/v1/test/example.com", json=load_test_data("test_data/get_domain_output.json")["api_result"]
        )
        expected_entry_context = load_test_data("test_data/get_domain_output.json")["expected_context"]

        command_res = EmailHippo.domain_reputation_command(client, {"domain": "example.com"}, 0)

        hr_keys = [
            "Registrar",
            "Registered On",
            "Domain Age",
            "Expires On",
            "Time To Expiry",
            "Updated On",
            "Status",
            "Name servers",
        ]

        assert command_res
        actual_entry_context = command_res[0].to_context()["EntryContext"]
        assert expected_entry_context == actual_entry_context
        assert all(key in command_res[0].readable_output for key in hr_keys)
        assert client.execution_metrics.success == 1

    def test_quota_command_success(self, requests_mock, client: Client):
        """
        Given:
            - a Client instance and a mocked API response
        When:
            - get_email_quota_command is called with a valid domain
        Then:
            - result returned as expected
            - execution metrics success is raised by 1
        """
        requests_mock.get(
            "https://test.com/customer/reports/v3/quota/test", json=load_test_data("test_data/get_quota_output.json")
        )

        command_res = EmailHippo.get_email_quota_command(client)

        hr_keys = ["Email Quota used", "Email Quota remaining"]

        assert command_res
        assert all(key in command_res.readable_output for key in hr_keys)
        assert "licenseKey" not in command_res.outputs
        assert client.execution_metrics.success == 1


class TestFailure:
    def test_get_email_reputation_failure_quota_limit(self, requests_mock, client: Client):
        """
        Given:
            a Client instance and a mocked failed quota limit API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            - a DemistoException is raised
            - matrix quota_error increased
        """
        requests_mock.get("https://test.com/v3/more/json/test/test@example.com", status_code=401, text="Insufficient quota")

        with pytest.raises(DemistoException):
            client.get_email_reputation("test@example.com")
        assert client.execution_metrics.quota_error == 1

    def test_get_email_reputation_failure_auth_error(self, requests_mock, client: Client):
        """
        Given:
            a Client instance and a mocked failed auth limit API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            - a DemistoException is raised
            - matrix auth_error increased
        """
        requests_mock.get(
            "https://test.com/v3/more/json/test/test@example.com",
            status_code=401,
        )

        with pytest.raises(DemistoException):
            client.get_email_reputation("test@example.com")
        assert client.execution_metrics.auth_error == 1

    def test_get_email_reputation_failure_general_error(self, requests_mock, client: Client):
        """
        Given:
            a Client instance and a mocked 400 API response
        When:
            get_email_reputation is called with a valid email address
        Then:
            - a DemistoException is raised
            - matrix general_error increased
        """
        requests_mock.get(
            "https://test.com/v3/more/json/test/test@example.com",
            status_code=400,
        )

        with pytest.raises(DemistoException):
            client.get_email_reputation("test@example.com")
        assert client.execution_metrics.general_error == 1
