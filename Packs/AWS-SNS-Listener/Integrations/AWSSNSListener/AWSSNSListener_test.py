from unittest.mock import MagicMock, patch

import pytest
from AWSSNSListener import SNSCertificateManager, handle_notification, is_valid_integration_credentials
from CommonServerPython import DemistoException

VALID_PAYLOAD = {
    "Type": "Notification",
    "MessageId": "uuid",
    "TopicArn": "topicarn",
    "Subject": "NotificationSubject",
    "Message": "NotificationMessage",
    "Timestamp": "2024-02-13T18:03:27.239Z",
    "SignatureVersion": "1",
    "Signature": b"sign",
    "SigningCertURL": "https://sns.example.amazonaws.com",
}


@pytest.fixture
def mock_params(mocker):
    return mocker.patch("AWSSNSListener.PARAMS", new={"credentials": {"identifier": "foo", "password": "bar"}}, autospec=False)


def test_handle_notification_valid():
    """
    Given a valid SNS notification message
    When handle_notification is called with the message and raw json
    Then should parse to a valid incident
    """
    raw_json = {}
    expected_notification = {
        "name": "NotificationSubject",
        "labels": [],
        "rawJSON": raw_json,
        "occurred": "2024-02-13T18:03:27.239Z",
        "details": "ExternalID:uuid TopicArn:topicarn Message:NotificationMessage",
        "type": "AWS-SNS Notification",
    }

    actual_incident = handle_notification(VALID_PAYLOAD, raw_json)

    assert actual_incident == expected_notification


@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_is_valid_sns_message(mock_PKey, mock_x509, requests_mock):
    """
    Given a valid SNS payload whose SigningCertURL serves a (mocked) certificate
    When SNSCertificateManager.is_valid_sns_message() is called
    Then the signature verification path returns True.
    """
    sNSCertificateManager = SNSCertificateManager()
    requests_mock.get(VALID_PAYLOAD["SigningCertURL"], text="-----BEGIN CERT-----\n-----END CERT-----")
    mock_PKey.verify_final.return_value = 1
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    mock_x509.get_subject.return_value = MagicMock(CN="sns.amazonaws.com")
    assert sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)


@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_not_valid_sns_message(mock_PKey, mock_x509, requests_mock, capfd):
    """
    Given a valid SNS payload whose signature fails verification
    When SNSCertificateManager.is_valid_sns_message() is called
    Then the method returns False.
    """
    sNSCertificateManager = SNSCertificateManager()
    requests_mock.get(VALID_PAYLOAD["SigningCertURL"], text="-----BEGIN CERT-----\n-----END CERT-----")
    mock_PKey.verify_final.return_value = 2
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    mock_x509.get_subject.return_value = MagicMock(CN="sns.amazonaws.com")
    with capfd.disabled():
        assert sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD) is False


@patch("fastapi.security.http.HTTPBasicCredentials")
def test_valid_credentials(mock_httpBasicCredentials, mock_params):
    """
    Given valid credentials, request headers and token
    When is_valid_integration_credentials is called
    Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = "foo"
    mock_httpBasicCredentials.password = "bar"
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(mock_httpBasicCredentials, request_headers, token)
    assert result is True
    assert header_name is None


@patch("fastapi.security.http.HTTPBasicCredentials")
def test_invalid_credentials(mock_httpBasicCredentials, mock_params):
    """
    Given invalid credentials, request headers and token
    When is_valid_integration_credentials is called
    Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = "foot"
    mock_httpBasicCredentials.password = "bark"
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(mock_httpBasicCredentials, request_headers, token)
    assert result is False


class TestValidateSnsUrl:
    """Tests for URL format validation in _validate_sns_url."""

    def test_valid_aws_sns_url_accepted(self):
        """Test that a valid AWS SNS URL passes validation."""
        from AWSSNSListener import _validate_sns_url

        _validate_sns_url("https://sns.us-east-1.amazonaws.com/cert.pem", "SigningCertURL")

    def test_valid_aws_china_url_accepted(self):
        """Test that a valid AWS China region URL passes validation."""
        from AWSSNSListener import _validate_sns_url

        _validate_sns_url("https://sns.cn-north-1.amazonaws.com.cn/cert.pem", "SigningCertURL")

    def test_non_https_url_rejected(self):
        """Test that a non-HTTPS URL is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="must use HTTPS"):
            _validate_sns_url("http://sns.us-east-1.amazonaws.com/cert.pem", "SigningCertURL")

    def test_non_aws_host_rejected(self):
        """Test that a non-AWS host is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="not an AWS SNS endpoint"):
            _validate_sns_url("https://attacker.example.com/cert.pem", "SigningCertURL")

    def test_aws_like_subdomain_rejected(self):
        """Test that a URL with an AWS-like subdomain on a different host is rejected."""
        from AWSSNSListener import _validate_sns_url

        with pytest.raises(DemistoException, match="not an AWS SNS endpoint"):
            _validate_sns_url("https://sns.us-east-1.amazonaws.com.evil.com/cert.pem", "SigningCertURL")
