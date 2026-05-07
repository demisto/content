import json
from unittest.mock import MagicMock, patch

import pytest
import requests
import AWSSNSListener
from AWSSNSListener import (
    RETRY_ATTEMPTS,
    SNSCertificateManager,
    create_incident_background,
    handle_notification,
    is_valid_integration_credentials,
)
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


@patch("AWSSNSListener.client")
@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_is_valid_sns_message(mock_client, mock_x509, mock_PKey):
    sNSCertificateManager = SNSCertificateManager()
    mock_resp = requests.models.Response()
    mock_resp.status_code = 200
    response_content = """-----BEGIN VALID CERTIFICATE-----
                          -----END CERTIFICATE-----"""
    mock_resp._content = str.encode(response_content)
    mock_client.get.return_value = mock_resp
    mock_PKey.verify_final.return_value = 1
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    mock_x509.get_subject.return_value = MagicMock(CN="sns.amazonaws.com")
    is_valid = sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)
    assert is_valid


@patch("AWSSNSListener.client")
@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_not_valid_sns_message(mock_client, mock_x509, mock_PKey, capfd):
    sNSCertificateManager = SNSCertificateManager()
    mock_resp = requests.models.Response()
    mock_resp.status_code = 200
    response_content = """-----BEGIN INVALID CERTIFICATE-----
                          -----END CERTIFICATE-----"""
    mock_resp._content = str.encode(response_content)
    mock_client.get.return_value = mock_resp
    mock_PKey.verify_final.return_value = 2
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    with capfd.disabled():
        is_valid = sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)
        assert is_valid is False


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


# ---------------------------------------------------------------------------
# Tests for the async incident creation path (BackgroundTasks-based fix).
# ---------------------------------------------------------------------------

SAMPLE_INCIDENT = {
    "name": "NotificationSubject",
    "labels": [],
    "rawJSON": json.dumps({"MessageId": "test-msg-id-123"}),
    "occurred": "2024-02-13T18:03:27.239Z",
    "details": "ExternalID:test-msg-id-123 TopicArn:topicarn Message:NotificationMessage",
    "type": "AWS-SNS Notification",
}


def test_create_incident_background_success(mocker):
    """
    Given demisto.createIncidents returns a truthy result on the first attempt
    When create_incident_background is invoked
    Then it should call createIncidents exactly once and never call updateModuleHealth.
    """
    create_mock = mocker.patch("AWSSNSListener.demisto.createIncidents", return_value=[{"id": "1"}])
    health_mock = mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    sleep_mock = mocker.patch("AWSSNSListener.time.sleep")
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(SAMPLE_INCIDENT)

    assert create_mock.call_count == 1
    health_mock.assert_not_called()
    sleep_mock.assert_not_called()


def test_create_incident_background_retry_then_success(mocker):
    """
    Given createIncidents raises an exception on the first two attempts and succeeds on the third
    When create_incident_background is invoked
    Then it should call createIncidents three times, log an error for each failed attempt,
    and never raise a Module Health alert.
    """
    create_mock = mocker.patch(
        "AWSSNSListener.demisto.createIncidents",
        side_effect=[Exception("transient 1"), Exception("transient 2"), [{"id": "1"}]],
    )
    health_mock = mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    error_mock = mocker.patch("AWSSNSListener.demisto.error")
    mocker.patch("AWSSNSListener.time.sleep")  # do not actually sleep in tests
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(SAMPLE_INCIDENT)

    assert create_mock.call_count == 3
    health_mock.assert_not_called()
    assert error_mock.call_count == 2
    for call in error_mock.call_args_list:
        assert "test-msg-id-123" in call.args[0]
        assert "createIncidents raised" in call.args[0]


def test_create_incident_background_exhausts_retries(mocker):
    """
    Given createIncidents fails on every attempt
    When create_incident_background is invoked
    Then it should call createIncidents RETRY_ATTEMPTS times, log an error per attempt,
    and call updateModuleHealth exactly once with a message containing the SNS MessageId.
    """
    create_mock = mocker.patch("AWSSNSListener.demisto.createIncidents", side_effect=Exception("permanent failure"))
    health_mock = mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    error_mock = mocker.patch("AWSSNSListener.demisto.error")
    mocker.patch("AWSSNSListener.time.sleep")
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(SAMPLE_INCIDENT)

    assert create_mock.call_count == RETRY_ATTEMPTS
    assert error_mock.call_count == RETRY_ATTEMPTS
    assert health_mock.call_count == 1
    health_message = health_mock.call_args.args[0]
    assert "test-msg-id-123" in health_message


def test_create_incident_background_empty_response_triggers_retry_and_health(mocker):
    """
    Given createIncidents returns falsy (empty list / None) on every attempt
    When create_incident_background is invoked
    Then it should retry the configured number of times, log an error per attempt,
    and finally call updateModuleHealth.
    """
    create_mock = mocker.patch("AWSSNSListener.demisto.createIncidents", return_value=[])
    health_mock = mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    error_mock = mocker.patch("AWSSNSListener.demisto.error")
    mocker.patch("AWSSNSListener.time.sleep")
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(SAMPLE_INCIDENT)

    assert create_mock.call_count == RETRY_ATTEMPTS
    assert error_mock.call_count == RETRY_ATTEMPTS
    for call in error_mock.call_args_list:
        assert "createIncidents returned empty" in call.args[0]
    health_mock.assert_called_once()


def test_create_incident_background_unparseable_rawjson_uses_unknown_id(mocker):
    """
    Given an incident whose rawJSON is not valid JSON
    When create_incident_background fails all retries
    Then the Module Health message should fall back to '<unknown>' for the MessageId.
    """
    bad_incident = dict(SAMPLE_INCIDENT, rawJSON="not-a-json")
    mocker.patch("AWSSNSListener.demisto.createIncidents", side_effect=Exception("boom"))
    health_mock = mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    error_mock = mocker.patch("AWSSNSListener.demisto.error")
    mocker.patch("AWSSNSListener.time.sleep")
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(bad_incident)

    health_mock.assert_called_once()
    assert "<unknown>" in health_mock.call_args.args[0]
    assert error_mock.call_count == RETRY_ATTEMPTS
    for call in error_mock.call_args_list:
        assert "<unknown>" in call.args[0]


def test_create_incident_background_stores_samples_only_when_enabled(mocker):
    """
    Given store_samples is enabled in PARAMS
    When create_incident_background succeeds
    Then store_samples should be called exactly once with the incident.
    """
    mocker.patch("AWSSNSListener.demisto.createIncidents", return_value=[{"id": "1"}])
    mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    mocker.patch("AWSSNSListener.time.sleep")
    store_mock = mocker.patch("AWSSNSListener.store_samples")
    mocker.patch("AWSSNSListener.PARAMS", new={"store_samples": True})

    create_incident_background(SAMPLE_INCIDENT)

    store_mock.assert_called_once_with(SAMPLE_INCIDENT)


def test_create_incident_background_skips_samples_when_disabled(mocker):
    """
    Given store_samples is disabled (default)
    When create_incident_background succeeds
    Then store_samples should not be called.
    """
    mocker.patch("AWSSNSListener.demisto.createIncidents", return_value=[{"id": "1"}])
    mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    mocker.patch("AWSSNSListener.time.sleep")
    store_mock = mocker.patch("AWSSNSListener.store_samples")
    mocker.patch("AWSSNSListener.PARAMS", new={})

    create_incident_background(SAMPLE_INCIDENT)

    store_mock.assert_not_called()


# ---------------------------------------------------------------------------
# Tests for semaphore behavior (only used by the async/background path).
# ---------------------------------------------------------------------------


def test_create_incident_background_acquires_semaphore(mocker):
    """
    Given the asynchronous (parallel) path is used
    When create_incident_background is invoked
    Then the INCIDENT_CREATE_SEMAPHORE SHOULD be acquired to cap concurrency.
    """
    mocker.patch("AWSSNSListener.demisto.createIncidents", return_value=[{"id": "1"}])
    mocker.patch("AWSSNSListener.demisto.updateModuleHealth")
    mocker.patch("AWSSNSListener.time.sleep")
    mocker.patch("AWSSNSListener.PARAMS", new={})
    semaphore_mock = mocker.patch("AWSSNSListener.INCIDENT_CREATE_SEMAPHORE")

    create_incident_background(SAMPLE_INCIDENT)

    semaphore_mock.__enter__.assert_called_once()
    semaphore_mock.__exit__.assert_called_once()
