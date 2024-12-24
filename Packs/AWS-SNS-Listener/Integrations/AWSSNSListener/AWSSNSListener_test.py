import pytest
from AWSSNSListener import handle_notification, is_valid_integration_credentials, SNSCertificateManager
from unittest.mock import patch
import requests

VALID_PAYLOAD = {
    "Type": "Notification",
    "MessageId": "uuid",
    "TopicArn": "topicarn",
    "Subject": "NotificationSubject",
    "Message": "NotificationMessage",
    "Timestamp": "2024-02-13T18:03:27.239Z",
    "SignatureVersion": "1",
    "Signature": b"sign",
    "SigningCertURL": "https://link.pem",
}


@pytest.fixture
def mock_params(mocker):
    return mocker.patch('AWSSNSListener.PARAMS', new={'credentials': {'identifier': 'foo', 'password': 'bar'}},
                        autospec=False)


def test_handle_notification_valid():
    '''
    Given a valid SNS notification message
    When handle_notification is called with the message and raw json
    Then should parse to a valid incident
    '''
    raw_json = {}
    expected_notification = {
        'name': 'NotificationSubject',
        'labels': [],
        'rawJSON': raw_json,
        'occurred': '2024-02-13T18:03:27.239Z',
        'details': 'ExternalID:uuid TopicArn:topicarn Message:NotificationMessage',
        'type': 'AWS-SNS Notification'
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
    response_content = '''-----BEGIN VALID CERTIFICATE-----
                          -----END CERTIFICATE-----'''
    mock_resp._content = str.encode(response_content)
    mock_client.get.return_value = mock_resp
    mock_PKey.verify_final.return_value = 1
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    is_valid = sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)
    assert is_valid


@patch("AWSSNSListener.client")
@patch("AWSSNSListener.X509")
@patch("M2Crypto.EVP.PKey")
def test_not_valid_sns_message(mock_client, mock_x509, mock_PKey, capfd):
    sNSCertificateManager = SNSCertificateManager()
    mock_resp = requests.models.Response()
    mock_resp.status_code = 200
    response_content = '''-----BEGIN INVALID CERTIFICATE-----
                          -----END CERTIFICATE-----'''
    mock_resp._content = str.encode(response_content)
    mock_client.get.return_value = mock_resp
    mock_PKey.verify_final.return_value = 2
    mock_x509.get_pubkey.return_value = mock_PKey
    mock_x509.load_cert_string.return_value = mock_x509
    with capfd.disabled():
        is_valid = sNSCertificateManager.is_valid_sns_message(VALID_PAYLOAD)
        assert is_valid is False


@patch('fastapi.security.http.HTTPBasicCredentials')
def test_valid_credentials(mock_httpBasicCredentials, mock_params):
    """
     Given valid credentials, request headers and token
     When is_valid_integration_credentials is called
     Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = 'foo'
    mock_httpBasicCredentials.password = 'bar'
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(
        mock_httpBasicCredentials, request_headers, token
    )
    assert result is True
    assert header_name is None


@patch('fastapi.security.http.HTTPBasicCredentials')
def test_invalid_credentials(mock_httpBasicCredentials, mock_params):
    """
     Given invalid credentials, request headers and token
     When is_valid_integration_credentials is called
     Then it should return True, header_name
    """
    mock_httpBasicCredentials.username = 'foot'
    mock_httpBasicCredentials.password = 'bark'
    request_headers = {}
    token = "sometoken"
    result, header_name = is_valid_integration_credentials(
        mock_httpBasicCredentials, request_headers, token
    )
    assert result is False
