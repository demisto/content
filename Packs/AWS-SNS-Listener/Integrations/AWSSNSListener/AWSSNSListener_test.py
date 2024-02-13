import pytest
from AWSSNSListener import handle_notification, AWS_SNS_CLIENT, is_valid_sns_message

id1_pub = [[{'uuid': 'a5b57ec5feaa', 'published': '2022-04-17T12:32:36.667'}]]

PAYLOAD = {'Type': 'Notification',
           'Message': 'foo',
           'Subject': 'NotificationSubject',
           'Timestamp': '2023-01-15T12:00:00Z',
           'MessageId': '59149ac9-b8c9-5b4c-8d2f-c7d4e8',
           'TopicArn': 'arn:aws:sns:us-east-1:123456789012:MyTopic',
           'SignatureVersion': '1',
           'Signature': 'OVRmweRaUfoatpLlbwHRahOpPjKL3qexIv7joeOLOGEcofr2enCv4PBlu8/VxdgrJodQfVss0t6m4aEDees5ce6lRflKXoYDaMOa0bYa7MCmRy5SCX/rjveklt1CJ1dDOpLg5zMXBLMvL2WXS5P7KQB7O89gSwo6nl7A65yWuT1W58ys0B1KXe2LnPtG3agAn/rEwrRbmFGvK9EjNEgVDKCrE41Iv9qF4WE8I5ISLDbBL/UifotXQHNDlsCFkyF99MLir/R  K8bOHVnsIh16OJxC5c/P236I0avoacOeqdOy1ijZ/d60K4m95T3C5MSFkwtd4QfRMRsdPLqNCXF2w=',
           'SigningCertURL': 'https://sns.eu-central-1.amazonaws.com/SimpleNotificationService-01d088a6f77103d0fe307c0069e40ed6.pem'
           }


@pytest.fixture
def dummy_client(mocker):
    '''
    A dummy client fixture for testing.
    '''
    events = [id1_pub]

    client = AWS_SNS_CLIENT('base_url')
    mocker.patch.object(client, 'get', side_effect=events)
    return client


@pytest.fixture
def mock_handle_proxy(mocker):
    mock = mocker.patch('AWSSNSListener.handle_proxy_for_long_running')
    mock.return_value = ({'http': 'http://127.0.0.1',
                          'https': 'https://127.0.0.1'},
                         True)
    return mock


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
        'occurred': '2023-01-15T12:00:00Z',
        'details': 'ExternalID:59149ac9-b8c9-5b4c-8d2f-c7d4e8 TopicArn:arn:aws:sns:us-east-1:123456789012:MyTopic Message:foo',
        'type': 'AWS-SNS Notification'
    }

    actual_incident = handle_notification(PAYLOAD, raw_json)

    assert actual_incident == expected_notification

    
def test_is_valid_sns_message(dummy_client):
    result = is_valid_sns_message(PAYLOAD)
    assert result is True

