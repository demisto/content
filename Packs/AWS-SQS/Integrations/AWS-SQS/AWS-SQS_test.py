import pytest
from AWSApiModule import AWSClient
aws_sqs = __import__('AWS-SQS')


class mock_class:
    def receive_message():
        pass

    def delete_message():
        pass


MOCK_FETCH_INCIDENTS = [
    (
        {'lastReceiptHandles': ['123456', '234567', '345678']},
        [{'Messages': [{'ReceiptHandle': '654321'}, {'ReceiptHandle': '765432'}]},
         {'Messages': [{'ReceiptHandle': '654321'}, {'ReceiptHandle': '765432'}]}],
        {'aws_client': AWSClient, 'aws_queue_url': '', 'max_fetch': 3, 'parse_body_as_json': False},
        3
    ),
    (
        {'lastReceiptHandles': ['123456', '234567', '345678']},
        [{'Messages': [{'ReceiptHandle': '654321'}, {'ReceiptHandle': '765432'}]},
         {'Messages': [{'ReceiptHandle': '654321'}, {'ReceiptHandle': '765432'}]}, {}],
        {'aws_client': AWSClient, 'aws_queue_url': '', 'max_fetch': 10, 'parse_body_as_json': False},
        4
    ),
    (
        {'lastReceiptHandles': ['123456', '234567', '345678']},
        [{'Messages': [{'ReceiptHandle': '123456'}, {'ReceiptHandle': '765432'}]},
         {'Messages': [{'ReceiptHandle': '654321'}, {'ReceiptHandle': '765432'}]}, {}],
        {'aws_client': AWSClient, 'aws_queue_url': '', 'max_fetch': 10, 'parse_body_as_json': False},
        3
    )
]


@pytest.mark.parametrize('lastReceiptHandles, messages, args, expected', MOCK_FETCH_INCIDENTS)
def test_fetch_incidents(mocker, lastReceiptHandles, messages, args, expected):

    mocker.patch.object(aws_sqs.demisto, 'getLastRun', return_value=lastReceiptHandles)
    mocker.patch.object(aws_sqs.demisto, 'setLastRun', return_value='test')
    client = mocker.patch.object(AWSClient, 'aws_session', return_value=mock_class())
    mocker.patch.object(client.return_value, 'receive_message', side_effect=messages)
    mocker.patch.object(client.return_value, 'delete_message', return_value='test')
    mocker.patch.object(aws_sqs, 'parse_incident_from_finding', return_value='test')
    incidents_mocker = mocker.patch.object(aws_sqs.demisto, 'incidents')
    aws_sqs.fetch_incidents(**args)
    assert len(incidents_mocker.call_args[0][0]) == expected
