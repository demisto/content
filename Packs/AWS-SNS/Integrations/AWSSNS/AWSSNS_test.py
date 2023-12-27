from unittest.mock import MagicMock
from AWSSNS import delete_topic, create_topic, send_message


def test_delete_topic_success():
    # Mocking the client.delete_topic method
    client = MagicMock()
    client.delete_topic.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}

    # Testing the function
    args = {'topicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}
    result = delete_topic(args, client)
    assert result == 'The Topic has been deleted'


def test_delete_topic_failure():
    # Mocking the client.delete_topic method
    client = MagicMock()
    client.delete_topic.side_effect = Exception('An error occurred')

    # Testing the function
    args = {'topicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}
    result = delete_topic(args, client)
    assert result == 'An error occurred while deleting the topic'


def test_create_topic_success():
    # Mocking the client.create_topic method
    client = MagicMock()
    client.create_topic.return_value = {'TopicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}

    # Testing the function
    args = {'topicName': 'MyTopic'}
    result = create_topic(args, client)
    assert result == {'ARN': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}


def test_create_topic_failure():
    # Mocking the client.create_topic method
    client = MagicMock()
    client.create_topic.side_effect = Exception('An error occurred')

    # Testing the function
    args = {'topicName': 'MyTopic'}
    result = create_topic(args, client)
    assert result == 'An error occurred while creating the topic'


def test_send_message_success():
    # Mocking the client.publish method
    client = MagicMock()
    client.publish.return_value = {'MessageId': '12345'}

    # Testing the function
    args = {'message': 'Hello, world!', 'topicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}
    result = send_message(args, client)
    assert result == {'AWS.SNS.SentMessages': [{'MessageId': '12345'}]}


def test_send_message_failure():
    # Mocking the client.publish method
    client = MagicMock()
    client.publish.side_effect = Exception('An error occurred')

    # Testing the function
    args = {'message': 'Hello, world!', 'topicArn': 'arn:aws:sns:us-west-2:123456789012:MyTopic'}
    result = send_message(args, client)
    assert result == 'An error occurred while sending the message'