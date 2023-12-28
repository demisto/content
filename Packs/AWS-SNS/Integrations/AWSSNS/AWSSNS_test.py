import pytest
from AWSSNS import delete_topic, create_topic, send_message, create_subscription, list_subscriptions_by_topic, list_topics


@pytest.fixture
def mock_tableToMarkdown(mocker):
    return mocker.patch('AWSSNS.tableToMarkdown')


@pytest.fixture
def sns_client(mocker):
    return mocker.Mock()


def test_create_subscription_success(sns_client):
    """
    Given a mocked SNS clien
    When create_subscription is called with valid args
    Then check the client called subscribe with expected args
    """
    args = {'topicArn': 'topic',
            'protocol': 'https',
            'returnSubscriptionArn': 'true',
            'deliveryPolicy': 'test_delivery',
            'filterPolicy': 'test_filter',
            'rawMessageDelivery': 'true',
            'redrivePolicy': 'test_redrive',
            'subscriptionRoleArn': 'test_role'
            }
    sns_client.subscribe.side_effect = [{'SubscriptionArn': 'test_arn'}]
    result = create_subscription(args, sns_client)
    assert result['EntryContext']['AWS.SNS.Subscriptions'] == {'SubscriptionArn': 'test_arn'}


def test_send_message_success(sns_client):
    """
    Given a mocked SNS client
    When send_message is called with valid args
    Then send_message should call the correct SNS client methods
    """
    args = {'message': 'hello',
            'topicArn': 'topic123',
            'targetArn': 'target123',
            'phoneNumber': '1234567890',
            'subject': 'test_subject',
            'messageStructure': 'test_structure',
            'messageDeduplicationId': 'test_msg_app_ip',
            'messageGroupId': 'test_msg_group_id',
            }
    sns_client.publish.side_effect = [{'MessageId': 'test_msg_id'}]
    result = send_message(args, sns_client)
    assert result['EntryContext']['AWS.SNS.SentMessages'][0] == {'MessageId': 'test_msg_id'}


def test_send_message_failure(sns_client):
    """
    Given a mocked SNS client configured to raise an exception
    When send_message is called
    Then an error message should return
    """
    sns_client.publish.side_effect = Exception('Error!')

    send_message_res = send_message({}, sns_client)

    assert send_message_res['Contents'] == 'Error!'


def test_create_topic_success(sns_client):
    """
    Given a mocked SNS client
    When create_topic is called with a valid topic name
    Then the create_topic method should call create_topic on the client with the correct args
    """
    topic_name = 'test_topic'
    args = {'topicName': topic_name,
            'deliveryPolicy': 'test_delivery',
            'displayName': 'test_display',
            'fifoTopic': 'true',
            'policy': 'test_policy',
            'kmsMasterKeyId': 'test_kms',
            'contentBasedDeduplication': 'true',
            }
    sns_client.create_topic.side_effect = [{'TopicArn': topic_name}]
    result = create_topic(args, sns_client)
    assert result['EntryContext'] == {'AWS.SNS.Topic': {'ARN': topic_name}}


def test_create_topic_failure(sns_client):
    """
    Given a mocked SNS client configured to raise an exception
    When create_topic is called
    Then an error message should return
    """
    sns_client.create_topic.side_effect = Exception('Error creating topic')
    args = {'topicName': 'test_topic'}
    result = create_topic(args, sns_client)
    assert result['Contents'] == 'Error creating topic'


def test_delete_topic_success(sns_client):
    """
    Given a mocked SNS client
    When delete_topic is called with a valid topic ARN
    Then delete_topic should call delete_topic on the client
    """
    topic_arn = {'topicArn': 'topic_arn'}
    response = {
        'ResponseMetadata': {
            'HTTPStatusCode': 200
        }}
    sns_client.delete_topic.side_effect = [response]
    result = delete_topic(topic_arn, sns_client)
    assert result == 'The Topic has been deleted'
    sns_client.delete_topic.assert_called_with(TopicArn='topic_arn')


def test_delete_topic_invalid_arn(sns_client):
    """
    Given a mocked SNS client
    When delete_topic is called with an invalid ARN and throws exception
    Then delete_topic should return an error with the exception message
    """
    invalid_arn = {'topicArn': 'invalidarn'}
    sns_client.delete_topic.side_effect = [Exception('Invalid ARN')]

    result = delete_topic(invalid_arn, sns_client)
    assert result['Contents'] == 'Invalid ARN'


def test_list_subscriptions_by_topic_with_topic_arn(sns_client):
    """
    Given a mock SNS client
    When list_subscriptions_by_topic is called with a topic ARN
    Then the client's list_subscriptions_by_topic method is called with the topic ARN
    """
    topic_arn = 'arn:aws:sns:us-east-1:123456789012:some-topic'
    sns_client.list_subscriptions_by_topic.side_effect = [{'Subscriptions': [{'SubscriptionArn': 'sub_arn'}]}]
    result = list_subscriptions_by_topic({'topicArn': topic_arn}, sns_client)
    assert result['EntryContext']['AWS.SNS.Subscriptions'] == [{'SubscriptionArn': 'sub_arn'}]
    sns_client.list_subscriptions_by_topic.assert_called_with(TopicArn=topic_arn)


def test_list_subscriptions_by_topic_with_next_token(sns_client):
    """
    Given a mock SNS client
    When list_subscriptions_by_topic is called with a next token
    Then the client's list_subscriptions_by_topic method is called with the next token
    """
    next_token = 'some-token'
    sns_client.list_subscriptions_by_topic.side_effect = [{'Subscriptions': [{'SubscriptionArn': next_token}]}]
    result = list_subscriptions_by_topic({'nextToken': next_token}, sns_client)
    assert result['EntryContext']['AWS.SNS.Subscriptions'] == [{'SubscriptionArn': next_token}]
    sns_client.list_subscriptions_by_topic.assert_called_with(NextToken=next_token)


def test_list_subscriptions_by_topic_with_no_args(sns_client):
    """
    Given a mock SNS client
    When list_subscriptions_by_topic is called without arguments
    Then the client's list_subscriptions_by_topic method is called without arguments
    """
    list_subscriptions_by_topic({}, sns_client)
    sns_client.list_subscriptions_by_topic.assert_called_with()


def test_list_topics_success(sns_client):
    """
    Given a mocked SNS client
    When list_topics is called with the client
    Then return a list of topic ARNs
    """
    sns_client.list_topics.return_value = {'Topics': ['topic1']}

    result = list_topics({}, sns_client)

    assert result['EntryContext']['AWS.SNS.Topics'][0]['TopicArn'] == 'topic1'


def test_list_topics_with_next_token(sns_client):
    """
    Given a mocked SNS client
    When list_topics is called with a nextToken
    Then return a list of topic ARNs
    """
    sns_client.list_topics.return_value = {'Topics': ['topic2']}

    args = {'nextToken': 'token123'}
    result = list_topics(args, sns_client)

    assert result['EntryContext']['AWS.SNS.Topics'][0]['TopicArn'] == 'topic2'


def test_list_topics_client_error(sns_client):
    """
    Given a mocked SNS client
    When the client raises an exception
    Then raise the exception
    """
    error_message = 'Some error'
    sns_client.list_topics.side_effect = Exception(error_message)

    result = list_topics({}, sns_client)
    assert result['Contents'] == error_message
