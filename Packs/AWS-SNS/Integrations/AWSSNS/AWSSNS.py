import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402


def create_entry(title, data, ec):  # pragme no cover
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def raise_error(error):  # pragma no cover
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


def create_subscription(args, client):
    try:
        attributes = {}
        kwargs = {
            'TopicArn': args.get('topicArn'),
            'Protocol': args.get('protocol')
        }
        if args.get('endpoint') is not None:
            kwargs.update({'Endpoint': args.get('endpoint')})
        if args.get('returnSubscriptionArn') is not None:
            kwargs.update({'ReturnSubscriptionArn': bool(args.get('returnSubscriptionArn'))})

        if args.get('deliveryPolicy') is not None:
            attributes.update({'DeliveryPolicy': args.get('deliveryPolicy')})
        if args.get('filterPolicy') is not None:
            attributes.update({'FilterPolicy': args.get('filterPolicy')})
        if args.get('rawMessageDelivery') is not None:
            attributes.update({'RawMessageDelivery': args.get('rawMessageDelivery')})
        if args.get('redrivePolicy') is not None:
            attributes.update({'RedrivePolicy': args.get('RedrivePolicy')})
        if args.get('subscriptionRoleArn') is not None:
            attributes.update({'SubscriptionRoleArn': args.get('subscriptionRoleArn')})
        if attributes:
            kwargs.update({'Attributes': attributes})

        response = client.subscribe(**kwargs)
        data = {'SubscriptionArn': response['SubscriptionArn']}

        ec = {'AWS.SNS.Subscriptions': data}
        return create_entry('AWS SNS Subscriptions', data, ec)

    except Exception as e:
        return raise_error(e)


def list_topics(args, client):
    try:
        data = []
        kwargs = {}
        if args.get('nextToken') is not None:
            kwargs.update({'NextToken': args.get('nextToken')})
        response = client.list_topics(**kwargs)
        for topic in response['Topics']:
            data.append({'TopicArn': topic})

        ec = {'AWS.SNS.Topics': data}
        return create_entry('AWS SNS Topics', data, ec)

    except Exception as e:
        return raise_error(e)


def list_subscriptions_by_topic(args, client):
    try:
        data = []
        kwargs = {}
        if args.get('topicArn') is not None:
            kwargs.update({'TopicArn': args.get('topicArn')})
        if args.get('nextToken') is not None:
            kwargs.update({'NextToken': args.get('nextToken')})
        response = client.list_subscriptions_by_topic(**kwargs)
        for subscription in response['Subscriptions']:
            data.append({'SubscriptionArn': subscription['SubscriptionArn']})

        ec = {'AWS.SNS.Subscriptions': data}
        return create_entry('AWS SNS Subscriptions', data, ec)

    except Exception as e:
        return raise_error(e)


def send_message(args, client):
    try:
        data = []
        kwargs = {
            'Message': args.get('message')
        }

        if args.get('topicArn') is not None:
            kwargs.update({'TopicArn': args.get('topicArn')})
        if args.get('targetArn') is not None:
            kwargs.update({'TargetArn': args.get('targetArn')})
        if args.get('phoneNumber') is not None:
            kwargs.update({'PhoneNumber': args.get('phoneNumber')})
        if args.get('subject') is not None:
            kwargs.update({'Subject': args.get('subject')})
        if args.get('messageStructure') is not None:
            kwargs.update({'MessageStructure': args.get('messageStructure')})
        if args.get('messageDeduplicationId') is not None:
            kwargs.update({'MessageDeduplicationId': args.get('messageDeduplicationId')})
        if args.get('messageGroupId') is not None:
            kwargs.update({'MessageGroupId': args.get('messageGroupId')})

        response = client.publish(**kwargs)
        data.append({'MessageId': response['MessageId']})
        ec = {'AWS.SNS.SentMessages': data}
        return create_entry('AWS SNS sent messages', data, ec)

    except Exception as e:
        return raise_error(e)


def create_topic(args, client):
    try:
        attributes = {}
        kwargs = {'Name': args.get('topicName')}
        if args.get('deliveryPolicy') is not None:
            attributes.update({'DeliveryPolicy': args.get('deliveryPolicy')})
        if args.get('displayName') is not None:
            attributes.update({'DisplayName': args.get('displayName')})
        if args.get('fifoTopic') is not None:
            attributes.update({'FifoTopic': bool(args.get('fifoTopic'))})
        if args.get('policy') is not None:
            attributes.update({'policy': args.get('Policy')})
        if args.get('kmsMasterKeyId') is not None:
            attributes.update({'KmsMasterKeyId': args.get('kmsMasterKeyId')})
        if args.get('contentBasedDeduplication') is not None:
            attributes.update({'ContentBasedDeduplication': args.get('contentBasedDeduplication')})
        if attributes:
            kwargs.update({'Attributes': attributes})

        response = client.create_topic(**kwargs)
        data = {'ARN': response['TopicArn']}
        ec = {'AWS.SNS.Topic': data}
        return create_entry('AWS SNS Topic', data, ec)

    except Exception as e:
        return raise_error(e)


def delete_topic(args, client):
    try:
        response = client.delete_topic(TopicArn=args.get('topicArn'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Topic has been deleted'

    except Exception as e:
        return raise_error(e)


def test_function(aws_client):  # pragma no cover
    try:
        client = aws_client.aws_session(service='sns')
        response = client.list_topics()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "ok"
    except Exception as e:
        return raise_error(e)


def main():  # pragma no cover

    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier', '')
    aws_secret_access_key = params.get('credentials', {}).get('password', '')
    verify_certificate = not params.get('insecure', False)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5

    commands = {
        'aws-sns-create-subscription': create_subscription,
        'aws-sns-list-topics': list_topics,
        'aws-sns-list-subscriptions-by-topic': list_subscriptions_by_topic,
        'aws-sns-send-message': send_message,
        'aws-sns-create-topic': create_topic,
        'aws-sns-delete-topic': delete_topic
    }

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)
        command = demisto.command()
        args = demisto.args()
        demisto.debug(f'Command being called is {command}')
        if command == 'test-module':
            return_results(test_function(aws_client))
        elif command in commands:
            client = aws_client.aws_session(
                service='sns',
                region=args.get('region'),
                role_arn=args.get('roleArn'),
                role_session_name=args.get('roleSessionName'),
                role_session_duration=args.get('roleSessionDuration'))
            return_results(commands[command](args, client))
        else:
            raise NotImplementedError(f'{command} is not an existing AWS-SNS command')

    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
