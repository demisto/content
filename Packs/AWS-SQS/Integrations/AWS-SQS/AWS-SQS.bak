import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def raise_error(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


def get_queue_url(args, client):
    try:
        kwargs = {'QueueName': args.get('queueName')}
        if args.get('queueOwnerAWSAccountId'):
            kwargs.update({'QueueOwnerAWSAccountId': args.get('queueOwnerAWSAccountId')})

        response = client.get_queue_url(**kwargs)
        data = ({'QueueUrl': response['QueueUrl']})

        ec = {'AWS.SQS.Queues': data}
        return create_entry('AWS SQS Queues', data, ec)

    except Exception as e:
        return raise_error(e)


def list_queues(args, client):
    try:
        data = []
        kwargs = {}
        if args.get('queueNamePrefix') is not None:
            kwargs.update({'QueueNamePrefix': args.get('queueNamePrefix')})
        response = client.list_queues(**kwargs)
        for queue in response['QueueUrls']:
            data.append({'QueueUrl': queue})

        ec = {'AWS.SQS.Queues': data}
        return create_entry('AWS SQS Queues', data, ec)

    except Exception as e:
        return raise_error(e)


def send_message(args, client):
    try:
        kwargs = {
            'QueueUrl': args.get('queueUrl'),
            'MessageBody': args.get('messageBody'),
        }
        if args.get('delaySeconds') is not None:
            kwargs.update({'DelaySeconds': int(args.get('delaySeconds'))})
        if args.get('messageGroupId') is not None:
            kwargs.update({'MessageGroupId': int(args.get('messageGroupId'))})

        response = client.send_message(**kwargs)
        data = ({
            'QueueUrl': args.get('queueUrl'),
            'MessageId': response['MessageId'],
        })
        if 'SequenceNumber' in response:
            data.update({'SequenceNumber': response['SequenceNumber']})
        if 'MD5OfMessageBody' in response:
            data.update({'MD5OfMessageBody': response['MD5OfMessageBody']})
        if 'MD5OfMessageAttributes' in response:
            data.update({'MD5OfMessageAttributes': response['MD5OfMessageAttributes']})

        ec = {'AWS.SQS.Queues(obj.QueueUrl === val.QueueUrl).SentMessages': data}
        return create_entry('AWS SQS Queues sent messages', data, ec)

    except Exception as e:
        return raise_error(e)


def create_queue(args, client):
    try:
        attributes = {}
        kwargs = {'QueueName': args.get('queueName')}
        if args.get('delaySeconds') is not None:
            attributes.update({'DelaySeconds': args.get('delaySeconds')})
        if args.get('maximumMessageSize') is not None:
            attributes.update({'MaximumMessageSize': args.get('maximumMessageSize')})
        if args.get('messageRetentionPeriod') is not None:
            attributes.update({'MessageRetentionPeriod': args.get('messageRetentionPeriod')})
        if args.get('receiveMessageWaitTimeSeconds') is not None:
            attributes.update({'ReceiveMessageWaitTimeSeconds': args.get('receiveMessageWaitTimeSeconds')})
        if args.get('visibilityTimeout') is not None:
            attributes.update({'VisibilityTimeout': int(args.get('visibilityTimeout'))})
        if args.get('kmsDataKeyReusePeriodSeconds') is not None:
            attributes.update({'KmsDataKeyReusePeriodSeconds': args.get('kmsDataKeyReusePeriodSeconds')})
        if args.get('kmsMasterKeyId') is not None:
            attributes.update({'KmsMasterKeyId': args.get('kmsMasterKeyId')})
        if args.get('policy') is not None:
            attributes.update({'Policy': args.get('policy')})
        if args.get('fifoQueue') is not None:
            attributes.update({'FifoQueue': args.get('fifoQueue')})
        if args.get('contentBasedDeduplication') is not None:
            attributes.update({'ContentBasedDeduplication': args.get('contentBasedDeduplication')})
        if attributes:
            kwargs.update({'Attributes': attributes})

        response = client.create_queue(**kwargs)
        data = ({'QueueUrl': response['QueueUrl']})
        ec = {'AWS.SQS.Queues': data}
        return create_entry('AWS SQS Queues', data, ec)

    except Exception as e:
        return raise_error(e)


def delete_queue(args, client):
    try:
        response = client.delete_queue(QueueUrl=args.get('queueUrl'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Queue has been deleted'

    except Exception as e:
        return raise_error(e)


def purge_queue(args, client):
    try:
        response = client.purge_queue(QueueUrl=args.get('queueUrl'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Queue has been Purged'

    except Exception as e:
        return raise_error(e)


def parse_incident_from_finding(message):
    incident = {}
    incident['name'] = "SQS MessageId: " + message["MessageId"]
    incident['rawJSON'] = json.dumps(message)
    return incident


def fetch_incidents(aws_client, aws_queue_url, max_fetch):
    try:
        client = aws_client.aws_session(service='sqs')
        receipt_handles = []  # type: list
        incidents = []  # type: list
        max_number_of_messages = min(max_fetch, 10)
        while len(incidents) < max_fetch:
            messages = client.receive_message(
                QueueUrl=aws_queue_url,
                MaxNumberOfMessages=max_number_of_messages,
                VisibilityTimeout=5,
                WaitTimeSeconds=5,
            )

            if "Messages" not in messages.keys():
                if len(incidents) == 0:
                    if demisto.command() == 'fetch-incidents':
                        demisto.incidents([])
                    return messages, incidents, receipt_handles
                else:
                    break

            for message in messages["Messages"]:
                receipt_handles.append(message['ReceiptHandle'])
                incidents.append(parse_incident_from_finding(message))
                if len(incidents) == max_fetch:
                    break

        demisto.incidents(incidents)
        for receipt_handle in receipt_handles:
            client.delete_message(QueueUrl=aws_queue_url, ReceiptHandle=receipt_handle)

    except Exception as e:
        return raise_error(e)


def test_function(aws_client):
    try:
        client = aws_client.aws_session(service='sqs')
        response = client.list_queues()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "ok"
    except Exception as e:
        return raise_error(e)


def main():

    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    aws_queue_url = params.get('queueUrl')
    max_fetch = min(params.get('max_fetch', 10), 100)

    commands = {
        'aws-sqs-get-queue-url': get_queue_url,
        'aws-sqs-list-queues': list_queues,
        'aws-sqs-send-message': send_message,
        'aws-sqs-create-queue': create_queue,
        'aws-sqs-delete-queue': delete_queue,
        'aws-sqs-purge-queue': purge_queue
    }

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)
        command = demisto.command()
        args = demisto.args()
        demisto.debug('Command being called is {}'.format(command))
        if command == 'test-module':
            return_results(test_function(aws_client))
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(aws_client, aws_queue_url, max_fetch)
            sys.exit(0)
        elif command in commands:
            client = aws_client.aws_session(
                service='sqs',
                region=args.get('region'),
                role_arn=args.get('roleArn'),
                role_session_name=args.get('roleSessionName'),
                role_session_duration=args.get('roleSessionDuration'))
            return_results(commands[command](args, client))
        else:
            raise NotImplementedError('{} is not an existing AWS-SQS command'.format(command))

    except Exception as e:
        return_error("Failed to execute {} command.\nError:\n{}".format(demisto.command(), str(e)))


from AWSApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
