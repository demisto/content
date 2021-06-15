import boto3
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from botocore.config import Config

AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_roleArn = demisto.params().get('roleArn')
AWS_roleSessionName = demisto.params().get('roleSessionName')
AWS_roleSessionDuration = demisto.params().get('sessionDuration')
AWS_rolePolicy = None
AWS_QUEUEURL = demisto.params().get('queueUrl')
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


def aws_session(service='sqs', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None, rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_roleArn and AWS_roleSessionName is not None:
        kwargs.update({
            'RoleArn': AWS_roleArn,
            'RoleSessionName': AWS_roleSessionName,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(AWS_roleSessionDuration)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_rolePolicy is not None:
        kwargs.update({'Policy': AWS_rolePolicy})

    if kwargs and not AWS_ACCESS_KEY_ID:  # login with Role ARN
        if not AWS_ACCESS_KEY_ID:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_roleArn:  # login with Access Key ID and Role ARN
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_roleArn,
            'RoleSessionName': AWS_roleSessionName,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:  # login with access key id, and if access key is None than permissions pulled from the service metadata
        if region is not None:
            client = boto3.client(service_name=service,
                                  region_name=region,
                                  aws_access_key_id=AWS_ACCESS_KEY_ID,
                                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                  verify=VERIFY_CERTIFICATE,
                                  config=config
                                  )
        else:
            client = boto3.client(service_name=service,
                                  region_name=AWS_DEFAULT_REGION,
                                  aws_access_key_id=AWS_ACCESS_KEY_ID,
                                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                  verify=VERIFY_CERTIFICATE,
                                  config=config
                                  )

    return client


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


def fetch_incidents():
    try:
        client = aws_session()
        messages = client.receive_message(
            QueueUrl=AWS_QUEUEURL,
            MaxNumberOfMessages=10,
            VisibilityTimeout=5,
            WaitTimeSeconds=5,
        )

        receipt_handles = []  # type: list
        incidents = []  # type: list

        if "Messages" not in messages.keys():
            if demisto.command() == 'fetch-incidents':
                demisto.incidents([])
            return messages, incidents, receipt_handles

        for message in messages["Messages"]:
            receipt_handles.append(message['ReceiptHandle'])
            incidents.append(parse_incident_from_finding(message))

        demisto.incidents(incidents)
        if receipt_handles is not None:
            # Archive findings
            for receipt_handle in receipt_handles:
                client.delete_message(QueueUrl=AWS_QUEUEURL, ReceiptHandle=receipt_handle)

    except Exception as e:
        return raise_error(e)


def test_function():
    try:
        client = aws_session()
        response = client.list_queues()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return "ok"
    except Exception as e:
        return raise_error(e)


def main():

    commands = {
        'aws-sqs-get-queue-url': get_queue_url,
        'aws-sqs-list-queues': list_queues,
        'aws-sqs-send-message': send_message,
        'aws-sqs-create-queue': create_queue,
        'aws-sqs-delete-queue': delete_queue,
        'aws-sqs-purge-queue': purge_queue
    }

    try:
        command = demisto.command()
        args = demisto.args()
        demisto.debug('Command being called is {}'.format(command))
        if command == 'test-module':
            return_results(test_function())
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents()
            sys.exit(0)
        elif command in commands:
            client = aws_session(
                region=args.get('region'),
                roleArn=args.get('roleArn'),
                roleSessionName=args.get('roleSessionName'),
                roleSessionDuration=args.get('roleSessionDuration'))
            return_results(commands[command](args, client))
        else:
            raise NotImplementedError('{} is not an existing AWS-SQS command'.format(command))

    except Exception as e:
        return_error("Failed to execute {} command.\nError:\n{}".format(demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
