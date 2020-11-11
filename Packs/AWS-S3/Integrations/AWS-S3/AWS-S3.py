import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import boto3
import io
import math
import json
from datetime import datetime, date
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

"""PARAMETERS"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
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


"""HELPER FUNCTIONS"""


def aws_session(service='s3', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and not AWS_ACCESS_KEY_ID:

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
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
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
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "{} {}".format(s, size_name[i])


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_bucket_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {'Bucket': args.get('bucket').lower()}
    if args.get('acl') is not None:
        kwargs.update({'ACL': args.get('acl')})
    if args.get('locationConstraint') is not None:
        kwargs.update({'CreateBucketConfiguration': {'LocationConstraint': args.get('locationConstraint')}})
    if args.get('grantFullControl') is not None:
        kwargs.update({'GrantFullControl': args.get('grantFullControl')})
    if args.get('grantRead') is not None:
        kwargs.update({'GrantRead': args.get('grantRead')})
    if args.get('grantReadACP') is not None:
        kwargs.update({'GrantReadACP': args.get('grantReadACP')})
    if args.get('grantWrite') is not None:
        kwargs.update({'GrantWrite': args.get('grantWrite')})
    if args.get('grantWriteACP') is not None:
        kwargs.update({'GrantWriteACP': args.get('grantWriteACP')})

    response = client.create_bucket(**kwargs)

    data.append({
        'BucketName': args.get('bucket'),
        'Location': response['Location']
    })
    ec = {'AWS.S3.Buckets': data}
    human_readable = tableToMarkdown('AWS S3 Buckets', data)
    return_outputs(human_readable, ec)


def delete_bucket_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.delete_bucket(Bucket=args.get('bucket').lower())
    if response['ResponseMetadata']['HTTPStatusCode'] == 204:
        demisto.results("the Bucket {bucket} was Deleted ".format(bucket=args.get('bucket')))


def list_buckets_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_buckets()
    for bucket in response['Buckets']:
        data.append({
            'BucketName': bucket['Name'],
            'CreationDate': datetime.strftime(bucket['CreationDate'], '%Y-%m-%dT%H:%M:%S')
        })
    ec = {'AWS.S3.Buckets(val.BucketName === obj.BucketName)': data}
    human_readable = tableToMarkdown('AWS S3 Buckets', data)
    return_outputs(human_readable, ec)


def get_bucket_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.get_bucket_policy(Bucket=args.get('bucket').lower())
    policy = json.loads(response['Policy'])
    statements = policy['Statement']
    for statement in statements:
        data.append({
            'BucketName': args.get('bucket'),
            'PolicyId': policy.get('Id'),
            'PolicyVersion': policy.get('Version'),
            'Sid': statement.get('Sid'),
            'Action': statement.get('Action'),
            'Principal': statement.get('Principal'),
            'Resource': statement.get('Resource'),
            'Effect': statement.get('Effect'),
            'Json': response.get('Policy')
        })
    ec = {'AWS.S3.Buckets(val.BucketName === obj.BucketName).Policy': data}
    human_readable = tableToMarkdown('AWS S3 Bucket Policy', data)
    return_outputs(human_readable, ec)


def put_bucket_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'Bucket': args.get('bucket').lower(),
        'Policy': args.get('policy')
    }
    if args.get('confirmRemoveSelfBucketAccess') is not None:
        kwargs.update({'ConfirmRemoveSelfBucketAccess': True if args.get(
            'confirmRemoveSelfBucketAccess') == 'True' else False})

    response = client.put_bucket_policy(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('Successfully applied Bucket policy to {bucket} bucket'.format(bucket=args.get('BucketName')))


def delete_bucket_policy_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    client.delete_bucket_policy(Bucket=args.get('bucket').lower())
    demisto.results('Policy deleted from {}'.format(args.get('bucket')))


def download_file_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = io.BytesIO()
    client.download_fileobj(args.get('bucket').lower(), args.get('key'), data)

    demisto.results(fileResult(args.get('key'), data.getvalue()))


def list_objects_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = []
    response = client.list_objects(Bucket=args.get('bucket'))
    for key in response['Contents']:
        data.append({
            'Key': key['Key'],
            'Size': convert_size(key['Size']),
            'LastModified': datetime.strftime(key['LastModified'], '%Y-%m-%dT%H:%M:%S')
        })

    ec = {'AWS.S3.Buckets(val.BucketName === args.get("bucket")).Objects': data}
    human_readable = tableToMarkdown('AWS S3 Bucket Objects', data)
    return_outputs(human_readable, ec)


def get_file_path(file_id):
    filepath_result = demisto.getFilePath(file_id)
    return filepath_result


def upload_file_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    path = get_file_path(args.get('entryID'))

    try:
        with open(path['path'], 'rb') as data:
            client.upload_fileobj(data, args.get('bucket'), args.get('key'))
            demisto.results('File {file} was uploaded successfully to {bucket}'.format(
                file=args.get('key'), bucket=args.get('bucket')))
    except (OSError, IOError) as e:
        return_error("Could not read file: {path}\n {msg}".format(path=path, msg=e.message))


"""COMMAND BLOCK"""
try:
    LOG('Command being called is {command}'.format(command=demisto.command()))
    if demisto.command() == 'test-module':
        client = aws_session()
        response = client.list_buckets()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')

    elif demisto.command() == 'aws-s3-create-bucket':
        create_bucket_command(demisto.args())

    elif demisto.command() == 'aws-s3-delete-bucket':
        delete_bucket_command(demisto.args())

    elif demisto.command() == 'aws-s3-list-buckets':
        list_buckets_command(demisto.args())

    elif demisto.command() == 'aws-s3-get-bucket-policy':
        get_bucket_policy_command(demisto.args())

    elif demisto.command() == 'aws-s3-put-bucket-policy':
        put_bucket_policy_command(demisto.args())

    elif demisto.command() == 'aws-s3-delete-bucket-policy':
        delete_bucket_policy_command(demisto.args())

    elif demisto.command() == 'aws-s3-download-file':
        download_file_command(demisto.args())

    elif demisto.command() == 'aws-s3-list-bucket-objects':
        list_objects_command(demisto.args())

    elif demisto.command() == 'aws-s3-upload-file':
        upload_file_command(demisto.args())

except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
        error=type(e)))
    LOG(e.message)

except Exception as e:
    return_error('Error has occurred in the AWS S3 Integration: {error}\n {message}'.format(
        error=type(e), message=e.message))
