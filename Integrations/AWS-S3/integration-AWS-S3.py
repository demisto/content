import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import boto3
import io
import math
import json
from datetime import datetime, date
from botocore.config import Config
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

AWS_DEFAULT_REGION = None  # demisto.params()['defaultRegion']
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None
AWS_access_key_id = demisto.params().get('access_key')
AWS_secret_access_key = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
if not demisto.params().get('proxy', False):
    config = Config(
        retries=dict(
            max_attempts=10
        )
    )
else:
    config = None


def aws_session(service='s3', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
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
    if kwargs and AWS_access_key_id is None:

        if AWS_access_key_id is None:
            sts_client = boto3.client('sts')
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
    elif AWS_access_key_id and AWS_roleArn:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_access_key_id,
            aws_secret_access_key=AWS_secret_access_key,
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
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_access_key_id,
                aws_secret_access_key=AWS_secret_access_key,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_access_key_id,
                aws_secret_access_key=AWS_secret_access_key,
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


def create_bucket(args):
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


def delete_bucket(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    response = client.delete_bucket(Bucket=args.get('bucket').lower())
    if response['ResponseMetadata']['HTTPStatusCode'] == 204:
        demisto.results("the Bucket {} was Deleted ".format(args.get('bucket')))


def list_buckets(args):
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


def get_bucket_policy(args):
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
            'PolicyId': policy['Id'],
            'PolicyVersion': policy['Version'],
            'Sid': statement['Sid'],
            'Action': statement['Action'],
            'Principal': statement['Principal'],
            'Resource': statement['Resource'],
            'Effect': statement['Effect'],
            'Json': response['Policy']
        })
    ec = {'AWS.S3.Buckets(val.BucketName === obj.BucketName).Policy': data}
    human_readable = tableToMarkdown('AWS S3 Bucket Policy', data)
    return_outputs(human_readable, ec)


def put_bucket_policy(args):
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
        demisto.results('Successfully applied Bucket policy to {} bucket'.format(args.get('BucketName')))


def delete_bucket_policy(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    client.delete_bucket_policy(Bucket=args.get('bucket').lower())
    demisto.results('Policy deleted from {}'.format(args.get('bucket')))


def download_file(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    data = io.BytesIO()
    client.download_fileobj(args.get('bucket').lower(), args.get('key'), data)

    demisto.results(fileResult(args.get('key'), data.getvalue()))


def list_objects(args):
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


def upload_file(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    path = get_file_path(args.get('entryID'))

    with open(path['path'], 'rb') as data:
        client.upload_fileobj(data, args.get('bucket'), args.get('key'))
        demisto.results('File {} was uploaded successfully to {}'.format(args.get('key'), args.get('bucket')))


"""COMMAND BLOCK"""
try:
    LOG('Command being called is {}'.format(demisto.command()))
    if demisto.command() == 'test-module':
        client = aws_session()
        response = client.list_buckets()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')

    elif demisto.command() == 'aws-s3-create-bucket':
        create_bucket(demisto.args())

    elif demisto.command() == 'aws-s3-delete-bucket':
        delete_bucket(demisto.args())

    elif demisto.command() == 'aws-s3-list-buckets':
        list_buckets(demisto.args())

    elif demisto.command() == 'aws-s3-get-bucket-policy':
        get_bucket_policy(demisto.args())

    elif demisto.command() == 'aws-s3-put-bucket-policy':
        put_bucket_policy(demisto.args())

    elif demisto.command() == 'aws-s3-delete-bucket-policy':
        delete_bucket_policy(demisto.args())

    elif demisto.command() == 'aws-s3-download-file':
        download_file(demisto.args())

    elif demisto.command() == 'aws-s3-delete-bucket-policy':
        delete_bucket_policy(demisto.args())

    elif demisto.command() == 'aws-s3-list-bucket-objects':
        list_objects(demisto.args())

    elif demisto.command() == 'aws-s3-upload-file':
        upload_file(demisto.args())

except Exception as e:
    return_error('Error has occurred in the AWS S3 Integration: {}\n {}'.format(type(e), e.message))
