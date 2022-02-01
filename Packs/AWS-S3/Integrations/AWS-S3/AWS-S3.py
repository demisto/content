import demistomock as demisto
from CommonServerPython import *

import io
import math
import json
from datetime import datetime, date
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 's3'

"""HELPER FUNCTIONS"""


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


def create_bucket_command(args, aws_client):
    client = aws_client. aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def delete_bucket_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    response = client.delete_bucket(Bucket=args.get('bucket').lower())
    if response['ResponseMetadata']['HTTPStatusCode'] == 204:
        demisto.results("the Bucket {bucket} was Deleted ".format(bucket=args.get('bucket')))


def list_buckets_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def get_bucket_policy_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def put_bucket_policy_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def delete_bucket_policy_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    client.delete_bucket_policy(Bucket=args.get('bucket').lower())
    demisto.results('Policy deleted from {}'.format(args.get('bucket')))


def download_file_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = io.BytesIO()
    client.download_fileobj(args.get('bucket').lower(), args.get('key'), data)

    demisto.results(fileResult(args.get('key'), data.getvalue()))


def list_objects_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    data = []
    kwargs = {
        'Bucket': args.get('bucket')
    }
    if args.get('delimiter') is not None:
        kwargs.update({'Delimiter': args.get('delimiter')})
    if args.get('prefix') is not None:
        kwargs.update({'Prefix': args.get('prefix')})

    client.list_objects(**kwargs)
    paginator = client.get_paginator('list_objects')
    for response in paginator.paginate(**kwargs):
        if response.get('Contents', None):
            for key in response['Contents']:
                data.append({
                    'Key': key['Key'],
                    'Size': convert_size(key['Size']),
                    'LastModified': datetime.strftime(key['LastModified'], '%Y-%m-%dT%H:%M:%S')
                })

    if len(data) > 0:
        ec = {'AWS.S3.Buckets(val.BucketName === args.get("bucket")).Objects': data}
        human_readable = tableToMarkdown('AWS S3 Bucket Objects', data)
        return_outputs(human_readable, ec)
    else:
        return_outputs("The {} bucket contains no objects.".format(args.get('bucket')))


def get_file_path(file_id):
    filepath_result = demisto.getFilePath(file_id)
    return filepath_result


def upload_file_command(args, aws_client):
    client = aws_client.aws_session(
        service=SERVICE,
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    path = get_file_path(args.get('entryID'))

    try:
        with open(path['path'], 'rb') as data:
            client.upload_fileobj(data, args.get('bucket'), args.get('key'))
            demisto.results('File {file} was uploaded successfully to {bucket}'.format(
                file=args.get('key'), bucket=args.get('bucket')))
    except (OSError, IOError) as e:
        return_error("Could not read file: {path}\n {msg}".format(path=path, msg=e.message))


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

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)

        command = demisto.command()
        args = demisto.args()

        LOG('Command being called is {command}'.format(command=demisto.command()))
        if command == 'test-module':
            client = aws_client.aws_session(service=SERVICE)
            response = client.list_buckets()
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                demisto.results('ok')

        elif command == 'aws-s3-create-bucket':
            create_bucket_command(args, aws_client)

        elif command == 'aws-s3-delete-bucket':
            delete_bucket_command(args, aws_client)

        elif command == 'aws-s3-list-buckets':
            list_buckets_command(args, aws_client)

        elif command == 'aws-s3-get-bucket-policy':
            get_bucket_policy_command(args, aws_client)

        elif command == 'aws-s3-put-bucket-policy':
            put_bucket_policy_command(args, aws_client)

        elif command == 'aws-s3-delete-bucket-policy':
            delete_bucket_policy_command(args, aws_client)

        elif command == 'aws-s3-download-file':
            download_file_command(args, aws_client)

        elif command == 'aws-s3-list-bucket-objects':
            list_objects_command(args, aws_client)

        elif command == 'aws-s3-upload-file':
            upload_file_command(args, aws_client)

    except Exception as e:
        return_error('Error has occurred in the AWS S3 Integration: {error}\n {message}'.format(
            error=type(e), message=e.message))


from AWSApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
