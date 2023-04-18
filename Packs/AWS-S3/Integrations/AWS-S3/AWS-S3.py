import demistomock as demisto
from CommonServerPython import *
import io
import math
import json
from datetime import datetime, date
import urllib3.util
from AWSApiModule import *  # noqa: E402
from http import HTTPStatus

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
    return f"{s} {size_name[i]}"


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_bucket_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    data = []
    kwargs = {'Bucket': args.get('bucket', '').lower()}
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

    data.append({'BucketName': args.get('bucket'), 'Location': response['Location']})
    human_readable = tableToMarkdown('AWS S3 Buckets', data)
    return CommandResults(readable_output=human_readable, outputs=data, outputs_prefix='AWS.S3.Buckets')


def delete_bucket_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )

    response = client.delete_bucket(Bucket=args.get('bucket', '').lower())
    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.NO_CONTENT:
        return CommandResults(readable_output=f"The requested bucket '{args.get('bucket')}' was deleted")
    return CommandResults(readable_output=f"The requested bucket '{args.get('bucket')}' was not found")


def list_buckets_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    data = []
    response = client.list_buckets()
    for bucket in response['Buckets']:
        data.append({'BucketName': bucket['Name'],
                     'CreationDate': datetime.strftime(bucket['CreationDate'], '%Y-%m-%dT%H:%M:%S')})
    human_readable = tableToMarkdown('AWS S3 Buckets', data)
    return CommandResults(readable_output=human_readable, outputs_prefix='AWS.S3.Buckets',
                          outputs_key_field='BucketName', outputs=data)


def get_bucket_policy_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    data = []
    response = client.get_bucket_policy(Bucket=args.get('bucket', '').lower())
    policy = json.loads(response['Policy'])
    statements = policy['Statement']
    for statement in statements:
        data.append(
            {'BucketName': args.get('bucket'), 'PolicyId': policy.get('Id'), 'PolicyVersion': policy.get('Version'),
             'Sid': statement.get('Sid'), 'Action': statement.get('Action'), 'Principal': statement.get('Principal'),
             'Resource': statement.get('Resource'), 'Effect': statement.get('Effect'), 'Json': response.get('Policy')})
    human_readable = tableToMarkdown('AWS S3 Bucket Policy', data)
    return CommandResults(readable_output=human_readable, outputs_prefix='AWS.S3.Buckets',
                          outputs_key_field='BucketName', outputs=data)


def put_bucket_policy_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    kwargs = {'Bucket': args.get('bucket', '').lower(), 'Policy': args.get('policy')}
    if args.get('confirmRemoveSelfBucketAccess') is not None:
        kwargs.update(
            {'ConfirmRemoveSelfBucketAccess': True if args.get('confirmRemoveSelfBucketAccess') == 'True' else False})

    response = client.put_bucket_policy(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(readable_output=f"Successfully applied bucket policy to {args.get('bucket')} bucket")
    return CommandResults(readable_output=f"Couldn't apply bucket policy to {args.get('bucket')} bucket")


def delete_bucket_policy_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    client.delete_bucket_policy(Bucket=args.get('bucket', '').lower())
    return CommandResults(readable_output=f"Policy deleted from {args.get('bucket')}")


def download_file_command(args: Dict[str, Any], aws_client: AWSClient):
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    data = io.BytesIO()
    client.download_fileobj(args.get('bucket', '').lower(), args.get('key'), data)

    demisto.results(fileResult(args.get('key'), data.getvalue()))


def list_objects_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    data = []
    kwargs = {'Bucket': args.get('bucket')}
    if args.get('delimiter') is not None:
        kwargs.update({'Delimiter': args.get('delimiter')})
    if args.get('prefix') is not None:
        kwargs.update({'Prefix': args.get('prefix')})

    client.list_objects(**kwargs)
    paginator = client.get_paginator('list_objects')
    for response in paginator.paginate(**kwargs):
        if response.get('Contents', None):
            for key in response['Contents']:
                data.append({'Key': key['Key'], 'Size': convert_size(key['Size']),
                             'LastModified': datetime.strftime(key['LastModified'], '%Y-%m-%dT%H:%M:%S')})

    if len(data) > 0:
        human_readable = tableToMarkdown('AWS S3 Bucket Objects', data)
        return CommandResults(readable_output=human_readable, outputs_prefix='AWS.S3.Buckets',
                              outputs_key_field='BucketName', outputs=data)
    return CommandResults(readable_output=f"The {args.get('bucket')} bucket contains no objects.")


def get_file_path(file_id):
    filepath_result = demisto.getFilePath(file_id)
    return filepath_result


def upload_file_command(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    path = get_file_path(args.get('entryID'))

    with open(path['path'], 'rb') as data:
        client.upload_fileobj(data, args.get('bucket'), args.get('key'))
        return CommandResults(
            readable_output=f"File {args.get('key')} was uploaded successfully to {args.get('bucket')}")


def get_public_access_block(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    response = client.get_public_access_block(Bucket=args.get('bucket'))
    public_access_block_configuration = response.get('PublicAccessBlockConfiguration')
    data = {'BucketName': args.get('bucket'), 'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': public_access_block_configuration.get('BlockPublicAcls'),
        'IgnorePublicAcls': public_access_block_configuration.get('IgnorePublicAcls'),
        'BlockPublicPolicy': public_access_block_configuration.get('BlockPublicPolicy'),
        'RestrictPublicBuckets': public_access_block_configuration.get('RestrictPublicBuckets'), }}
    human_readable = tableToMarkdown('AWS S3 Bucket Public Access Block', data)
    return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.S3.Buckets',
                          outputs_key_field='BucketName')


def put_public_access_block(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    kwargs = {'Bucket': args.get('bucket'),
              'PublicAccessBlockConfiguration': {'BlockPublicAcls': argToBoolean(args.get('BlockPublicAcls')),
                                                 'IgnorePublicAcls': argToBoolean(args.get('IgnorePublicAcls')),
                                                 'BlockPublicPolicy': argToBoolean(args.get('BlockPublicPolicy')),
                                                 'RestrictPublicBuckets': argToBoolean(
                                                     args.get('RestrictPublicBuckets'))}}
    response = client.put_public_access_block(**kwargs)

    if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
        return CommandResults(
            readable_output=f"Successfully applied public access block to the {args.get('bucket')} bucket")
    return CommandResults(readable_output=f"Couldn't apply public access block to the {args.get('bucket')} bucket")


def get_bucket_encryption(args: Dict[str, Any], aws_client: AWSClient) -> CommandResults:
    client = aws_client.aws_session(service=SERVICE, region=args.get('region'), role_arn=args.get('roleArn'),
                                    role_session_name=args.get('roleSessionName'),
                                    role_session_duration=args.get('roleSessionDuration'), )
    kwargs = {'Bucket': args.get('bucket')}
    if args.get('expectedBucketOwner') is not None:
        kwargs.update({'ExpectedBucketOwner': args.get('expectedBucketOwner')})
    try:
        response = client.get_bucket_encryption(**kwargs)
    except client.exceptions.ClientError as ex:
        if ex.response.get('Error', {}).get('Code', '') != 'ServerSideEncryptionConfigurationNotFoundError':
            raise ex
        response = {}
    data = {'BucketName': args.get('bucket'),
            'ServerSideEncryptionConfiguration': response.get('ServerSideEncryptionConfiguration')}
    human_readable = tableToMarkdown('AWS S3 Bucket Encryption', data)
    return CommandResults(outputs=data, readable_output=human_readable, outputs_prefix='AWS.S3.Buckets',
                          outputs_key_field='BucketName')


def main():  # pragma: no cover
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    sts_endpoint_url = params.get('sts_endpoint_url') or None
    endpoint_url = params.get('endpoint_url') or None

    try:
        command = demisto.command()
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries, sts_endpoint_url=sts_endpoint_url, endpoint_url=endpoint_url)

        args = demisto.args()

        demisto.info(f'Command being called is {demisto.command()}')
        if command == 'test-module':
            client = aws_client.aws_session(service=SERVICE)
            response = client.list_buckets()
            if response['ResponseMetadata']['HTTPStatusCode'] == HTTPStatus.OK:
                demisto.results('ok')

        elif command == 'aws-s3-create-bucket':
            return_results(create_bucket_command(args, aws_client))

        elif command == 'aws-s3-delete-bucket':
            return_results(delete_bucket_command(args, aws_client))

        elif command == 'aws-s3-list-buckets':
            return_results(list_buckets_command(args, aws_client))

        elif command == 'aws-s3-get-bucket-policy':
            return_results(get_bucket_policy_command(args, aws_client))

        elif command == 'aws-s3-put-bucket-policy':
            return_results(put_bucket_policy_command(args, aws_client))

        elif command == 'aws-s3-delete-bucket-policy':
            return_results(delete_bucket_policy_command(args, aws_client))

        elif command == 'aws-s3-download-file':
            download_file_command(args, aws_client)

        elif command == 'aws-s3-list-bucket-objects':
            return_results(list_objects_command(args, aws_client))

        elif command == 'aws-s3-upload-file':
            return_results(upload_file_command(args, aws_client))

        elif command == 'aws-s3-get-public-access-block':
            return_results(get_public_access_block(args, aws_client))

        elif command == 'aws-s3-put-public-access-block':
            return_results(put_public_access_block(args, aws_client))

        elif command == 'aws-s3-get-bucket-encryption':
            return_results(get_bucket_encryption(args, aws_client))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
