import json

import pytest
import importlib
from http import HTTPStatus

AWS_S3 = importlib.import_module("AWS-S3")

TEST_PARAMS = {'region': 'test_region', 'roleArn': 'test_arn', 'roleSessionName': 'test_role_session',
               'roleSessionDuration': 'test_role_session_duration'}


class AWSClient:
    def aws_session(self):
        pass


class Boto3Client:
    def create_bucket(self):
        pass

    def delete_bucket(self):
        pass

    def list_buckets(self):
        pass

    def get_bucket_policy(self):
        pass

    def put_bucket_policy(self):
        pass

    def delete_bucket_policy(self):
        pass

    def download_fileobj(self):
        pass

    def list_objects(self):
        pass

    def get_paginator(self):
        pass

    def put_public_access_block(self):
        pass

    def get_bucket_encryption(self):
        pass


class paginator:
    def paginate(self):
        pass


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def convert_size(size_bytes):
    import math

    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"


def test_create_bucket_command(mocker):
    """
    Given:
    - A bucket name and location.
    When:
    - Calling create_bucket_command method.
    Then:
    - Ensure that the bucket was successfully created.
    """
    from CommonServerPython import tableToMarkdown
    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)
    response = {'Location': 'us-west-2'}
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "create_bucket", return_value=response)

    client = AWSClient()
    data = [{'BucketName': args.get('bucket'), 'Location': response['Location']}]
    res = AWS_S3.create_bucket_command(args, client)
    assert tableToMarkdown('AWS S3 Buckets', data) == res.readable_output


@pytest.mark.parametrize('res, excepted', [({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.NO_CONTENT}}, 'deleted'),
                                           ({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.NOT_FOUND}},
                                            'not found')])
def test_delete_bucket_command(mocker, res, excepted):
    """
    Given:
    - A bucket name.
    When:
    - Calling delete_bucket_command method.
    Then:
    - Ensure that the bucket was successfully deleted.
    """
    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "delete_bucket", return_value=res)

    client = AWSClient()

    res = AWS_S3.delete_bucket_command(args, client)
    assert res.readable_output == f"The requested bucket '{args.get('bucket')}' was {excepted}"


def test_list_bucket_command(mocker):
    """
    Given:
    - A bucket name.
    When:
    - Calling list_bucket_command method.
    Then:
    - Ensure that the bucket list was successfully retrieve.
    """
    from datetime import datetime
    args = TEST_PARAMS
    response = {'Buckets': [{'Name': 'test_1', 'CreationDate': datetime(2022, 1, 1)},
                            {'Name': 'test_2', 'CreationDate': datetime(2022, 2, 2)}]}
    excepted = [{'BucketName': bucket.get('Name'),
                 'CreationDate': datetime.strftime(bucket['CreationDate'], '%Y-%m-%dT%H:%M:%S')} for bucket in
                response.get('Buckets')]
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_buckets", return_value=response)

    client = AWSClient()

    res = AWS_S3.list_buckets_command(args, client)
    assert res.outputs == excepted


TEST_POLICY = {'Policy': """
                   {
                       "Id": "1",
                       "Version": "1.0.0",
                       "Statement": [
                           {
                               "BucketName": "bucket_name_1",
                               "Sid": "Sid_1",
                               "Action": "action_1",
                               "Principal": "principal_1",
                               "Resource": "resource_1",
                               "Effect": "effect_1"
                           },
                           {
                               "BucketName": "bucket_name_2",
                               "Sid": "Sid_2",
                               "Action": "action_2",
                               "Principal": "principal_2",
                               "Resource": "resource_2",
                               "Effect": "effect_2"
                           }
                       ]
                   }
                   """}


def test_get_bucket_policy_command(mocker):
    """
    Given:
    - A bucket name.
    When:
    - Calling get_bucket_policy_command method.
    Then:
    - Ensure that the bucket policy was successfully retrieve.
    """
    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)
    excepted = util_load_json('test_data/get_bucket_policy.json')
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "get_bucket_policy", return_value=TEST_POLICY)
    client = AWSClient()

    res = AWS_S3.get_bucket_policy_command(args, client)
    for output in res.outputs:
        output.pop('Json')
    assert res.outputs == excepted


@pytest.mark.parametrize('res, excepted',
                         [({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.OK}}, 'Successfully applied'),
                          ({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.NOT_FOUND}}, "Couldn't apply")])
def test_put_bucket_policy_command(mocker, res, excepted):
    """
    Given:
    - A bucket name and bucket policy.
    When:
    - Calling put_bucket_policy_command method.
    Then:
    - Ensure that the bucket policy was successfully applied.
    """
    args = {'bucket': 'test_bucket', 'Policy': 'test_policy'}
    args.update(TEST_PARAMS)

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "put_bucket_policy", return_value=res)

    client = AWSClient()

    res = AWS_S3.put_bucket_policy_command(args, client)
    assert res.readable_output == f"{excepted} bucket policy to {args.get('bucket')} bucket"


def test_delete_bucket_policy(mocker):
    """
    Given:
    - A bucket name.
    When:
    - Calling delete_bucket_policy method.
    Then:
    - Ensure that the bucket policy was successfully deleted.
    """
    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "delete_bucket_policy")

    client = AWSClient()

    res = AWS_S3.delete_bucket_policy_command(args, client)
    assert res.readable_output == f"Policy deleted from {args.get('bucket')}"


def test_list_objects_command(mocker):
    """
    Given:
    - A bucket name.
    When:
    - Calling list_objects_command method.
    Then:
    - Ensure that the bucket object list was successfully retrieve.
    """
    from datetime import datetime

    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)
    contents = {'Key': 'key_1', 'Size': 1024, 'LastModified': datetime(2020, 1, 1)}
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "list_objects")
    mocker.patch.object(Boto3Client, "get_paginator", return_value=paginator())
    mocker.patch.object(paginator, "paginate", return_value=[{'Contents': [contents]}])

    client = AWSClient()

    res = AWS_S3.list_objects_command(args, client)
    assert res.outputs[0].get('Key') == contents.get('Key')
    assert res.outputs[0].get('Size') == convert_size(contents.get('Size'))
    assert res.outputs[0].get('LastModified') == datetime.strftime(contents.get('LastModified'), '%Y-%m-%dT%H:%M:%S')


@pytest.mark.parametrize('res, excepted',
                         [({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.OK}}, 'Successfully applied'),
                          ({'ResponseMetadata': {'HTTPStatusCode': HTTPStatus.NOT_FOUND}}, "Couldn't apply")])
def test_put_public_access_block_command(mocker, res, excepted):
    """
    Given:
    - A bucket name, block public Acls, Ignore public, block public policy and restrict public buckets.
    When:
    - Calling put_public_access_block method.
    Then:
    - Ensure that the bucket public access block has been updated.
    """
    args = {'bucket': 'test_bucket', 'BlockPublicAcls': 'false', 'IgnorePublicAcls': 'false',
            'BlockPublicPolicy': 'false', 'RestrictPublicBuckets': 'false'}
    args.update(TEST_PARAMS)

    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "put_public_access_block", return_value=res)

    client = AWSClient()

    res = AWS_S3.put_public_access_block(args, client)
    assert res.readable_output == f"{excepted} public access block to the {args.get('bucket')} bucket"


def test_get_bucket_encryption(mocker):
    """
    Given:
    - A bucket name.
    When:
    - Calling get_bucket_encryption method.
    Then:
    - Ensure that the bucket encryption was successfully retrieved.
    """
    from CommonServerPython import tableToMarkdown
    args = {'bucket': 'test_bucket'}
    args.update(TEST_PARAMS)
    encryption = {'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}
    response = {'ServerSideEncryptionConfiguration': encryption}
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, "get_bucket_encryption", return_value=response)

    client = AWSClient()
    data = [{'BucketName': args.get('bucket'), 'ServerSideEncryptionConfiguration': encryption}]
    res = AWS_S3.get_bucket_encryption(args, client)
    assert tableToMarkdown('AWS S3 Bucket Encryption', data) == res.readable_output
