import json

import pytest
from typing import Any
from collections.abc import Callable
from AWS_Lambda import (
    _parse_policy_response,
    get_policy_command,
    list_versions_by_function_command,
    get_function_url_config_command,
    get_function_configuration_command,
    delete_function_command,
    delete_function_url_config_command,
    create_function_command,
    publish_layer_version_command,
    list_layer_version_command,
    delete_layer_version_command
)


class MockClient:
    """
    A mock client class for AWS Lambda API.

    This class provides mock implementations of the AWS Lambda API methods for testing purposes.
    """

    def get_policy(self) -> None:
        return

    def list_versions_by_function(self) -> None:
        return

    def get_function_url_config(self) -> None:
        return

    def get_function_configuration(self) -> None:
        return

    def delete_function(self) -> None:
        return

    def delete_function_url_config(self) -> None:
        return

    def create_function(self) -> None:
        return

    def publish_layer_version(self) -> None:
        return

    def delete_layer_version(self) -> None:
        return

    def list_layer_versions(self) -> None:
        return


def util_load_json(path: str):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "data, expected_policy, expected_statement ",
    [
        (
            {
                "Policy": {
                    "Statement": [
                        {
                            "Sid": "statement1",
                            "Effect": "Allow",
                            "Action": "action1",
                            "Resource": "resource1",
                            "Principal": "1",
                        }
                    ]
                }
            },
            {
                "Principal": "1",
                "Sid": "statement1",
                "Effect": "Allow",
                "Action": "action1",
                "Resource": "resource1",
            },
            None,
        ),
        (
            {
                "RevisionId": "1",
                "Policy": {
                    "Id": "policy1",
                    "Version": "1",
                    "Statement": [
                        {
                            "Sid": "statement1",
                            "Effect": "Allow",
                            "Action": "action1",
                            "Resource": "resource1",
                            "Principal": "0",
                        },
                        {
                            "Sid": "statement2",
                            "Effect": "Deny",
                            "Action": "action2",
                            "Resource": "resource2",
                            "Principal": "1",
                        },
                    ]
                }
            },
            {
                "Id": "policy1",
                "Version": "1",
                "RevisionId": "1",
            },
            [
                {
                    "Sid": "statement1",
                    "Effect": "Allow",
                    "Action": "action1",
                    "Resource": "resource1",
                    "Principal": "0",
                },
                {
                    "Sid": "statement2",
                    "Effect": "Deny",
                    "Action": "action2",
                    "Resource": "resource2",
                    "Principal": "1",
                },
            ],
        ),
    ],
)
def test_parse_policy_response(data, expected_policy, expected_statement):
    parsed_policy, parsed_statement = _parse_policy_response(data)
    assert parsed_policy == expected_policy
    assert parsed_statement == expected_statement


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                "Policy": '{"Version":"0000-00-00","Id":"dummy", \
                "Statement":[ \
                    { \
                        "Sid":"dummy","Effect":"Allow", \
                        "Principal":{"dummy":"dummy:dummy"}, \
                        "Action":"lambda:InvokeFunction", \
                        "Resource":"dummy:country:00:function:dummy-function:0"}, \
                     { \
                        "Sid":"dummy2","Effect":"Allow", \
                        "Principal":{"dummy2":"dummy2:dummy2"}, \
                        "Action":"lambda:InvokeFunction", \
                        "Resource":"dummy2:country:00:function:dummy2-function:1"} ]}',
                "RevisionId": "00000-00000-00000-00000-00000",
                "ResponseMetadata": {"string": "string"},
            },
            {
                "Policy": {
                    "Version": "0000-00-00",
                    "Id": "dummy",
                    "Statement": [
                        {
                            "Sid": "dummy",
                            "Effect": "Allow",
                            "Principal": {"dummy": "dummy:dummy"},
                            "Action": "lambda:InvokeFunction",
                            "Resource": "dummy:country:00:function:dummy-function:0",
                        },
                        {
                            "Sid": "dummy2",
                            "Effect": "Allow",
                            "Principal": {"dummy2": "dummy2:dummy2"},
                            "Action": "lambda:InvokeFunction",
                            "Resource": "dummy2:country:00:function:dummy2-function:1",
                        },
                    ],
                },
                "RevisionId": "00000-00000-00000-00000-00000",
            },
        )
    ],
)
def test_get_policy_command(mocker, test_data: dict, excepted_data: dict):
    """
    Test case for the get_policy_command function.

    Args:
        mocker: The mocker object for mocking dependencies.
        test_data (dict): Test data representing the policy response.
        expected_data (dict): Expected policy data to be compared with the command result.

    Given:
    - A mock policy response.

    When:
    - Calling the get_policy_command function.

    Then:
    - Ensure that the outputs of the command result match the expected data.
    """
    client = MockClient()
    mocker.patch.object(client, "get_policy", return_value=test_data)

    res = get_policy_command(args={"functionName": "test"}, aws_client=client)
    assert res.outputs == excepted_data


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                "ResponseMetadata": {"string": "string"},
                "Versions": [
                    {
                        "FunctionName": "string",
                        "FunctionArn": "string",
                        "Runtime": "nodejs",
                        "Role": "string",
                    },
                ],
            },
            {
                "Versions": [
                    {
                        "FunctionName": "string",
                        "FunctionArn": "string",
                        "Runtime": "nodejs",
                        "Role": "string",
                    },
                ],
            },
        ),
        (
            {
                "NextMarker": "test",
                "ResponseMetadata": {"string": "string"},
                "Versions": [
                    {
                        "FunctionName": "string",
                        "FunctionArn": "string",
                        "Runtime": "nodejs",
                        "Role": "string",
                    },
                ],
            },
            {
                "NextMarker": "test",
                "Versions": [
                    {
                        "FunctionName": "string",
                        "FunctionArn": "string",
                        "Runtime": "nodejs",
                        "Role": "string",
                    },
                ],
            },
        ),
    ],
)
def test_list_versions_by_function_command(
    mocker, test_data: dict[str, Any], excepted_data: dict[str, Any]
):
    """
    Test case for the list_versions_by_function_command function.

    Args:
        mocker: The mocker object for mocking dependencies.
        test_data (dict): Test data representing the versions response.
        expected_data (dict): Expected versions data to be compared with the command result.

    Given:
    - A mock versions response.

    When:
    - Calling list_versions_by_function_command function.

    Then:
    - If the result contains one item, ensure that the outputs match the expected data.
    - If the result contains two items,
        ensure that the first item's readable output provides a token for retrieving
        the next version and the second item's outputs match the expected data.
    """
    client = MockClient()
    mocker.patch.object(client, "list_versions_by_function", return_value=test_data)

    res = list_versions_by_function_command(
        args={"functionName": "test"}, aws_client=client
    )
    if test_data.get("NextMarker") and res.readable_output:
        assert "To get the next version run the command with the Marker argument with the value: test" in res.readable_output
    assert res.outputs == excepted_data


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                "ResponseMetadata": {"string": "string"},
                "FunctionUrl": "string",
                "FunctionArn": "string",
                "AuthType": "AWS_IAM",
                "Cors": {
                    "AllowCredentials": True,
                    "AllowHeaders": [
                        "string",
                    ],
                },
                "CreationTime": "string",
                "LastModifiedTime": "string",
                "InvokeMode": "BUFFERED",
            },
            {
                "FunctionUrl": "string",
                "FunctionArn": "string",
                "AuthType": "AWS_IAM",
                "Cors": {
                    "AllowCredentials": True,
                    "AllowHeaders": [
                        "string",
                    ],
                },
                "CreationTime": "string",
                "LastModifiedTime": "string",
                "InvokeMode": "BUFFERED",
            },
        )
    ],
)
def test_get_function_url_config_command(
    mocker, test_data: dict[str, Any], excepted_data: dict[str, Any]
):
    """
    Test case for the get_function_url_config_command function.

    Args:
        mocker: The mocker object for mocking dependencies.
        test_data (dict): Test data representing the function URL configuration response.
        expected_data (dict): Expected function URL configuration data to be compared with the command result.

    Given:
    - A mock function URL configuration response.

    When:
    - Calling get_function_url_config_command function.

    Then:
    - Ensure that the function URL configuration is correctly retrieved and matches the expected data.
    """
    client = MockClient()
    mocker.patch.object(client, "get_function_url_config", return_value=test_data)

    res = get_function_url_config_command(
        args={"functionName": "test"}, aws_client=client
    )
    assert res.outputs == excepted_data


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                "CodeSha256": "test",
                "CodeSize": 5797206,
                "Description": "Process image objects from Amazon S3.",
                "Environment": {
                    "Variables": {
                        "BUCKET": "my-bucket-test",
                        "PREFIX": "inbound",
                    },
                },
                "FunctionArn": "arn:aws:lambda:us-west-2:test:function:my-function",
                "FunctionName": "my-function",
                "Handler": "index.handler",
                "KMSKeyArn": "arn:aws:kms:us-west-2:test:key/test123",
                "LastModified": "2020-04-10T19:06:32.563+0000",
                "TracingConfig": {
                    "Mode": "Active",
                },
                "Version": "$LATEST",
                "ResponseMetadata": {
                    "...": "...",
                },
            },
            {
                "CodeSha256": "test",
                "CodeSize": 5797206,
                "Description": "Process image objects from Amazon S3.",
                "Environment": {
                    "Variables": {
                        "BUCKET": "my-bucket-test",
                        "PREFIX": "inbound",
                    },
                },
                "FunctionArn": "arn:aws:lambda:us-west-2:test:function:my-function",
                "FunctionName": "my-function",
                "Handler": "index.handler",
                "KMSKeyArn": "arn:aws:kms:us-west-2:test:key/test123",
                "LastModified": "2020-04-10T19:06:32.563+0000",
                "TracingConfig": {
                    "Mode": "Active",
                },
                "Version": "$LATEST",
            },
        )
    ],
)
def test_get_function_configuration_command(
    mocker, test_data: dict[str, Any], excepted_data: dict[str, Any]
):
    """
    Test case for the get_function_configuration_command function.

    Args:
        mocker: The mocker object for mocking dependencies.
        test_data (dict): Test data representing the function configuration response.
        expected_data (dict): Expected function configuration data to be compared with the command result.

    Given:
    - A mock function configuration response.

    When:
    - Calling get_function_configuration_command function.

    Then:
    - Ensure that the function configuration is correctly retrieved and matches the expected data.
    """
    client = MockClient()
    mocker.patch.object(client, "get_function_configuration", return_value=test_data)

    res = get_function_configuration_command(
        args={"functionName": "test"}, aws_client=client
    )
    assert res.outputs == excepted_data


@pytest.mark.parametrize(
    "func_command, func_client",
    [
        (delete_function_command, "delete_function"),
        (delete_function_url_config_command, "delete_function_url_config"),
    ],
)
def test_delete_function_and_url_config_commands(
    mocker, func_command: Callable, func_client: str
):
    """
    Test two cases for the scenario of deleting a function and url config with a qualifier.

    Args:
        mocker: The mocker object for mocking dependencies.
        func_command (Callable): The delete function command to be tested.
        func_client (str): The name of the function client.

    Given:
    - A function name with a qualifier.

    When:
    - The delete_function_command function is called.
    - The delete_function_url_config_command function is called.

    Then:
    - Ensure that the function is successfully deleted.
    - Ensure that the function url config is successfully deleted.
    """
    client = MockClient()
    mocker.patch.object(client, func_client, return_value={})

    args = {"functionName": "test-function", "qualifier": "test-qualifier"}

    result = func_command(args, client)

    assert result.readable_output == "Deleted test-function Successfully"


def test_create_function_command(mocker):
    """
        Given: Params for create lambda function command
        When: Running the command
        Then: Assert that the correct command result is returned.
    """
    client = MockClient()
    mocker.patch.object(client, 'create_function', return_value=util_load_json('test_data/create_function.json'))

    args = {"functionName": "TestLambdaFunction",
            "code": "lambda_function.py.zip",
            "runtime": "python3.8",
            "description": "test lambda function",
            "role": "test-role",
            "handler": "test handler",
            "layers": "test layer",
            "vpcConfig": "{\"SubnetIds\": [\"subnet-1\",\"subnet-2\",\"3\"], \"SecurityGroupIds\":[\"sg-1\"]}",
            "packageType": "Zip"}

    kwargs = {'Code': {'ZipFile': b"test"},
              'FunctionName': 'TestLambdaFunction',
              'Runtime': 'python3.8',
              'Role': 'test-role',
              'Handler': 'test handler',
              'Description': 'test lambda function',
              'PackageType': 'Zip',
              'Layers': ['test layer'],
              'VpcConfig': {'SubnetIds': ['subnet-1', 'subnet-2', 'subnet-3'],
                            'SecurityGroupIds': ['sg-1']}}

    mocker.patch('AWS_Lambda.prepare_create_function_kwargs', return_value=kwargs)

    results = create_function_command(args, client)

    assert results.outputs_key_field == 'FunctionArn'
    assert results.outputs_prefix == 'AWS.Lambda.Functions'
    assert len(results.outputs.keys()) == 13


def test_publish_layer_version_command(mocker):
    """
        Given: Params for publish layer version command
        When: Running the command
        Then: Assert that the correct command result is returned.
    """
    client = MockClient()
    mocker.patch.object(client, 'publish_layer_version', return_value=util_load_json('test_data/publish_layer.json'))
    mocker.patch('AWS_Lambda.read_zip_to_bytes')

    args = {"layer-name": "testLayer",
            "description": "test lambda function",
            "zip-file": "test",
            "CompatibleRuntimes": "nodejs",
            "CompatibleArchitectures": "x86_64",
            }

    results = publish_layer_version_command(args, client)

    assert results.outputs_key_field == 'LayerVersionArn'
    assert results.outputs_prefix == 'AWS.Lambda.Layers'
    assert len(results.outputs.keys()) == 7


def test_delete_layer_version_command(mocker):
    """
        Given: Params for delete layer version command
        When: Running the command
        Then: Assert that the correct command result is returned.
    """
    client = MockClient()
    mocker.patch.object(client, 'delete_layer_version')

    args = {"layer-name": "testLayer",
            "version-number": "2"
            }

    results = delete_layer_version_command(args, client)

    assert results.readable_output == 'Deleted version number 2 of testLayer Successfully'


def test_list_layer_version_command(mocker):
    """
        Given: Params for list layer versions.
        When: Running the command
        Then: Assert that the correct command result is returned.
    """
    client = MockClient()
    mocker.patch.object(client, 'list_layer_versions', return_value=util_load_json('test_data/list_layer_version.json'))

    args = {"layer-name": "testLayer"}

    results = list_layer_version_command(args, client)

    assert len(results.outputs.keys()) == 2
