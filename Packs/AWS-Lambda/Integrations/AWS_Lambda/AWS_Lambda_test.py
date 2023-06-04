import pytest
from AWS_Lambda import (
    get_policy_command,
    list_versions_by_function_command,
    get_function_url_config_command,
    get_function_configuration_command,
    delete_function_command
)


class MockClient:
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


@pytest.mark.parametrize(
    "test_data, excepted_data",
    [
        (
            {
                "Policy": '{"Version":"0000-00-00","Id":"dummy","Statement":[{"Sid":"dummy","Effect":"Allow","Principal":{"dummy":"dummy:dummy"},"Action":"lambda:InvokeFunction","Resource":"dummy:country:00:function:dummy-function:0"}]}',
                "RevisionId": "00000-00000-00000-00000-00000",
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
                        }
                    ],
                },
                "RevisionId": "00000-00000-00000-00000-00000",
            },
        )
    ],
)
def test_get_policy_command(mocker, test_data: dict, excepted_data: dict):
    client = MockClient()
    mocker.patch.object(client, "get_policy", return_value=test_data)

    res = get_policy_command(args={"functionName": "test"}, aws_client=client)
    assert res.outputs == excepted_data


@pytest.mark.parametrize(
    "test_data",
    [
        (
            {
                "NextMarker": "string",
                "Versions": [
                    {
                        "FunctionName": "string",
                        "FunctionArn": "string",
                        "Runtime": "nodejs",
                        "Role": "string",
                        "Handler": "string",
                        "CodeSize": 123,
                        "Description": "string",
                        "Timeout": 123,
                        "MemorySize": 123,
                        "LastModified": "string",
                        "CodeSha256": "string",
                        "Version": "string",
                        "VpcConfig": {
                            "SubnetIds": [
                                "string",
                            ],
                            "SecurityGroupIds": [
                                "string",
                            ],
                            "VpcId": "string",
                        },
                        "DeadLetterConfig": {"TargetArn": "string"},
                        "Environment": {
                            "Variables": {"string": "string"},
                            "Error": {"ErrorCode": "string", "Message": "string"},
                        },
                        "KMSKeyArn": "string",
                        "TracingConfig": {"Mode": "Active"},
                        "MasterArn": "string",
                        "RevisionId": "string",
                        "Layers": [
                            {
                                "Arn": "string",
                                "CodeSize": 123,
                                "SigningProfileVersionArn": "string",
                                "SigningJobArn": "string",
                            },
                        ],
                        "State": "Pending",
                    },
                ],
            }
        )
    ],
)
def test_list_versions_by_function_command(mocker, test_data: dict):
    client = MockClient()
    mocker.patch.object(client, "list_versions_by_function", return_value=test_data)

    res = list_versions_by_function_command(
        args={"functionName": "test"}, aws_client=client
    )
    assert res.outputs == test_data


@pytest.mark.parametrize(
    "test_data",
    [
        (
            {
                "FunctionUrl": "string",
                "FunctionArn": "string",
                "AuthType": "AWS_IAM",
                "Cors": {
                    "AllowCredentials": True,
                    "AllowHeaders": [
                        "string",
                    ],
                    "AllowMethods": [
                        "string",
                    ],
                    "AllowOrigins": [
                        "string",
                    ],
                    "ExposeHeaders": [
                        "string",
                    ],
                    "MaxAge": 123,
                },
                "CreationTime": "string",
                "LastModifiedTime": "string",
                "InvokeMode": "BUFFERED",
            }
        )
    ],
)
def test_get_function_url_config_command(mocker, test_data: dict):
    client = MockClient()
    mocker.patch.object(client, "get_function_url_config", return_value=test_data)

    res = get_function_url_config_command(
        args={"functionName": "test"}, aws_client=client
    )
    assert res.outputs == test_data


@pytest.mark.parametrize(
    "test_data",
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
                "LastUpdateStatus": "Successful",
                "MemorySize": 256,
                "RevisionId": "test123",
                "Role": "arn:aws:iam::test123:role/lambda-role",
                "Runtime": "nodejs12.x",
                "State": "Active",
                "Timeout": 15,
                "TracingConfig": {
                    "Mode": "Active",
                },
                "Version": "$LATEST",
                "ResponseMetadata": {
                    "...": "...",
                },
            }
        )
    ],
)
def test_get_function_configuration_command(mocker, test_data: dict):
    client = MockClient()
    mocker.patch.object(client, "get_function_configuration", return_value=test_data)

    res = get_function_configuration_command(
        args={"functionName": "test"}, aws_client=client
    )
    assert res.outputs == test_data


def test_delete_function_command_happy_path_with_qualifier(mocker):
    """
    Given:
    - Function name with a qualifier.

    When:
    - Calling delete_function_command function.

    Then:
    - Ensure the function is successfully deleted.
    """
    client = MockClient()
    mocker.patch.object(client, "delete_function", return_value={'ResponseMetadata': {'HTTPStatusCode': 204}})

    args = {'functionName': 'test-function', 'qualifier': 'test-qualifier'}

    result = delete_function_command(args, client)

    assert result.readable_output == 'Deleted Successfully'
