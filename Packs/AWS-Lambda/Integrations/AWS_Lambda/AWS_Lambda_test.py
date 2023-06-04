import pytest
from AWS_Lambda import get_policy_command, list_versions_by_function_command


class MockClient:
    def get_policy(self) -> None:
        return

    def list_versions_by_function(self) -> None:
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
