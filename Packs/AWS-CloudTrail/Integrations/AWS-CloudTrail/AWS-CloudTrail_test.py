from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401
import pytest
import importlib


PARAMS = {
    "defaultRegion": "us-west-2",
    "roleArn": "arn",
    "roleSessionName": "name",
    "sessionDuration": "5",
    "insecure": True,
    "credentials": {"identifier": "user", "password": "pass"},
}

CREATE_UPDATE_TRAIL_ARGS = {
    "s3BucketName": "",
    "s3KeyPrefix": "",
    "snsTopicName": "",
    "includeGlobalServiceEvents": "True",
    "isMultiRegionTrail": "True",
    "enableLogFileValidation": "True",
    "cloudWatchLogsLogGroupArn": "",
    "cloudWatchLogsRoleArn": "",
    "kmsKeyId": "",
}

VALID_RESPONSE_METADATA = {"ResponseMetadata": {"HTTPStatusCode": 200}}


@pytest.fixture
def aws_cloudtrail():
    return importlib.import_module("AWS-CloudTrail")


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch.object(demisto, "params", return_value=PARAMS)


@pytest.fixture
def return_results_func(mocker, aws_cloudtrail):
    return mocker.patch.object(aws_cloudtrail, "return_results")


@pytest.fixture
def return_error_func(mocker, aws_cloudtrail):
    return mocker.patch.object(aws_cloudtrail, "return_error")


class Config:
    def __init__(self):
        self._user_provided_options = {"region_name": PARAMS["defaultRegion"]}


class CloudTrailClient:
    def __init__(self) -> None:
        self._client_config = Config()
        self._trail = {
            "Name": "name",
            "S3BucketName": "name",
            "IncludeGlobalServiceEvents": "true",
            "IsMultiRegionTrail": "true",
            "TrailARN": "trailARN",
            "LogFileValidationEnabled": "true",
            "SnsTopicName": "name",
            "S3KeyPrefix": "prefix",
            "SnsTopicARN": "arn",
            "CloudWatchLogsLogGroupArn": "arn",
            "CloudWatchLogsRoleArn": "arn",
            "KmsKeyId": "id",
            "HomeRegion": "region",
        }

    def create_trail(self, **kwargs):
        return self._trail

    def delete_trail(self, **kwargs):
        return VALID_RESPONSE_METADATA

    def describe_trails(self, **kwargs):
        return {"trailList": [self._trail]} | VALID_RESPONSE_METADATA

    def update_trail(self, **kwargs):
        return self._trail

    def start_logging(self, **kwargs):
        return VALID_RESPONSE_METADATA

    def stop_logging(self, **kwargs):
        return VALID_RESPONSE_METADATA

    def lookup_events(self, **kwargs):
        return None

    def get_trail_status(self, **kwargs):
        return {"IsLogging": True}

    def get_paginator(self, _):
        class Paginator:
            def paginate(self, **kwargs):
                return [{"Events": [{"Username": "user"}]}]
        return Paginator()


class STSClient:
    def assume_role(self, **kwargs):
        return {
            "Credentials": {
                "AccessKeyId": "1",
                "SecretAccessKey": "2",
                "SessionToken": "3",
            },
        }


def mock_boto3_client(service_name, *args, **kwargs):
    if service_name == 'sts':
        return STSClient()
    return CloudTrailClient()


def test_aws_session_params(mocker, aws_cloudtrail):
    """
    Given
    - demisto parameters
    When
    - Calling aws_session()
    Then
    - Ensure a cloudtrail client is returned
    """
    mocker.patch.object(aws_cloudtrail.boto3, "client", side_effect=mock_boto3_client)
    assert aws_cloudtrail.aws_session()


def test_aws_session_args(mocker, aws_cloudtrail):
    """
    Given
    - demisto parameters
    - demisto args
    When
    - Calling aws_session() with args
    Then
    - Ensure a cloudtrail client is returned
    """
    mocker.patch.object(aws_cloudtrail.boto3, "client", side_effect=mock_boto3_client)
    args = {
        "region": "us-west-2",
        "roleArn": "arn",
        "roleSessionName": "name",
        "roleSessionDuration": "5",
    }
    assert aws_cloudtrail.aws_session(**args)


def mock_command(mocker, aws_cloudtrail, command, args):
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(aws_cloudtrail.boto3, "client", side_effect=mock_boto3_client)


def test_cloudtrail_test_module(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto parameters
    When
    - running test-module command
    Then
    - Ensure "ok" is returned
    """
    mock_command(mocker, aws_cloudtrail, "test-module", {})
    aws_cloudtrail.main()
    command_result = return_results_func.call_args[0][0]
    assert command_result == "ok"


def test_cloudtrail_test_module_bad(mocker, aws_cloudtrail, return_error_func):
    """
    Given
    - demisto parameters
    When
    - running test-module command
    - A ResponseParserError is raised
    Then
    - Ensure return_error is called as expected
    """
    mock_command(mocker, aws_cloudtrail, "test-module", {})
    mocker.patch.object(CloudTrailClient, "describe_trails", side_effect=aws_cloudtrail.ResponseParserError("err"))
    aws_cloudtrail.main()
    error = return_error_func.call_args[0][0]
    assert "Could not connect to the AWS endpoint" in error


def test_cloudtrail_create_trail(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-create-trail command
    Then
    - Ensure the command result is returned as expected
    """
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-create-trail", CREATE_UPDATE_TRAIL_ARGS)
    aws_cloudtrail.main()
    command_result: CommandResults = return_results_func.call_args[0][0]
    outputs: dict = command_result.outputs
    assert outputs["Name"] == "name"


def test_cloudtrail_delete_trail(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-delete-trail command
    Then
    - Ensure output is returned as expected
    """
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-delete-trail", {"name": "name"})
    aws_cloudtrail.main()
    command_result = return_results_func.call_args[0][0]
    assert "was deleted" in command_result


def test_cloudtrail_describe_trails(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-describe-trail command
    Then
    - Ensure the command result is returned as expected
    """
    args = {"trailNameList": "", "includeShadowTrails": ""}
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-describe-trails", args)
    aws_cloudtrail.main()
    command_result: CommandResults = return_results_func.call_args[0][0]
    outputs: list[dict] = command_result.outputs
    assert outputs[0]["Name"] == "name"


def test_cloudtrail_update_trail(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-update-trail command
    Then
    - Ensure the command result is returned as expected
    """
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-update-trail", CREATE_UPDATE_TRAIL_ARGS)
    aws_cloudtrail.main()
    command_result: CommandResults = return_results_func.call_args[0][0]
    outputs: dict = command_result.outputs
    assert outputs["Name"] == "name"


def test_cloudtrail_start_logging(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-start-logging command
    Then
    - Ensure output is returned as expected
    """
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-start-logging", {"name": "name"})
    aws_cloudtrail.main()
    command_result = return_results_func.call_args[0][0]
    assert "started logging" in command_result


def test_cloudtrail_stop_logging(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-stop-logging command
    Then
    - Ensure output is returned as expected
    """
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-stop-logging", {"name": "name"})
    aws_cloudtrail.main()
    command_result = return_results_func.call_args[0][0]
    assert "stopped logging" in command_result


def test_cloudtrail_lookup_events(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-lookup-events command
    Then
    - Ensure the command result is returned as expected
    """
    args = {"startTime": "2021-01-01T00:00:00", "endTime": "2021-01-01T00:00:00"}
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-lookup-events", args)
    aws_cloudtrail.main()
    command_result: CommandResults = return_results_func.call_args[0][0]
    outputs: list[dict] = command_result.outputs
    assert outputs[0]["Username"] == "user"


def test_cloudtrail_get_trail_status(mocker, aws_cloudtrail, return_results_func):
    """
    Given
    - demisto args
    When
    - running aws-cloudtrail-get-trail-status command
    Then
    - Ensure the command result is returned as expected
    """
    args = {"name": "name"}
    mock_command(mocker, aws_cloudtrail, "aws-cloudtrail-get-trail-status", args)
    aws_cloudtrail.main()
    command_result: CommandResults = return_results_func.call_args[0][0]
    outputs: dict = command_result.outputs
    assert "IsLogging" in outputs
