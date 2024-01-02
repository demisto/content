import json
import io
from botocore.response import StreamingBody
import importlib
import demistomock as demisto  # noqa: F401
import AWSApiModule

AWS_Bedrock = importlib.import_module("AwsBedrock")

TEST_PARAMS = {
    'roleArn': 'test_arn',
    'roleSessionName': 'test_role_session',
    'roleSessionDuration': 'test_role_session_duration',
    'defaultRegion': 'us-east-1'
}


class AWSClient:  # pragma: no cover
    def aws_session(self, **kwargs):
        pass


class AWSBedrockClient:  # pragma: no cover
    def invoke_model(self):
        pass

    def list_foundation_models(self):
        pass


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_ask_command(mocker):
    """
    Given:
    - A basic question.
    When:
    - Calling aws-bedrock-ask command.
    Then:
    - Ensure that the result is correct and JSON.
    """
    from AwsBedrock import ask_command
    args = {'question': '3 + 3', 'model': 'anthropic.claude-v2', 'max_tokens_to_sample': "30"}
    response = util_load_json('test_data/aws_bedrock_response.json')
    mocker.patch.object(AWSBedrockClient, "invoke_model", return_value=response)
    aws_bedrock_session = AWSBedrockClient()
    body_encoded = json.dumps(response['body']).encode('utf-8')
    response['body'] = StreamingBody(io.BytesIO(body_encoded), len(body_encoded))
    service_resp = ask_command(aws_bedrock_session, args)
    assert "result" in service_resp.raw_response['completion'] and "6" in service_resp.raw_response['completion']
    assert "HTTP Code 200" in service_resp.readable_output


def test_aws_bedrock_session(mocker):
    from AwsBedrock import test_function

    response = util_load_json('test_data/aws_bedrock_response.json')
    mocker.patch.object(AWSClient, "aws_session", return_value=AWSBedrockClient())
    mocker.patch.object(AWSBedrockClient, "list_foundation_models", return_value=response)

    client = AWSClient()
    aws_bedrock_session = test_function(client)
    assert aws_bedrock_session == "ok"


def test_get_aws_config(mocker):
    from AwsBedrock import get_aws_config
    mocker.patch.object(demisto, "params", return_value=TEST_PARAMS)
    client = get_aws_config(demisto.params())

    assert isinstance(client, AWSApiModule.AWSClient)
