from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


def ask_command(bedrock, args):

    question = args.get('question')
    body = json.dumps({
        "prompt": f"\n\nHuman:{question}\n\nAssistant:",
        "max_tokens_to_sample": int(args.get("max_tokens_to_sample")),
        "temperature": 0.1,
        "top_p": 0.9,
    })

    modelId = args.get("model")
    accept = 'application/json'
    contentType = 'application/json'

    response = bedrock.invoke_model(body=body, modelId=modelId, accept=accept, contentType=contentType)

    response_body = json.loads(response.get('body').read())

    return CommandResults(
        outputs_prefix='AWS.Bedrock',
        readable_output=f'AWS Bedrock API returns with HTTP Code '
                        f'{response.get("ResponseMetadata",{}).get("HTTPStatusCode",{})}\n{response_body.get("completion")}',
        outputs=response_body.get("completion"),
        raw_response=response_body
    )


def get_aws_config(params):
    # AWS Config
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key', {}).get('password')
    aws_secret_access_key = params.get('secret_key', {}).get('password')
    verify_certificate = not params.get('insecure', False)
    timeout = params.get('timeout')
    retries = params.get('retries') or 5
    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                           retries)
    return aws_client


def test_function(aws_client):
    client = aws_client.aws_session(service='bedrock')

    response = client.list_foundation_models()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return 'ok'


def main() -> None:

    command = demisto.command()
    aws_client = get_aws_config(demisto.params())
    bedrock = aws_client.aws_session(service='bedrock-runtime')

    try:
        if command == 'test-module':
            return_results(test_function(aws_client))
        elif command == 'aws-bedrock-ask-question':
            return_results(ask_command(bedrock, demisto.args()))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


from AWSApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
