import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os
import sys

import boto3

params = demisto.params()
if not params['proxy']:
    del os.environ['http_proxy']
    del os.environ['https_proxy']
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']


def invoke_enpoint(runtime, endpoint_name, payload):
    return runtime.invoke_endpoint(EndpointName=endpoint_name, ContentType='application/json',
                                   Body=json.dumps(payload, ensure_ascii=False).encode('utf-8', 'ignore'))


aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('AWSAccessKey')
aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('AWSSecretKey')
sts_regional_endpoint = params.get('sts_regional_endpoint') or None
if sts_regional_endpoint:
    demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={sts_regional_endpoint}")
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = sts_regional_endpoint.lower()

runtime = boto3.Session(aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        region_name=params['AWSRegion']).client('runtime.sagemaker')  # type: ignore[call-overload]
endpoint_name = params['EndpointName']


def parse_results(result):
    res = []
    for r in result:
        res.append({
            'Label': r['label'][0],
            'Probability': r['probability']
        })
    return res


if demisto.command() == 'test-module':
    response = invoke_enpoint(runtime, endpoint_name, ["test"])
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')
    sys.exit(0)
if demisto.command() == 'predict-phishing':
    input_text = demisto.args()['inputText']
    if type(input_text) is not list:
        input_text = [input_text]
    response = invoke_enpoint(runtime, endpoint_name, input_text)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        raise Exception("Failed to invoke enpoint")
    result = json.loads(response['Body'].read().decode())
    predictions = parse_results(result)

    context = {
        "DBotPhishingPrediction": predictions
    }
    demisto.results({
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': predictions,
        'EntryContext': context,
        "HumanReadable": tableToMarkdown('DBot label suggestion', predictions),
        "HumanReadableFormat": formats["markdown"]
    })
