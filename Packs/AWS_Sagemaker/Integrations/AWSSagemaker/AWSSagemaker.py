import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os
import sys

import boto3

if not demisto.params()['proxy']:
    del os.environ['http_proxy']
    del os.environ['https_proxy']
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']


def invoke_enpoint(runtime, endpoint_name, payload):
    return runtime.invoke_endpoint(EndpointName=endpoint_name, ContentType='application/json',
                                   Body=json.dumps(payload, ensure_ascii=False).encode('utf-8', 'ignore'))


aws_access_key_id = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('AWSAccessKey')
aws_secret_access_key = demisto.params().get('credentials', {}).get('password') or demisto.params().get('AWSSecretKey')

runtime = boto3.Session(aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        region_name=demisto.params()['AWSRegion']).client('runtime.sagemaker')
endpoint_name = demisto.params()['EndpointName']


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
    if type(input_text) != list:
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
