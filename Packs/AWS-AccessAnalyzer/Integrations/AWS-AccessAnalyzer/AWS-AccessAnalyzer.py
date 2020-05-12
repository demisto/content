import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""IMPORTS"""
import boto3
import json
from datetime import datetime, date
from botocore.config import Config


"""GLOBAL VARIABLES"""
AWS_DEFAULT_REGION = demisto.params().get('defaultRegion')
AWS_ROLE_ARN = demisto.params().get('roleArn')
AWS_ROLE_SESSION_NAME = demisto.params().get('roleSessionName')
AWS_ROLE_SESSION_DURATION = demisto.params().get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = demisto.params().get('access_key')
AWS_SECRET_ACCESS_KEY = demisto.params().get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


def aws_session(service='accessanalyzer', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME is not None:
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_ROLE_SESSION_DURATION is not None:
        kwargs.update({'DurationSeconds': int(AWS_ROLE_SESSION_DURATION)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_ROLE_POLICY is not None:
        kwargs.update({'Policy': AWS_ROLE_POLICY})
    if kwargs and AWS_ACCESS_KEY_ID is None:

        if AWS_ACCESS_KEY_ID is None:
            sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE)
            sts_response = sts_client.assume_role(**kwargs)
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=AWS_DEFAULT_REGION,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=VERIFY_CERTIFICATE,
                    config=config
                )
    elif AWS_ACCESS_KEY_ID and AWS_ROLE_ARN:
        sts_client = boto3.client(
            service_name='sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            verify=VERIFY_CERTIFICATE,
            config=config
        )
        kwargs.update({
            'RoleArn': AWS_ROLE_ARN,
            'RoleSessionName': AWS_ROLE_SESSION_NAME,
        })
        sts_response = sts_client.assume_role(**kwargs)
        client = boto3.client(
            service_name=service,
            region_name=AWS_DEFAULT_REGION,
            aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
            aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
            aws_session_token=sts_response['Credentials']['SessionToken'],
            verify=VERIFY_CERTIFICATE,
            config=config
        )
    else:
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                verify=VERIFY_CERTIFICATE,
                config=config
            )

    return client


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def list_analyzers_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration')
    )

    data = []

    response = client.list_analyzers()
    for analyzer in response['analyzers']:
        data.append(analyzer)
    data = json.loads(json.dumps(data, cls=DatetimeEncoder))

    ec = {'AWS.AccessAnalyzer.Analyzers(val.arn === obj.arn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Analyzers", data)
    return_outputs(human_readable, ec)


def list_analyzed_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'analyzerArn': args.get('analyzerArn')
    }

    if args.get('maxResults'):
        kwargs['maxResults'] = int(args.get('maxResults'))
    if args.get('resourceType'):
        kwargs['resourceType'] = args.get('resourceType')

    response = client.list_analyzed_resources(**kwargs)
    data = []
    for resource in response['analyzedResources']:
        resource['analyzerArn'] = args.get('analyzerArn')
        data.append(resource)

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def list_findings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'analyzerArn': args.get('analyzerArn')
    }

    if args.get('maxResults'):
        kwargs['maxResults'] = int(args.get('maxResults'))

    filters = {}
    if args.get('resourceType'):
        filters['resourceType'] = {"eq": [args.get('resourceType')]}

    if args.get('status'):
        filters['status'] = {"eq": [args.get('status')]}

    if len(filters) > 0:
        kwargs['filter'] = filters

    response = client.list_findings(**kwargs)
    data = json.loads(json.dumps(response['findings'], cls=DatetimeEncoder))

    ec = {'AWS.AccessAnalyzer.Findings(val.id === obj.id)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Findings", data)
    return_outputs(human_readable, ec)


def get_analyzed_resource_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'resourceArn': args.get('resourceArn')
    }

    response = client.get_analyzed_resource(**kwargs)
    data = json.loads(json.dumps(response['resource'], cls=DatetimeEncoder))
    data['analyzerArn'] = args.get('analyzerArn')

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def get_finding_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'id': args.get('findingId')
    }

    response = client.get_finding(**kwargs)
    data = json.loads(json.dumps(response['finding'], cls=DatetimeEncoder))
    data['analyzerArn'] = args.get('analyzerArn')

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def start_resource_scan_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'resourceArn': args.get('resourceArn')
    }

    response = client.start_resource_scan(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Resource scan request sent.")


def update_findings_command(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    ids = args.get('findingIds').split(',')

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'ids': ids,
        'status': args.get('status')
    }

    response = client.update_findings(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Findings updated")


def test_function():
    try:
        client = aws_session()
        response = client.list_analyzers()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            demisto.results('ok')
        else:
            return_error(str(response))

    except Exception as e:
        return return_error(str(e))


"""EXECUTION BLOCK"""
try:
    if demisto.command() == 'test-module':
        result = test_function()
    elif demisto.command() == 'aws-access-analyzer-list-analyzers':
        list_analyzers_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-list-analyzed-resource':
        list_analyzed_resource_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-list-findings':
        list_findings_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-get-analyzed-resource':
        get_analyzed_resource_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-get-finding':
        get_finding_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-start-resource-scan':
        start_resource_scan_command(demisto.args())
    elif demisto.command() == 'aws-access-analyzer-update-findings':
        update_findings_command(demisto.args())

except Exception as e:
    return_error(f"Error has occured in AWS Access Analyzer Integration: {str(e)}")
