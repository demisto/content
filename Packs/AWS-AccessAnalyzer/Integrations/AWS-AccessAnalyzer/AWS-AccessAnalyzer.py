import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""IMPORTS"""
import boto3
import json
from datetime import datetime, date, timedelta
from botocore.config import Config


"""GLOBAL VARIABLES"""
params = demisto.params()
AWS_DEFAULT_REGION = params.get('defaultRegion')
AWS_ROLE_ARN = params.get('role_arn')
AWS_ROLE_SESSION_NAME = params.get('role_session_name')
AWS_ROLE_SESSION_DURATION = params.get('sessionDuration')
AWS_ROLE_POLICY = None
AWS_ACCESS_KEY_ID = params.get('credentials', {}).get('identifier') or params.get('access_key')
AWS_SECRET_ACCESS_KEY = params.get('credentials', {}).get('password') or params.get('secret_key')
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
# TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
# proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
# config = Config(
#     connect_timeout=1,
#     retries=dict(
#         max_attempts=5
#     ),
#     proxies=proxies
# )


def get_session(aws_client: AWSClient, **kwargs):

    return aws_client.aws_session(service='accessanalyzer', **kwargs)


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def list_analyzers_command(aws_session):
    data = []

    response = aws_session.list_analyzers()
    for analyzer in response['analyzers']:
        data.append(analyzer)
    data = json.loads(json.dumps(data, cls=DatetimeEncoder))

    ec = {'AWS.AccessAnalyzer.Analyzers(val.arn === obj.arn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Analyzers", data)
    return_outputs(human_readable, ec)


def list_analyzed_resource_command(aws_session):
    
    kwargs = {
        'analyzerArn': args.get('analyzerArn')
    }

    if args.get('maxResults'):
        kwargs['maxResults'] = int(args.get('maxResults'))
    if args.get('resourceType'):
        kwargs['resourceType'] = args.get('resourceType')

    response = aws_session.list_analyzed_resources(**kwargs)
    data = []
    for resource in response['analyzedResources']:
        resource['analyzerArn'] = args.get('analyzerArn')
        data.append(resource)

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def get_findings_command(aws_session):
    

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

    if args.get('nextToken'):
        kwargs['nextToken'] = args.get('nextToken')

    kwargs['sort'] = {
        'attributeName': 'UpdatedAt',
        'orderBy': 'DESC'
    }

    if len(filters) > 0:
        kwargs['filter'] = filters

    response = aws_session.list_findings(**kwargs)
    data = json.loads(json.dumps(response, cls=DatetimeEncoder))

    return [data] if isinstance(data, dict) else data


def list_findings_command(aws_session):
    

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

    response = aws_session.list_findings(**kwargs)
    data = json.loads(json.dumps(response['findings'], cls=DatetimeEncoder))

    ec = {'AWS.AccessAnalyzer.Findings(val.id === obj.id)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Findings", data)
    return_outputs(human_readable, ec)


def get_analyzed_resource_command(aws_session):
    

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'resourceArn': args.get('resourceArn')
    }

    response = aws_session.get_analyzed_resource(**kwargs)
    data = json.loads(json.dumps(response['resource'], cls=DatetimeEncoder))
    data['analyzerArn'] = args.get('analyzerArn')

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def get_finding_command(aws_session):
    

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'id': args.get('findingId')
    }

    response = aws_session.get_finding(**kwargs)
    data = json.loads(json.dumps(response['finding'], cls=DatetimeEncoder))
    data['analyzerArn'] = args.get('analyzerArn')

    ec = {'AWS.AccessAnalyzer.Analyzers(val.analyzerArn === obj.analyzerArn)': data}
    human_readable = tableToMarkdown("AWS Access Analyzer Resource", data)
    return_outputs(human_readable, ec)


def start_resource_scan_command(aws_session):
    

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'resourceArn': args.get('resourceArn')
    }

    response = aws_session.start_resource_scan(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Resource scan request sent.")


def update_findings_command(aws_session):
    

    ids = args.get('findingIds').split(',')

    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'ids': ids,
        'status': args.get('status')
    }

    response = aws_session.update_findings(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("Findings updated")


def test_function() -> str:
    err_msg = ''
    try:
        client = get_session()
        response = aws_session.list_analyzers()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

        err_msg = str(response)
    except Exception as e:
        err_msg = str(e)
    
    raise DemistoException(f'Failed to run test-module: {err_msg}')

def fetch_incidents(last_run: dict = None):
    params = demisto.params()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time') if isinstance(last_run, dict) else None

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        today = datetime.today()
        delta = today - timedelta(days=50)
        last_fetch = date_to_timestamp(delta)

    incidents: list = []
    findings_args = {}
    findings_args['role_arn'] = params.get('role_arn')
    findings_args['region'] = params.get('region')
    findings_args['role_session_name'] = params.get('role_session_name')
    findings_args['role_session_duration'] = params.get('role_session_duration')
    findings_args['analyzerArn'] = params.get('analyzerArn')
    findings_args['maxResults'] = 25

    nextToken = None
    incidents = []
    tmp_last_fetch = last_fetch

    while True:

        if nextToken:
            findings_args['nextToken'] = nextToken
        raw_incidents = get_findings_command(findings_args)

        for raw_incident in raw_incidents[0]['findings']:
            incident = {
                'name': f"AWS Access Analyzer Alert - {raw_incident['id']}",
                'occurred': raw_incident['updatedAt'] + 'Z',
                'rawJSON': json.dumps(raw_incident)
            }

            inc_timestamp = date_to_timestamp(raw_incident['updatedAt'])

            if inc_timestamp > int(last_fetch):
                incidents.append(incident)
                if inc_timestamp > tmp_last_fetch:
                    tmp_last_fetch = inc_timestamp
            else:
                break

        if 'nextToken' in raw_incidents[0]:
            nextToken = raw_incidents[0]['nextToken']
        else:
            break

    demisto.setLastRun({"time": tmp_last_fetch or last_fetch})
    demisto.incidents(incidents)


def main():
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('role_arn')
    aws_role_session_name = params.get('role_session_name')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = demisto.params().get('timeout')
    retries = demisto.params().get('retries', 5)
    validate_params(aws_default_region, aws_role_arn,
                    aws_role_session_name, aws_access_key_id,
                    aws_secret_access_key)

    aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                           aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                           retries)
    command = demisto.command()
    args = demisto.args()
    commands = {
        'aws-access-analyzer-list-analyzers': list_analyzers_command,
        'aws-access-analyzer-list-analyzed-resource': list_analyzed_resource_command,
        'aws-access-analyzer-list-findings': list_findings_command,
        'aws-access-analyzer-get-analyzed-resource': get_analyzed_resource_command,
        'aws-access-analyzer-get-finding': get_finding_command,
        'aws-access-analyzer-start-resource-scan': start_resource_scan_command,
        'aws-access-analyzer-update-findings': update_findings_command,
    }
    try:
        if command == 'test-module':
            return_results(test_function())
        elif command == 'fetch-incidents':
            fetch_incidents(demisto.getLastRun())
        else:
            return_results(commands[command](aws_session))
        # elif command == 'aws-access-analyzer-list-analyzers':
        #     list_analyzers_command(aws_session)
        # elif command == 'aws-access-analyzer-list-analyzed-resource':
        #     list_analyzed_resource_command(aws_session)
        # elif command == 'aws-access-analyzer-list-findings':
        #     list_findings_command(aws_session)
        # elif command == 'aws-access-analyzer-get-analyzed-resource':
        #     get_analyzed_resource_command(aws_session)
        # elif command == 'aws-access-analyzer-get-finding':
        #     get_finding_command(aws_session)
        # elif command == 'aws-access-analyzer-start-resource-scan':
        #     start_resource_scan_command(aws_session)
        # elif command == 'aws-access-analyzer-update-findings':
        #     update_findings_command(aws_session)
    except Exception as e:
        return_error(f"Error has occurred in AWS Access Analyzer Integration: {str(e)}")


from AWSApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()