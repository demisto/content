import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""IMPORTS"""
import json
from datetime import datetime, date
import dateparser


def get_aws_session(aws_client, args, **kwargs):

    return aws_client.aws_session(
        service='accessanalyzer',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
        **kwargs)


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def list_analyzers_command(aws_client, args):

    client = get_aws_session(aws_client, args)
    response = client.list_analyzers()
    rew_response = json.loads(json.dumps(response, cls=DatetimeEncoder))
    analyzers = rew_response['analyzers']
    return CommandResults(
        outputs_prefix='AWS.AccessAnalyzer.Analyzers',
        outputs_key_field='arn',
        outputs=analyzers,
        readable_output=tableToMarkdown("AWS Access Analyzer Analyzers", analyzers, headerTransform=pascalToSpace),
        raw_response=rew_response
    )


def list_analyzed_resource_command(aws_client, args):
    analyzer_arn = args.get('analyzerArn')
    kwargs = {
        'analyzerArn': analyzer_arn,
    }
    if args.get('maxResults'):
        kwargs['maxResults'] = int(args.get('maxResults'))
    if args.get('resourceType'):
        kwargs['resourceType'] = args.get('resourceType')

    client = get_aws_session(aws_client, args)
    response = client.list_analyzed_resources(**kwargs)
    analyzed_resources = [
        resource | {'analyzerArn': analyzer_arn}
        for resource in response['analyzedResources']
    ]
    headers = ['resourceArn', 'resourceOwnerAccount', 'resourceType']
    return CommandResults(
        outputs_prefix='AWS.AccessAnalyzer.Resource',
        outputs_key_field='resourceArn',
        outputs=analyzed_resources,
        readable_output=tableToMarkdown("AWS Access Analyzer Resources",
                                        analyzed_resources,
                                        headers=headers,
                                        headerTransform=pascalToSpace),
        raw_response=response
    )


def list_findings_command(aws_client, args):
    response = get_findings(aws_client, args)
    findings = [
        finding | {'analyzerArn': args.get('analyzerArn')}
        for finding in response['findings']
    ]
    headers = ['id', 'resource', 'principal', 'condition', 'updatedAt', 'status']
    return CommandResults(
        outputs_prefix='AWS.AccessAnalyzer.Finding',
        outputs_key_field='id',
        outputs=findings,
        readable_output=tableToMarkdown("AWS Access Analyzer Findings",
                                        findings,
                                        headers=headers,
                                        headerTransform=pascalToSpace),
        raw_response=response
    )


def get_analyzed_resource_command(aws_client, args):

    client = get_aws_session(aws_client, args)
    response = client.get_analyzed_resource(analyzerArn=args.get('analyzerArn'), resourceArn=args.get('resourceArn'))

    response = json.loads(json.dumps(response, cls=DatetimeEncoder))
    resource = response['resource']
    resource['analyzerArn'] = args.get('analyzerArn')

    return CommandResults(
        outputs_prefix='AWS.AccessAnalyzer.Resource',
        outputs_key_field='id',
        outputs=resource,
        readable_output=tableToMarkdown("AWS Access Analyzer Resource", resource, headerTransform=pascalToSpace),
        raw_response=response
    )


def get_finding_command(aws_client, args):

    client = get_aws_session(aws_client, args)
    response = client.get_finding(analyzerArn=args.get('analyzerArn'), id=args.get('findingId'))
    response = json.loads(json.dumps(response, cls=DatetimeEncoder))
    finding = response['finding']
    finding['analyzerArn'] = args.get('analyzerArn')

    return CommandResults(
        outputs_prefix='AWS.AccessAnalyzer.Finding',
        outputs_key_field='id',
        outputs=finding,
        readable_output=tableToMarkdown("AWS Access Analyzer Finding", finding, headerTransform=pascalToSpace),
        raw_response=response
    )


def start_resource_scan_command(aws_client, args):
    client = get_aws_session(aws_client, args)
    client.start_resource_scan(analyzerArn=args.get('analyzerArn'), resourceArn=args.get('resourceArn'))
    return "Resource scan request sent."


def update_findings_command(aws_client, args):
    client = get_aws_session(aws_client, args)
    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'ids': argToList(args.get('findingIds')),
        'status': args.get('status')
    }

    client.update_findings(**kwargs)
    return "Findings updated."


def test_function(aws_client, args) -> str:
    err_msg = ''
    try:
        client = get_aws_session(aws_client, args)
        response = client.list_analyzers()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

        err_msg = str(response)
    except Exception as e:
        err_msg = str(e)

    raise DemistoException(f'Failed to run test-module: {err_msg}')


def get_filters(args):
    return {
        field: {"eq": [args.get(field)]}
        for field in ('resourceType', 'status')
        if args.get(field)
    }


def get_findings(aws_client, args):
    kwargs = {
        'analyzerArn': args.get('analyzerArn'),
        'sort': {
            'attributeName': 'UpdatedAt',
            'orderBy': 'DESC'
        }
    }

    if args.get('maxResults'):
        kwargs['maxResults'] = int(args.get('maxResults'))

    if args.get('nextToken'):
        kwargs['nextToken'] = args.get('nextToken')

    if filters := get_filters(args):
        kwargs['filter'] = filters

    client = get_aws_session(aws_client, args)
    response = client.list_findings(**kwargs)
    return json.loads(json.dumps(response, cls=DatetimeEncoder))


def get_earliest_fetch_time():
    last_run = demisto.getLastRun()
    params = demisto.params()
    earliest_fetch_time = last_run and last_run.get('time')
    demisto.debug(f'{last_run=}')
    # Handle first time fetch, fetch incidents retroactively
    if not earliest_fetch_time:
        first_fetch = dateparser.parse(params.get('first_fetch', '3 days'))
        earliest_fetch_time = date_to_timestamp(first_fetch)
    return earliest_fetch_time


def fetch_incidents(aws_client):
    params = demisto.params()
    findings_args = {
        'roleArn': params.get('roleArn'),
        'region': params.get('region'),
        'roleSessionName': params.get('roleSessionName'),
        'roleSessionDuration': params.get('roleSessionDuration'),
        'analyzerArn': params.get('analyzerArn'),
        'maxResults': int(params.get('max_fetch', 25))
    }

    latest_finding_time = earliest_fetch_time = get_earliest_fetch_time()
    incidents: list = []
    should_stop_fetch = False

    demisto.debug(f'{findings_args=}')
    demisto.debug(f'{earliest_fetch_time=}')
    while True:
        findings_response = get_findings(aws_client, findings_args)
        for finding in findings_response['findings']:

            finding_timestamp = date_to_timestamp(finding['updatedAt'])
            if finding_timestamp <= int(earliest_fetch_time):
                demisto.debug(f'{finding_timestamp=} is less then {earliest_fetch_time=} - stop fetching')
                should_stop_fetch = True
                break

            latest_finding_time = max(finding_timestamp, int(latest_finding_time))
            incidents.append({
                'name': f"AWS Access Analyzer Alert - {finding['id']}",
                'occurred': finding['updatedAt'] + 'Z',
                'rawJSON': json.dumps(finding)
            })

        if should_stop_fetch or 'nextToken' not in findings_response:
            break

        findings_args['nextToken'] = findings_response['nextToken']

    demisto.debug(f'next last_run: {latest_finding_time=}')
    demisto.setLastRun({"time": latest_finding_time})
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
        'test-module': test_function,
        'aws-access-analyzer-list-analyzers': list_analyzers_command,
        'aws-access-analyzer-list-analyzed-resource': list_analyzed_resource_command,
        'aws-access-analyzer-list-findings': list_findings_command,
        'aws-access-analyzer-get-analyzed-resource': get_analyzed_resource_command,
        'aws-access-analyzer-get-finding': get_finding_command,
        'aws-access-analyzer-start-resource-scan': start_resource_scan_command,
        'aws-access-analyzer-update-findings': update_findings_command,
    }
    try:
        if command == 'fetch-incidents':
            fetch_incidents(aws_client)
        else:
            return_results(commands[command](aws_client, args))
    except Exception as e:
        return_error(f"Error has occurred in AWS Access Analyzer Integration: {str(e)}")


from AWSApiModule import *  # noqa: E402

if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
