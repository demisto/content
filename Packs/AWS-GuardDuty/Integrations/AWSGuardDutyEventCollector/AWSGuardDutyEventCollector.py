import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402

import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

CLIENT_SERVICE = 'guardduty'
MAX_IDS_PER_REQ = 50
MAX_RESULTS = 50
GD_SEVERITY_DICT = {
    'Low': 1,
    'Medium': 4,
    'High': 7
}


def get_events(aws_client, collect_from, collect_from_default, last_ids, severity, limit=MAX_RESULTS, detectors_num=MAX_RESULTS):

    events = []
    detector_ids = []
    next_token = None
    new_last_ids = last_ids.copy()
    new_collect_from = collect_from.copy()

    # List all detectors
    while next_token != 'invalid':
        list_detectors_args = {'MaxResults': detectors_num}
        if next_token:
            list_detectors_args.update({'NextToken': next_token})

        response = aws_client.list_detectors(**list_detectors_args)
        detector_ids += response.get('DetectorIds', [])
        next_token = response.get('NextToken', 'invalid')

    for detector_id in detector_ids:
        next_token = None
        finding_ids = []
        detector_events = []
        # List all finding ids
        while next_token != 'invalid' and len(events) + len(finding_ids) < limit:
            list_finding_args = {
                'DetectorId': detector_id,
                'FindingCriteria': {
                    'Criterion': {
                        'updatedAt': {'Gte': date_to_timestamp(collect_from.get(detector_id, collect_from_default))},
                        'severity': {'Gte': GD_SEVERITY_DICT.get(severity, 1)}
                    }
                },
                'SortCriteria': {
                    'AttributeName': 'updatedAt',
                    'OrderBy': 'ASC'
                },
                'MaxResults': limit
            }
            if next_token:
                list_finding_args.update({'NextToken': next_token})
            list_findings = aws_client.list_findings(**list_finding_args)
            finding_ids += list_findings.get('FindingIds', [])
            next_token = list_findings.get('NextToken', 'invalid')

            # Handle duplicates and findings updated at the same time.
            if last_ids.get(detector_id) and last_ids.get(detector_id) in finding_ids:
                finding_ids = finding_ids[finding_ids.index(last_ids.get(detector_id)) + 1:]

        # Get all relevant findings
        chunked_finding_ids = [finding_ids[i: i + MAX_IDS_PER_REQ] for i in range(0, len(finding_ids), MAX_IDS_PER_REQ)]
        for chunk_of_finding_ids in chunked_finding_ids:
            findings_response = aws_client.get_findings(DetectorId=detector_id, FindingIds=chunk_of_finding_ids)
            detector_events += findings_response.get('Findings', [])

        events += detector_events

        if finding_ids:
            new_last_ids[detector_id] = finding_ids[-1]

        if detector_events:
            new_collect_from[detector_id] = detector_events[-1].get('updatedAt')

    return events, new_last_ids, new_collect_from


def main():
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5
    aws_gd_severity = params.get('gd_severity', '')
    first_fetch = arg_to_datetime(params.get('first_fetch'))
    limit = arg_to_number(params.get('limit'))

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        # proxy is being handled in AWSClient.
        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries)

        client = aws_client.aws_session(service=CLIENT_SERVICE, region=aws_default_region)

        command = demisto.command()
        if command == 'test-module':
            get_events(aws_client=client,
                       collect_from={},
                       collect_from_default=first_fetch,
                       last_ids={},
                       severity=aws_gd_severity,
                       limit=1,
                       detectors_num=1)
            return_results('ok')

        if command in ('aws-gd-get-events', 'fetch-events'):
            events = []
            if command == 'aws-gd-get-events':

                collect_from = arg_to_datetime(demisto.args().get('collect_from', params.get('first_fetch')))
                severity = demisto.args().get('severity', aws_gd_severity)
                command_limit = demisto.args().get('limit', limit)
                events, new_last_ids, new_collect_from = get_events(aws_client=client,
                                                                    collect_from={},
                                                                    collect_from_default=collect_from,
                                                                    last_ids={},
                                                                    severity=severity,
                                                                    limit=command_limit)

                command_results = CommandResults(
                    readable_output=tableToMarkdown('AWSGuardDuty Logs', events, headerTransform=pascalToSpace),
                    outputs_prefix='AWSGuardDuty.Logs',
                    outputs_key_field='event.id',
                    outputs=events,
                    raw_response=events,
                )
                return_results(command_results)

            if command == 'fetch-events':
                last_run = demisto.getLastRun()
                collect_from = last_run.get('collect_from', {})
                last_ids = last_run.get('last_ids', {})

                events, new_last_ids, new_collect_from = get_events(aws_client=client,
                                                                    collect_from=collect_from,
                                                                    collect_from_default=first_fetch,
                                                                    last_ids=last_ids,
                                                                    severity=aws_gd_severity,
                                                                    limit=limit)

                demisto.setLastRun({
                    'collect_from': new_collect_from,
                    'last_ids': new_last_ids
                })

            if argToBoolean(demisto.args().get('should_push_events', 'true')):
                send_events_to_xsiam(events, params.get('vendor', 'AWS'), params.get('product', 'GuardDuty'))

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command in AWSGuardDutyEventCollector.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
