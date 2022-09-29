from datetime import datetime, date
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
import urllib3.util
import boto3

# Disable insecure warnings
urllib3.disable_warnings()

SERVICE = 'guardduty'


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj: Any):  # pylint: disable=E0202
        if isinstance(obj, datetime):  # type: ignore
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):  # type: ignore  # pylint: disable=E0602
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_detector(client: boto3.client, args: dict):
    kwargs = {'Enable': True if args.get('enable') == 'True' else False}
    response = client.create_detector(**kwargs)
    data = ({'DetectorId': response['DetectorId']})
    readable_output = tableToMarkdown('AWS GuardDuty Detectors', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors',
                          outputs_key_field='DetectorId')


def delete_detector(client: boto3.client, args: dict):
    response = client.delete_detector(DetectorId=args.get('detectorId'))
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The Detector {args.get('detectorId')} has been deleted"
    else:
        raise Exception(f"The Detector {args.get('detectorId')} failed to delete.")


def get_detector(client: boto3.client, args: dict):
    response = client.get_detector(DetectorId=args.get('detectorId'))
    data = ({
        'DetectorId': args.get('detectorId'),
        'CreatedAt': response['CreatedAt'],
        'ServiceRole': response['ServiceRole'],
        'Status': response['Status'],
        'UpdatedAt': response['UpdatedAt'],
    })
    readable_output = tableToMarkdown('AWS GuardDuty Detectors', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors',
                          outputs_key_field='DetectorId')


def update_detector(client: boto3.client, args: dict):
    response = client.update_detector(
        DetectorId=args.get('detectorId'),
        Enable=True if args.get('enable') == 'True' else False
    )
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The Detector {args.get('detectorId')} has been Updated"
    else:
        raise Exception(f"Detector {args.get('detectorId')} failed to update. Response was: {response}")


def list_detectors(client: boto3.client, args: dict):
    response = client.list_detectors()
    detector = response['DetectorIds']
    # Only takes the first detector in the list, this should be addressed when rewriting.
    data = ({
        'DetectorId': detector[0]
    })
    readable_output = tableToMarkdown('AWS GuardDuty Detectors', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors',
                          outputs_key_field='DetectorId')


def create_ip_set(client: boto3.client, args: dict):
    kwargs = {'DetectorId': args.get('detectorId')}
    if args.get('activate') is not None:
        kwargs.update({'Activate': True if args.get('activate') == 'True' else False})
    if args.get('format') is not None:
        kwargs.update({'Format': args.get('format')})
    if args.get('location') is not None:
        kwargs.update({'Location': args.get('location')})
    if args.get('name') is not None:
        kwargs.update({'Name': args.get('name')})

    response = client.create_ip_set(**kwargs)

    data = ({
        'DetectorId': args.get('detectorId'),
        'IpSetId': response['IpSetId']
    })
    readable_output = tableToMarkdown('AWS GuardDuty IPSets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.IPSet',
                          outputs_key_field='IpSetId')


def delete_ip_set(client: boto3.client, args: dict):
    response = client.delete_ip_set(
        DetectorId=args.get('detectorId'),
        IpSetId=args.get('ipSetId')
    )
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The IPSet {args.get('ipSetId')} has been deleted from Detector {args.get('detectorId')}"

    else:
        raise Exception(f"Failed to delete ip set {args.get('ipSetId')} . Response was: {response}")


def update_ip_set(client: boto3.client, args: dict):
    kwargs = {
        'DetectorId': args.get('detectorId'),
        'IpSetId': args.get('ipSetId')
    }
    if args.get('activate'):
        kwargs.update({'Activate': True if args.get('activate') == 'True' else False})
    if args.get('location'):
        kwargs.update({'Location': args.get('location')})
    if args.get('name'):
        kwargs.update({'Name': args.get('name')})

    response = client.update_ip_set(**kwargs)

    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The IPSet {args.get('ipSetId')} has been Updated"

    else:
        raise Exception(f"Failed updating ip set {args.get('ipSetId')} . Response was: {response}")


def get_ip_set(client: boto3.client, args: dict):

    response = client.get_ip_set(DetectorId=args.get('detectorId'),
                                 IpSetId=args.get('ipSetId'))
    data = ({'DetectorId': args.get('detectorId'),
             'IpSetId': args.get('ipSetId'),
             'Format': response['Format'],
             'Location': response['Location'],
             'Name': response['Name'],
             'Status': response['Status']})

    readable_output = tableToMarkdown('AWS GuardDuty IPSets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.IPSet',
                          outputs_key_field='IpSetId')


def list_ip_sets(client: boto3.client, args: dict):
    response = client.list_ip_sets(DetectorId=args.get('detectorId'))
    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for ipset in response['IpSetIds']:
        data.append({'IpSetId': ipset})

    readable_output = tableToMarkdown('AWS GuardDuty IPSets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.IPSet',
                          outputs_key_field='IpSetId')


def create_threat_intel_set(client: boto3.client, args: dict):

    kwargs = {'DetectorId': args.get('detectorId')}
    if args.get('activate') is not None:
        kwargs.update({'Activate': True if args.get('activate') == 'True' else False})
    if args.get('format') is not None:
        kwargs.update({'Format': args.get('format')})
    if args.get('location') is not None:
        kwargs.update({'Location': args.get('location')})
    if args.get('name') is not None:
        kwargs.update({'Name': args.get('name')})

    response = client.create_threat_intel_set(**kwargs)

    data = ({
        'DetectorId': args.get('detectorId'),
        'ThreatIntelSetId': response['ThreatIntelSetId']
    })

    readable_output = tableToMarkdown('AWS GuardDuty ThreatIntel Set', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.ThreatIntelSet',
                          outputs_key_field='ThreatIntelSetId')


def delete_threat_intel_set(client: boto3.client, args: dict):
    response = client.delete_threat_intel_set(
        DetectorId=args.get('detectorId'),
        ThreatIntelSetId=args.get('threatIntelSetId')
    )
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The ThreatIntel Set {args.get('threatIntelSetId')} has been deleted from Detector {args.get('detectorId')}"
    else:
        raise Exception(f"Failed to delete ThreatIntel set {args.get('threatIntelSetId')} . Response was: {response}")


def get_threat_intel_set(client: boto3.client, args: dict):

    response = client.get_threat_intel_set(
        DetectorId=args.get('detectorId'),
        ThreatIntelSetId=args.get('threatIntelSetId')
    )
    data = ({
        'DetectorId': args.get('detectorId'),
        'ThreatIntelSetId': args.get('threatIntelSetId'),
        'Format': response['Format'],
        'Location': response['Location'],
        'Name': response['Name'],
        'Status': response['Status']
    })

    readable_output = tableToMarkdown('AWS GuardDuty ThreatIntel Set', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.ThreatIntelSet',
                          outputs_key_field='ThreatIntelSetId')


def list_threat_intel_sets(client: boto3.client, args: dict):
    response = client.list_threat_intel_sets(DetectorId=args.get('detectorId'))
    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for threatintelset in response['ThreatIntelSetIds']:
        data.append({'ThreatIntelSetId': threatintelset})

    readable_output = tableToMarkdown('AWS GuardDuty ThreatIntel Sets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.ThreatIntelSet',
                          outputs_key_field='ThreatIntelSetId')


def update_threat_intel_set(client: boto3.client, args: dict):
    kwargs = {
        'DetectorId': args.get('detectorId'),
        'ThreatIntelSetId': args.get('threatIntelSetId')
    }
    if args.get('activate'):
        kwargs.update({'Activate': True if args.get('activate') == 'True' else False})
    if args.get('location'):
        kwargs.update({'Location': args.get('location')})
    if args.get('name'):
        kwargs.update({'Name': args.get('name')})
    response = client.update_threat_intel_set(**kwargs)

    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The ThreatIntel set {args.get('threatIntelSetId')} has been updated"
    else:
        raise Exception(f"Failed updating ThreatIntel set {args.get('threatIntelSetId')}. "
                        f"Response was: {response}")


def severity_mapping(severity: int):
    if severity <= 3.9:
        demistoSevirity = 1
    elif severity >= 4 and severity <= 6.9:
        demistoSevirity = 2
    elif severity >= 7 and severity <= 8.9:
        demistoSevirity = 3
    else:
        demistoSevirity = 0

    return demistoSevirity


def gd_severity_mapping(severity: str):
    if severity == 'Low':
        gdSevirity = 1
    elif severity == 'Medium':
        gdSevirity = 4
    elif severity == 'High':
        gdSevirity = 7
    else:
        gdSevirity = 1

    return gdSevirity


def list_findings(client: boto3.client, args: dict):

    paginator = client.get_paginator('list_findings')
    response_iterator = paginator.paginate(DetectorId=args.get('detectorId'))
    data = []
    for page in response_iterator:
        for finding in page['FindingIds']:
            data.append({'FindingId': finding})

    readable_output = tableToMarkdown('AWS GuardDuty Findings', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Findings',
                          outputs_key_field='')


def get_findings(client: boto3.client, args: dict):
    response = client.get_findings(
        DetectorId=args.get('detectorId'),
        FindingIds=argToList(args.get('findingIds')))

    data = []
    for finding in response['Findings']:
        data.append({
            'AccountId': finding['AccountId'],
            'Arn': finding['Arn'],
            'CreatedAt': finding['CreatedAt'],
            'Description': finding['Description'],
            'Id': finding['Id'],
            'Region': finding['Region'],
            'Title': finding['Title'],
            'Type': finding['Type'],
        })

    output = json.dumps(response['Findings'], cls=DatetimeEncoder)
    raw = json.loads(output)
    readable_output = tableToMarkdown('AWS GuardDuty Findings', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          raw_response=raw,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Findings',
                          outputs_key_field='Id')


def parse_incident_from_finding(finding: dict):
    incident: dict = dict()
    incident['name'] = finding['Title']
    incident['details'] = finding['Description']
    incident['occurred'] = finding['CreatedAt']
    incident['severity'] = severity_mapping(finding['Severity'])
    incident['rawJSON'] = json.dumps(finding, default=str)
    return incident


def fetch_incidents(client: boto3.client, aws_gd_severity: str):
    incidents = []
    response = client.list_detectors()
    detector = response['DetectorIds']

    list_findings = client.list_findings(
        DetectorId=detector[0], FindingCriteria={
            'Criterion': {
                'service.archived': {'Eq': ['false', 'false']},
                'severity': {'Gt': gd_severity_mapping(aws_gd_severity)}
            }
        }
    )

    get_findings = client.get_findings(DetectorId=detector[0], FindingIds=list_findings['FindingIds'])

    for finding in get_findings['Findings']:
        incident = parse_incident_from_finding(finding)
        incidents.append(incident)

    # Create demisto incidents
    demisto.incidents(incidents)
    if incidents is not None:
        # Archive findings
        client.archive_findings(DetectorId=detector[0], FindingIds=list_findings['FindingIds'])


def create_sample_findings(client: boto3.client, args: dict):
    kwargs = {'DetectorId': args.get('detectorId')}
    if args.get('findingTypes') is not None:
        kwargs.update({'FindingTypes': argToList(args.get('findingTypes'))})

    response = client.create_sample_findings(**kwargs)

    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Sample Findings were generated"
    else:
        raise Exception(f"Failed to generate findings. Response was: {response}")


def archive_findings(client: boto3.client, args: dict):
    kwargs = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})

    response = client.archive_findings(**kwargs)

    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings were archived"
    else:
        raise Exception(f"Failed to archive findings. Response was: {response}")


def unarchive_findings(client: boto3.client, args: dict):
    kwargs: dict = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})

    response = client.unarchive_findings(**kwargs)

    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings were unarchived"
    else:
        raise Exception(f"Failed to archive findings. Response was: {response}")


def update_findings_feedback(client: boto3.client, args: dict):
    kwargs = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})
    if args.get('comments') is not None:
        kwargs.update({'Comments': argToList(args.get('comments'))})
    if args.get('feedback') is not None:
        kwargs.update({'Feedback': argToList(args.get('feedback'))})

    response = client.update_findings_feedback(**kwargs)
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings Feedback sent!"
    else:
        raise Exception(f"Failed to send findings feedback. Response was: {response}")


def list_members(client: boto3.client, args: dict):
    response = client.list_members(DetectorId=args.get('detectorId'))
    data = response.get('Members')

    readable_output = tableToMarkdown('AWS GuardDuty Members', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Members',
                          outputs_key_field='AccountId')


def get_members(client: boto3.client, args: dict):
    accountId_list = []
    accountId_list.append(args.get('accountIds'))

    response = client.get_members(
        DetectorId=args.get('detectorId'),
        AccountIds=accountId_list
    )

    members_response = response.get('Members', [])
    filtered_members = [member for member in members_response if member]

    readable_output = tableToMarkdown('AWS GuardDuty Members', filtered_members) if filtered_members else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=filtered_members,
                          outputs_prefix='AWS.GuardDuty.Members',
                          outputs_key_field='AccountId')


def connection_test(client: boto3.client):
    response = client.list_detectors()
    if response.get('DetectorIds'):
        return 'ok'
    else:
        raise Exception(f"Error listing detectors. Response was {response}")


def main():   # pragma: no cover
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_role_policy = None
    aws_access_key_id = params.get('access_key')
    aws_secret_access_key = params.get('secret_key')
    aws_gd_severity = params.get('gs_severity', '')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries)
        args = demisto.args()

        client = aws_client.aws_session(service=SERVICE, region=args.get('region'),
                                        role_arn=args.get('roleArn'),
                                        role_session_name=args.get('roleSessionName'),
                                        role_session_duration=args.get('roleSessionDuration'))

        # The command demisto.command() holds the command sent from the user.
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            result = connection_test(client)

        elif demisto.command() == 'aws-gd-create-detector':
            result = create_detector(client, demisto.args())

        elif demisto.command() == 'aws-gd-delete-detector':
            result = delete_detector(client, demisto.args())

        elif demisto.command() == 'aws-gd-get-detector':
            result = get_detector(client, demisto.args())

        elif demisto.command() == 'aws-gd-update-detector':
            result = update_detector(client, demisto.args())

        elif demisto.command() == 'aws-gd-create-ip-set':
            result = create_ip_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-delete-ip-set':
            result = delete_ip_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-list-detectors':
            result = list_detectors(client, demisto.args())

        elif demisto.command() == 'aws-gd-update-ip-set':
            result = update_ip_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-get-ip-set':
            result = get_ip_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-list-ip-sets':
            result = list_ip_sets(client, demisto.args())

        elif demisto.command() == 'aws-gd-create-threatintel-set':
            result = create_threat_intel_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-delete-threatintel-set':
            result = delete_threat_intel_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-get-threatintel-set':
            result = get_threat_intel_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-list-threatintel-sets':
            result = list_threat_intel_sets(client, demisto.args())

        elif demisto.command() == 'aws-gd-update-threatintel-set':
            result = update_threat_intel_set(client, demisto.args())

        elif demisto.command() == 'aws-gd-list-findings':
            result = list_findings(client, demisto.args())

        elif demisto.command() == 'aws-gd-get-findings':
            result = get_findings(client, demisto.args())

        elif demisto.command() == 'aws-gd-create-sample-findings':
            result = create_sample_findings(client, demisto.args())

        elif demisto.command() == 'aws-gd-archive-findings':
            result = archive_findings(client, demisto.args())

        elif demisto.command() == 'aws-gd-unarchive-findings':
            result = unarchive_findings(client, demisto.args())

        elif demisto.command() == 'aws-gd-update-findings-feedback':
            result = update_findings_feedback(client, demisto.args())

        elif demisto.command() == 'aws-gd-list-members':
            result = list_members(client, demisto.args())

        elif demisto.command() == 'aws-gd-get-members':
            result = get_members(client, demisto.args())

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client, aws_gd_severity)
            sys.exit(0)

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented in AWSGuardDuty integration.')

        return_results(result)

    except Exception as e:
        return_error(f'Error has occurred in the AWS GuardDuty Integration: {type(e)}\n {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
