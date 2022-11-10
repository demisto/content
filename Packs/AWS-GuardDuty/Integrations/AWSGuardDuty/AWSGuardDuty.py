import json
from datetime import datetime, date
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from AWSApiModule import *  # noqa: E402
import urllib3.util
import boto3
from collections import defaultdict
from typing import Tuple

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

SERVICE = 'guardduty'

FINDING_FREQUENCY = {
    'Fifteen Minutes': 'FIFTEEN_MINUTES',
    'One Hour': 'ONE_HOUR',
    'Six Hours': 'SIX_HOURS'
}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
MAX_INCIDENTS_TO_FETCH = 50
MAX_RESULTS_RESPONSE = 50


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj: Any):  # pylint: disable=E0202
        if isinstance(obj, datetime):  # type: ignore
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):  # type: ignore  # pylint: disable=E0602
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_detector(client: boto3.client, args: dict):
    kwargs = {'Enable': argToBoolean(args.get('enabled', False))}

    if args.get('findingFrequency'):
        kwargs['FindingPublishingFrequency'] = FINDING_FREQUENCY[args['findingFrequency']]
    get_dataSources = dict()
    if args.get('enableKubernetesLogs'):
        get_dataSources.update(
            {'Kubernetes': {'AuditLogs': {'Enable': argToBoolean(args['enableKubernetesLogs'])}}})
    if args.get('ebsVolumesMalwareProtection'):
        get_dataSources.update({'MalwareProtection': {
            'ScanEc2InstanceWithFindings': {'EbsVolumes': argToBoolean(args['ebsVolumesMalwareProtection'])}}})
    if args.get('enableS3_logs'):
        get_dataSources.update({'S3Logs': {'Enable': argToBoolean(args['enableS3_logs'])}})
    if get_dataSources:
        kwargs['DataSources'] = get_dataSources

    response = client.create_detector(**kwargs)
    data = ({'DetectorId': response['DetectorId']})

    readable_output = tableToMarkdown('AWS GuardDuty Detectors - detector created successfully',
                                      data) if data else 'No result were found'
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
        'CloudTrailStatus': demisto.get(response, 'DataSources.CloudTrail.Status'),
        'DNSLogsStatus': demisto.get(response, 'DataSources.DNSLogs.Status'),
        'FlowLogsStatus': demisto.get(response, 'DataSources.FlowLogs.Status'),
        'S3LogsStatus': demisto.get(response, 'DataSources.S3Logs.Status'),
        'KubernetesAuditLogsStatus': demisto.get(response, 'DataSources.Kubernetes.AuditLogs.Status'),
        'MalwareProtectionStatus': demisto.get(response, 'DataSources.MalwareProtection.ScanEc2InstanceWithFindings'
                                                         '.EbsVolumes.Status'),
        'MalwareProtectionReason': demisto.get(response, 'DataSources.MalwareProtection.ScanEc2InstanceWithFindings'
                                                         '.EbsVolumes.Reason'),
        'Tags': response.get('Tags'),

    })
    readable_output = tableToMarkdown('AWS GuardDuty Detectors', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors',
                          outputs_key_field='DetectorId')


def update_detector(client: boto3.client, args: dict):
    kwargs = {'Enable': argToBoolean(args.get('enable', False)), 'DetectorId': args.get('detectorId')}

    if args.get('findingFrequency'):
        kwargs['FindingPublishingFrequency'] = FINDING_FREQUENCY[args['findingFrequency']]
    get_dataSources = dict()
    if args.get('enableKubernetesLogs'):
        get_dataSources.update(
            {'Kubernetes': {'AuditLogs': {'Enable': argToBoolean(args['enableKubernetesLogs'])}}})
    if args.get('ebsVolumesMalwareProtection'):
        get_dataSources.update({'MalwareProtection': {
            'ScanEc2InstanceWithFindings': {'EbsVolumes': argToBoolean(args['ebsVolumesMalwareProtection'])}}})
    if args.get('enableS3_logs'):
        get_dataSources.update({'S3Logs': {'Enable': argToBoolean(args['enableS3_logs'])}})
    if get_dataSources:
        kwargs['DataSources'] = get_dataSources

    response = client.update_detector(**kwargs)
    if response == dict() or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The Detector {args.get('detectorId')} has been Updated successfully"
    else:
        raise Exception(f"Detector {args.get('detectorId')} failed to update. Response was: {response}")


def list_detectors(client: boto3.client, args: dict):
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_detectors')
    response_iterator = paginator.paginate(
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for detector in page_response['DetectorIds']:
                data.append({'DetectorId': detector})
            if page:
                break

    readable_output = tableToMarkdown('AWS GuardDuty Detectors',
                                      data) if data else 'No result were found'
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
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_ip_sets')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId'),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for IpSetId in page_response['IpSetIds']:
                data.append({'IpSetId': IpSetId})
            if page:
                break

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
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_threat_intel_sets')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId'),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for detector in page_response['ThreatIntelSetIds']:
                data.append({'ThreatIntelSetId': detector})
            if page:
                break

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
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_findings')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId'),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for finding in page_response['FindingIds']:
                data.append({'FindingId': finding})
            if page:
                break

    readable_output = tableToMarkdown('AWS GuardDuty Findings', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Findings',
                          outputs_key_field='')


def get_pagination_args(args: dict):
    """
    Gets and validates pagination arguments.
    :param args: The command arguments (page, page_size or limit)
    :return: limit, page_size, page after validation and convert
    """

    # Automatic Pagination
    limit = arg_to_number(args.get('limit', MAX_RESULTS_RESPONSE))

    # Manual Pagination
    page = arg_to_number(args['page']) if args.get('page') else None
    if page is not None and page <= 0:
        raise Exception('page argument must be greater than 0')

    page_size = arg_to_number(args['page_size']) if args.get('page_size') else MAX_RESULTS_RESPONSE
    if not 0 < page_size <= MAX_RESULTS_RESPONSE:  # type: ignore
        raise Exception(f'page_size argument must be between 1 to {MAX_RESULTS_RESPONSE}')

    if page:
        limit = page * page_size

    return limit, page_size, page


def parse_finding(finding: dict):
    parsed_finding: dict = dict()

    # Common Fields
    parsed_finding['Account ID'] = finding['AccountId']
    parsed_finding['Occurred'] = finding['CreatedAt']
    parsed_finding['Description'] = finding['Description']
    parsed_finding['Region'] = finding['Region']
    parsed_finding['Alert Id'] = finding['Id']
    parsed_finding['Title'] = finding['Title']
    parsed_finding['Severity'] = severity_mapping(finding['Severity'])
    parsed_finding['Last Update Time'] = finding['UpdatedAt']

    # Custom Fields
    parsed_finding['AWS Arn'] = finding.get('Arn')
    parsed_finding['AWS GuardDuty Confidence Score'] = finding.get('Confidence')
    parsed_finding['AWS GuardDuty Partition'] = finding.get('Partition')
    parsed_finding['AWS GuardDuty Resource Type'] = demisto.get(finding, 'Resource.ResourceType')
    parsed_finding['AWS GuardDuty Type'] = finding.get('Type')
    parsed_finding['AWS GuardDuty Schema Version'] = finding.get('SchemaVersion')
    parsed_finding['AWS GuardDuty Service'] = demisto.get(finding, 'Resource.Service')
    parsed_finding['AWS GuardDuty Access Key Details'] = demisto.get(finding, 'Resource.AccessKeyDetails')
    parsed_finding['AWS GuardDuty Kubernetes User Details'] = \
        demisto.get(finding, 'Resource.KubernetesDetails.KubernetesUserDetails')
    parsed_finding['AWS GuardDuty Kubernetes Workload Details'] = \
        demisto.get(finding, 'Resource.KubernetesDetails.KubernetesWorkloadDetails')
    parsed_finding['AWS GuardDuty Ebs Volume Details'] = demisto.get(finding, 'Resource.EbsVolumeDetails')
    parsed_finding['AWS GuardDuty Container Details'] = demisto.get(finding, 'Resource.ContainerDetails')

    resource_instance_details = demisto.get(finding, 'Resource.InstanceDetails')
    if resource_instance_details:
        if 'IamInstanceProfile' in resource_instance_details:
            parsed_finding['AWS GuardDuty Iam Instance Profile'] = resource_instance_details.pop('IamInstanceProfile')
        if 'NetworkInterfaces' in resource_instance_details:
            parsed_finding['AWS GuardDuty Network Interface'] = resource_instance_details.pop('NetworkInterfaces')
        parsed_finding['AWS GuardDuty Instance Details'] = resource_instance_details

    # TODO MAYBE CHANGE THE DATETIME IN DIFFERENT WAY
    eks_cluster_details = json.dumps(demisto.get(finding, 'Resource.EksClusterDetails'), cls=DatetimeEncoder)
    if eks_cluster_details != 'null':
        parsed_finding['AWS GuardDuty Eks Cluster Details'] = json.loads(eks_cluster_details)

    ecs_cluster_details = json.dumps(demisto.get(finding, 'Resource.EcsClusterDetails'), cls=DatetimeEncoder)
    if ecs_cluster_details != 'null':
        parsed_finding['AWS GuardDuty Ecs Cluster Details'] = json.loads(ecs_cluster_details)

    s3_bucket_details = json.dumps(demisto.get(finding, 'Resource.S3BucketDetails'), cls=DatetimeEncoder)
    if s3_bucket_details != 'null':
        parsed_finding['AWS GuardDuty S3 Bucket Details'] = json.loads(s3_bucket_details)

    return parsed_finding


def get_findings(client: boto3.client, args: dict):
    response = client.get_findings(
        DetectorId=args.get('detectorId'),
        FindingIds=argToList(args.get('findingIds')))

    data = []
    for finding in response['Findings']:
        data.append(parse_finding(finding))

    output = json.dumps(response['Findings'], cls=DatetimeEncoder)
    raw = json.loads(output)
    readable_output = tableToMarkdown('AWS GuardDuty Findings', data, removeNull=True) if data else 'No result were found'
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


def time_to_unix_epoch(date_time: str):
    """
    :param date_time: The time and date in '%Y-%m-%dT%H:%M:%S.%fZ' format
    :return: Timestamp in Unix Epoch millisecond format
    example: date_time = '2017-02-10 00:09:35.000000+00:00' to 1486685375000
    """
    return int(dateparser.parse(date_time).timestamp() * 1000)


def fetch_incidents(client: boto3.client, aws_gd_severity: str, last_run: dict, fetch_limit: int,
                    first_fetch_time: str) -> Tuple[Dict[str, Any], List[dict]]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): boto3.client client
        aws_gd_severity: Guard Duty Severity level
        last_run (dict): {'latest_created_time' (string): The greatest incident created_time we fetched from last fetch,
                          'latest_updated_time' (string): The greatest incident updated_time we fetched from last fetch,
                          'last_incidents_ids' (set): The last incidents ids of the latest_created_time,
                          'last_next_token' (string): The value of NextToken from the previous response to continue listing data.}
        fetch_limit (int): Maximum numbers of incidents per fetch
        first_fetch_time (str): If last_fetch is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """

    # Get the latest_created_time, latest_updated_time, last_incidents_ids, and last_next_token if exist
    latest_created_time = last_run.get('latest_created_time')
    last_incidents_ids = last_run.get('last_incidents_ids', [])
    last_next_token = last_run.get('last_next_token', "")
    latest_updated_time = last_run.get('latest_updated_time', "")

    # Handle first time fetch
    if latest_created_time is None:
        latest_created_time = dateparser.parse(dateparser.parse(first_fetch_time).strftime(DATE_FORMAT))
    else:
        latest_created_time = dateparser.parse(latest_created_time)

    response = client.list_detectors()
    detector = response['DetectorIds']

    created_time_to_ids = defaultdict(list)
    created_time_to_ids[latest_created_time] = last_incidents_ids
    criterion_conditions = {'severity': {'Gt': gd_severity_mapping(aws_gd_severity)}}
    if latest_updated_time and not last_next_token:
        criterion_conditions['updatedAt'] = {'Gte': time_to_unix_epoch(latest_updated_time)}
    if last_incidents_ids:
        criterion_conditions['id'] = {'Neq': last_incidents_ids}

    demisto.info(f'Fetching Amazon GuardDuty findings for the {detector[0]} since: {str(latest_created_time)}')

    incidents: list[dict] = []
    while True:
        left_to_fetch = fetch_limit - len(incidents)
        max_results = MAX_INCIDENTS_TO_FETCH if left_to_fetch > MAX_INCIDENTS_TO_FETCH else left_to_fetch

        list_findings = client.list_findings(
            DetectorId=detector[0], FindingCriteria={
                'Criterion': criterion_conditions},
            SortCriteria={'AttributeName': 'createdAt', 'OrderBy': 'ASC'},
            MaxResults=max_results,
            NextToken=last_next_token
        )
        last_next_token = list_findings["NextToken"]
        get_findings = client.get_findings(DetectorId=detector[0], FindingIds=list_findings['FindingIds'],
                                           SortCriteria={'AttributeName': 'createdAt', 'OrderBy': 'ASC'})

        for finding in get_findings['Findings']:
            incident_created_time = dateparser.parse(finding['CreatedAt'])
            incident_updated_time = finding['UpdatedAt']
            incident_id = finding["Id"]

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time >= latest_created_time:

                demisto.debug(f'Add Incident with ID {incident_id}, occured: {str(incident_created_time)}, '
                              f'updated: {incident_updated_time}')

                # update the last run: latest_updated_time, latest_updated_time
                latest_created_time = incident_created_time
                if not latest_updated_time:
                    latest_updated_time = incident_updated_time
                elif dateparser.parse(incident_updated_time) > dateparser.parse(latest_updated_time):
                    latest_updated_time = incident_updated_time
                created_time_to_ids[latest_created_time].append(incident_id)

                incident = parse_incident_from_finding(finding)
                incidents.append(incident)

        # if there is no next_token, or we have reached the fetch_limit -> break
        if fetch_limit - len(incidents) == 0 or not last_next_token:
            demisto.debug('fetch_limit has been reached or there is no next token')
            break

    next_run = {'latest_created_time': latest_created_time.strftime(DATE_FORMAT),
                'latest_updated_time': latest_updated_time,
                'last_incidents_ids': created_time_to_ids[latest_created_time],
                'last_next_token': last_next_token}

    demisto.debug(f'{next_run=}')
    demisto.debug(f'fetched {len(incidents)} incidents')
    return next_run, incidents


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
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_members')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId'),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for Member in page_response['Members']:
                data.append({'Member': Member})
            if page:
                break

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

    readable_output = tableToMarkdown('AWS GuardDuty Members',
                                      filtered_members) if filtered_members else 'No result were found'
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


def main():  # pragma: no cover
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
    first_fetch_time = params.get('first_fetch_time', '10 minutes').strip()
    fetch_limit = arg_to_number(params.get('fetch_limit', 10))

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
            next_run, incidents = fetch_incidents(client, aws_gd_severity, last_run=demisto.getLastRun(),
                                                  fetch_limit=fetch_limit,
                                                  first_fetch_time=first_fetch_time)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
            sys.exit(0)

        else:
            raise NotImplementedError(f'Command {demisto.command()} is not implemented in AWSGuardDuty integration.')

        return_results(result)

    except Exception as e:
        return_error(f'Error has occurred in the AWS GuardDuty Integration: {type(e)}\n {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
