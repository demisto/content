import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from datetime import datetime, date
from AWSApiModule import *  # noqa: E402
from collections import defaultdict
from typing import TYPE_CHECKING

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_guardduty import GuardDutyClient
    from mypy_boto3_guardduty.type_defs import (
        FindingTypeDef,
        ConditionTypeDef
    )


''' CONSTANTS '''

SERVICE = 'guardduty'

FINDING_FREQUENCY = {
    'Fifteen Minutes': 'FIFTEEN_MINUTES',
    'One Hour': 'ONE_HOUR',
    'Six Hours': 'SIX_HOURS'
}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
MAX_RESULTS_RESPONSE = 50


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj: Any):  # pylint: disable=E0202
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):  # pylint: disable=E0602
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_detector(client: "GuardDutyClient", args: dict) -> CommandResults:
    """
    Creates a single Amazon GuardDuty detector.
    """
    kwargs = {'Enable': argToBoolean(args.get('enabled', False))}

    if args.get('findingFrequency'):
        kwargs['FindingPublishingFrequency'] = FINDING_FREQUENCY[args['findingFrequency']]
    get_dataSources = {}
    if args.get('enableKubernetesLogs'):
        get_dataSources.update(
            {'Kubernetes': {'AuditLogs': {'Enable': argToBoolean(args['enableKubernetesLogs'])}}})
    if args.get('ebsVolumesMalwareProtection'):
        get_dataSources.update({'MalwareProtection': {
            'ScanEc2InstanceWithFindings': {'EbsVolumes': argToBoolean(args['ebsVolumesMalwareProtection'])}}})
    if args.get('enableS3Logs'):
        get_dataSources.update({'S3Logs': {'Enable': argToBoolean(args['enableS3Logs'])}})
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


def delete_detector(client: "GuardDutyClient", args: dict):
    response = client.delete_detector(DetectorId=args.get('detectorId', ''))
    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The Detector {args.get('detectorId')} has been deleted"
    else:
        raise Exception(f"The Detector {args.get('detectorId')} failed to delete.")


def get_detector(client: "GuardDutyClient", args: dict) -> CommandResults:
    """
    Retrieves an Amazon GuardDuty detector specified by the detectorId.
    """
    response = client.get_detector(DetectorId=args.get('detectorId', ''))
    data = ({
        'DetectorId': args.get('detectorId'),
        'CreatedAt': response.get('CreatedAt'),
        'ServiceRole': response.get('ServiceRole'),
        'Status': response.get('Status'),
        'UpdatedAt': response.get('UpdatedAt'),
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
    readable_output = tableToMarkdown('AWS GuardDuty Detectors', data,
                                      removeNull=True) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors',
                          outputs_key_field='DetectorId')


def update_detector(client: "GuardDutyClient", args: dict) -> str:
    """
    Updates the Amazon GuardDuty detector specified by the detectorId.
    """
    kwargs = {'Enable': argToBoolean(args.get('enable', False)), 'DetectorId': args.get('detectorId')}

    if args.get('findingFrequency'):
        kwargs['FindingPublishingFrequency'] = FINDING_FREQUENCY[args['findingFrequency']]
    get_dataSources = {}
    if args.get('enableKubernetesLogs'):
        get_dataSources.update(
            {'Kubernetes': {'AuditLogs': {'Enable': argToBoolean(args['enableKubernetesLogs'])}}})
    if args.get('ebsVolumesMalwareProtection'):
        get_dataSources.update({'MalwareProtection': {
            'ScanEc2InstanceWithFindings': {'EbsVolumes': argToBoolean(args['ebsVolumesMalwareProtection'])}}})
    if args.get('enableS3Logs'):
        get_dataSources.update({'S3Logs': {'Enable': argToBoolean(args['enableS3Logs'])}})
    if get_dataSources:
        kwargs['DataSources'] = get_dataSources

    response = client.update_detector(**kwargs)
    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The Detector {args.get('detectorId')} has been updated successfully"
    else:
        raise Exception(f"Detector {args.get('detectorId')} failed to update. Response was: {response}")


def list_detectors(client: "GuardDutyClient", args: dict) -> CommandResults:
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


def create_ip_set(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {'DetectorId': args.get('detectorId')}
    if args.get('activate') is not None:
        kwargs.update({'Activate': args.get('activate') == 'True'})
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


def delete_ip_set(client: "GuardDutyClient", args: dict):
    response = client.delete_ip_set(
        DetectorId=args.get('detectorId', ''),
        IpSetId=args.get('ipSetId', '')
    )
    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The IPSet {args.get('ipSetId')} has been deleted from Detector {args.get('detectorId')}"

    else:
        raise Exception(f"Failed to delete ip set {args.get('ipSetId')} . Response was: {response}")


def update_ip_set(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {
        'DetectorId': args.get('detectorId'),
        'IpSetId': args.get('ipSetId')
    }
    if args.get('activate'):
        kwargs.update({'Activate': args.get('activate') == 'True'})
    if args.get('location'):
        kwargs.update({'Location': args.get('location')})
    if args.get('name'):
        kwargs.update({'Name': args.get('name')})

    response = client.update_ip_set(**kwargs)

    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The IPSet {args.get('ipSetId')} has been Updated"

    else:
        raise Exception(f"Failed updating ip set {args.get('ipSetId')} . Response was: {response}")


def get_ip_set(client: "GuardDutyClient", args: dict):
    response = client.get_ip_set(DetectorId=args.get('detectorId', ''),
                                 IpSetId=args.get('ipSetId', ''))
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


def list_ip_sets(client: "GuardDutyClient", args: dict) -> CommandResults:
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_ip_sets')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId', ''),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for ipSet in page_response['IpSetIds']:
                data.append({'IpSetId': ipSet})
            if page:
                break

    readable_output = tableToMarkdown('AWS GuardDuty IPSets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.IPSet',
                          outputs_key_field='IpSetId')


def create_threat_intel_set(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {'DetectorId': args.get('detectorId')}
    if args.get('activate') is not None:
        kwargs.update({'Activate': args.get('activate') == 'True'})
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


def delete_threat_intel_set(client: "GuardDutyClient", args: dict):
    response = client.delete_threat_intel_set(
        DetectorId=args.get('detectorId', ''),
        ThreatIntelSetId=args.get('threatIntelSetId', '')
    )
    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The ThreatIntel Set {args.get('threatIntelSetId')} has been deleted from Detector {args.get('detectorId')}"
    else:
        raise Exception(f"Failed to delete ThreatIntel set {args.get('threatIntelSetId')} . Response was: {response}")


def get_threat_intel_set(client: "GuardDutyClient", args: dict):
    response = client.get_threat_intel_set(
        DetectorId=args.get('detectorId', ''),
        ThreatIntelSetId=args.get('threatIntelSetId', '')
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


def list_threat_intel_sets(client: "GuardDutyClient", args: dict) -> CommandResults:
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_threat_intel_sets')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId', ''),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    data.append({'DetectorId': args.get('detectorId')})
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for threatIntelSet in page_response['ThreatIntelSetIds']:
                data.append({'ThreatIntelSetId': threatIntelSet})
            if page:
                break

    readable_output = tableToMarkdown('AWS GuardDuty ThreatIntel Sets', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Detectors.ThreatIntelSet',
                          outputs_key_field='ThreatIntelSetId')


def update_threat_intel_set(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {
        'DetectorId': args.get('detectorId'),
        'ThreatIntelSetId': args.get('threatIntelSetId')
    }
    if args.get('activate'):
        kwargs.update({'Activate': args.get('activate') == 'True'})
    if args.get('location'):
        kwargs.update({'Location': args.get('location')})
    if args.get('name'):
        kwargs.update({'Name': args.get('name')})
    response = client.update_threat_intel_set(**kwargs)

    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return f"The ThreatIntel set {args.get('threatIntelSetId')} has been updated"
    else:
        raise Exception(f"Failed updating ThreatIntel set {args.get('threatIntelSetId')}. "
                        f"Response was: {response}")


def severity_mapping(severity: Optional[float]) -> Optional[int]:
    demisto_severity = None
    if severity:
        if severity <= 3.9:
            demisto_severity = 1
        elif 4 <= severity <= 6.9:
            demisto_severity = 2
        elif 7 <= severity <= 8.9:
            demisto_severity = 3
        else:
            demisto_severity = 0
    return demisto_severity


def gd_severity_mapping(severity_list: List[str]):
    if 'Low' in severity_list:
        gd_severity = 1
    elif 'Medium' in severity_list:
        gd_severity = 4
    elif 'High' in severity_list:
        gd_severity = 7
    else:
        gd_severity = 1

    return gd_severity


def list_findings(client: "GuardDutyClient", args: dict) -> CommandResults:
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_findings')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId', ''),
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


def get_pagination_args(args: dict) -> tuple[int, int, Optional[int]]:
    """
    Gets and validates pagination arguments.
    :param args: The command arguments (page, page_size or limit)
    :return: limit, page_size, page after validation and convert
    """

    # Automatic Pagination
    limit = arg_to_number(args.get('limit')) or MAX_RESULTS_RESPONSE

    # Manual Pagination
    page = arg_to_number(args.get('page'))
    if page is not None and page <= 0:
        raise DemistoException('page argument must be greater than 0')

    page_size = arg_to_number(args.get('page_size')) or MAX_RESULTS_RESPONSE
    if not 0 < page_size <= MAX_RESULTS_RESPONSE:
        raise DemistoException(f'page_size argument must be between 1 to {MAX_RESULTS_RESPONSE}')

    if page:
        limit = page * page_size

    return limit, page_size, page


def parse_finding(finding: "FindingTypeDef") -> Dict[str, Any]:
    """
    Parse the finding data to output, context format
    :param finding: Contains information about the finding,
    which is generated when abnormal or suspicious activity is detected.
    :return: parsed_finding
    """
    parsed_finding: dict = {}
    parsed_finding['AccountId'] = finding.get('AccountId')
    parsed_finding['CreatedAt'] = finding.get('CreatedAt')
    parsed_finding['Description'] = finding.get('Description')
    parsed_finding['Region'] = finding.get('Region')
    parsed_finding['Id'] = finding.get('Id')
    parsed_finding['Title'] = finding.get('Title')
    parsed_finding['Type'] = finding.get('Type')
    parsed_finding['Severity'] = severity_mapping(finding.get('Severity'))
    parsed_finding['UpdatedAt'] = finding.get('UpdatedAt')

    parsed_finding['Arn'] = finding.get('Arn')
    parsed_finding['Confidence'] = finding.get('Confidence')
    parsed_finding['Partition'] = finding.get('Partition')
    parsed_finding['SchemaVersion'] = finding.get('SchemaVersion')
    parsed_finding['Service'] = json.dumps(finding.get('Service'), cls=DatetimeEncoder)
    parsed_finding['ResourceType'] = demisto.get(finding, 'Resource.ResourceType')

    get_resource = finding.get('Resource')
    if get_resource:
        parsed_finding['Resource'] = {k: json.dumps(v, cls=DatetimeEncoder) for k, v in get_resource.items()
                                      if k != 'ResourceType'}
    return parsed_finding


def get_findings(client: "GuardDutyClient", args: dict) -> dict:
    return_raw_response = argToBoolean(args.get('returnRawResponse', 'false'))

    response = client.get_findings(
        DetectorId=args.get('detectorId', ''),
        FindingIds=argToList(args.get('findingIds')))

    data = []
    for finding in response['Findings']:
        data.append(parse_finding(finding))

    output = json.dumps(response['Findings'], cls=DatetimeEncoder)
    raw = json.loads(output)

    headers = ['Id', 'Title', 'Description', 'Type', 'ResourceType', 'CreatedAt', 'AccountId', 'Arn']
    readable_output = tableToMarkdown('AWS GuardDuty Findings', data, removeNull=True, headers=headers) \
        if data else 'No result were found'

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': raw if raw else data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable_output,
        'EntryContext': {"AWS.GuardDuty.Findings(val.FindingId === obj.Id)": raw if return_raw_response else data}
    }


def parse_incident_from_finding(finding: "FindingTypeDef") -> Dict[str, Any]:
    incident: dict = {}
    incident['name'] = finding.get('Title')
    incident['details'] = finding.get('Description')
    incident['occurred'] = finding.get('CreatedAt')
    incident['severity'] = severity_mapping(finding.get('Severity'))
    incident['rawJSON'] = json.dumps(finding, default=str)
    return incident


def time_to_unix_epoch(date_time: datetime) -> int:
    """
    :param date_time: The time and date in '%Y-%m-%dT%H:%M:%S.%fZ' format
    :return: Timestamp in Unix Epoch millisecond format
    example: date_time = dateparser.parse('2017-02-10 00:09:35.000000+00:00') to 1486685375000
    """
    return int(date_time.timestamp() * 1000)


def fetch_incidents(client: "GuardDutyClient", aws_gd_severity: List[str], last_run: dict, fetch_limit: int,
                    first_fetch_time: str, is_archive: bool) -> tuple[Dict[str, Any], List[dict]]:
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): "GuardDutyClient" client
        aws_gd_severity (List[str]): Guard Duty Severity level
        last_run (dict): {'latest_created_time' (string): The greatest incident created_time we fetched from last fetch,
                          'latest_updated_time' (string): The greatest incident updated_time we fetched from last fetch,
                          'last_incidents_ids' (list): The last incidents ids of the latest_created_time,
                          'last_next_token' (string): The value of NextToken from the previous response to continue listing data.}
        fetch_limit (int): Maximum numbers of incidents per fetch
        first_fetch_time (str): If last_fetch is None then fetch all incidents since first_fetch_time
        is_archive (bool): Archive findings After Fetch
    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """

    # Get the latest_created_time, latest_updated_time, last_incidents_ids, and last_next_token if exist
    latest_created_time = last_run.get('latest_created_time')
    last_incidents_ids = last_run.get('last_incidents_ids', [])
    last_next_token = last_run.get('last_next_token', "")
    if latest_updated_time := last_run.get('latest_updated_time', ""):
        latest_updated_time = dateparser.parse(latest_updated_time)

    # Handle first time fetch
    if latest_created_time is None:
        latest_created_time = dateparser.parse(dateparser.parse(
            first_fetch_time).strftime(DATE_FORMAT))  # type: ignore[union-attr]
    else:
        latest_created_time = dateparser.parse(latest_created_time)

    response = client.list_detectors()
    detector = response['DetectorIds']

    created_time_to_ids = defaultdict(list)
    created_time_to_ids[latest_created_time] = last_incidents_ids

    # Represents the criteria to be used in the filter for querying findings.
    criterion_conditions: Dict[str, ConditionTypeDef] = {}
    criterion_conditions['severity'] = {'Gte': gd_severity_mapping(aws_gd_severity)}
    if is_archive:
        demisto.debug('Fetching Amazon GuardDuty with Archive')
        criterion_conditions['service.archived'] = {'Eq': ['false']}
    if not last_next_token and latest_updated_time:
        criterion_conditions['updatedAt'] = {'Gte': time_to_unix_epoch(latest_updated_time)}
    if last_incidents_ids:
        criterion_conditions['id'] = {'Neq': last_incidents_ids[:]}

    demisto.info(f'Fetching Amazon GuardDuty findings for the {detector[0]} since: {str(latest_created_time)}')

    incidents: list[dict] = []
    while True:
        left_to_fetch = fetch_limit - len(incidents)
        max_results = min(MAX_RESULTS_RESPONSE, left_to_fetch)

        list_findings_res = client.list_findings(
            DetectorId=detector[0],
            FindingCriteria={'Criterion': criterion_conditions},
            SortCriteria={'AttributeName': 'createdAt', 'OrderBy': 'ASC'},
            MaxResults=max_results,
            NextToken=last_next_token
        )
        last_next_token = list_findings_res.get("NextToken", "")
        finding_ids = list_findings_res.get('FindingIds', [])
        get_findings_res = client.get_findings(DetectorId=detector[0], FindingIds=finding_ids,
                                               SortCriteria={'AttributeName': 'createdAt', 'OrderBy': 'ASC'})

        for finding in get_findings_res['Findings']:
            incident_created_time = dateparser.parse(finding.get('CreatedAt', ""))
            incident_updated_time = dateparser.parse(finding.get('UpdatedAt', ""))
            incident_id = finding.get("Id")

            # Update the latest_updated_time
            if not latest_updated_time or (incident_updated_time and incident_updated_time > latest_updated_time):
                latest_updated_time = incident_updated_time

            # Update last run (latest_created_time) and add incident if the incident is newer than last fetch
            if (incident_created_time and latest_created_time) and incident_created_time >= latest_created_time:
                demisto.debug(f'Added Incident with ID {incident_id}, occured: {str(incident_created_time)}, '
                              f'updated: {str(incident_updated_time)}')

                latest_created_time = incident_created_time
                created_time_to_ids[latest_created_time].append(incident_id)

                incident = parse_incident_from_finding(finding)
                incidents.append(incident)

        if incidents and is_archive:
            # Archive findings
            demisto.debug(f'Archived {len(finding_ids)} findings.')
            client.archive_findings(DetectorId=detector[0], FindingIds=finding_ids)

        # if there is no next_token, or we have reached the fetch_limit -> break
        if not last_next_token or fetch_limit - len(incidents) == 0:
            demisto.debug('fetch_limit has been reached or there is no next token')
            break

    next_run = {'latest_created_time': latest_created_time.strftime(DATE_FORMAT) if latest_created_time else None,
                'latest_updated_time': latest_updated_time.strftime(DATE_FORMAT) if latest_updated_time else None,
                'last_incidents_ids': created_time_to_ids[latest_created_time],
                'last_next_token': last_next_token}

    demisto.debug(f'{next_run=}')
    demisto.debug(f'fetched {len(incidents)} incidents')
    return next_run, incidents


def create_sample_findings(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {'DetectorId': args.get('detectorId')}
    if args.get('findingTypes') is not None:
        kwargs.update({'FindingTypes': argToList(args.get('findingTypes'))})

    response = client.create_sample_findings(**kwargs)

    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Sample Findings were generated"
    else:
        raise Exception(f"Failed to generate findings. Response was: {response}")


def archive_findings(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})

    response = client.archive_findings(**kwargs)

    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings were archived"
    else:
        raise Exception(f"Failed to archive findings. Response was: {response}")


def unarchive_findings(client: "GuardDutyClient", args: dict):
    kwargs: dict = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})

    response = client.unarchive_findings(**kwargs)

    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings were unarchived"
    else:
        raise Exception(f"Failed to archive findings. Response was: {response}")


def update_findings_feedback(client: "GuardDutyClient", args: dict):
    kwargs: dict[str, Any] = {'DetectorId': args.get('detectorId')}
    if args.get('findingIds') is not None:
        kwargs.update({'FindingIds': argToList(args.get('findingIds'))})
    if args.get('comments') is not None:
        kwargs.update({'Comments': argToList(args.get('comments'))})
    if args.get('feedback') is not None:
        kwargs.update({'Feedback': argToList(args.get('feedback'))})

    response = client.update_findings_feedback(**kwargs)
    if response == {} or response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
        return "Findings Feedback sent!"
    else:
        raise Exception(f"Failed to send findings feedback. Response was: {response}")


def list_members(client: "GuardDutyClient", args: dict) -> CommandResults:
    limit, page_size, page = get_pagination_args(args)

    paginator = client.get_paginator('list_members')
    response_iterator = paginator.paginate(
        DetectorId=args.get('detectorId', ''),
        PaginationConfig={
            'MaxItems': limit,
            'PageSize': page_size,
        }
    )

    data = []
    for i, page_response in enumerate(response_iterator):
        if page is None or (page - 1) == i:
            for member in page_response['Members']:
                data.append({'Member': member})
            if page:
                break

    readable_output = tableToMarkdown('AWS GuardDuty Members', data) if data else 'No result were found'
    return CommandResults(readable_output=readable_output,
                          outputs=data,
                          outputs_prefix='AWS.GuardDuty.Members',
                          outputs_key_field='AccountId')


def get_members(client: "GuardDutyClient", args: dict):
    accountId_list = []
    accountId_list.append(args.get('accountIds', ''))

    response = client.get_members(
        DetectorId=args.get('detectorId', ''),
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


def connection_test(client: "GuardDutyClient"):
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
    aws_access_key_id = params.get('credentials', {}).get('identifier') or params.get('access_key')
    aws_secret_access_key = params.get('credentials', {}).get('password') or params.get('secret_key')
    aws_gd_severity = params.get('gs_severity', [])
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5
    first_fetch_time = params.get('first_fetch_time', '10 minutes').strip()
    fetch_limit = arg_to_number(params.get('fetch_limit', 10))
    is_archive = argToBoolean(params.get('is_archive', False))
    sts_endpoint_url = params.get('sts_endpoint_url') or None
    endpoint_url = params.get('endpoint_url') or None

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate,
                               timeout, retries, sts_endpoint_url=sts_endpoint_url, endpoint_url=endpoint_url)
        args = demisto.args()

        client: GuardDutyClient = aws_client.aws_session(service=SERVICE, region=args.get('region'),
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
            next_run, incidents = fetch_incidents(client=client, aws_gd_severity=aws_gd_severity,
                                                  last_run=demisto.getLastRun(),
                                                  fetch_limit=fetch_limit,  # type: ignore[arg-type]
                                                  first_fetch_time=first_fetch_time, is_archive=is_archive)
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
