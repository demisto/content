import boto3
from datetime import datetime, date
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from botocore.config import Config

AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None
AWS_GD_SEVERITY = demisto.params()['gs_severity']
VERIFY_CERTIFICATE = not demisto.params().get('insecure', True)
proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
config = Config(
    connect_timeout=1,
    retries=dict(
        max_attempts=5
    ),
    proxies=proxies
)


def aws_session(service='guardduty', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None, rolePolicy=None):
    kwargs = {}
    if roleArn and roleSessionName is not None:
        kwargs.update({
            'RoleArn': roleArn,
            'RoleSessionName': roleSessionName,
        })
    elif AWS_roleArn and AWS_roleSessionName is not None:
        kwargs.update({
            'RoleArn': AWS_roleArn,
            'RoleSessionName': AWS_roleSessionName,
        })

    if roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(roleSessionDuration)})
    elif AWS_roleSessionDuration is not None:
        kwargs.update({'DurationSeconds': int(AWS_roleSessionDuration)})

    if rolePolicy is not None:
        kwargs.update({'Policy': rolePolicy})
    elif AWS_rolePolicy is not None:
        kwargs.update({'Policy': AWS_rolePolicy})

    if kwargs:
        sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE,
                                  region_name=AWS_DEFAULT_REGION)
        sts_response = sts_client.assume_role(**kwargs)
        if region is not None:
            client = boto3.client(
                service_name=service,
                region_name=region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
            )
        else:
            client = boto3.client(
                service_name=service,
                region_name=AWS_DEFAULT_REGION,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken']
            )
    else:
        if region is not None:
            client = boto3.client(service_name=service, region_name=region)
        else:
            client = boto3.client(service_name=service, region_name=AWS_DEFAULT_REGION)

    return client


def parse_finding_ids(finding_ids):
    id_list = finding_ids.replace(" ", "")
    findingsids = id_list.split(",")
    return findingsids


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):  # pylint: disable=E0202
        if isinstance(obj, datetime):  # type: ignore
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):  # type: ignore  # pylint: disable=E0602
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


def raise_error(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


def create_detector(args):
    try:
        client = aws_session(
            service='guardduty',
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'Enable': True if args.get('enable') == 'True' else False}
        response = client.create_detector(**kwargs)
        data = ({
            'DetectorId': response['DetectorId']
        })
        ec = {'AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId)': data}
        return create_entry('AWS GuardDuty Detectors', data, ec)

    except Exception as e:
        return raise_error(e)


def delete_detector(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.delete_detector(DetectorId=args.get('detectorId'))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Detector {0} has been deleted'.format(args.get('detectorId'))

    except Exception as e:
        return raise_error(e)


def get_detector(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        response = client.get_detector(DetectorId=args.get('detectorId'))
        data = ({
            'DetectorId': args.get('detectorId'),
            'CreatedAt': response['CreatedAt'],
            'ServiceRole': response['ServiceRole'],
            'Status': response['Status'],
            'UpdatedAt': response['UpdatedAt'],
        })
        ec = {'AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId)': data}
        return create_entry('AWS GuardDuty Detectors', data, ec)

    except Exception as e:
        return raise_error(e)


def update_detector(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.update_detector(
            DetectorId=args.get('detectorId'),
            Enable=True if args.get('enable') == 'True' else False
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The Detector {0} has been Updated'.format(args.get('detectorId'))

    except Exception as e:
        return raise_error(e)


def list_detectors(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.list_detectors()
        detector = response['DetectorIds']

        data = ({
            'DetectorId': detector[0]
        })
        ec = {'AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId)': data}
        return create_entry('AWS GuardDuty Detectors', data, ec)
    except Exception as e:
        return raise_error(e)


def create_ip_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

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
        ec = {"AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).IPSet(val.IpSetId === obj.IpSetId)": data}
        return create_entry('AWS GuardDuty IPSets', data, ec)

    except Exception as e:
        return e  # raise_error(e)


def delete_ip_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.delete_ip_set(
            DetectorId=args.get('detectorId'),
            IpSetId=args.get('ipSetId')
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The IPSet {0} has been deleted from Detector {1}'.format(args.get('ipSetId'), args.get('detectorId'))

    except Exception as e:
        return raise_error(e)


def update_ip_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
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

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The IPSet {0} has been Updated'.format(args.get('ipSetId'))

    except Exception as e:
        return raise_error(e)


def get_ip_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.get_ip_set(
            DetectorId=args.get('detectorId'),
            IpSetId=args.get('ipSetId')
        )
        data = ({
            'DetectorId': args.get('detectorId'),
            'IpSetId': args.get('ipSetId'),
            'Format': response['Format'],
            'Location': response['Location'],
            'Name': response['Name'],
            'Status': response['Status']
        })
        ec = {"AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).IPSet(val.IpSetId === obj.IpSetId)": data}
        return create_entry('AWS GuardDuty IPSets', data, ec)

    except Exception as e:
        return raise_error(e)


def list_ip_sets(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.list_ip_sets(DetectorId=args.get('detectorId'))
        data = []
        data.append({
            'DetectorId': args.get('detectorId')
        })
        for ipset in response['IpSetIds']:
            data.append({
                'IpSetId': ipset
            })
        ec = {"AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).IPSet(val.IpSetId === obj.IpSetId)": data}
        return create_entry('AWS GuardDuty IPSets', data, ec)

    except Exception as e:
        return raise_error(e)


def create_threat_intel_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
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
        ec = {
            "AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).ThreatIntelSet"
            "(val.ThreatIntelSetId === obj.ThreatIntelSetId)": data}
        return create_entry('AWS GuardDuty ThreatIntel Set', data, ec)

    except Exception as e:
        return raise_error(e)


def delete_threat_intel_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.delete_threat_intel_set(
            DetectorId=args.get('detectorId'),
            ThreatIntelSetId=args.get('threatIntelSetId')
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The ThreatIntel Set {0} has been deleted from Detector {1}'.format(args.get('ipSetId'),
                                                                                       args.get('detectorId'))

    except Exception as e:
        return raise_error(e)


def get_threat_intel_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
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
        ec = {
            "AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).ThreatIntelSet"
            "(val.ThreatIntelSetId === obj.ThreatIntelSetId)": data}
        return create_entry('AWS GuardDuty ThreatIntel Set', data, ec)

    except Exception as e:
        return raise_error(e)


def list_threat_intel_sets(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.list_threat_intel_sets(DetectorId=args.get('detectorId'))
        data = []
        data.append({
            'DetectorId': args.get('detectorId')
        })
        for threatintelset in response['ThreatIntelSetIds']:
            data.append({
                'ThreatIntelSetId': threatintelset
            })
        ec = {
            "AWS.GuardDuty.Detectors(val.DetectorId === obj.DetectorId).ThreatIntelSet"
            "(val.ThreatIntelSetId === obj.ThreatIntelSetId)": data}
        return create_entry('AWS GuardDuty IPSets', data, ec)

    except Exception as e:
        return raise_error(e)


def update_threat_intel_set(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
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
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'The ThreatIntel Set {0} has been Updated'.format(args.get('threatIntelSetId'))

    except Exception as e:
        return raise_error(e)


def severity_mapping(severity):
    if severity <= 3.9:
        demistoSevirity = 1
    elif severity >= 4 and severity <= 6.9:
        demistoSevirity = 2
    elif severity >= 7 and severity <= 8.9:
        demistoSevirity = 3
    else:
        demistoSevirity = 0

    return demistoSevirity


def gd_severity_mapping(severity):
    if severity == 'Low':
        gdSevirity = 1
    elif severity == 'Medium':
        gdSevirity = 4
    elif severity == 'High':
        gdSevirity = 7
    else:
        gdSevirity = 1

    return gdSevirity


def list_findings(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        paginator = client.get_paginator('list_findings')
        response_iterator = paginator.paginate(DetectorId=args.get('detectorId'))
        data = []
        for page in response_iterator:
            for finding in page['FindingIds']:
                data.append({'FindingId': finding})

        ec = {"AWS.GuardDuty.Findings": data}
        return create_entry('AWS GuardDuty Findings', data, ec)

    except Exception as e:
        return raise_error(e)


def get_findings(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        response = client.get_findings(
            DetectorId=args.get('detectorId'),
            FindingIds=parse_finding_ids(args.get('findingIds')))

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
        ec = {"AWS.GuardDuty.Findings(val.FindingId === obj.Id)": raw}
        return create_entry('AWS GuardDuty Findings', data, ec)

    except Exception as e:
        return raise_error(e)


def parse_incident_from_finding(finding):
    incident = {}
    incident['name'] = finding['Title']
    incident['details'] = finding['Description']
    incident['occurred'] = finding['CreatedAt']
    incident['severity'] = severity_mapping(finding['Severity'])
    incident['rawJSON'] = json.dumps(finding)
    return incident


def fetch_incidents():
    try:
        client = aws_session()
        incidents = []
        response = client.list_detectors()
        detector = response['DetectorIds']

        list_findings = client.list_findings(
            DetectorId=detector[0], FindingCriteria={
                'Criterion': {
                    'service.archived': {'Eq': ['false', 'false']},
                    'severity': {'Gt': gd_severity_mapping(AWS_GD_SEVERITY)}
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

    except Exception as e:
        return raise_error(e)


def create_sample_findings(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'DetectorId': args.get('detectorId')}
        if args.get('findingTypes') is not None:
            kwargs.update({'FindingTypes': parse_finding_ids(args.get('findingTypes'))})

        response = client.create_sample_findings(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'Sample Findings were generated'

    except Exception as e:
        return raise_error(e)


def archive_findings(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'DetectorId': args.get('detectorId')}
        if args.get('findingIds') is not None:
            kwargs.update({'FindingIds': parse_finding_ids(args.get('findingIds'))})

        response = client.archive_findings(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'Findings were archived'

    except Exception as e:
        return raise_error(e)


def unarchive_findings(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )
        kwargs = {'DetectorId': args.get('detectorId')}
        if args.get('findingIds') is not None:
            kwargs.update({'FindingIds': parse_finding_ids(args.get('findingIds'))})

        response = client.unarchive_findings(**kwargs)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'Findings were Unarchived'

    except Exception as e:
        return raise_error(e)


def update_findings_feedback(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        kwargs = {'DetectorId': args.get('detectorId')}
        if args.get('findingIds') is not None:
            kwargs.update({'FindingIds': parse_finding_ids(args.get('findingIds'))})
        if args.get('comments') is not None:
            kwargs.update({'Comments': parse_finding_ids(args.get('comments'))})
        if args.get('feedback') is not None:
            kwargs.update({'Feedback': parse_finding_ids(args.get('feedback'))})

        response = client.update_findings_feedback(**kwargs)
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'Findings Feedback sent!'

    except Exception as e:
        return raise_error(e)


def list_members(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        response = client.list_members(DetectorId=args.get('detectorId'))

        ec = {"AWS.GuardDuty.Members(val.AccountId === obj.AccountId)": response['Members']}
        return create_entry('AWS GuardDuty Members', response['Members'], ec)

    except Exception as e:
        return raise_error(e)


def get_members(args):
    try:
        client = aws_session(
            region=args.get('region'),
            roleArn=args.get('roleArn'),
            roleSessionName=args.get('roleSessionName'),
            roleSessionDuration=args.get('roleSessionDuration'),
        )

        accountId_list = []
        accountId_list.append(args.get('accountIds'))

        response = client.get_members(
            DetectorId=args.get('detectorId'),
            AccountIds=accountId_list
        )

        ec = {"AWS.GuardDuty.Members(val.AccountId === obj.AccountId)": response['Members']}
        return create_entry('AWS GuardDuty Members', response['Members'], ec)

    except Exception as e:
        return raise_error(e)


def test_function():
    try:
        client = aws_session()
        response = client.list_detectors()
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return 'ok'

    except Exception as e:
        return raise_error(e)


# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    result = test_function()

if demisto.command() == 'aws-gd-create-detector':
    result = create_detector(demisto.args())

if demisto.command() == 'aws-gd-delete-detector':
    result = delete_detector(demisto.args())

if demisto.command() == 'aws-gd-get-detector':
    result = get_detector(demisto.args())

if demisto.command() == 'aws-gd-update-detector':
    result = update_detector(demisto.args())

if demisto.command() == 'aws-gd-create-ip-set':
    result = create_ip_set(demisto.args())

if demisto.command() == 'aws-gd-delete-ip-set':
    result = delete_ip_set(demisto.args())

if demisto.command() == 'aws-gd-list-detectors':
    result = list_detectors(demisto.args())

if demisto.command() == 'aws-gd-update-ip-set':
    result = update_ip_set(demisto.args())

if demisto.command() == 'aws-gd-get-ip-set':
    result = get_ip_set(demisto.args())

if demisto.command() == 'aws-gd-list-ip-sets':
    result = list_ip_sets(demisto.args())

if demisto.command() == 'aws-gd-create-threatintel-set':
    result = create_threat_intel_set(demisto.args())

if demisto.command() == 'aws-gd-delete-threatintel-set':
    result = delete_threat_intel_set(demisto.args())

if demisto.command() == 'aws-gd-get-threatintel-set':
    result = get_threat_intel_set(demisto.args())

if demisto.command() == 'aws-gd-list-threatintel-sets':
    result = list_threat_intel_sets(demisto.args())

if demisto.command() == 'aws-gd-update-threatintel-set':
    result = update_threat_intel_set(demisto.args())

if demisto.command() == 'aws-gd-list-findings':
    result = list_findings(demisto.args())

if demisto.command() == 'aws-gd-get-findings':
    result = get_findings(demisto.args())

if demisto.command() == 'aws-gd-create-sample-findings':
    result = create_sample_findings(demisto.args())

if demisto.command() == 'aws-gd-archive-findings':
    result = archive_findings(demisto.args())

if demisto.command() == 'aws-gd-unarchive-findings':
    result = unarchive_findings(demisto.args())

if demisto.command() == 'aws-gd-update-findings-feedback':
    result = update_findings_feedback(demisto.args())

if demisto.command() == 'aws-gd-list-members':
    result = list_members(demisto.args())

if demisto.command() == 'aws-gd-get-members':
    result = get_members(demisto.args())

if demisto.command() == 'fetch-incidents':
    fetch_incidents()
    sys.exit(0)

demisto.results(result)
sys.exit(0)
