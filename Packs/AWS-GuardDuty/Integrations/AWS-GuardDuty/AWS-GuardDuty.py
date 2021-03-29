import boto3
from botocore.config import Config
from botocore.parsers import ResponseParserError
from datetime import datetime, date


import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_ROLE_ARN = demisto.params()['roleArn']
AWS_ROLE_SESSION_NAME = demisto.params()['roleSessionName']
AWS_ROLE_SESSION_DURATION = demisto.params()['sessionDuration']
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
AWS_GD_SEVERITY = demisto.params()['gs_severity']


def aws_session(service='guardduty', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
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
    if kwargs and not AWS_ACCESS_KEY_ID:

        if not AWS_ACCESS_KEY_ID:
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


def parse_finding_ids(finding_ids):
    id_list = finding_ids.replace(" ", "")
    findingsids = id_list.split(",")
    return findingsids


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def create_detector(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty Detectors', data)
    return_outputs(human_readable, ec)


def delete_detector(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    response = client.delete_detector(DetectorId=args.get('detectorId'))
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return_results('The Detector {0} has been deleted'.format(args.get('detectorId')))


def get_detector(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty Detectors', data)
    return_outputs(human_readable, ec)


def update_detector(args):
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
        return_results('The Detector {0} has been Updated'.format(args.get('detectorId')))
    else:
        return_results("Failed to update detector with ID {}".format(args.get('detectorId')))


def list_detectors(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty Detectors', data)
    return_outputs(human_readable, ec)


def create_ip_set(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty IPSets', data)
    return_outputs(human_readable, ec)


def delete_ip_set(args):
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
        return_results('The IPSet {0} has been deleted from Detector {1}'.format(args.get('ipSetId'), args.get('detectorId')))


def update_ip_set(args):
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
        return_results('The IPSet {0} has been Updated'.format(args.get('ipSetId')))


def get_ip_set(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty IPSets', data)
    return_outputs(human_readable, ec)


def list_ip_sets(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty IPSets', data)
    return_outputs(human_readable, ec)


def create_threat_intel_set(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty ThreatIntel Set', data)
    return_outputs(human_readable, ec)


def delete_threat_intel_set(args):
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
        return_results('The ThreatIntel Set {0} has been deleted from Detector {1}'.format(args.get('ipSetId'),
                       args.get('detectorId')))


def get_threat_intel_set(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty ThreatIntel Set', data)
    return_outputs(human_readable, ec)


def list_threat_intel_sets(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty IPSets', data)
    return_outputs(human_readable, ec)


def update_threat_intel_set(args):
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
        return_results('The ThreatIntel Set {0} has been Updated'.format(args.get('threatIntelSetId')))


def severity_mapping(severity):
    if severity <= 3.9:
        demisto_severity = 1
    elif severity >= 4 and severity <= 6.9:
        demisto_severity = 2
    elif severity >= 7 and severity <= 8.9:
        demisto_severity = 3
    else:
        demisto_severity = 0

    return demisto_severity


def gd_severity_mapping(severity):
    if severity == 'Low':
        gd_severity = 1
    elif severity == 'Medium':
        gd_severity = 4
    elif severity == 'High':
        gd_severity = 7
    else:
        gd_severity = 1

    return gd_severity


def list_findings(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty Findings', data)
    return_outputs(human_readable, ec)


def get_findings(args):
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
    human_readable = tableToMarkdown('AWS GuardDuty Findings', data)
    return_outputs(human_readable, ec)


def parse_incident_from_finding(finding):
    incident = {}
    incident['name'] = finding['Title']
    incident['details'] = finding['Description']
    incident['occurred'] = finding['CreatedAt']
    incident['severity'] = severity_mapping(finding['Severity'])
    incident['rawJSON'] = json.dumps(finding, cls=DatetimeEncoder)
    return incident


def fetch_incidents():
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


def create_sample_findings(args):
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
        return_results('Sample Findings were generated')


def archive_findings(args):
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
        return_results('Findings were archived')


def unarchive_findings(args):
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
        return_results('Findings were Unarchived')


def update_findings_feedback(args):
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
        return_results('Findings Feedback sent!')


def test_function():
    client = aws_session()
    response = client.list_detectors()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return_results('ok')
    else:
        return_error("Test failed. Please verify your configuration.")


def main():
    try:
        LOG('Command being called is {command}'.format(command=demisto.command()))
        # The command demisto.command() holds the command sent from the user.
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_function()

        if demisto.command() == 'aws-gd-create-detector':
            create_detector(demisto.args())

        if demisto.command() == 'aws-gd-delete-detector':
            delete_detector(demisto.args())

        if demisto.command() == 'aws-gd-get-detector':
            get_detector(demisto.args())

        if demisto.command() == 'aws-gd-update-detector':
            update_detector(demisto.args())

        if demisto.command() == 'aws-gd-create-ip-set':
            create_ip_set(demisto.args())

        if demisto.command() == 'aws-gd-delete-ip-set':
            delete_ip_set(demisto.args())

        if demisto.command() == 'aws-gd-list-detectors':
            list_detectors(demisto.args())

        if demisto.command() == 'aws-gd-update-ip-set':
            update_ip_set(demisto.args())

        if demisto.command() == 'aws-gd-get-ip-set':
            get_ip_set(demisto.args())

        if demisto.command() == 'aws-gd-list-ip-sets':
            list_ip_sets(demisto.args())

        if demisto.command() == 'aws-gd-create-threatintel-set':
            create_threat_intel_set(demisto.args())

        if demisto.command() == 'aws-gd-delete-threatintel-set':
            delete_threat_intel_set(demisto.args())

        if demisto.command() == 'aws-gd-get-threatintel-set':
            get_threat_intel_set(demisto.args())

        if demisto.command() == 'aws-gd-list-threatintel-sets':
            list_threat_intel_sets(demisto.args())

        if demisto.command() == 'aws-gd-update-threatintel-set':
            update_threat_intel_set(demisto.args())

        if demisto.command() == 'aws-gd-list-findings':
            list_findings(demisto.args())

        if demisto.command() == 'aws-gd-get-findings':
            get_findings(demisto.args())

        if demisto.command() == 'aws-gd-create-sample-findings':
            create_sample_findings(demisto.args())

        if demisto.command() == 'aws-gd-archive-findings':
            archive_findings(demisto.args())

        if demisto.command() == 'aws-gd-unarchive-findings':
            unarchive_findings(demisto.args())

        if demisto.command() == 'aws-gd-update-findings-feedback':
            update_findings_feedback(demisto.args())

        if demisto.command() == 'fetch-incidents':
            fetch_incidents()

    except ResponseParserError as e:
        return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
            error=e))
        LOG(e.message)

    except Exception as e:
        LOG(e)
        return_error('Error has occurred in the AWS GuardDuty Integration: {code}\n {message}'.format(
                     code=type(e), message=e))


# python2 uses __builtin__ python3 uses builtins
if __name__ in ("__builtin__", "builtins"):
    main()
