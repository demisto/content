import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import boto3
import datetime


'''GLOBAL VARIABLES'''
AWS_DEFAULT_REGION = demisto.params()['defaultRegion']
AWS_roleArn = demisto.params()['roleArn']
AWS_roleSessionName = demisto.params()['roleSessionName']
AWS_roleSessionDuration = demisto.params()['sessionDuration']
AWS_rolePolicy = None


def aws_session(service='acm', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None):
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
        sts_client = boto3.client('sts')
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


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r'key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)', flags=re.I)
    for f in tags_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse field: %s' % (f,))
            continue

        tags.append({
            'Key': match.group(1),
            'Value': match.group(2)
        })
    return tags


def parse_subnet_mappings(subnets_str):
    subnets = []
    regex = re.compile(r'subnetid=([\w\d_:.-]+),allocationid=([ /\w\d@_,.*-]+)', flags=re.I)
    for f in subnets_str.split(';'):
        match = regex.match(f)
        if match is None:
            demisto.log('could not parse field: %s' % (f,))
            continue

        subnets.append({
            'SubnetId': match.group(1),
            'AllocationId': match.group(2)
        })
    return subnets


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, datetime.date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def create_entry(title, data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(title, data) if data else 'No result were found',
        'EntryContext': ec
    }


'''MAIN FUNCTIONS'''
def describe_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)

    response = client.describe_certificate(CertificateArn=args.get('certificateArn'))
    cert = response['Certificate']
    data = ({
        'CertificateArn': cert['CertificateArn'],
        'DomainName': cert['DomainName'],
        'Serial': cert['Serial'],
        'Subject': cert['Subject'],
        'Issuer': cert['Issuer'],
        'Status': cert['Status'],
        'KeyAlgorithm': cert['KeyAlgorithm'],
        'SignatureAlgorithm': cert['SignatureAlgorithm'],
        'Type': cert['Type'],
        'Region': obj['_user_provided_options']['region_name'],
    })

    raw = json.loads(json.dumps(response['Certificate'], cls=DatetimeEncoder))
    if raw:
        raw.update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.ACM.Certificates(val.CertificateArn === obj.CertificateArn)': raw}
    demisto.results(create_entry('AWS ACM Certificates', data, ec))


def list_certificates(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    obj = vars(client._client_config)
    kwargs = {}
    data = []
    includes = {}

    if args.get('certificateStatuses') is not None:
        kwargs.update({'CertificateStatuses': args.get('certificateStatuses')})
    if args.get('extendedKeyUsage') is not None:
        includes.update({'extendedKeyUsage': [args.get('extendedKeyUsage')]})
    if args.get('keyUsage') is not None:
        includes.update({'keyUsage': [args.get('keyUsage')]})
    if args.get('keyTypes') is not None:
        includes.update({'keyTypes': [args.get('keyTypes')]})
    if includes:
        kwargs.update({'Includes': includes})

    response = client.list_certificates(**kwargs)
    for cert in response['CertificateSummaryList']:
        data.append({
            'CertificateArn': cert['CertificateArn'],
            'DomainName': cert['DomainName'],
            'Region': obj['_user_provided_options']['region_name'],
        })

    ec = {'AWS.ACM.Certificates(val.CertificateArn === obj.CertificateArn)': data}
    demisto.results(create_entry('AWS ACM Certificates', data, ec))


def add_tags_to_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'CertificateArn': args.get('certificateArn'),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.add_tags_to_certificate(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Certificate was Tagged successfully")


def remove_tags_from_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'CertificateArn': args.get('certificateArn'),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.remove_tags_from_certificate(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Certificate Tags were removed successfully")


def list_tags_for_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'CertificateArn': args.get('certificateArn')}
    response = client.list_tags_for_certificate(**kwargs)

    data = ({'CertificateArn': args.get('certificateArn')})
    for tag in response['Tags']:
        data.update({
            tag['Key']: tag['Value']
        })

    ec = {'AWS.ACM.Certificates(val.CertificateArn === obj.CertificateArn).Tags': data}
    demisto.results(create_entry('AWS ACM Certificate Tags', data, ec))


def get_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'CertificateArn': args.get('certificateArn')}
    response = client.get_certificate(**kwargs)

    data = ({
        'CertificateArn': args.get('certificateArn'),
        'Certificate': response['Certificate'],
        'CertificateChain': response['CertificateChain']
    })

    ec = {'AWS.ACM.Certificates(val.CertificateArn === obj.CertificateArn)': data}
    demisto.results(create_entry('AWS ACM Certificate', data, ec))


def test_function():
    client = aws_session()
    response = client.list_certificates()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


'''EXECUTION BLOCK'''
try:
    if demisto.command() == 'test-module':
        test_function()
    if demisto.command() == 'aws-acm-describe-certificate':
        describe_certificate(demisto.args())
    if demisto.command() == 'aws-acm-list-certificates':
        list_certificates(demisto.args())
    if demisto.command() == 'aws-acm-add-tags-to-certificate':
        add_tags_to_certificate(demisto.args())
    if demisto.command() == 'aws-acm-remove-tags-from-certificate':
        remove_tags_from_certificate(demisto.args())
    if demisto.command() == 'aws-acm-list-tags-for-certificate':
        list_tags_for_certificate(demisto.args())
    if demisto.command() == 'aws-acm-get-certificate':
        get_certificate(demisto.args())
except Exception as e:
    LOG(e)
    LOG.print_log(False)
    return_error(e.message)
