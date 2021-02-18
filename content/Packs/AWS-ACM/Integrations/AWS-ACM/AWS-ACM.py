import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

'''IMPORTS'''
import re
import boto3
import json
from datetime import datetime, date
from botocore.config import Config
from botocore.parsers import ResponseParserError
import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()

'''GLOBAL VARIABLES'''
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


def aws_session(service='acm', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
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


def parse_tag_field(tags_str):
    tags = []
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.*-]+)", flags=re.I)
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
    regex = re.compile(r"subnetid=([\w\d_:.-]+),allocationid=([ /\w\d@_,.*-]+)", flags=re.I)
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
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)


def parse_resource_ids(resource_id):
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


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
        'CertificateArn': cert.get('CertificateArn'),
        'DomainName': cert.get('DomainName'),
        'Subject': cert.get('Subject'),
        'Issuer': cert.get('Issuer'),
        'Status': cert.get('Status'),
        'KeyAlgorithm': cert.get('KeyAlgorithm'),
        'SignatureAlgorithm': cert.get('SignatureAlgorithm'),
        'Type': cert.get('Type'),
        'Region': obj['_user_provided_options']['region_name'],
    })

    if 'Serial' in cert:
        data.update({'Serial': cert['Serial']})

    try:
        raw = json.loads(json.dumps(response['Certificate'], cls=DatetimeEncoder))
    except ValueError as e:
        return_error('Could not decode/encode the raw response - {err_msg}'.format(err_msg=e))

    if raw:
        raw.update({'Region': obj['_user_provided_options']['region_name']})
    ec = {'AWS.ACM.Certificates(val.CertificateArn === obj.CertificateArn)': raw}
    human_readable = tableToMarkdown('AWS ACM Certificates', data)
    return_outputs(human_readable, ec)


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
    human_readable = tableToMarkdown('AWS ACM Certificates', data)
    return_outputs(human_readable, ec)


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
    human_readable = tableToMarkdown('AWS ACM Certificate Tags', data)
    return_outputs(human_readable, ec)


def get_certificate(args):
    client = aws_session(
        region=args.get('region'),
        roleArn=args.get('roleArn'),
        roleSessionName=args.get('roleSessionName'),
        roleSessionDuration=args.get('roleSessionDuration'),
    )

    kwargs = {'CertificateArn': args.get('certificateArn')}
    response = client.get_certificate(**kwargs)

    if 'Certificate' in response:
        fileResult('Certificate.pem', response['Certificate'])
    if 'CertificateChain' in response:
        fileResult('CertificateChain.pem', response['CertificateChain'])

    demisto.results('### Certificate files for ARN: {arn}'.format(arn=args.get('certificateArn')))


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
except ResponseParserError as e:
    return_error('Could not connect to the AWS endpoint. Please check that the region is valid.\n {error}'.format(
        error=type(e)))
    LOG(str(e))

except Exception as e:
    LOG(str(e))
    return_error('Error has occurred in the AWS ACM Integration: {code}\n {message}'.format(
        code=type(e), message=str(e)))
