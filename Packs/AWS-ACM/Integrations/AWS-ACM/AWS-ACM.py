import boto3
import demistomock as demisto  # noqa: F401
from botocore.config import Config
from CommonServerPython import *  # noqa: F401

'''IMPORTS'''
import json
import re
from datetime import date, datetime

import urllib3.util

# Disable insecure warnings
urllib3.disable_warnings()
# contrib comment
# second comment


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


def describe_certificate(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def list_certificates(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def add_tags_to_certificate(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'CertificateArn': args.get('certificateArn'),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.add_tags_to_certificate(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Certificate was Tagged successfully")


def remove_tags_from_certificate(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )
    kwargs = {
        'CertificateArn': args.get('certificateArn'),
        'Tags': parse_tag_field(args.get('tags'))
    }
    response = client.remove_tags_from_certificate(**kwargs)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results("The Certificate Tags were removed successfully")


def list_tags_for_certificate(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
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


def get_certificate(args, aws_client):
    client = aws_client.aws_session(
        service='acm',
        region=args.get('region'),
        role_arn=args.get('roleArn'),
        role_session_name=args.get('roleSessionName'),
        role_session_duration=args.get('roleSessionDuration'),
    )

    kwargs = {'CertificateArn': args.get('certificateArn')}
    response = client.get_certificate(**kwargs)

    if 'Certificate' in response:
        fileResult('Certificate.pem', response['Certificate'])
    if 'CertificateChain' in response:
        fileResult('CertificateChain.pem', response['CertificateChain'])

    demisto.results('### Certificate files for ARN: {arn}'.format(arn=args.get('certificateArn')))


def test_function(aws_client):
    client = aws_client.aws_session(service='acm')
    response = client.list_certificates()
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        demisto.results('ok')


def main():
    try:
        params = demisto.params()
        aws_default_region = params.get('defaultRegion')
        aws_role_arn = params.get('roleArn')
        aws_role_session_name = params.get('roleSessionName')
        aws_role_session_duration = params.get('sessionDuration')
        aws_role_policy = None
        aws_access_key_id = params.get('access_key')
        aws_secret_access_key = params.get('secret_key')
        verify_certificate = not params.get('insecure', True)
        timeout = demisto.params().get('timeout')
        retries = demisto.params().get('retries') or 5

        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                               aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout,
                               retries)
        args = demisto.args()
        command = demisto.command()

        if command == 'test-module':
            test_function(aws_client)
        if command == 'aws-acm-describe-certificate':
            describe_certificate(args, aws_client)
        if command == 'aws-acm-list-certificates':
            list_certificates(args, aws_client)
        if command == 'aws-acm-add-tags-to-certificate':
            add_tags_to_certificate(args, aws_client)
        if command == 'aws-acm-remove-tags-from-certificate':
            remove_tags_from_certificate(args, aws_client)
        if command == 'aws-acm-list-tags-for-certificate':
            list_tags_for_certificate(args, aws_client)
        if command == 'aws-acm-get-certificate':
            get_certificate(args, aws_client)

    except Exception as e:
        LOG(str(e))
        return_error('Error has occurred in the AWS ACM Integration: {code}\n {message}'.format(
            code=type(e), message=str(e)))


### GENERATED CODE ###
# This code was inserted in place of an API module.


def validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key):
    """
    Validates that the provided parameters are compatible with the appropriate authentication method.
    """
    if not aws_default_region:
        raise DemistoException('You must specify AWS default region.')

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException('You must provide Access Key id and Secret key id to configure the instance with '
                               'credentials.')
    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException('Role session name is required when using role ARN.')


class AWSClient:

    def __init__(self, aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                 aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries):
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        self.aws_role_session_duration = aws_role_session_duration
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.verify_certificate = verify_certificate

        proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=dict(
                max_attempts=int(retries)
            ),
            proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg('retries')  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config['retries'] = dict(max_attempts=int(retries))
        timeout = demisto.getArg('timeout')
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config['read_timeout'] = read_timeout
            command_config['connect_timeout'] = connect_timeout
        if retries or timeout:
            demisto.debug('Merging client config settings: {}'.format(command_config))
            self.config = self.config.merge(Config(**command_config))

    def aws_session(self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None,
                    role_policy=None):
        kwargs = {}

        self.update_config()

        if role_arn and role_session_name is not None:
            kwargs.update({
                'RoleArn': role_arn,
                'RoleSessionName': role_session_name,
            })
        elif self.aws_role_arn and self.aws_role_session_name is not None:
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })

        if role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(role_session_duration)})
        elif self.aws_role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(self.aws_role_session_duration)})

        if role_policy is not None:
            kwargs.update({'Policy': role_policy})
        elif self.aws_role_policy is not None:
            kwargs.update({'Policy': self.aws_role_policy})

        if kwargs and not self.aws_access_key_id:  # login with Role ARN

            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=self.aws_default_region)
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=self.verify_certificate,
                    config=self.config
                )
        elif self.aws_access_key_id and self.aws_role_arn:  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name='sts',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
            kwargs.update({
                'RoleArn': self.aws_role_arn,
                'RoleSessionName': self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=self.config
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(service_name=service,
                                  region_name=region if region else self.aws_default_region)

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:
            timeout_vals = timeout.split(',')
            read_timeout = int(timeout_vals[0])
        except ValueError:
            raise DemistoException("You can specify just the read timeout (for example 60) or also the connect "
                                   "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                                   "specified, a default of 10 second will be used.")
        connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])
        return read_timeout, connect_timeout


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
