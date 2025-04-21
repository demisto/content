from CommonServerPython import *
from CommonServerUserPython import *
import boto3
from botocore.config import Config

STS_ENDPOINTS = {
    "us-gov-west-1": "https://sts.us-gov-west-1.amazonaws.com",
    "us-gov-east-1": "https://sts.us-gov-east-1.amazonaws.com",
}  # See: https://docs.aws.amazon.com/general/latest/gr/sts.html


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


def extract_session_from_secret(secret_key, session_token):
    """
    Extract the session token from the secret_key field.
    """
    if secret_key and '@@@' in secret_key and not session_token:
        return secret_key.split('@@@')[0], secret_key.split('@@@')[1]
    else:
        return secret_key, session_token


class AWSClient:

    def __init__(self, aws_default_region, aws_role_arn, aws_role_session_name, aws_role_session_duration,
                 aws_role_policy, aws_access_key_id, aws_secret_access_key, verify_certificate, timeout, retries,
                 aws_session_token=None, sts_endpoint_url=None, endpoint_url=None):

        self.sts_endpoint_url = sts_endpoint_url
        self.endpoint_url = endpoint_url
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        # handle cases where aws_role_session_duration can be also empty string
        self.aws_role_session_duration = aws_role_session_duration if aws_role_session_duration else None
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key, self.aws_session_token = extract_session_from_secret(aws_secret_access_key, aws_session_token)
        self.verify_certificate = verify_certificate

        sts_regional_endpoint = demisto.params().get("sts_regional_endpoint") or None
        if sts_regional_endpoint:
            demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={sts_regional_endpoint}")
            os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = sts_regional_endpoint.lower()

        proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries={
                "max_attempts": int(retries)
            },
            proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg('retries')  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config['retries'] = {"max_attempts": int(retries)}
        timeout = demisto.getArg('timeout')
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config['read_timeout'] = read_timeout
            command_config['connect_timeout'] = connect_timeout
        if retries or timeout:
            demisto.debug('Merging client config settings: {}'.format(command_config))
            self.config = self.config.merge(Config(**command_config))  # type: ignore[arg-type]

    def aws_session(self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None,
                    role_policy=None):
        kwargs = {}
        client = None

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

        demisto.debug(f'{kwargs=}')
        self.sts_endpoint_url = self.sts_endpoint_url or STS_ENDPOINTS.get(region) or STS_ENDPOINTS.get(self.aws_default_region)

        if kwargs and not self.aws_access_key_id:  # login with Role ARN
            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=region if region else self.aws_default_region,
                                          endpoint_url=self.sts_endpoint_url)
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                    aws_session_token=sts_response['Credentials']['SessionToken'],
                    verify=self.verify_certificate,
                    config=self.config,
                    endpoint_url=self.endpoint_url
                )
        elif self.aws_access_key_id and (role_arn or self.aws_role_arn):  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name='sts',
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.sts_endpoint_url
            )
            kwargs.update({
                'RoleArn': role_arn or self.aws_role_arn,
                'RoleSessionName': role_session_name or self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        elif self.aws_session_token and not self.aws_role_arn:  # login with session token
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(service_name=service,
                                  region_name=region if region else self.aws_default_region,
                                  endpoint_url=self.endpoint_url)

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:

            if isinstance(timeout, int):
                read_timeout = timeout
                connect_timeout = 10

            else:
                timeout_vals = timeout.split(',')
                read_timeout = int(timeout_vals[0])
                # the default connect timeout is 10
                connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])

        except ValueError:
            raise DemistoException("You can specify just the read timeout (for example 60) or also the connect "
                                   "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                                   "specified, a default of 10 second will be used.")
        return read_timeout, connect_timeout
