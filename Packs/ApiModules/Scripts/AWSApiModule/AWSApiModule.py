import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
from botocore.config import Config


def get_timeout(timeout):
    if not timeout:
        timeout = "60,10"  # default values
    timeout_vals = timeout.split(',')
    read_timeout = int(timeout_vals[0])
    connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])
    return read_timeout, connect_timeout


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
        (read_timeout, connect_timeout) = get_timeout(timeout)
        self.config = Config(
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries=dict(
                max_attempts=int(retries)
            ),
            proxies=proxies
        )

    """HELPER FUNCTIONS"""

    def aws_session(self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None,
                    role_policy=None):
        kwargs = {}
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
        if kwargs and not self.aws_access_key_id:

            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=self.config, verify=self.verify_certificate,
                                          region_name=self.aws_default_region)
                sts_response = sts_client.assume_role(**kwargs)
                if region is not None:
                    client = boto3.client(
                        service_name=service,
                        region_name=region,
                        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                        aws_session_token=sts_response['Credentials']['SessionToken'],
                        verify=self.verify_certificate,
                        config=self.config
                    )
                else:
                    client = boto3.client(
                        service_name=service,
                        region_name=self.aws_default_region,
                        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                        aws_session_token=sts_response['Credentials']['SessionToken'],
                        verify=self.verify_certificate,
                        config=self.config
                    )
        elif self.aws_access_key_id and self.aws_role_arn:
            sts_client = boto3.client(
                service_name='sts',
                region_name=region if region else self.aws_default_region,
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
        elif self.aws_access_key_id and not self.aws_role_arn:
            if region is not None:
                client = boto3.client(
                    service_name=service,
                    region_name=region,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    verify=self.verify_certificate,
                    config=self.config
                )
            else:
                client = boto3.client(
                    service_name=service,
                    region_name=self.aws_default_region,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    verify=self.verify_certificate,
                    config=self.config
                )
        else:
            if region is not None:
                client = boto3.client(service_name=service, region_name=region)
            else:
                client = boto3.client(service_name=service, region_name=AWS_DEFAULT_REGION)

        return client
