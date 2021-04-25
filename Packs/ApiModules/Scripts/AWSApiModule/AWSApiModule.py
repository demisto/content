import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
from botocore.config import Config
from typing import Dict, Any
import traceback


class AWSClient:
    """

    """

    def __init__(self, service='iam', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
                rolePolicy=None, aws_role_session_name=None, aws_role_session_duration=None, aws_role_policy=None,
                aws_access_key_id=None, aws_secret_access_key=None, verify_certificate=None, aws_default_region=None):
        self.service = service
        self.region = region
        self.roleArn = roleArn
        self.roleSessionName = roleSessionName
        self.roleSessionDuration = roleSessionDuration
        self.rolePolicy = rolePolicy
        self.aws_role_session_name = aws_role_session_name
        self.aws_role_session_duration = aws_role_session_duration
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.verify_certificate = verify_certificate
        self.aws_default_region = aws_default_region

    def aws_session(self):
        proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
        config = Config(
            connect_timeout=1,
            retries=dict(
                max_attempts=5
            ),
            proxies=proxies
        )
        kwargs = {}
        if self.roleArn and self.aws_role_session_name is not None:
            kwargs.update({
                'RoleArn': self.roleArn,
                'RoleSessionName': self.aws_role_session_name,
            })
        elif self.roleArn and self.aws_role_session_name is not None:
            kwargs.update({
                'RoleArn': roleArn,
                'RoleSessionName':  self.aws_role_session_name,
            })

        if self.roleSessionDuration is not None:
            kwargs.update({'DurationSeconds': int(self.roleSessionDuration)})
        elif self.self.aws_role_session_duration is not None:
            kwargs.update({'DurationSeconds': int(self.self.aws_role_session_duration)})

        if self.rolePolicy is not None:
            kwargs.update({'Policy': self.rolePolicy})
        elif self.aws_role_policy is not None:
            kwargs.update({'Policy': self.aws_role_policy})
        if kwargs and not self.aws_access_key_id:

            if not self.aws_access_key_id:
                sts_client = boto3.client('sts', config=config, verify=self.verify_certificate,
                                          region_name=self.aws_default_region)
                sts_response = sts_client.assume_role(**kwargs)
                if self.region is not None:
                    client = boto3.client(
                        service_name=self.service,
                        region_name=self.region,
                        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                        aws_session_token=sts_response['Credentials']['SessionToken'],
                        verify=self.verify_certificate,
                        config=config
                    )
                else:
                    client = boto3.client(
                        service_name=self.service,
                        region_name=self.aws_default_region,
                        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                        aws_session_token=sts_response['Credentials']['SessionToken'],
                        verify=self.verify_certificate,
                        config=config
                    )
        elif self.aws_access_key_id and AWS_ROLE_ARN:
            sts_client = boto3.client(
                service_name='sts',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=config
            )
            kwargs.update({
                'RoleArn': AWS_ROLE_ARN,
                'RoleSessionName': self.aws_role_session_name,
            })
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=self.service,
                region_name=self.aws_default_region,
                aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
                aws_session_token=sts_response['Credentials']['SessionToken'],
                verify=self.verify_certificate,
                config=config
            )
        else:
            if self.region is not None:
                client = boto3.client(
                    service_name=self.service,
                    region_name=self.region,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    verify=self.verify_certificate,
                    config=config
                )
            else:
                client = boto3.client(
                    service_name=self.service,
                    region_name=self.aws_default_region,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    verify=self.verify_certificate,
                    config=config
                )

        return client
