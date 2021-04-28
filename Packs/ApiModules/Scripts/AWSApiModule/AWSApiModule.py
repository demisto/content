import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import boto3
from botocore.config import Config


# class AWSClient:
#     """
#
#     """
#
#     def __init__(self, service='iam', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
#                 rolePolicy=None, aws_role_session_name=None, aws_role_session_duration=None, aws_role_policy=None,
#                 aws_access_key_id=None, aws_secret_access_key=None, verify_certificate=None, aws_default_region=None):
#         self.service = service
#         self.region = region
#         self.roleArn = roleArn
#         self.roleSessionName = roleSessionName
#         self.roleSessionDuration = roleSessionDuration
#         self.rolePolicy = rolePolicy
#         self.aws_role_session_name = aws_role_session_name
#         self.aws_role_session_duration = aws_role_session_duration
#         self.aws_role_policy = aws_role_policy
#         self.aws_access_key_id = aws_access_key_id
#         self.aws_secret_access_key = aws_secret_access_key
#         self.verify_certificate = verify_certificate
#         self.aws_default_region = aws_default_region
#
#     def aws_session(self):
#         proxies = handle_proxy(proxy_param_name='proxy', checkbox_default_value=False)
#         config = Config(
#             connect_timeout=1,
#             retries=dict(
#                 max_attempts=5
#             ),
#             proxies=proxies
#         )
#         kwargs = {}
#         if self.roleArn and self.aws_role_session_name is not None:
#             kwargs.update({
#                 'RoleArn': self.roleArn,
#                 'RoleSessionName': self.aws_role_session_name,
#             })
#         elif self.roleArn and self.aws_role_session_name is not None:
#             kwargs.update({
#                 'RoleArn': roleArn,
#                 'RoleSessionName':  self.aws_role_session_name,
#             })
#
#         if self.roleSessionDuration is not None:
#             kwargs.update({'DurationSeconds': int(self.roleSessionDuration)})
#         elif self.self.aws_role_session_duration is not None:
#             kwargs.update({'DurationSeconds': int(self.self.aws_role_session_duration)})
#
#         if self.rolePolicy is not None:
#             kwargs.update({'Policy': self.rolePolicy})
#         elif self.aws_role_policy is not None:
#             kwargs.update({'Policy': self.aws_role_policy})
#         if kwargs and not self.aws_access_key_id:
#
#             if not self.aws_access_key_id:
#                 sts_client = boto3.client('sts', config=config, verify=self.verify_certificate,
#                                           region_name=self.aws_default_region)
#                 sts_response = sts_client.assume_role(**kwargs)
#                 if self.region is not None:
#                     client = boto3.client(
#                         service_name=self.service,
#                         region_name=self.region,
#                         aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
#                         aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
#                         aws_session_token=sts_response['Credentials']['SessionToken'],
#                         verify=self.verify_certificate,
#                         config=config
#                     )
#                 else:
#                     client = boto3.client(
#                         service_name=self.service,
#                         region_name=self.aws_default_region,
#                         aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
#                         aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
#                         aws_session_token=sts_response['Credentials']['SessionToken'],
#                         verify=self.verify_certificate,
#                         config=config
#                     )
#         elif self.aws_access_key_id and AWS_ROLE_ARN:
#             sts_client = boto3.client(
#                 service_name='sts',
#                 aws_access_key_id=self.aws_access_key_id,
#                 aws_secret_access_key=self.aws_secret_access_key,
#                 verify=self.verify_certificate,
#                 config=config
#             )
#             kwargs.update({
#                 'RoleArn': AWS_ROLE_ARN,
#                 'RoleSessionName': self.aws_role_session_name,
#             })
#             sts_response = sts_client.assume_role(**kwargs)
#             client = boto3.client(
#                 service_name=self.service,
#                 region_name=self.aws_default_region,
#                 aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
#                 aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
#                 aws_session_token=sts_response['Credentials']['SessionToken'],
#                 verify=self.verify_certificate,
#                 config=config
#             )
#         else:
#             if self.region is not None:
#                 client = boto3.client(
#                     service_name=self.service,
#                     region_name=self.region,
#                     aws_access_key_id=self.aws_access_key_id,
#                     aws_secret_access_key=self.aws_secret_access_key,
#                     verify=self.verify_certificate,
#                     config=config
#                 )
#             else:
#                 client = boto3.client(
#                     service_name=self.service,
#                     region_name=self.aws_default_region,
#                     aws_access_key_id=self.aws_access_key_id,
#                     aws_secret_access_key=self.aws_secret_access_key,
#                     verify=self.verify_certificate,
#                     config=config
#                 )
#
#         return client


class AWSClient:
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

    """HELPER FUNCTIONS"""

    def aws_session(service='ec2', region=None, roleArn=None, roleSessionName=None, roleSessionDuration=None,
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
                sts_client = boto3.client('sts', config=config, verify=VERIFY_CERTIFICATE,
                                          region_name=AWS_DEFAULT_REGION)
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
