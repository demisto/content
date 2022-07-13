from AWSApiModule import *
import importlib
AWS_EC2 = importlib.import_module("AWS-EC2")


def create_client():
    aws_client_args = {
        'aws_default_region': 'us-east-1',
        'aws_role_arn': None,
        'aws_role_session_name': None,
        'aws_role_session_duration': None,
        'aws_role_policy': None,
        'aws_access_key_id': 'test_access_key',
        'aws_secret_access_key': 'test_secret_key',
        'aws_session_token': 'test_sts_token',
        'verify_certificate': False,
        'timeout': 60,
        'retries': 3
    }

    client = AWSClient(**aws_client_args)
    return client

def test_aws_ec2_authorize_security_group_egress_rule():
    """
    Given
    - get-members command

    When
    - running authorize-security-group-egress-command.

    Then
    - Ensure that empty map is not returned to the context
    """
    args = {"roupId": "sg-0566450bb5ae17c7d",
            "IpPermissionsfromPort": 23,
            "IpPermissionsToPort":23,
            "IpPermissionsIpProtocol": "TCP",
            "region": ,
            "roleArn": ,
            "roleSessionName":,
            "roleSessionDuration":}
    aws_client = create_client()
    AWS_EC2.authorize_security_group_egress_command(args, aws_client)
