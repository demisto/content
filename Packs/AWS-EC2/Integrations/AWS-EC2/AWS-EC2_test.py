from AWSApiModule import *
import importlib
import pytest
AWS_EC2 = importlib.import_module("AWS-EC2")


VALID_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
              "IpPermissionsfromPort": 23,
              "IpPermissionsToPort": 23,
              "IpPermissionsIpProtocol": "TCP",
              "region": "reg",
              "roleArn": "role",
              "roleSessionName": "role_Name",
              "roleSessionDuration": 200}

IPPERMISSIONSFULL_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
                          "IpPermissionsFull": """[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                          "Ipv6Ranges": [], "PrefixListIds": [], "UserIdGroupPairs": []}]"""}

INVALID_ARGS = {"groupId": "sg-0566450bb5ae17c7d",
                "region": "reg",
                "roleArn": "role",
                "roleSessionName": "role_Name",
                "roleSessionDuration": 200}


class Boto3Client:
    def authorize_security_group_egress(self, **kwargs):
        pass

    def authorize_security_group_ingress(self, **kwargs):
        pass

    def describe_ipam_resource_discoveries(self, **kwargs):
        pass

    def describe_ipam_resource_discovery_associations(self, **kwargs):
        pass

    def get_ipam_discovered_public_addresses(self, **kwargs):
        pass


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


def validate_kwargs(*args, **kwargs):
    normal_kwargs = {'IpPermissions': [{'ToPort': 23, 'FromPort': 23, 'UserIdGroupPairs': [{}], 'IpProtocol': 'TCP'}],
                     'GroupId': 'sg-0566450bb5ae17c7d'}
    ippermsfull_kwargs = {'GroupId': 'sg-0566450bb5ae17c7d', 'IpPermissions':
                          [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                           'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': []}]}
    if kwargs in (normal_kwargs, ippermsfull_kwargs):
        return {'ResponseMetadata': {'HTTPStatusCode': 200}, 'Return': "some_return_value"}
    else:
        return {'ResponseMetadata': {'HTTPStatusCode': 404}, 'Return': "some_return_value"}


@pytest.mark.parametrize('args, expected_results', [
    (IPPERMISSIONSFULL_ARGS, "The Security Group ingress rule was created"),
    (INVALID_ARGS, None)
])
def test_aws_ec2_authorize_security_group_ingress_rule(mocker, args, expected_results):
    """
    Given
    - authorize-security-group-ingress-command arguments and aws client
    - Case 1: Valid arguments.
    - Case 2: Invalid arguments.
    When
    - running authorize-security-group-ingress-command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that the right message was resulted return true.
    - Case 2: Should ensure that no message was resulted return true.
    """
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'authorize_security_group_ingress', side_effect=validate_kwargs)
    mocker.patch.object(demisto, 'results')
    AWS_EC2.authorize_security_group_ingress_command(args, aws_client)
    if not expected_results:
        assert not demisto.results.call_args
    else:
        results = demisto.results.call_args[0][0]
        assert results == expected_results


def test_create_policy_kwargs_dict():
    """
    Given
    - empty policy kwargs

    When
    - running create_policy_kwargs_dict function

    Then
    - make sure that create_policy_kwargs_dict does not fail on any exception

    """
    assert AWS_EC2.create_policy_kwargs_dict({}) == {}


@pytest.mark.parametrize('args, expected_results', [
    (VALID_ARGS, "The Security Group egress rule was created"),
    (INVALID_ARGS, None)
])
def test_aws_ec2_authorize_security_group_egress_rule(mocker, args, expected_results):
    """
    Given
    - authorize-security-group-egress-command arguments and aws client
    - Case 1: Valid arguments.
    - Case 2: Invalid arguments.
    When
    - running authorize-security-group-egress-command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that the right message was resulted return true.
    - Case 2: Should ensure that no message was resulted return true.
    """
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'authorize_security_group_egress', side_effect=validate_kwargs)
    mocker.patch.object(demisto, 'results')
    AWS_EC2.authorize_security_group_egress_command(args, aws_client)
    if not expected_results:
        assert not demisto.results.call_args
    else:
        results = demisto.results.call_args[0][0]
        assert results == expected_results


@pytest.mark.parametrize('filter, expected_results', [
    ("Name=iam-instance-profile.arn,Values=arn:aws:iam::664798938958:instance-profile/AmazonEKSNodeRole",
     [{'Name': 'iam-instance-profile.arn', 'Values': ['arn:aws:iam::664798938958:instance-profile/AmazonEKSNodeRole']}])
])
def test_parse_filter_field(filter, expected_results):
    """
    Given
    - A filter string.
    - Case 1: a filter string including ':' in the value.
    When
    - Running parse_filter_field method.
    Then
    - Ensure that the filter was parsed correctly.
    - Case 1: Should ensure that the filter value include the whole value (including the part after the ':').
    """
    res = AWS_EC2.parse_filter_field(filter)
    assert res == expected_results


@pytest.mark.parametrize('return_boto, expected_results', [
    ({'IpamResourceDiscoveries': []}, 'No Ipam Resource Discoveries were found.'),
    ({"IpamResourceDiscoveries":
        {
            "IpamResourceDiscoveryArn": "arn:aws:ec2::222222222222:ipam-resource-discovery/ipam-res-disco-11111111111111111",
            "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
            "IpamResourceDiscoveryRegion": "us-east-1",
            "IsDefault": True,
            "OperatingRegions": [
                {
                    "RegionName": "ap-south-1"
                }
            ],
            "OwnerId": "222222222222",
            "State": "create-complete",
            "Tags": []
        }
      }, "### Ipam Resource Discoveries\n"
         "|IpamResourceDiscoveryArn|IpamResourceDiscoveryId|IpamResourceDiscoveryRegion|IsDefault|OperatingRegions|OwnerId|"
         "State|Tags|\n|---|---|---|---|---|---|---|---|\n"
         "| arn:aws:ec2::222222222222:ipam-resource-discovery/ipam-res-disco-11111111111111111 | ipam-res-disco-111111111"
         "11111111 | us-east-1 | true | {'RegionName': 'ap-south-1'} | 222222222222 | create-complete |  |\n")
])
def test_describe_ipam_resource_discoveries_command(mocker, return_boto, expected_results):
    """
    Given
    - aws-ec2-describe-ipam-resource-discoveries arguments and aws client
    - Case 1: no information returned.
    - Case 2: Information returned.
    When
    - running aws-ec2-describe-ipam-resource-discoveries command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that generic "nothing found" message returned.
    - Case 2: Should ensure that information on resource was returned.
    """
    mocker.patch.object(Boto3Client, 'describe_ipam_resource_discoveries', return_value=return_boto)
    results = AWS_EC2.describe_ipam_resource_discoveries_command({}, Boto3Client)
    assert results.readable_output == expected_results


@pytest.mark.parametrize('return_boto, expected_results', [
    ({'IpamResourceDiscoveryAssociations': []}, 'No Ipam Resource Discovery Associations were found.'),
    ({"IpamResourceDiscoveryAssociations":
        {
            "IpamArn": "arn:aws:ec2::222222222222:ipam/ipam-11111111111111111",
            "IpamId": "ipam-11111111111111111",
            "IpamRegion": "us-east-1",
            "IpamResourceDiscoveryAssociationArn": "example:arn",
            "IpamResourceDiscoveryAssociationId": "ipam-res-disco-assoc-11111111111111111",
            "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
            "IsDefault": True,
            "OwnerId": "222222222222",
            "ResourceDiscoveryStatus": "active",
            "State": "associate-complete",
            "Tags": []
        }
      }, "### Ipam Resource Discovery Associations\n"
         "|IpamArn|IpamId|IpamRegion|IpamResourceDiscoveryAssociationArn|IpamResourceDiscoveryAssociationId|"
         "IpamResourceDiscoveryId|IsDefault|OwnerId|ResourceDiscoveryStatus|State|Tags|\n"
         "|---|---|---|---|---|---|---|---|---|---|---|\n"
         "| arn:aws:ec2::222222222222:ipam/ipam-11111111111111111 | ipam-11111111111111111 | us-east-1 | example:arn | ipam-"
         "res-disco-assoc-11111111111111111 | ipam-res-disco-11111111111111111 | true | 222222222222 | active | associate-comp"
         "lete |  |\n")
])
def test_describe_ipam_resource_discovery_associations_command(mocker, return_boto, expected_results):
    """
    Given
    - aws-ec2-describe-ipam-resource-discovery-associations arguments and aws client
    - Case 1: no information returned.
    - Case 2: Information returned.
    When
    - running aws-ec2-describe-ipam-resource-discovery-associations command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that generic "nothing found" message returned.
    - Case 2: Should ensure that information on resource was returned.
    """
    mocker.patch.object(Boto3Client, 'describe_ipam_resource_discovery_associations', return_value=return_boto)
    results = AWS_EC2.describe_ipam_resource_discovery_associations_command({}, Boto3Client)
    assert results.readable_output == expected_results


@pytest.mark.parametrize('return_boto, expected_results', [
    ({'IpamDiscoveredPublicAddresses': []}, 'No Ipam Discovered Public Addresses were found.'),
    ({"IpamDiscoveredPublicAddresses":
        {
            "Address": "1.1.1.1",
            "AddressAllocationId": "eipalloc-11111111111111111",
            "AddressOwnerId": "222222222222",
            "AddressRegion": "us-east-1",
            "AddressType": "amazon-owned-eip",
            "AssociationStatus": "associated",
            "InstanceId": "i-11111111111111111",
            "IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
            "NetworkBorderGroup": "us-east-1",
            "NetworkInterfaceDescription": "",
            "NetworkInterfaceId": "eni-11111111111111111",
            "PublicIpv4PoolId": "amazon",
            "SampleTime": "2023-11-26T02:00:45",
            "SecurityGroups": [
                {
                    "GroupId": "sg-11111111111111111",
                    "GroupName": "example_sg"
                }
            ],
            "SubnetId": "subnet-11111111111111111",
            "Tags": {
                "EipTags": []
            },
            "VpcId": "vpc-11111111111111111"
        }
      }, "### Ipam Discovered Public Addresses\n"
         "|Address|AddressAllocationId|AddressOwnerId|AddressRegion|AddressType|AssociationStatus|InstanceId|IpamResourceDiscover"
         "yId|NetworkBorderGroup|NetworkInterfaceDescription|NetworkInterfaceId|PublicIpv4PoolId|SampleTime|SecurityGroups|Subnet"
         "Id|Tags|VpcId|\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
         "| 1.1.1.1 | eipalloc-11111111111111111 | 222222222222 | us-east-1 | amazon-owned-eip | associated | i-11111111111111111"
         " | ipam-res-disco-11111111111111111 | us-east-1 |  | eni-11111111111111111 | amazon | 2023-11-26T02:00:45 | {'GroupId':"
         " 'sg-11111111111111111', 'GroupName': 'example_sg'} | subnet-11111111111111111 | EipTags:  | vpc-11111111111111111 |\n")
])
def test_get_ipam_discovered_public_addresses_command(mocker, return_boto, expected_results):
    """
    Given
    - aws-ec2-get-ipam-discovered-public-addresses arguments and aws client
    - Case 1: no information returned.
    - Case 2: Information returned.
    When
    - running aws-ec2-get-ipam-discovered-public-addresses command.
    Then
    - Ensure that the information was parsed correctly
    - Case 1: Should ensure that generic "nothing found" message returned.
    - Case 2: Should ensure that information on resource was returned.
    """
    aws_client = create_client()
    mocker.patch.object(AWSClient, "aws_session", return_value=Boto3Client())
    mocker.patch.object(Boto3Client, 'get_ipam_discovered_public_addresses', return_value=return_boto)
    args = {"IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
            "AddressRegion": "us-east-1",
            "Filters": "Name=address,Values=1.1.1.1"}
    results = AWS_EC2.get_ipam_discovered_public_addresses_command(args, aws_client)
    assert results.readable_output == expected_results