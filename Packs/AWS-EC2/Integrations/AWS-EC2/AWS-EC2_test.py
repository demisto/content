from CommonServerPython import *  # noqa: F401
import demistomock as demisto  # noqa: F401
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

    def create_vpc_endpoint(self, **kwargs):
        pass


AWS_EC2.build_client = lambda _: Boto3Client


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


def test_aws_ec2_authorize_security_group_ingress_rule(mocker):
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
    mocker.patch.object(Boto3Client, 'authorize_security_group_ingress', side_effect=validate_kwargs)
    mocker.patch.object(AWS_EC2, 'return_results')

    # Case 1
    with pytest.raises(DemistoException, match='Unexpected response from AWS - EC2:'):
        AWS_EC2.authorize_security_group_ingress_command(INVALID_ARGS)

    # Case 2
    result = AWS_EC2.authorize_security_group_ingress_command(IPPERMISSIONSFULL_ARGS)
    assert result.readable_output == "The Security Group ingress rule was created"


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


def test_aws_ec2_authorize_security_group_egress_rule(mocker):
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
    mocker.patch.object(Boto3Client, 'authorize_security_group_egress', side_effect=validate_kwargs)
    mocker.patch.object(AWS_EC2, 'return_results')

    # Case 1
    with pytest.raises(DemistoException, match='Unexpected response from AWS - EC2:'):
        AWS_EC2.authorize_security_group_egress_command(INVALID_ARGS)

    # Case 2
    result = AWS_EC2.authorize_security_group_egress_command(VALID_ARGS)
    assert result.readable_output == "The Security Group egress rule was created"


@pytest.mark.parametrize('filter, expected_results', [
    ("Name=iam-instance-profile.arn,Values=arn:aws:iam::123456789012:instance-profile/AmazonEKSNodeRole",
     [{'Name': 'iam-instance-profile.arn', 'Values': ['arn:aws:iam::123456789012:instance-profile/AmazonEKSNodeRole']}])
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


def mock_command_func(_):
    return CommandResults(
        outputs=[{}],
        readable_output='readable_output',
        outputs_prefix='prefix',
    )


def test_run_on_all_accounts(mocker):
    """
    Given:
        - The accounts_to_access and access_role_name params are provided.

    When:
        - Calling a command function that is decorated with test_account_runner.

    Then:
        - Ensure account_runner runs the command function for each of the accounts provided.
    """
    AWS_EC2.ROLE_NAME = 'name'
    AWS_EC2.PARAMS = {'accounts_to_access': '1,2'}
    mocker.patch.object(demisto, 'getArg', return_value=None)

    # list as output
    result_func = AWS_EC2.run_on_all_accounts(mock_command_func)
    results: list[CommandResults] = result_func({})

    assert results[0].readable_output == '#### Result for account `1`:\nreadable_output'
    assert results[0].outputs == [{'AccountId': '1'}]
    assert results[1].readable_output == '#### Result for account `2`:\nreadable_output'
    assert results[1].outputs == [{'AccountId': '2'}]

    # dict as output
    result_func = AWS_EC2.run_on_all_accounts(lambda _: CommandResults(
        outputs={},
        readable_output='readable_output',
        outputs_prefix='prefix',
    ))
    results: list[CommandResults] = result_func({})

    assert results[0].readable_output == '#### Result for account `1`:\nreadable_output'
    assert results[0].outputs == {'AccountId': '1'}
    assert results[1].readable_output == '#### Result for account `2`:\nreadable_output'
    assert results[1].outputs == {'AccountId': '2'}


@pytest.mark.parametrize('role_name, roleArn', [
    (None, None), ('name', 'role'),
])
def test_run_on_all_accounts_no_new_func(mocker, role_name, roleArn):
    """
    Given:
        - 1. The access_role_name param is not provided.
        - 2. The roleArn arg is provided.

    When:
        - Calling a command function that is decorated with test_account_runner.

    Then:
        - Ensure account_runner returns the command function unchanged.
    """
    # case 1
    AWS_EC2.ROLE_NAME = role_name
    AWS_EC2.IS_ARN_PROVIDED = True

    result_func = AWS_EC2.run_on_all_accounts(mock_command_func)
    result: CommandResults = result_func({})

    assert result.readable_output == 'readable_output'
    assert result.outputs == [{}]

    # case 2
    AWS_EC2.ROLE_NAME = None
    AWS_EC2.IS_ARN_PROVIDED = False

    result_func = AWS_EC2.run_on_all_accounts(mock_command_func)
    result: CommandResults = result_func({})

    assert result.readable_output == 'readable_output'
    assert result.outputs == [{}]


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
    results = AWS_EC2.describe_ipam_resource_discoveries_command({})
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
    results = AWS_EC2.describe_ipam_resource_discovery_associations_command({})
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
    mocker.patch.object(Boto3Client, 'get_ipam_discovered_public_addresses', return_value=return_boto)
    args = {"IpamResourceDiscoveryId": "ipam-res-disco-11111111111111111",
            "AddressRegion": "us-east-1",
            "Filters": "Name=address,Values=1.1.1.1"}
    results = AWS_EC2.get_ipam_discovered_public_addresses_command(args)
    assert results.readable_output == expected_results


def test_create_vpc_endpoint_command(mocker):
    """
    Given
    - aws-ec2-aws-ec2-create-vpc-endpoint arguments and aws client

    When
    - running aws-ec2-aws-ec2-create-vpc-endpoint command.
    Then
    - Ensure that the information was parsed correctly
    - Ensure that the correct response was returned

    """

    return_boto = {
        'VpcEndpoint': {
            'VpcEndpointId': 'test_endpoint_id',
            'VpcEndpointType': 'Interface',
            'VpcId': 'test_id',
            'ServiceName': 'test_service_name',
            'State': 'PendingAcceptance',
            'PolicyDocument': 'test',
            'RouteTableIds': [
                'test',
            ],
            'SubnetIds': [
                'test',
            ],
            'Groups': [
                {
                    'GroupId': 'test',
                    'GroupName': 'test'
                },
            ],
            'IpAddressType': 'ipv4',
            'DnsOptions': {
                'DnsRecordIpType': 'ipv4',
                'PrivateDnsOnlyForInboundResolverEndpoint': True
            },
            'PrivateDnsEnabled': True,
            'RequesterManaged': True,
            'NetworkInterfaceIds': [
                'test',
            ],
            'DnsEntries': [
                {
                    'DnsName': 'test',
                    'HostedZoneId': 'test'
                },
            ],
            'CreationTimestamp': datetime(2015, 1, 1),
            'Tags': [
                {
                    'Key': 'test',
                    'Value': 'test'
                },
            ],
            'OwnerId': 'test',
            'LastError': {
                'Message': 'test',
                'Code': 'test'
            }
        },
        'ClientToken': 'test'
    }

    mocker.patch.object(Boto3Client, 'create_vpc_endpoint', return_value=return_boto)
    results = AWS_EC2.create_vpc_endpoint_command({'vpcId': 'test_endpoint_id',
                                                   'serviceName': 'test',
                                                   'tagSpecifications': '{"test": "test-tag"}'})

    assert results.outputs == return_boto.get('VpcEndpoint')
