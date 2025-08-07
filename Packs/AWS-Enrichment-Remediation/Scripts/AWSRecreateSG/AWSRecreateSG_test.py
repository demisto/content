import demistomock as demisto  # noqa: F401
import pytest


@pytest.mark.parametrize(
    "rule, first_rule_created",
    [
        (
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "10.0.0.0/16", "Description": "allow all traffic from VPC"}, {"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 0,
                "ToPort": 21,
            },
        ),
        (
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 0,
                "ToPort": 23,
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 0,
                "ToPort": 21,
            },
        ),
        (
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 1,
                "ToPort": 22,
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 1,
                "ToPort": 21,
            },
        ),
        (
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 22,
                "ToPort": 100,
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 23,
                "ToPort": 100,
            },
        ),
        (
            {
                "IpProtocol": "tcp",
                "IpRanges": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 22,
                "ToPort": 100,
            },
            {
                "IpProtocol": "tcp",
                "IpRanges": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
                "FromPort": 23,
                "ToPort": 100,
            },
        ),
    ],
)
def test_split_rule(rule, first_rule_created):
    """Tests split_rule helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to split_rule helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import split_rule

    args = {"rule": rule, "port": 22, "protocol": "tcp"}
    result = split_rule(**args)
    assert result[0] == first_rule_created


def test_instance_info(mocker):
    """Tests instance_info helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to instance_info helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import instance_info
    from test_data.sample import INSTANCE_INFO

    mocker.patch.object(demisto, "executeCommand", return_value=INSTANCE_INFO)
    args = {"instance_id": "fake-instance-id", "public_ip": "1.1.1.1", "assume_role": "test_role", "region": "us-east-1"}
    result = instance_info(**args)
    assert result == ({"eni-00000000000000000": ["sg-00000000000000000"]}, "AWS - EC2")


def test_sg_fix(mocker):
    """Tests sg_fix helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to sg_fix helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import sg_fix
    from test_data.sample import SG_INFO, NEW_SG

    mocker.patch.object(demisto, "executeCommand", return_value=NEW_SG)
    args = {
        "sg_info": SG_INFO,
        "port": 22,
        "protocol": "tcp",
        "assume_role": "test_role",
        "instance_to_use": "AWS - EC2",
        "region": "us-east-1",
    }
    result = sg_fix(**args)
    assert result == {"new-sg": "sg-00000000000000001"}


def test_determine_excessive_access(mocker):
    """Tests determine_excessive_access helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to determine_excessive_access helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSRecreateSG import determine_excessive_access
    from test_data.sample import SG_INFO, NEW_SG

    def executeCommand(name, *_):
        return {"aws-ec2-describe-security-groups": SG_INFO, "aws-ec2-create-security-group": NEW_SG}.get(name)

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {
        "int_sg_mapping": {"eni-00000000000000000": ["sg-00000000000000000"]},
        "port": 22,
        "protocol": "tcp",
        "assume_role": "test_role",
        "instance_to_use": "AWS - EC2",
        "region": "us-east-1",
    }
    result = determine_excessive_access(**args)
    assert result == [{"int": "eni-00000000000000000", "old-sg": "sg-00000000000000000", "new-sg": "sg-00000000000000001"}]


def test_aws_recreate_sg(mocker):
    """Tests aws_recreate_sg  function.

    Given:
        - Mocked arguments
    When:
        - Sending args to aws_recreate_sg  function.
    Then:
        - Checks the output of the function with the expected output.
    """
    from AWSRecreateSG import aws_recreate_sg
    from test_data.sample import SG_INFO, INSTANCE_INFO, NEW_SG

    def execute_command(command, *_):
        return {
            "aws-ec2-describe-security-groups": SG_INFO,
            "aws-ec2-create-security-group": NEW_SG,
            "aws-ec2-describe-instances": INSTANCE_INFO,
        }.get(command)

    mocker.patch.object(demisto, "executeCommand", side_effect=execute_command)
    args = {"instance_id": "fake-instance-id", "public_ip": "1.1.1.1", "port": "22", "protocol": "tcp"}
    command_results = aws_recreate_sg(args)
    readable_output = command_results.readable_output
    correct_output = "For interface eni-00000000000000000: \r\nreplaced SG sg-00000000000000000 with sg-00000000000000001 \r\n"
    assert readable_output == correct_output
