import demistomock as demisto  # noqa: F401
import pytest


@pytest.mark.parametrize(
    "rule, first_rule_created",
    [
        ({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [],
          "UserIdGroupPairs": []}, {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
                                    'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 21}),
        ({"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [],
          "UserIdGroupPairs": [], 'FromPort': 0, 'ToPort': 23},
         {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
          'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 0, 'ToPort': 21}),
        ({"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [],
          "UserIdGroupPairs": [], 'FromPort': 1, 'ToPort': 22},
         {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
          'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 1, 'ToPort': 21}),
        ({"IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [], "PrefixListIds": [],
          "UserIdGroupPairs": [], 'FromPort': 22, 'ToPort': 100},
         {'IpProtocol': 'tcp', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
          'PrefixListIds': [], 'UserIdGroupPairs': [], 'FromPort': 23, 'ToPort': 100}),
    ]
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
    args = {"instance_id": "fake-instance-id", "public_ip": "1.1.1.1"}
    result = instance_info(**args)
    assert result == {'eni-00000000000000000': ['sg-00000000000000000']}


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
    from test_data.sample import SG_INFO
    new_sg = [{'Type': 1, 'Contents': {'AWS.EC2.SecurityGroups': {'GroupId': 'sg-00000000000000001'}}}]
    mocker.patch.object(demisto, "executeCommand", return_value=new_sg)
    args = {"sg_info": SG_INFO, "port": 22, "protocol": "tcp"}
    result = sg_fix(**args)
    assert result == {'new-sg': 'sg-00000000000000001'}


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
    from test_data.sample import SG_INFO
    new_sg = [{'Type': 1, 'Contents': {'AWS.EC2.SecurityGroups': {'GroupId': 'sg-00000000000000001'}}}]

    def executeCommand(name, args):
        if name == "aws-ec2-describe-security-groups":
            return SG_INFO
        elif name == "aws-ec2-create-security-group":
            return new_sg

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"int_sg_mapping": {'eni-00000000000000000': ['sg-00000000000000000']}, "port": 22, "protocol": "tcp"}
    result = determine_excessive_access(**args)
    assert result == [{'int': 'eni-00000000000000000', 'old-sg': 'sg-00000000000000000', 'new-sg': 'sg-00000000000000001'}]


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
    from test_data.sample import SG_INFO, INSTANCE_INFO
    new_sg = [{'Type': 1, 'Contents': {'AWS.EC2.SecurityGroups': {'GroupId': 'sg-00000000000000001'}}}]

    def executeCommand(name, args):
        if name == "aws-ec2-describe-security-groups":
            return SG_INFO
        elif name == "aws-ec2-create-security-group":
            return new_sg
        elif name == "aws-ec2-describe-instances":
            return INSTANCE_INFO

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"instance_id": "fake-instance-id", "public_ip": "1.1.1.1", "port": "22", "protocol": "tcp"}
    result = aws_recreate_sg(args)
    correct_output = "For interface eni-00000000000000000: \r\nreplaced SG sg-00000000000000000 with sg-00000000000000001 \r\n"
    assert result == correct_output
