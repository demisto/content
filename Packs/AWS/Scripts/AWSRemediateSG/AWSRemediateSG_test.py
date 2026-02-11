import demistomock as demisto  # noqa: F401
import pytest
import json


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


NEW_SG = [{"Type": 1, "Contents": {"GroupId": "sg-00000000000000001"}}]


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
                "IpRanges": [
                    {
                        "CidrIp": "0.0.0.0/0",
                        "Description": "Allow rule created by Cortex remediation from All Traffic rule omitting TCP port 22.",
                    }
                ],
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
    from AWSRemediateSG import split_rule

    args = {"rule": rule, "port": 22, "protocol": "tcp"}
    result = split_rule(**args)
    assert result[0] == first_rule_created


def test_fix_excessive_access(mocker):
    """Tests determine_excessive_access helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to determine_excessive_access helper function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from AWSRemediateSG import fix_excessive_access

    SG_INFO = util_load_json("./test_data/original_sg_sample.json")

    def executeCommand(name, *_):
        return {"aws-ec2-security-groups-describe": SG_INFO, "aws-ec2-security-group-create": NEW_SG}.get(name)

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {
        "account_id": "123456789012",
        "sg_list": ["sg-00000000000000000"],
        "port": 22,
        "protocol": "tcp",
        "integration_instance": "AWS",
        "region": "us-east-1",
    }
    result = fix_excessive_access(**args)
    assert result == [{"new-sg": "sg-00000000000000001", "old-sg": "sg-00000000000000000"}]


def test_aws_recreate_sg(mocker):
    """Tests aws_recreate_sg  function.

    Given:
        - Mocked arguments
    When:
        - Sending args to aws_recreate_sg  function.
    Then:
        - Checks the output of the function with the expected output.
    """
    from AWSRemediateSG import aws_recreate_sg

    SG_INFO = util_load_json("./test_data/original_sg_sample.json")

    def execute_command(command, *_):
        return {
            "aws-ec2-security-groups-describe": SG_INFO,
            "aws-ec2-security-group-create": NEW_SG,
            "aws-ec2-tags-create": True,
        }.get(command)

    mocker.patch.object(demisto, "executeCommand", side_effect=execute_command)
    args = {
        "account_id": "0123456789012",
        "resource_id": "fake-instance-id",
        "sg_list": "sg-00000000000000000",
        "port": "22",
        "protocol": "tcp",
        "region": "us-east-1",
        "integration_instance": "AWS",
    }
    command_results = aws_recreate_sg(args)
    readable_output = command_results.raw_response
    correct_output = {
        "ResourceID": "fake-instance-id",
        "ReplacementSet": [
            {"new-sg": "sg-00000000000000001", "old-sg": "sg-00000000000000000"}
        ],
        "UpdatedSGList": ["sg-00000000000000001"],
        "RemediationRequired": True,
    }

    assert readable_output == correct_output


class TestSGFix:
    def test_sg_fix_recreate_list_contents(self, mocker):
        """Test that sg_fix creates the correct recreate_list for remediation.

        Given:
            - A security group with an overly permissive TCP 0-65535 rule to 0.0.0.0/0
              and a direct port 22 rule to 0.0.0.0/0, plus a TCP egress rule.
        When:
            - sg_fix is called to remediate port 22.
        Then:
            - A new SG is created with tags copied from the original.
            - All ingress rules are batched into a single authorize call containing
              the split rules (port ranges excluding 22) and private CIDR rules.
            - The original egress rule is added via a single egress authorize call.
            - The AWS default all-traffic egress rule is revoked (since the original
              SG did not have an IpProtocol "-1" all-traffic rule).
        """

        from AWSRemediateSG import sg_fix

        # Mock the security group creation response
        mock_sg_create_response = [{"Type": 1, "Contents": {"GroupId": "sg-new123456789"}}]

        # Mock the tag creation response
        mock_tag_create_response = [{"Type": 1, "Contents": "Success"}]

        # Mock the ingress rule creation response (single batched call)
        mock_ingress_response = [{"Type": 1, "Contents": "Success"}]

        # Mock the egress rule creation response
        mock_egress_response = [{"Type": 1, "Contents": "Success"}]

        # Mock the egress rule revoke response
        mock_egress_revoke_response = [{"Type": 1, "Contents": "Success"}]

        # Setup the mock to return different responses for different commands
        def mock_command_side_effect(command, args):
            if command == "aws-ec2-security-group-create":
                return mock_sg_create_response
            elif command == "aws-ec2-tags-create":
                return mock_tag_create_response
            elif command == "aws-ec2-security-group-ingress-authorize":
                return mock_ingress_response
            elif command == "aws-ec2-security-group-egress-authorize":
                return mock_egress_response
            elif command == "aws-ec2-security-group-egress-revoke":
                return mock_egress_revoke_response
            return []

        mock_execute_command = mocker.patch.object(demisto, "executeCommand", side_effect=mock_command_side_effect)

        # Test parameters
        account_id = "717007404259"
        SG_INFO = util_load_json("./test_data/original_sg_sample.json")
        port = 22
        protocol = "tcp"
        integration_instance = "test-instance"
        region = "us-east-1"

        # Execute the function
        result = sg_fix(account_id, SG_INFO, port, protocol, integration_instance, region)

        # Verify the function returned the new security group ID
        assert result == {"new-sg": "sg-new123456789"}

        # Verify executeCommand was called the correct number of times:
        # 1 SG creation + 1 tag creation + 1 batched ingress + 1 egress authorize + 1 egress revoke = 5
        assert mock_execute_command.call_count == 5

        # --- Verify batched ingress rules ---
        ingress_calls = [
            call for call in mock_execute_command.call_args_list if call[0][0] == "aws-ec2-security-group-ingress-authorize"
        ]

        # Should have exactly 1 batched ingress call
        assert len(ingress_calls) == 1

        # Parse the batched ip_permissions payload
        ingress_call_args = ingress_calls[0][0][1]
        actual_rules = json.loads(ingress_call_args["ip_permissions"])

        # Load expected rules (flat list: 2 split rules + 3 private CIDR rules)
        expected_rules = util_load_json("./test_data/fixed_sg_sample.json")

        # Should contain 5 rules total (2 from split + 3 private CIDRs)
        assert len(actual_rules) == 5

        # Verify each expected rule is present in the actual rules (order may vary)
        for expected_rule in expected_rules:
            assert expected_rule in actual_rules, (
                f"Expected rule not found in batched ingress call: {expected_rule}"
            )

        # Verify the ingress call targets the new SG
        assert ingress_call_args["group_id"] == "sg-new123456789"
        assert ingress_call_args["account_id"] == account_id
        assert ingress_call_args["region"] == region
        assert ingress_call_args["using"] == integration_instance

        # --- Verify egress authorize call ---
        egress_authorize_calls = [
            call for call in mock_execute_command.call_args_list if call[0][0] == "aws-ec2-security-group-egress-authorize"
        ]
        assert len(egress_authorize_calls) == 1

        egress_call_args = egress_authorize_calls[0][0][1]
        actual_egress_rules = json.loads(egress_call_args["ip_permissions"])

        # The original SG has a single TCP 0-65535 egress rule to 0.0.0.0/0.
        # Since it is NOT an IpProtocol "-1" all-traffic rule, it is added as-is.
        expected_egress = [
            {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": [],
            }
        ]
        assert actual_egress_rules == expected_egress

        # --- Verify egress revoke call ---
        # The original SG does NOT have an IpProtocol "-1" all-traffic egress rule,
        # so the AWS auto-created default must be revoked.
        egress_revoke_calls = [
            call for call in mock_execute_command.call_args_list if call[0][0] == "aws-ec2-security-group-egress-revoke"
        ]
        assert len(egress_revoke_calls) == 1

        revoke_call_args = egress_revoke_calls[0][0][1]
        revoked_rules = json.loads(revoke_call_args["ip_permissions"])
        expected_revoke = [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ]
        assert revoked_rules == expected_revoke

        # --- Verify security group creation parameters ---
        sg_create_call = next(
            call for call in mock_execute_command.call_args_list if call[0][0] == "aws-ec2-security-group-create"
        )
        sg_create_args = sg_create_call[0][1]

        assert sg_create_args["account_id"] == account_id
        assert "demo-sg_cortex_remediation_" in sg_create_args["group_name"]
        assert sg_create_args["vpc_id"] == "vpc-061c242911e464170"
        assert sg_create_args["description"] == "Copied from Security Group demo-sg by Cortex."
        assert sg_create_args["region"] == region
        assert sg_create_args["using"] == integration_instance

    def test_sg_fix_no_changes_needed(self, mocker):
        """Test that sg_fix returns empty dict when no changes are needed"""

        from AWSRemediateSG import sg_fix

        # Create sg_info with no problematic rules
        safe_sg_info = [
            {
                "Type": 1,
                "Contents": {
                    "SecurityGroups": [
                        {
                            "Description": "safe-sg",
                            "GroupId": "sg-safe123",
                            "GroupName": "safe-sg",
                            "IpPermissions": [
                                {
                                    "FromPort": 22,
                                    "IpProtocol": "tcp",
                                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # Private IP only
                                    "Ipv6Ranges": [],
                                    "PrefixListIds": [],
                                    "ToPort": 22,
                                    "UserIdGroupPairs": [],
                                }
                            ],
                            "IpPermissionsEgress": [],
                            "VpcId": "vpc-061c242911e464170",
                        }
                    ]
                },
            }
        ]

        mock_execute_command = mocker.patch.object(demisto, "executeCommand")

        result = sg_fix("123456789", safe_sg_info, 22, "tcp", "test-instance", "us-east-1")

        # Should return empty dict since no changes needed
        assert result == {}

        # Should not have called executeCommand since no new SG needed
        assert mock_execute_command.call_count == 0
