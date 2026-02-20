import demistomock as demisto  # noqa: F401
import pytest
import json
import copy
import ipaddress
from CommonServerPython import DemistoException


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


NEW_SG = [{"Type": 1, "Contents": {"GroupId": "sg-00000000000000001"}}]


def test_identify_integration_instance(mocker):
    """Tests identify_integration_instance helper function.

    Given:
        - Command results from aws-ec2-security-groups-describe when multiple integration instances are configured
            and one is connected to the account where the requested object resides and the other is connected to a
            different account.
    When:
        - Identifying the result with a successful response
    Then:
        - The function returns the name of the integration instance to use and security group data was returned
    """
    from AWSRemediateSG import identify_integration_instance

    RESULT = util_load_json("./test_data/multi_integration_instances.json")

    mocker.patch.object(demisto, "executeCommand", return_value=RESULT)

    instance_to_use, sg_info = identify_integration_instance("1234", "sg-00000000000000000", "us-east-1")

    assert instance_to_use == "AWS_instance_2"
    assert sg_info == [RESULT[1]]


def test_identify_integration_instance_error(mocker):
    """Tests identify_integration_instance helper function.

    Given:
        - Command results from aws-ec2-security-groups-describe when multiple integration instances are configured
            and all instances return errors.
    When:
        - Handling multiple results that are all errors
    Then:
        - The function raises an exception
    """
    from AWSRemediateSG import identify_integration_instance

    RESULT = util_load_json("./test_data/multi_integration_instances_with_errors.json")

    mocker.patch.object(demisto, "executeCommand", return_value=RESULT)

    with pytest.raises(DemistoException):
        identify_integration_instance("1234", "sg-00000000000000000", "us-east-1")


@pytest.mark.parametrize(
    "rule, first_rule_created",
    [
        (
            {
                "IpProtocol": "-1",
                "IpRanges": [
                    {
                        "CidrIp": "10.0.0.0/16",
                        "Description": "allow all traffic from VPC",
                    },
                    {"CidrIp": "0.0.0.0/0"},
                ],
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
                "FromPort": 23,
                "ToPort": 23,
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
        "remediation_allow_ranges": "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
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
        "ReplacementSet": [{"new-sg": "sg-00000000000000001", "old-sg": "sg-00000000000000000"}],
        "UpdatedSGList": ["sg-00000000000000001"],
        "RemediationRequired": True,
    }

    assert readable_output == correct_output


def test_parse_tag_field_with_valid_single_tag():
    """
    Given: A valid tag string with single key-value pair.
    When: parse_tag_field processes the input.
    Then: It should return a list with one properly formatted tag dictionary.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("key=Key1,value=Value1")
    assert result == [{"Key": "Key1", "Value": "Value1"}]


def test_parse_tag_field_with_multiple_valid_tags():
    """
    Given: A valid tag string with multiple key-value pairs separated by semicolons.
    When: parse_tag_field processes the input.
    Then: It should return a list with multiple properly formatted tag dictionaries.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("key=Key1,value=Value1;key=Key2,value=Value2")
    assert result == [{"Key": "Key1", "Value": "Value1"}, {"Key": "Key2", "Value": "Value2"}]


def test_parse_tag_field_with_none_input():
    """
    Given: A None value is passed to parse_tag_field function.
    When: The function attempts to process the None input.
    Then: It should return an empty list.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field(None)
    assert result == []


def test_parse_tag_field_with_empty_string():
    """
    Given: An empty string is passed to parse_tag_field function.
    When: The function attempts to process the empty string.
    Then: It should return an empty list.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("")
    assert result == []


def test_parse_tag_field_with_invalid_format():
    """
    Given: A tag string with invalid format (missing value part).
    When: parse_tag_field processes the malformed input.
    Then: It should raise an error.
    """
    from AWSRemediateSG import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1")


def test_parse_tag_field_with_mixed_valid_and_invalid_tags():
    """
    Given: A tag string with both valid and invalid formatted tags.
    When: parse_tag_field processes the mixed input.
    Then: It should raise an error.
    """
    from AWSRemediateSG import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1,value=Value1;invalid-tag;key=Key2,value=Value2")


def test_parse_tag_field_with_empty_value(mocker):
    """
    Given: A tag string with empty value part.
    When: parse_tag_field processes the input with empty value.
    Then: It should return a tag with empty value string.
    """
    from AWSRemediateSG import parse_tag_field

    mocker.patch.object(demisto, "debug")
    result = parse_tag_field("key=Key1,value=")
    assert result == [{"Key": "Key1", "Value": ""}]


def test_parse_tag_field_with_special_characters_in_key():
    """
    Given: A tag string with special characters allowed in key.
    When: parse_tag_field processes the input with special characters.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("key=aws:ec2:test,value=test.test")
    assert result == [{"Key": "aws:ec2:test", "Value": "test.test"}]


def test_parse_tag_field_with_spaces_in_key():
    """
    Given: A tag string with spaces in the key name.
    When: parse_tag_field processes the input with spaces.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("key=My Tag Name,value=MyValue")
    assert result == [{"Key": "My Tag Name", "Value": "MyValue"}]


def test_parse_tag_field_with_maximum_key_length():
    """
    Given: A tag string with key at maximum allowed length (128 characters).
    When: parse_tag_field processes the input with maximum key length.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWSRemediateSG import parse_tag_field

    max_key = "a" * 128
    result = parse_tag_field(f"key={max_key},value=test")
    assert result == [{"Key": max_key, "Value": "test"}]


def test_parse_tag_field_with_maximum_value_length():
    """
    Given: A tag string with value at maximum allowed length (256 characters).
    When: parse_tag_field processes the input with maximum value length.
    Then: It should return a properly formatted tag dictionary.
    """
    from AWSRemediateSG import parse_tag_field

    max_value = "a" * 256
    result = parse_tag_field(f"key=TestKey,value={max_value}")
    assert result == [{"Key": "TestKey", "Value": max_value}]


def test_parse_tag_field_with_key_exceeding_maximum_length():
    """
    Given: A tag string with key exceeding maximum allowed length (129 characters).
    When: parse_tag_field processes the input with oversized key.
    Then: It should raise an error.
    """
    from AWSRemediateSG import parse_tag_field

    oversized_key = "a" * 129
    with pytest.raises(ValueError):
        parse_tag_field(f"key={oversized_key},value=test")


def test_parse_tag_field_with_value_exceeding_maximum_length():
    """
    Given: A tag string with value exceeding maximum allowed length (257 characters).
    When: parse_tag_field processes the input with oversized value.
    Then: It should raise an error.
    """
    from AWSRemediateSG import parse_tag_field

    oversized_value = "a" * 257
    with pytest.raises(ValueError):
        parse_tag_field(f"key=TestKey,value={oversized_value}")


def test_parse_tag_field_with_exactly_fifty_tags(mocker):
    """
    Given: A tag string with exactly 50 tags (maximum allowed).
    When: parse_tag_field processes the input with 50 tags.
    Then: It should return all 50 tags without truncation.
    """
    from AWSRemediateSG import parse_tag_field

    mock_debug = mocker.patch.object(demisto, "debug")

    tags_string = ";".join([f"key=Key{i},value=Value{i}" for i in range(50)])
    result = parse_tag_field(tags_string)

    assert len(result) == 50
    assert result[0] == {"Key": "Key0", "Value": "Value0"}
    assert result[49] == {"Key": "Key49", "Value": "Value49"}
    mock_debug.assert_not_called()


def test_parse_tag_field_with_more_than_fifty_tags(mocker):
    """
    Given: A tag string with more than 50 tags (exceeds maximum).
    When: parse_tag_field processes the input with too many tags.
    Then: It should return only the first 50 tags and log a debug message.
    """
    from AWSRemediateSG import parse_tag_field

    mock_debug = mocker.patch.object(demisto, "debug")

    tags_string = ";".join([f"key=Key{i},value=Value{i}" for i in range(55)])
    result = parse_tag_field(tags_string)

    assert len(result) == 50
    assert result[0] == {"Key": "Key0", "Value": "Value0"}
    assert result[49] == {"Key": "Key49", "Value": "Value49"}
    mock_debug.assert_called_once_with("Number of tags is larger then 50, parsing only first 50 tags.")


def test_parse_tag_field_with_missing_comma_separator():
    """
    Given: A tag string missing comma separator between key and value.
    When: parse_tag_field processes the input without proper separator.
    Then: It should raise an error.
    """
    from AWSRemediateSG import parse_tag_field

    with pytest.raises(ValueError):
        parse_tag_field("key=Key1 value=Value1")


def test_parse_tag_field_with_extra_whitespace():
    """
    Given: A tag string with extra whitespace around the tag.
    When: parse_tag_field processes the input with whitespace.
    Then: It should handle the whitespace properly based on regex matching.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("  key=Key1,value=Value1  ")
    assert result == [{"Key": "Key1", "Value": "Value1"}]


def test_parse_tag_field_with_numeric_keys_and_values():
    """
    Given: A tag string with numeric characters in keys and values.
    When: parse_tag_field processes the numeric input.
    Then: It should return properly formatted tag dictionaries.
    """
    from AWSRemediateSG import parse_tag_field

    result = parse_tag_field("key=123,value=456;key=Cost123,value=100.50")
    assert result == [{"Key": "123", "Value": "456"}, {"Key": "Cost123", "Value": "100.50"}]


def test_parse_tag_field_debug_logging_for_invalid_tag(mocker):
    """
    Given: A tag string with invalid format.
    When: parse_tag_field processes the invalid input.
    Then: It should log a debug message about the unparseable tag.
    """
    from AWSRemediateSG import parse_tag_field

    mocker.patch.object(demisto, "debug")

    invalid_tag = "invalid-format"
    with pytest.raises(ValueError):
        parse_tag_field(invalid_tag)


class TestBuildAllowRangeRules:
    """Tests for the build_allow_range_rules function."""

    DESCRIPTION = "Internal access rule automatically created by Cortex remediation."

    def _make_expected_rule(self, protocol, port, cidr_key, range_key, ip_str):
        """Helper to build an expected rule dict."""
        ip_ranges: dict[str, list] = {"IpRanges": [], "Ipv6Ranges": []}
        ip_ranges[range_key] = [{cidr_key: ip_str, "Description": self.DESCRIPTION}]
        return {
            "IpProtocol": protocol,
            **ip_ranges,
            "PrefixListIds": [],
            "UserIdGroupPairs": [],
            "FromPort": port,
            "ToPort": port,
        }

    def test_ipv4_networks_with_has_ipv4_true(self):
        """
        Given:
            - A list of IPv4 networks and has_ipv4=True, has_ipv6=False.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns one rule per IPv4 network with CidrIp in IpRanges.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12")]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=22)

        assert len(result) == 2
        assert result[0] == self._make_expected_rule("tcp", 22, "CidrIp", "IpRanges", "10.0.0.0/8")
        assert result[1] == self._make_expected_rule("tcp", 22, "CidrIp", "IpRanges", "172.16.0.0/12")

    def test_ipv6_networks_with_has_ipv6_true(self):
        """
        Given:
            - A list of IPv6 networks and has_ipv4=False, has_ipv6=True.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns one rule per IPv6 network with CidrIpv6 in Ipv6Ranges.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("fd00::/8"), ipaddress.ip_network("2001:db8::/32")]
        result = build_allow_range_rules(ranges, has_ipv4=False, has_ipv6=True, protocol="tcp", port=443)

        assert len(result) == 2
        assert result[0] == self._make_expected_rule("tcp", 443, "CidrIpv6", "Ipv6Ranges", "fd00::/8")
        assert result[1] == self._make_expected_rule("tcp", 443, "CidrIpv6", "Ipv6Ranges", "2001:db8::/32")

    def test_mixed_ipv4_and_ipv6_both_flags_true(self):
        """
        Given:
            - A list containing both IPv4 and IPv6 networks, with has_ipv4=True and has_ipv6=True.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns rules for both IPv4 and IPv6 entries, IPv4 first then IPv6.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("fd00::/8"),
        ]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=True, protocol="udp", port=53)

        assert len(result) == 2
        assert result[0] == self._make_expected_rule("udp", 53, "CidrIp", "IpRanges", "10.0.0.0/8")
        assert result[1] == self._make_expected_rule("udp", 53, "CidrIpv6", "Ipv6Ranges", "fd00::/8")

    def test_ipv4_filtered_out_when_has_ipv4_false(self):
        """
        Given:
            - A list containing both IPv4 and IPv6 networks, but has_ipv4=False.
        When:
            - build_allow_range_rules is called.
        Then:
            - Only IPv6 rules are returned; IPv4 entries are filtered out.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("fd00::/8"),
        ]
        result = build_allow_range_rules(ranges, has_ipv4=False, has_ipv6=True, protocol="tcp", port=22)

        assert len(result) == 1
        assert result[0] == self._make_expected_rule("tcp", 22, "CidrIpv6", "Ipv6Ranges", "fd00::/8")

    def test_ipv6_filtered_out_when_has_ipv6_false(self):
        """
        Given:
            - A list containing both IPv4 and IPv6 networks, but has_ipv6=False.
        When:
            - build_allow_range_rules is called.
        Then:
            - Only IPv4 rules are returned; IPv6 entries are filtered out.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("fd00::/8"),
        ]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=22)

        assert len(result) == 1
        assert result[0] == self._make_expected_rule("tcp", 22, "CidrIp", "IpRanges", "10.0.0.0/8")

    def test_empty_ranges_returns_empty_list(self):
        """
        Given:
            - An empty remediation_allow_ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns an empty list.
        """
        from AWSRemediateSG import build_allow_range_rules

        result = build_allow_range_rules([], has_ipv4=True, has_ipv6=True, protocol="tcp", port=22)

        assert result == []

    def test_both_flags_false_returns_empty_list(self):
        """
        Given:
            - A list of IPv4 and IPv6 networks, but both has_ipv4=False and has_ipv6=False.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns an empty list since no address family is enabled.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("fd00::/8")]
        result = build_allow_range_rules(ranges, has_ipv4=False, has_ipv6=False, protocol="tcp", port=22)

        assert result == []

    def test_each_rule_has_correct_structure(self):
        """
        Given:
            - A single IPv4 network in the ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - The returned rule contains all required keys: IpProtocol, IpRanges, Ipv6Ranges,
              PrefixListIds, UserIdGroupPairs, FromPort, ToPort.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("10.0.0.0/8")]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=3389)

        assert len(result) == 1
        rule = result[0]
        assert rule["IpProtocol"] == "tcp"
        assert rule["FromPort"] == 3389
        assert rule["ToPort"] == 3389
        assert rule["PrefixListIds"] == []
        assert rule["UserIdGroupPairs"] == []
        assert len(rule["IpRanges"]) == 1
        assert rule["Ipv6Ranges"] == []

    def test_ipv4_rule_has_empty_ipv6_ranges(self):
        """
        Given:
            - An IPv4 network in the ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - The generated rule has a populated IpRanges and an empty Ipv6Ranges.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("192.168.0.0/16")]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=22)

        assert result[0]["IpRanges"] != []
        assert result[0]["Ipv6Ranges"] == []

    def test_ipv6_rule_has_empty_ipv4_ranges(self):
        """
        Given:
            - An IPv6 network in the ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - The generated rule has a populated Ipv6Ranges and an empty IpRanges.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("fd00::/8")]
        result = build_allow_range_rules(ranges, has_ipv4=False, has_ipv6=True, protocol="tcp", port=22)

        assert result[0]["IpRanges"] == []
        assert result[0]["Ipv6Ranges"] != []

    def test_udp_protocol(self):
        """
        Given:
            - An IPv4 network with protocol="udp".
        When:
            - build_allow_range_rules is called.
        Then:
            - The generated rule has IpProtocol set to "udp".
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("10.0.0.0/8")]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="udp", port=53)

        assert result[0]["IpProtocol"] == "udp"

    def test_multiple_ipv4_ranges_produce_separate_rules(self):
        """
        Given:
            - Three IPv4 networks in the ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - Returns three separate rules, one per network, each with its own IpRanges entry.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=22)

        assert len(result) == 3
        cidrs = [rule["IpRanges"][0]["CidrIp"] for rule in result]
        assert cidrs == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def test_description_is_set_correctly(self):
        """
        Given:
            - An IPv4 network in the ranges list.
        When:
            - build_allow_range_rules is called.
        Then:
            - Each rule's IP range entry has the correct Description field.
        """
        from AWSRemediateSG import build_allow_range_rules

        ranges = [ipaddress.ip_network("10.0.0.0/8")]
        result = build_allow_range_rules(ranges, has_ipv4=True, has_ipv6=False, protocol="tcp", port=22)

        assert result[0]["IpRanges"][0]["Description"] == self.DESCRIPTION


class TestCreateSecurityGroup:
    """Tests for the create_security_group function."""

    MOCK_NEW_SG_RESPONSE = [{"Type": 1, "Contents": {"GroupId": "sg-new123456789"}}]

    @staticmethod
    def _build_sg_info(group_name: str, vpc_id: str = "vpc-abc123") -> list[dict]:
        """Helper to build a minimal sg_info structure for create_security_group."""
        return [
            {
                "Type": 1,
                "Contents": {
                    "SecurityGroups": [
                        {
                            "GroupName": group_name,
                            "VpcId": vpc_id,
                        }
                    ]
                },
            }
        ]

    def test_create_security_group_new_name(self, mocker):
        """Test create_security_group with a GroupName that does not contain the remediation suffix.

        Given:
            - A security group with GroupName 'my-sg' that has no '_cortex_remediation_' suffix.
        When:
            - create_security_group is called.
        Then:
            - The new group name starts with 'my-sg_cortex_remediation_' followed by a 4-digit random number.
            - _run_command is called with the correct arguments including the derived name, VpcId, and description.
            - The returned GroupId matches the mocked response.
        """
        from AWSRemediateSG import create_security_group

        mock_run_command = mocker.patch("AWSRemediateSG._run_command", return_value=self.MOCK_NEW_SG_RESPONSE)

        sg_info = self._build_sg_info("my-sg")
        result = create_security_group(
            account_id="123456789012",
            sg_info=sg_info,
            region="us-east-1",
            integration_instance="AWS",
        )

        assert result == "sg-new123456789"

        mock_run_command.assert_called_once()
        call_args = mock_run_command.call_args[0]
        assert call_args[0] == "aws-ec2-security-group-create"

        cmd_args = call_args[1]
        assert cmd_args["account_id"] == "123456789012"
        assert cmd_args["group_name"].startswith("my-sg_cortex_remediation_")
        # The suffix should be _cortex_remediation_ followed by a 4-digit number
        suffix_number = cmd_args["group_name"].split("_cortex_remediation_")[1]
        assert suffix_number.isdigit()
        assert len(suffix_number) == 4
        assert cmd_args["vpc_id"] == "vpc-abc123"
        assert cmd_args["description"] == "Copied from Security Group my-sg by Cortex."
        assert cmd_args["region"] == "us-east-1"
        assert cmd_args["using"] == "AWS"

    def test_create_security_group_existing_remediation_suffix(self, mocker):
        """Test create_security_group with a GroupName that already contains the remediation suffix.

        Given:
            - A security group with GroupName 'my-sg_cortex_remediation_2000'.
        When:
            - create_security_group is called.
        Then:
            - The old random number is replaced; the new name starts with 'my-sg_cortex_remediation_'
              followed by a fresh 4-digit random number (not necessarily 2000).
            - _run_command is called with the correct arguments.
            - The returned GroupId matches the mocked response.
        """
        from AWSRemediateSG import create_security_group

        mock_run_command = mocker.patch("AWSRemediateSG._run_command", return_value=self.MOCK_NEW_SG_RESPONSE)

        sg_info = self._build_sg_info("my-sg_cortex_remediation_2000")
        result = create_security_group(
            account_id="123456789012",
            sg_info=sg_info,
            region="eu-west-1",
            integration_instance="AWS_prod",
        )

        assert result == "sg-new123456789"

        mock_run_command.assert_called_once()
        call_args = mock_run_command.call_args[0]
        assert call_args[0] == "aws-ec2-security-group-create"

        cmd_args = call_args[1]
        assert cmd_args["account_id"] == "123456789012"
        # The base name 'my-sg' should be preserved, with a new random suffix
        assert cmd_args["group_name"].startswith("my-sg_cortex_remediation_")
        # Ensure the old '2000' was replaced (the name should not contain two remediation suffixes)
        assert cmd_args["group_name"].count("_cortex_remediation_") == 1
        suffix_number = cmd_args["group_name"].split("_cortex_remediation_")[1]
        assert suffix_number.isdigit()
        assert len(suffix_number) == 4
        assert cmd_args["vpc_id"] == "vpc-abc123"
        assert cmd_args["description"] == "Copied from Security Group my-sg_cortex_remediation_2000 by Cortex."
        assert cmd_args["region"] == "eu-west-1"
        assert cmd_args["using"] == "AWS_prod"


class TestApplyEgressRules:
    """Tests for the apply_egress_rules function."""

    ACCOUNT_ID = "123456789012"
    NEW_SG_ID = "sg-new123456789"
    REGION = "us-east-1"
    INSTANCE = "test-instance"

    DEFAULT_REVOKE_RULE = [
        {
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
            "PrefixListIds": [],
            "UserIdGroupPairs": [],
        }
    ]

    def test_no_egress_rules(self, mocker):
        """Case 1: Original SG has NO egress rules at all.

        Given:
            - An empty original_egress list (no egress rules on the original SG).
        When:
            - apply_egress_rules is called.
        Then:
            - No egress authorize call is made (nothing to add).
            - The AWS auto-created default all-traffic rule is revoked.
        """
        from AWSRemediateSG import apply_egress_rules

        mock_run_command = mocker.patch("AWSRemediateSG._run_command")

        apply_egress_rules(
            original_egress=[],
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        # Should only have the revoke call, no authorize call
        assert mock_run_command.call_count == 1

        call_args = mock_run_command.call_args_list[0]
        assert call_args[0][0] == "aws-ec2-security-group-egress-revoke"
        revoked_rules = json.loads(call_args[0][1]["ip_permissions"])
        assert revoked_rules == self.DEFAULT_REVOKE_RULE
        assert call_args[0][1]["group_id"] == self.NEW_SG_ID
        assert call_args[0][1]["account_id"] == self.ACCOUNT_ID
        assert call_args[0][1]["region"] == self.REGION
        assert call_args[0][1]["using"] == self.INSTANCE

    def test_only_default_rule(self, mocker):
        """Case 2: Original SG has ONLY the default all-traffic rule (IPv4 only).

        Given:
            - An original_egress list containing only the default IpProtocol "-1" / 0.0.0.0/0 rule.
        When:
            - apply_egress_rules is called.
        Then:
            - No egress authorize call is made (the default is already auto-created by AWS).
            - No egress revoke call is made (the original had the default, so we keep it).
        """
        from AWSRemediateSG import apply_egress_rules

        mock_run_command = mocker.patch("AWSRemediateSG._run_command")

        original_egress = [
            {
                "IpProtocol": "-1",
                "PrefixListIds": [],
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            }
        ]

        apply_egress_rules(
            original_egress=original_egress,
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        # No calls at all — AWS default is kept as-is
        assert mock_run_command.call_count == 0

    def test_default_plus_other_rules(self, mocker):
        """Case 3: Original SG has the default all-traffic rule PLUS other rules/ranges.

        Given:
            - An original_egress list with:
              * An IpProtocol "-1" entry containing both 0.0.0.0/0 and 1.2.3.4/32 in IpRanges.
              * A separate TCP 443 rule to 4.3.2.1/32.
        When:
            - apply_egress_rules is called.
        Then:
            - An egress authorize call is made containing:
              * The all-traffic entry with 0.0.0.0/0 stripped, keeping only 1.2.3.4/32.
              * The TCP 443 rule as-is.
            - No egress revoke call is made (the original had the default all-traffic rule).
        """
        from AWSRemediateSG import apply_egress_rules

        mock_run_command = mocker.patch("AWSRemediateSG._run_command")

        original_egress = [
            {
                "IpProtocol": "-1",
                "PrefixListIds": [],
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0"},
                    {"CidrIp": "1.2.3.4/32"},
                ],
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            },
            {
                "PrefixListIds": [],
                "FromPort": 443,
                "IpRanges": [{"CidrIp": "4.3.2.1/32"}],
                "ToPort": 443,
                "IpProtocol": "tcp",
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            },
        ]

        apply_egress_rules(
            original_egress=original_egress,
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        # Only an authorize call, no revoke
        assert mock_run_command.call_count == 1

        call_args = mock_run_command.call_args_list[0]
        assert call_args[0][0] == "aws-ec2-security-group-egress-authorize"
        actual_rules = json.loads(call_args[0][1]["ip_permissions"])

        # Should contain 2 rules: the modified all-traffic entry and the TCP 443 rule
        assert len(actual_rules) == 2

        # First rule: all-traffic with 0.0.0.0/0 stripped, only 1.2.3.4/32 remains
        all_traffic_rule = actual_rules[0]
        assert all_traffic_rule["IpProtocol"] == "-1"
        assert all_traffic_rule["IpRanges"] == [{"CidrIp": "1.2.3.4/32"}]

        # Second rule: TCP 443 preserved as-is
        tcp_rule = actual_rules[1]
        assert tcp_rule["IpProtocol"] == "tcp"
        assert tcp_rule["FromPort"] == 443
        assert tcp_rule["ToPort"] == 443
        assert tcp_rule["IpRanges"] == [{"CidrIp": "4.3.2.1/32"}]

        # Verify the authorize call targets the correct SG
        assert call_args[0][1]["group_id"] == self.NEW_SG_ID
        assert call_args[0][1]["account_id"] == self.ACCOUNT_ID
        assert call_args[0][1]["region"] == self.REGION
        assert call_args[0][1]["using"] == self.INSTANCE

        # Verify ignore_already_exists=True was passed
        assert call_args[1].get("ignore_already_exists") is True

    def test_specific_rules_no_default(self, mocker):
        """Case 4: Original SG has egress rules but NO default all-traffic rule.

        Given:
            - An original_egress list with:
              * An IpProtocol "-1" entry with only 1.2.3.4/32 (no 0.0.0.0/0).
              * A TCP 443 rule to 4.3.2.1/32.
        When:
            - apply_egress_rules is called.
        Then:
            - An egress authorize call is made with both rules as-is.
            - The AWS auto-created default all-traffic rule is revoked.
        """
        from AWSRemediateSG import apply_egress_rules

        mock_run_command = mocker.patch("AWSRemediateSG._run_command")

        original_egress = [
            {
                "IpProtocol": "-1",
                "PrefixListIds": [],
                "IpRanges": [{"CidrIp": "1.2.3.4/32"}],
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            },
            {
                "PrefixListIds": [],
                "FromPort": 443,
                "IpRanges": [{"CidrIp": "4.3.2.1/32"}],
                "ToPort": 443,
                "IpProtocol": "tcp",
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            },
        ]

        apply_egress_rules(
            original_egress=original_egress,
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        # Should have both authorize and revoke calls
        assert mock_run_command.call_count == 2

        # Verify authorize call
        authorize_call = mock_run_command.call_args_list[0]
        assert authorize_call[0][0] == "aws-ec2-security-group-egress-authorize"
        actual_rules = json.loads(authorize_call[0][1]["ip_permissions"])
        assert len(actual_rules) == 2
        # Both rules should be passed through as-is
        assert actual_rules[0]["IpProtocol"] == "-1"
        assert actual_rules[0]["IpRanges"] == [{"CidrIp": "1.2.3.4/32"}]
        assert actual_rules[1]["IpProtocol"] == "tcp"
        assert actual_rules[1]["FromPort"] == 443
        assert actual_rules[1]["IpRanges"] == [{"CidrIp": "4.3.2.1/32"}]

        # Verify revoke call
        revoke_call = mock_run_command.call_args_list[1]
        assert revoke_call[0][0] == "aws-ec2-security-group-egress-revoke"
        revoked_rules = json.loads(revoke_call[0][1]["ip_permissions"])
        assert revoked_rules == self.DEFAULT_REVOKE_RULE

    def test_default_with_ipv6_preserves_ipv6(self, mocker):
        """All-traffic entry with both 0.0.0.0/0 and ::/0 strips only the IPv4 default.

        Given:
            - An original_egress list with a single IpProtocol "-1" entry containing
              0.0.0.0/0 in IpRanges and ::/0 in Ipv6Ranges.
        When:
            - apply_egress_rules is called.
        Then:
            - An egress authorize call is made with the entry modified: IpRanges is empty
              (0.0.0.0/0 stripped) but Ipv6Ranges with ::/0 is preserved.
            - No revoke call is made (original had the default all-traffic rule).
        """
        from AWSRemediateSG import apply_egress_rules

        mock_run_command = mocker.patch("AWSRemediateSG._run_command")

        original_egress = [
            {
                "IpProtocol": "-1",
                "PrefixListIds": [],
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ]

        apply_egress_rules(
            original_egress=original_egress,
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        # Only authorize, no revoke (original had the default)
        assert mock_run_command.call_count == 1

        call_args = mock_run_command.call_args_list[0]
        assert call_args[0][0] == "aws-ec2-security-group-egress-authorize"
        actual_rules = json.loads(call_args[0][1]["ip_permissions"])

        assert len(actual_rules) == 1
        assert actual_rules[0]["IpProtocol"] == "-1"
        assert actual_rules[0]["IpRanges"] == []  # 0.0.0.0/0 stripped
        assert actual_rules[0]["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]  # preserved

    def test_does_not_mutate_original_egress(self, mocker):
        """Verify that apply_egress_rules does not mutate the input original_egress list.

        Given:
            - An original_egress list with a default all-traffic entry containing additional CIDRs.
        When:
            - apply_egress_rules is called.
        Then:
            - The original_egress list and its nested dicts remain unchanged after the call.
        """
        from AWSRemediateSG import apply_egress_rules

        mocker.patch("AWSRemediateSG._run_command")

        original_egress = [
            {
                "IpProtocol": "-1",
                "PrefixListIds": [],
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0"},
                    {"CidrIp": "1.2.3.4/32"},
                ],
                "UserIdGroupPairs": [],
                "Ipv6Ranges": [],
            }
        ]
        original_egress_snapshot = copy.deepcopy(original_egress)

        apply_egress_rules(
            original_egress=original_egress,
            account_id=self.ACCOUNT_ID,
            new_id=self.NEW_SG_ID,
            region=self.REGION,
            integration_instance=self.INSTANCE,
        )

        assert original_egress == original_egress_snapshot
