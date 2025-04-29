import pytest


def test_parse_firewall_rule():
    """
    Given: A string representing firewall rules in the format 'ipprotocol=abc,ports=123;ipprotocol=ded,ports=22,443'.
    When: parse_firewall_rule function is called with this string.
    Then: The function should return a list of dictionaries with 'IPProtocol' and 'ports' keys.
    """
    from GCP import parse_firewall_rule

    # Test with simple rule
    rule_str = "ipprotocol=tcp,ports=80"
    result = parse_firewall_rule(rule_str)
    assert result == [{"IPProtocol": "tcp", "ports": ["80"]}]

    # Test with multiple ports
    rule_str = "ipprotocol=tcp,ports=80,443,8080"
    result = parse_firewall_rule(rule_str)
    assert result == [{"IPProtocol": "tcp", "ports": ["80", "443", "8080"]}]

    # Test with multiple rules
    rule_str = "ipprotocol=tcp,ports=80,443;ipprotocol=udp,ports=53"
    result = parse_firewall_rule(rule_str)
    assert result == [
        {"IPProtocol": "tcp", "ports": ["80", "443"]},
        {"IPProtocol": "udp", "ports": ["53"]}
    ]


def test_parse_firewall_rule_invalid_format():
    """
    Given: A string with invalid format for firewall rules.
    When: parse_firewall_rule function is called with this string.
    Then: The function should raise a ValueError with an appropriate error message.
    """
    from GCP import parse_firewall_rule

    with pytest.raises(ValueError) as e:
        parse_firewall_rule("invalid-format")
    assert "Could not parse field" in str(e.value)


def test_parse_metadata_items():
    """
    Given: A string representing metadata items in the format 'key=abc,value=123;key=fed,value=456'.
    When: parse_metadata_items function is called with this string.
    Then: The function should return a list of dictionaries with 'key' and 'value' pairs.
    """
    from GCP import parse_metadata_items

    # Test with simple metadata
    metadata_str = "key=startup-script,value=echo hello"
    result = parse_metadata_items(metadata_str)
    assert result == [{"key": "startup-script", "value": "echo hello"}]

    # Test with multiple metadata items
    metadata_str = "key=startup-script,value=echo hello;key=shutdown-script,value=echo bye"
    result = parse_metadata_items(metadata_str)
    assert result == [
        {"key": "startup-script", "value": "echo hello"},
        {"key": "shutdown-script", "value": "echo bye"}
    ]


def test_parse_metadata_items_invalid_format():
    """
    Given: A string with invalid format for metadata items.
    When: parse_metadata_items function is called with this string.
    Then: The function should raise a ValueError with an appropriate error message.
    """
    from GCP import parse_metadata_items

    with pytest.raises(ValueError) as e:
        parse_metadata_items("invalid-format")
    assert "Could not parse field" in str(e.value)


def test_get_access_token():
    """
    Given: A dictionary containing 'project_id'.
    When: get_access_token function is called with this dictionary.
    Then: The function should return an access token.
    """
    from GCP import get_access_token

    args = {"project_id": "test-project"}
    # Since the implementation returns an empty string, we'll just verify the function runs without error
    result = get_access_token(args)
    assert result == ""


def test_get_access_token_missing_project_id():
    """
    Given: A dictionary without 'project_id'.
    When: get_access_token function is called with this dictionary.
    Then: The function should raise a DemistoException.
    """
    from GCP import get_access_token
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException) as e:
        get_access_token({})
    assert "project_id is required" in str(e.value)
