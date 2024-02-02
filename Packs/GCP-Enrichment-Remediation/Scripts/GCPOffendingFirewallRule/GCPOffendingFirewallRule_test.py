import demistomock as demisto  # noqa: F401
from CommonServerPython import CommandResults


def test_test_range_func(mocker):
    """Tests test_range helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to lookup helper function.
    Then:
        - Checks the output of the helpedfunction with the expected output.
    """
    from GCPOffendingFirewallRule import test_range

    assert test_range("20-25", "22")
    assert not test_range("20-21", "22")


def test_test_match_func(mocker):
    """Tests test_match helper function.

    Given:
        - Mocked arguments
    When:
        - Sending args to lookup helper function.
    Then:
        - Checks the output of the helpedfunction with the expected output.
    """
    from GCPOffendingFirewallRule import test_match

    port = "22"
    protocol = "tcp"
    no_tags = []
    net_tags = ["test-tag"]
    # Matches on
    # all protocol and no target tags
    assert test_match(
        port,
        protocol,
        {
            "allowed": [{"IPProtocol": "all"}],
            "direction": "INGRESS",
            "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
        },
        no_tags,
    )
    # single port and target tags
    assert test_match(
        port,
        protocol,
        {
            "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            "direction": "INGRESS",
            "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
            "targetTags": ["test-tag"],
        },
        net_tags,
    )
    # port range and no target tags
    assert test_match(
        port,
        protocol,
        {
            "allowed": [{"IPProtocol": "tcp", "ports": ["20-25"]}],
            "direction": "INGRESS",
            "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
        },
        no_tags,
    )

    # Doesn't match on
    # wrong port/protocol
    assert not test_match(
        "50",
        "udp",
        {
            "allowed": [{"IPProtocol": "tcp", "ports": ["20-25"]}],
            "direction": "INGRESS",
            "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
        },
        no_tags,
    )
    # wrong target tag
    assert not test_match(
        port,
        protocol,
        {
            "allowed": [{"IPProtocol": "tcp", "ports": ["20-25"]}],
            "direction": "INGRESS",
            "disabled": False,
            "sourceRanges": ["0.0.0.0/0"],
            "targetTags": ["test-tag"],
        },
        ['bad_tag'],
    )
    # Disabled
    assert not test_match(
        port,
        protocol,
        {
            "allowed": [{"IPProtocol": "all"}],
            "direction": "INGRESS",
            "disabled": True,
            "sourceRanges": ["0.0.0.0/0"],
        },
        no_tags,
    )
