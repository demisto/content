import demistomock as demisto

from ImportFromMinemeld import process_ip_list, main

TEST_LIST_NAME = "testList"
TEST_V6_LIST_NAME = "testListv6"

TEST_V4_NODE = {
    TEST_LIST_NAME: {
        "inputs": [],
        "output": True,
        "prototype": "stdlib.listIPv4Generic"
    },
}

TEST_V6_NODE = {
    TEST_V6_LIST_NAME: {
        "inputs": [],
        "output": True,
        "prototype": "stdlib.listIPv6Generic"
    },
}

TEST_IPV4_INDICATORS = [
    {
        "comment": "Example Comment",
        "indicator": "66.66.66.66",
        "share_level": "green"
    },
    {
        "comment": "Test another comment",
        "indicator": "88.88.8.8",
        "share_level": "green"
    },
    {
        "comment": "cidr comment",
        "indicator": "125.10.10.0/24",
        "share_level": "green"
    }
]

TEST_IPV6_INDICATORS = [
    {
        "comment": "Example Comment",
        "indicator": "2400:a000::23",
        "share_level": "red"
    },
    {
        "comment": "Test another comment",
        "indicator": "2400:a000::/32",
        "share_level": "green"
    }
]


class MockClient:
    def get_indicators(self, *args, **kwargs):
        if args[0] == TEST_LIST_NAME:
            return TEST_IPV4_INDICATORS
        elif args[0] == TEST_V6_LIST_NAME:
            return TEST_IPV6_INDICATORS

    def get_nodes(self, *args, **kwargs):
        r = {
            TEST_LIST_NAME: TEST_V4_NODE.get(TEST_LIST_NAME),
            TEST_V6_LIST_NAME: TEST_V6_NODE.get(TEST_V6_LIST_NAME)
        }
        return r


def test_process_ipv4_indicators():
    """
    Given an IPv4 list, ensure the indicators are processed as the correct types.
    """
    mock_client = MockClient()
    r = process_ip_list(mock_client, TEST_LIST_NAME, TEST_V4_NODE, "IP")
    assert len(r) == 3
    assert r[2].get("type") == "CIDR"
    assert r[0].get("type") == "IP"


def test_process_ipv6_indicators():
    """
    Given an IPv6 list, ensure the indicators are processed as the correct types.
    """
    mock_client = MockClient()
    r = process_ip_list(mock_client, TEST_V6_LIST_NAME, TEST_V6_NODE, "IPv6")
    assert len(r) == 2
    assert r[1].get("type") == "IPv6CIDR"
    assert r[0].get("type") == "IPv6"


def test_mock_main(mocker):
    """
    Test the full main with a mocked client and test data.
    Test data should result in 5 indicators being created.

    """
    mock_client = MockClient()
    mocker.patch.object(demisto, "executeCommand")
    main(mock_client)
    assert demisto.executeCommand.call_count == 5
