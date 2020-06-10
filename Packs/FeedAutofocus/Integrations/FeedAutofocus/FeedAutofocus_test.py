from FeedAutofocus import Client

INDICATORS = [
    "d4da1b2d5554587136f2bcbdf0a6a1e29ab83f1d64a4b2049f9787479ad02fad",
    "19.117.63.253",
    "19.117.63.253:8080",
    "domaintools.com",
    "flake8.pycqa.org/en/latest",
    "19.117.63.253/28",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348/32",
    "19.117.63.253:28/other/path"
]

TYPES = [
    "File",
    "IP",
    "IP",
    "Domain",
    "URL",
    "CIDR",
    "IPv6",
    "IPv6CIDR",
    "URL"
]


def test_type_finder():
    client = Client(api_key="a", insecure=False, proxy=None, indicator_feeds=['Daily Threat Feed'])
    for i in range(0, 9):
        indicator_type = client.find_indicator_type(INDICATORS[i])
        assert indicator_type == TYPES[i]


def test_url_format():
    client = Client(api_key="a", insecure=False, proxy=None, indicator_feeds=['Daily Threat Feed'])
    url1 = "https://autofocus.paloaltonetworks.com/IOCFeed/{ID}/{Name}"
    url2 = "autofocus.paloaltonetworks.com/IOCFeed/{ID2}/{Name2}"
    assert client.url_format(url1) == "https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/{ID}/{Name}"
    assert client.url_format(url2) == "https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/{ID2}/{Name2}"
