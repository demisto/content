from AutofocusFeed import Client

INDICATORS = [
    "d4da1b2d5554587136f2bcbdf0a6a1e29ab83f1d64a4b2049f9787479ad02fad",
    "19.117.63.253",
    "domaintools.com",
    "flake8.pycqa.org/en/latest",
    "19.117.63.253/28",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348",
    "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"
]

TYPES = [
    "File",
    "IP",
    "Domain",
    "URL",
    "CIDR",
    "IPv6",
    "IPv6CIDR"
]


def test_type_finder():
    client = Client(api_key="a", insecure=False, proxy=None, indicator_feeds=['Daily Threat Feed'])
    for i in range(0, 7):
        indicator_type = client.find_indicator_type(INDICATORS[i])
        assert indicator_type == TYPES[i]
