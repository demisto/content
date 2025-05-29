import json

from FeedFeedly import Client

URL = (
    "https://api.feedly.com/v3/enterprise/ioc?"
    "streamId=tag%2FenterpriseName%2Fcategory%2Fuuid&count=20"
    "&newerThan=0"
    "&client=feedly.demisto.client"
)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_build_iterator(requests_mock):
    """

    Given:
        - Output of the feed API
    When:
        - When calling fetch_indicators or get_indicators
    Then:
        - Returns a list of the indicators parsed from the API's response

    """
    with open("test_data/api_call_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_ips = {"31.31.194.65", "95.213.205.83", "77.223.124.212"}
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.fetch_indicators_from_stream("tag/enterpriseName/category/uuid", 0)
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}
    assert expected_ips == ip_indicators

    report = next(indicator for indicator in indicators if indicator["type"] == "Feedly Report")
    assert report["fields"]["description"].startswith("Recently, threat actors have")

    assert len(report["relationships"]) == 13

    feedly_tags = {"Domains", "Feedly AI", "IPs", "TTPs"}
    threat_tags = {"RMS", "TA505"}
    ttp_tags = {"T1112", "T1125", "T1132.001", "T1566", "T1566.001"}

    assert set(report["fields"]["tags"]) == feedly_tags | threat_tags | ttp_tags
