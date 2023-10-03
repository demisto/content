import json

from FeedFeedly import Client

URL = "https://api.feedly.com/v3/enterprise/ioc?streamId=tag%2FenterpriseName%2Fcategory%2Fuuid&count=20&newerThan=0&client=feedly.demisto.client"


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
    expected_ip = "1.2.3.4"
    client = Client(base_url=URL, verify=False, proxy=False,)
    indicators = client.fetch_indicators_from_stream("tag/enterpriseName/category/uuid", 0)
    ip_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}
    assert {expected_ip} == ip_indicators
    report = next(indicator for indicator in indicators if indicator["type"] == "Report")
    assert report["fields"]["description"] == "This is a report."
