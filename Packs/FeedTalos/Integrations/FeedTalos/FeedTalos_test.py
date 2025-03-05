from FeedTalos import Client


URL = "https://talosintelligence.com/documents/ip-blacklist"


def test_build_iterator(requests_mock):
    with open("test_data/FeedTalos_mock.txt") as file:
        response = file.read()
    requests_mock.get(URL, text=response)
    expected_ipv4 = "91.212.135.158"
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )
    indicators = client.build_iterator()
    ipv4_indicators = {indicator["value"] for indicator in indicators if indicator["type"] == "IP"}
    assert expected_ipv4 in ipv4_indicators
