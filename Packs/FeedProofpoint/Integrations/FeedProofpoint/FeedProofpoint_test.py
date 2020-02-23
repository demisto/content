from FeedProofpoint import Client, fetch_indicators_command

url = "https://example.com"
auth_code = "cool"
client = Client(url, auth_code)


def test_fetch_ips(requests_mock):
    ip_path = "./TestData/detailed-iprep.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get(
        "https://example.com/cool/reputation/detailed-iprepdata.txt", text=data
    )
    indicators = fetch_indicators_command(client, client.IP_TYPE)
    assert 4 == len(indicators)


def test_fetch_domains(requests_mock):
    ip_path = "./TestData/detalied-domainrepdata.txt"
    with open(ip_path) as f:
        data = f.read()
    requests_mock.get(
        "https://example.com/cool/reputation/detailed-domainrepdata.txt", text=data
    )
    indicators = fetch_indicators_command(client, client.DOMAIN_TYPE)
    assert 9 == len(indicators)
