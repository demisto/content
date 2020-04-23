from FeedGCPWhitelist import Client, google_base_dns, fetch_cidr


def test_fetch_cidr():
    client = Client(google_base_dns, False, False)
    cidr_arr = fetch_cidr(client)
    assert len(cidr_arr) > 0
