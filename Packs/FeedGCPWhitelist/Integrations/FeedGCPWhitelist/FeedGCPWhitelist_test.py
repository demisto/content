from FeedGCPWhitelist import Client, google_base_dns


def test_build_iterator():
    client = Client(google_base_dns, False, False)
    cidr_arr = client.build_iterator()
    assert len(cidr_arr) > 0
