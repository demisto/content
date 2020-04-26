from FeedGCPWhitelist import Client, GOOGLE_BASE_DNS


def test_build_iterator():
    client = Client(GOOGLE_BASE_DNS, False, False)
    cidr_arr = client.build_iterator()
    assert len(cidr_arr) > 0
