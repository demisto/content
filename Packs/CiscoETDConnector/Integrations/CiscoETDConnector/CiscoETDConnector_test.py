from CiscoETDConnector import ETDClient


def test_get_links():
    response = {"data": {"message": ["https://test1"], "audit": ["https://test2"], "connection": ["https://test3"]}}

    client = ETDClient(base_url="https://dummy", params={})

    links = client.get_links(response)

    assert links == [("message", "https://test1"), ("audit", "https://test2"), ("connection", "https://test3")]
