from ETDXsoarConnector import ETDClient


def test_get_links():
    """
    Given:
        ETD log export API response
    When:
        Extracting message download links
    Then:
        Verify message links are returned
    """
    response = {
        "data": {
            "message": [
                "https://test1",
                "https://test2"
            ]
        }
    }
    client = ETDClient(
        base_url="https://dummy",
        params={}
    )
    links = client.get_links(response)
    assert links == [
        "https://test1",
        "https://test2"
    ]
