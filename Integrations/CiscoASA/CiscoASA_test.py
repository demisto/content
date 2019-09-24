import demistomock as demisto
from CiscoASA import Client


def test_get_all_rules(requests_mock):
    """
    ## test if there are no rule if there isn't a problem
    ## check all rules are returned
    ## check only In/Out/Global
    ## use requests_mock
    """
    from CiscoASA import list_rules_command
    mock_response = {"a": 1}
    requests_mock.get("https://example.com/wow", json=mock_response)

    client = Client('https://example.com', 'username', 'password', True, [])
    assert {} == client.http_request("GET", "/wow")
