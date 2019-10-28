from Database import Client

"""
Response from API mock.
[
    [ID, DATE, NAME, URGENCY]
]
"""

RESPONSE_MOCK = [
    [1, "2010-01-01T00:00:00Z", 'Guy Freund', 'HIGH'],
    [2, "2011-01-01T00:00:00Z", 'Guy Freund', 'MED'],
    [3, "2012-01-01T00:00:00Z", 'Guy Freund', 'LOW']
]

URL = "http://123-fake-api.com"


class TestQuery:
    client = Client(URL)

    def test_query(self, requests_mock):
        from Database import query_command
        requests_mock.post(URL, json=RESPONSE_MOCK)
        r = query_command(self.client, {"query": "qqq"})
        assert r == 1
