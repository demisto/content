from XForceExchange import Client, ip_command

MOCK_BASE_URL = 'https://www.this-is-a-fake-url.com'
MOCK_API_KEY = 'FAKE-API-KEY'
MOCK_PASSWORD = 'FAKE-PASSWORD'

MOCK_IP = '8.8.8.8'

MOCK_IP_RESP = {
    "ip": "8.8.8.8",
    "history": [
        {
            "created": "2012-03-22T07:26:00.000Z",
            "reason": "Regional Internet Registry",
            "geo": {
                "country": "United States",
                "countrycode": "US"
            },
            "ip": "8.0.0.0/8",
            "categoryDescriptions": {},
            "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
            "score": 1,
            "cats": {}
        }],
    "subnets": [
        {
            "created": "2018-04-24T06:22:00.000Z",
            "reason": "Regional Internet Registry",
            "reason_removed": True,
            "asns": {
                "3356": {
                    "removed": True,
                    "cidr": 8
                }
            },
            "ip": "8.0.0.0",
            "categoryDescriptions": {},
            "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
            "score": 1,
            "cats": {},
            "subnet": "8.0.0.0/8"
        }
    ],
    "cats": {},
    "geo": {
        "country": "United States",
        "countrycode": "US"
    },
    "score": 1,
    "reason": "Regional Internet Registry",
    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
    "categoryDescriptions": {},
    "tags": []
}


def test_ip(requests_mock):
    requests_mock.get(MOCK_BASE_URL + f'/ipr/{MOCK_IP}', json=MOCK_IP_RESP)

    client = Client(MOCK_BASE_URL,
                    MOCK_API_KEY,
                    MOCK_PASSWORD,
                    True, False)
    args = {
        'ip': MOCK_IP
    }
    _, outputs, _ = ip_command(client, args)
    assert outputs['IP(obj.Address==val.Address)']['Address'] == MOCK_IP
