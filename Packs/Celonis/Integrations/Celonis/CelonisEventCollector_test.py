import json

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MOCK_BASEURL = "https://example.com"
MOCK_API_KEY = "API_KEY"


def create_client():
    from CelonisEventCollector import Client
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        client_id=MOCK_API_KEY
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_sort_events_by_timestamp():
    pass