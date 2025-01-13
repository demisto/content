import copy
import json
import pytest

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

MOCK_BASEURL = "https://example.com"
MOCK_API_KEY = "API_KEY"


def create_client():
    from ProofpointIsolationEventCollector import Client
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        api_key=MOCK_API_KEY
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())

