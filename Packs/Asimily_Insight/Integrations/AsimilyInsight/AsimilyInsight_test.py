import pytest
from CommonServerPython import *
from AsimilyInsight import Client

SERVER_URL = "http://localhost"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def client():
    return Client()
