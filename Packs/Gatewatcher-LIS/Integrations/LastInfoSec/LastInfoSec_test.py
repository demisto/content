from LastInfoSec import (
    lis_get_by_minute,
    lis_get_by_value,
    GwClient,
    GwAPIException
)

import inspect
import json
import pytest


def load_json(file):
    with open(file, 'r') as f:
        return json.load(f)


@pytest.fixture
def get_by_minute():
    return load_json("test_data/get_by_minute.json")


@pytest.fixture
def get_by_minute_result():
    return load_json("test_data/get_by_minute_result.json")


@pytest.fixture
def get_by_value():
    return load_json("test_data/get_by_value.json")


@pytest.fixture
def get_by_value_result():
    return load_json("test_data/get_by_value_result.json")


@pytest.fixture
def prefix_mapping():
    return {
        "lis_get_by_minute": "LIS.GetByMinute",
        "lis_get_by_minute_with_filter": "LIS.GetByMinute",
        "lis_get_by_value": "LIS.GetByValue",
    }


@pytest.fixture
def client():
    client = GwClient(token="XZXZXZXZXZXZXZXXZ")
    return client


@pytest.mark.parametrize("error", [{"Minute": "error"}, {"Minute": "2", "Type": "Filename"},
                                   {"Minute": "2", "Risk": "Informational"}])
def test_lis_get_by_minute_with_error(client, prefix_mapping, error, get_by_minute, get_by_minute_result):
    with pytest.raises(ValueError):
        lis_get_by_minute(client, error)


def test_lis_get_by_minute_with_filter(client, requests_mock, prefix_mapping, get_by_minute, get_by_minute_result):
    args = {
        "Minute": "2",
        "Type": "SHA1",
        "Risk": "Suspicious",
        "TLP": "white",
        "Categories": "malware"
    }
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        json=get_by_minute,
        status_code=200
    )
    response = lis_get_by_minute(client, args)
    assert response.outputs == [get_by_minute_result[0]]
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_minute(client, args)


def test_lis_get_by_minute(client, requests_mock, prefix_mapping, get_by_minute, get_by_minute_result):
    args = {
        "Minute": "2"
    }
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        json=get_by_minute,
        status_code=200
    )
    response = lis_get_by_minute(client, args)
    assert response.outputs == get_by_minute_result
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.get(
        f"https://api.client.lastinfosec.com/v2/lis/getbyminutes/2?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_minute(client, args)


def test_lis_get_by_value(client, requests_mock, prefix_mapping, get_by_value, get_by_value_result):
    args = {"Value": "b71c7db7c4b20c354f63820df1f5cd94dbec97849afa690675d221964b8176b5"}
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        json=get_by_value,
        status_code=200
    )
    response = lis_get_by_value(client, args)
    assert response.outputs == get_by_value_result
    assert response.outputs_prefix == prefix_mapping[
        inspect.stack()[0][3].replace("test_", "")
    ]
    requests_mock.post(
        f"https://api.client.lastinfosec.com/v2/lis/search?api_key={client.token}&headers=false",
        status_code=500
    )
    with pytest.raises(GwAPIException):
        lis_get_by_value(client, args)
