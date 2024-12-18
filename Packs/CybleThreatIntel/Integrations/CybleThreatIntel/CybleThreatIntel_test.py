from unittest.mock import patch

import demistomock as demisto

from datetime import datetime, timedelta
import json
import pytz
import pytest


UTC = pytz.UTC

input_value = json.load(open("test_data/input.json"))
params = input_value['params']
args = input_value['args']
args2 = input_value['args2']
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S+00:00"


def load_json_file(filename):
    """
    Loads the json content and return the json object
    :param filename:
    :return:
    """
    content = None
    with open(f"test_data/{filename}") as f:
        content = json.load(f)
    return content


def test_get_recursively():
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    val = Client.get_recursively(client, mock_response_1[0][0]['indicators'][0], "value")
    assert isinstance(val, list)
    assert 'URL Watchlist' in val
    assert 'http://kbjunktest.com/path' in val


def test_build_indicators():
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    mock_response_2 = load_json_file("results.json")
    val = Client.build_indicators(client, args, mock_response_1[0])
    assert isinstance(val, list)
    assert mock_response_2 == val


def test_get_parse_to_json():
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = str(open("test_data/data.xml").read())
    mock_response_3 = load_json_file("data.json")
    val = Client.parse_to_json(client, mock_response_1)
    assert isinstance(val, dict)
    assert mock_response_3 == val


def test_get_taxii(mocker):
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = str(open("test_data/data.xml").read())
    mock_response_3 = load_json_file("data.json")
    mocker.patch.object(client, 'fetch', return_value=[mock_response_1])
    val, time = Client.get_taxii(client, args)
    assert isinstance(val, list)
    assert isinstance(time, str)
    assert mock_response_3 == val[0]


def test_get_taxii_failure(mocker):
    from CybleThreatIntel import Client
    client = Client(params)

    mocker.patch.object(client, 'fetch', return_value=[])
    val, time = Client.get_taxii(client, args)
    assert isinstance(val, list)
    assert [] == val


def test_get_taxii_error(mocker, capfd):
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = """
                <stix:STIX_Package id="example:Package-19548504-7169-4b2e-9b54-0fa1c3d931f8" version="1.2">
                </stix:STIX_Package>
                """
    mocker.patch.object(client, 'fetch', return_value=[mock_response_1])
    mocker.patch.object(demisto, 'debug')
    Client.get_taxii(client, args)

    assert "Namespace prefix stix on STIX_Package is not defined" in demisto.debug.call_args[0][0]


def test_get_services(mocker):
    from CybleThreatIntel import Client
    client = Client(params)

    mocker.patch.object(client, 'client', return_value=[])
    val = Client.get_services(client)
    assert isinstance(val, list)
    assert val == []


def test_module(mocker):
    """
    Test the basic test command for Cyble Threat Intel
    :return:
    """
    # import requests_mock
    from CybleThreatIntel import Client, get_test_response
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    mocker.patch.object(client, 'get_taxii', return_value=mock_response_1)
    response = get_test_response(client, {})

    assert isinstance(response, str)
    assert response == 'ok'


def test_module_failure(mocker):
    """
    Test the basic test command for Cyble Threat Intel
    :return:
    """
    # import requests_mock
    from CybleThreatIntel import Client, get_test_response
    client = Client(params)

    mocker.patch.object(client, 'get_taxii', return_value=[])
    response = get_test_response(client, {})

    assert isinstance(response, str)
    assert response == 'Unable to Contact Feed Service, Please Check the parameters.'


def test_module_error(mocker):
    """
    Test the basic test command for Cyble Threat Intel
    :return:
    """
    from CybleThreatIntel import Client, get_test_response
    client = Client(params)
    mocker.patch.object(client, 'get_taxii', return_value={})
    response = get_test_response(client, {})

    assert isinstance(response, str)
    assert response == 'Unable to Contact Feed Service, Please Check the parameters.'


def test_cyble_fetch_taxii(mocker):
    from CybleThreatIntel import Client, cyble_fetch_taxii
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    mock_response_2 = load_json_file("results.json")
    mocker.patch.object(client, 'get_taxii', return_value=mock_response_1)
    mocker.patch.object(client, 'build_indicators', return_value=mock_response_2)
    response = cyble_fetch_taxii(client, args).outputs

    assert response[0]['rawJSON'] == mock_response_1[0][0]


@pytest.mark.parametrize(
    "begin", [
        "2022-06-73 00:00:00",
        "2022-46-13 00:00:00",
        "2022-06-13 88:00:00",
        "2022-06-13 00:67:00",
        "2022-06-13 00:00:67"
    ]
)
def test_cyble_fetch_taxii_error(mocker, begin):
    from CybleThreatIntel import Client, cyble_fetch_taxii
    client = Client(params)

    args = {
        "limit": 5,
        "begin": begin,
        "end": "2022-06-13 00:00:00",
        "collection": "phishing_url"
    }

    mock_response_1 = load_json_file("test.json")
    mock_response_2 = load_json_file("results.json")
    mocker.patch.object(client, 'get_taxii', return_value=mock_response_1)
    mocker.patch.object(client, 'build_indicators', return_value=mock_response_2)
    error_val = None
    try:
        cyble_fetch_taxii(client, args).outputs
    except Exception as e:
        error_val = e.args[0]

    assert "Invalid date format received" in error_val


def test_fetch_indicators(mocker):
    from CybleThreatIntel import Client, fetch_indicators
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    mock_response_2 = load_json_file("results.json")
    mocker.patch.object(client, 'get_taxii', return_value=mock_response_1)
    mocker.patch.object(client, 'build_indicators', return_value=mock_response_2)
    raw_response = fetch_indicators(client)

    assert raw_response == mock_response_2


def test_limit_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": -5,
        "begin": "2022-06-11 00:00:00",
        "end": "2022-06-13 00:00:00",
        "collection": "phishing_url"
    }
    with capfd.disabled(), pytest.raises(ValueError, match=f"Limit should be positive, limit: {args.get('limit', 0)}"):
        validate_input(args=args)


def test_sdate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": "2022-06-73 00:00:00",
        "end": "2022-06-13 00:00:00",
        "collection": "phishing_url"
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Invalid date format received"):
        validate_input(args=args)


def test_edate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": "2022-06-13 00:00:00",
        "end": "2022-06-73 00:00:00",
        "collection": "phishing_url"
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Invalid date format received"):
        validate_input(args=args)


@pytest.mark.parametrize(
    "limit", [1, 10, 174, 1060]
)
def test_date_validate_input(capfd, limit):
    from CybleThreatIntel import validate_input

    args = {
        "limit": limit,
        "begin": str(datetime.now(tz=UTC).strftime(DATETIME_FORMAT)),
        "end": str((datetime.now(tz=UTC) - timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Start date cannot be after end date"):
        validate_input(args=args)


def test_idate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str(datetime.now(tz=UTC).strftime(DATETIME_FORMAT)),
        "end": str((datetime.now(tz=UTC) + timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled(), pytest.raises(ValueError, match="End date must be a date before or equal to current"):
        validate_input(args=args)


def test_end_date_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str((datetime.now(tz=UTC) + timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "end": str(datetime.now(tz=UTC).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled(), pytest.raises(ValueError, match="Start date must be a date before or equal to current"):
        validate_input(args=args)


def test_collection_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str((datetime.now(tz=UTC) - timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "end": str(datetime.now(tz=UTC).strftime(DATETIME_FORMAT)),
        "collection": ""
    }

    with capfd.disabled(), pytest.raises(ValueError, match="Collection Name should be provided: None"):
        validate_input(args=args)


def test_feed_collection(mocker):
    from CybleThreatIntel import Client, get_feed_collection
    client = Client(params)

    mock_response_1 = load_json_file("collection.json")
    mocker.patch.object(client, 'get_services', return_value=mock_response_1)
    response = get_feed_collection(client).outputs
    assert isinstance(response, dict)
    assert response == mock_response_1


def test_build_indicators_single_observable():
    """
    Given: A single observable with a valid value.
    When: build_indicators is called with one indicator entry.
    Then: A single indicator should be returned with correct type and value.
    """
    from CybleThreatIntel import Client

    client = Client(params)

    input_data = [{
        "indicators": [{
            "observable": [{"value": "1.1.1.1"}],
            "title": "Test Indicator",
            "timestamp": "2024-01-01T00:00:00Z"
        }]
    }]

    recursive_returns = ["1.1.1.1"]

    with patch.object(client, 'get_recursively', return_value=recursive_returns), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.side_effect = lambda x: "IP" if x == "1.1.1.1" else None
        args = {}
        result = client.build_indicators(args, input_data)

    assert len(result) == 1
    assert result[0]["value"] == "1.1.1.1"
    assert result[0]["type"] == "IP"
    assert result[0]["title"] == "Test Indicator"
    assert result[0]["time"] == "2024-01-01T00:00:00Z"
    assert result[0]["service"] == "Cyble Feed"


def test_build_indicators_multiple_observables():
    """
    Given: Multiple observables, including a domain and an IP.
    When: build_indicators is called with these observables.
    Then: A single indicator should be returned with a type and value determined by the order detected.
    """
    from CybleThreatIntel import Client

    client = Client(params)

    input_data = [{
        "indicators": [{
            "observable": [{"value": "www.test.com"}, {"value": "1.1.1.1"}],
            "title": "Mixed Indicator",
            "timestamp": "2024-01-02T00:00:00Z"
        }]
    }]

    recursive_returns = ["www.test.com", "1.1.1.1"]

    with patch.object(client, 'get_recursively', return_value=recursive_returns), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        def side_effect(value):
            if "test.com" in str(value):
                return "Domain"
            elif "1.1.1.1" in str(value):
                return "IP"
            return None

        mock_auto_detect.side_effect = side_effect
        args = {}
        result = client.build_indicators(args, input_data)

    assert len(result) == 1
    assert result[0]["title"] == "Mixed Indicator"
    assert result[0]["time"] == "2024-01-02T00:00:00Z"
    assert result[0]["service"] == "Cyble Feed"
    # Check the type and value chosen
    assert result[0]["type"] in ["Domain", "IP"]
    assert result[0]["value"] in ["www.test.com", "1.1.1.1"]


def test_build_indicators_no_observable_field():
    """
    Given: Input data with no observable field.
    When: build_indicators is called.
    Then: No indicators should be returned.
    """
    from CybleThreatIntel import Client

    client = Client(params)

    input_data = [{
        "observables": {
            "observables": [{"value": None}]
        }
    }]

    with patch.object(client, 'get_recursively', return_value=None), \
            patch('CommonServerPython.auto_detect_indicator_type') as mock_auto_detect:
        mock_auto_detect.return_value = None
        args = {}
        result = client.build_indicators(args, input_data)

    assert len(result) == 0
