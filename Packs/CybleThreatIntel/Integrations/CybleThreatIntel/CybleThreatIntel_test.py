from datetime import datetime, timedelta, timezone
import demistomock as demisto
import json
import pytest

input_value = json.load(open("test_data/input.json", "r"))
params = input_value['params']
args = input_value['args']
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S+00:00"


def load_json_file(filename):
    """
    Loads the json content and return the json object
    :param filename:
    :return:
    """
    content = None
    with open("test_data/{0}".format(filename), 'r') as f:
        content = json.load(f)
    return content


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
    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Limit should be positive, limit: {args.get('limit', 0)}"):
            validate_input(args=args)


def test_sdate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": "2022-06-73 00:00:00",
        "end": "2022-06-13 00:00:00",
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"Invalid date format received"):
            validate_input(args=args)


def test_edate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": "2022-06-13 00:00:00",
        "end": "2022-06-73 00:00:00",
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"Invalid date format received"):
            validate_input(args=args)


def test_date_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str(datetime.now(timezone.utc).strftime(DATETIME_FORMAT)),
        "end": str((datetime.now(timezone.utc) - timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"Start date cannot be after end date"):
            validate_input(args=args)


def test_idate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str(datetime.now(timezone.utc).strftime(DATETIME_FORMAT)),
        "end": str((datetime.now(timezone.utc) + timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError, match=f"End date must be a date before or equal to current"):
            validate_input(args=args)


def test_end_date_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str((datetime.now(timezone.utc) + timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "end": str(datetime.now(timezone.utc).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Start date must be a date before or equal to current"):
            validate_input(args=args)


def test_collection_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        "limit": 5,
        "begin": str((datetime.now(timezone.utc) - timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "end": str(datetime.now(timezone.utc).strftime(DATETIME_FORMAT)),
        "collection": ""
    }

    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Collection Name should be provided: None"):
            validate_input(args=args)


def test_feed_collection(mocker):
    from CybleThreatIntel import Client, get_feed_collection
    client = Client(params)

    mock_response_1 = load_json_file("collection.json")
    mocker.patch.object(client, 'get_services', return_value=mock_response_1)
    response = get_feed_collection(client).outputs
    assert isinstance(response, dict)
    assert response == mock_response_1
