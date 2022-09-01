from datetime import datetime, timedelta, timezone
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


def test_get_recursively():
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = load_json_file("test.json")
    val = Client.get_recursively(client, mock_response_1[0][0], "value")
    assert isinstance(val, list)
    assert 'URL Watchlist' in val


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

    mock_response_1 = str(open("test_data/data.xml", "r").read())
    mock_response_3 = load_json_file("data.json")
    val = Client.parse_to_json(client, mock_response_1)
    assert isinstance(val, dict)
    assert mock_response_3 == val


def test_get_taxii(mocker):
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = str(open("test_data/data.xml", "r").read())
    mock_response_3 = load_json_file("data.json")
    mocker.patch.object(client, 'fetch', return_value=[mock_response_1])
    val, time = Client.get_taxii(client, args)
    assert isinstance(val, list)
    assert isinstance(time, str)
    assert mock_response_3 == val[0]


def test_get_taxii_invalid(mocker, capfd):
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = str(open("test_data/data_err.xml", "r").read())
    mocker.patch.object(client, 'fetch', return_value=[mock_response_1])
    with capfd.disabled():
        try:
            val, time = Client.get_taxii(client, args)
        except Exception as e:
            error_val = e.args[0]

    assert "Last fetch time retrieval failed." in error_val


def test_get_taxii_failure(mocker):
    from CybleThreatIntel import Client
    client = Client(params)

    mocker.patch.object(client, 'fetch', return_value=[])
    val, time = Client.get_taxii(client, args)
    assert isinstance(val, list)
    assert time is None
    assert [] == val


def test_get_taxii_error(mocker, capfd):
    from CybleThreatIntel import Client
    client = Client(params)

    mock_response_1 = """
                <stix:STIX_Package id="example:Package-19548504-7169-4b2e-9b54-0fa1c3d931f8" version="1.2">
                </stix:STIX_Package>
                """
    mocker.patch.object(client, 'fetch', return_value=[mock_response_1])
    with capfd.disabled():
        try:
            val, time = Client.get_taxii(client, args)
        except Exception as e:
            error_val = e.args[0]

    assert "Namespace prefix stix on STIX_Package is not defined" in error_val


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

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match="Invalid date format received"):
            validate_input(args=args)


@pytest.mark.parametrize(
    "limit", [1, 10, 174, 1060]
)
def test_date_validate_input(capfd, limit):
    from CybleThreatIntel import validate_input

    args = {
        "limit": limit,
        "begin": str(datetime.now(timezone.utc).strftime(DATETIME_FORMAT)),
        "end": str((datetime.now(timezone.utc) - timedelta(days=1)).strftime(DATETIME_FORMAT)),
        "collection": "phishing_url"
    }

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match="Start date cannot be after end date"):
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
        with pytest.raises(ValueError, match="End date must be a date before or equal to current"):
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
        with pytest.raises(ValueError, match="Start date must be a date before or equal to current"):
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
        with pytest.raises(ValueError, match="Collection Name should be provided: None"):
            validate_input(args=args)


def test_feed_collection(mocker):
    from CybleThreatIntel import Client, get_feed_collection
    client = Client(params)

    mock_response_1 = load_json_file("collection.json")
    mocker.patch.object(client, 'get_services', return_value=mock_response_1)
    response = get_feed_collection(client).outputs
    assert isinstance(response, dict)
    assert response == mock_response_1
