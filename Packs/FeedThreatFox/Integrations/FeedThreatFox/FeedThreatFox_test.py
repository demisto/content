from CommonServerPython import DemistoException, FeedIndicatorType
import json
from freezegun import freeze_time
import pytest

import FeedThreatFox as ftf

CLIENT = ftf.Client(base_url="https://threatfox-api.abuse.ch/")


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_get_indicators_request(mocker):
    """
    Given:
        - A query.

    When:
        - Running get_indicators_request function.

    Then:
        - The http request is called with the right query.
    """
    http_request = mocker.patch.object(CLIENT, "_http_request", return_value={})
    query = {"query": "ioc", "id": 41}
    CLIENT.get_indicators_request(query)
    assert http_request.call_args.kwargs["json_data"] == query


test_check_params_good_arguments_data = [
    (
        {"id": 41, "limit": 10},  # case id with unnecessary limit
        ("id"),  # expected
    ),
    (
        {"search_term": "1.1.1.1"},  # case search_term
        ("search_term"),  # expected
    ),
    (
        {"hash": "2151c4b970eff0071948dbbc19066aa4"},  # case hash
        ("hash"),  # expected
    ),
    (
        {"tag": "Magecart", "limit": 10},  # case tag with limit
        ("tag"),  # expected
    ),
    (
        {"malware": "Cobalt Strike", "limit": 10},  # case malware without limit (limit is needed, there is a default value)
        ("malware"),  # expected
    ),
]


@pytest.mark.parametrize("query_args, expected_result", test_check_params_good_arguments_data)
def test_check_args_good_arguments(query_args, expected_result):
    """
    Given:
        - Good arguments for a query.

    When:
        - Running check_params function.

    Then:
        - The function returns (True, {the argument's name}).
    """
    from FeedThreatFox import check_args_for_query

    query_arg = check_args_for_query(query_args)
    assert query_arg == expected_result


test_check_params_bad_arguments_data = [
    ({"days": 1, "tag": "bla"}),  # case two argument are given
    ({}),  # case no arguments are given
]


@pytest.mark.parametrize("query_args", test_check_params_bad_arguments_data)
def test_check_args_bad_arguments(query_args):
    """
    Given:
        - Wrong arguments for a query.

    When:
        - Running check_params function.

    Then:
        - The function returns (False, None).
    """
    from FeedThreatFox import check_args_for_query

    with pytest.raises(DemistoException):
        check_args_for_query(query_args)


test_create_query_data = [
    (
        "tag",
        {
            "tag": "bla",
            "limit": 10,
            "id": None,
            "search_term": None,
            "hash": None,
            "days": None,
            "malware": None,
        },  # case tag  with needed limit
        {"query": "taginfo", "tag": "bla", "limit": 10},
    ),  # expected query with limit
    (
        "tag",
        {
            "tag": "bla",
            "limit": None,
            "id": None,
            "search_term": None,
            "hash": None,
            "days": None,
            "malware": None,
        },  # case tag with no needed limit
        {"query": "taginfo", "tag": "bla", "limit": 50},
    ),  # expected query with default limit
]


@pytest.mark.parametrize("query_arg, args, expected_query", test_create_query_data)
def test_create_query(query_arg, args, expected_query):
    """
    Given:
        - Wrong arguments for a query.

    When:
        - Running create_query function.

    Then:
        - The function returns (False, None).
    """
    from FeedThreatFox import create_query

    query = create_query(
        query_arg,
        id=args["id"],
        search_term=args["search_term"],
        hash=args["hash"],
        tag=args["tag"],
        malware=args["malware"],
        limit=args["limit"],
    )
    assert query == expected_query


def test_threatfox_get_indicators_command__bad_args():
    """
    Given:
        - Invalid arguments.

    When:
        - Running threatfox-get-indicators command.

    Then:
        - An exception is thrown.
    """
    from FeedThreatFox import threatfox_get_indicators_command
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException):
        threatfox_get_indicators_command(CLIENT, {"days": 1, "tag": "bla"})


def test_threatfox_get_indicators_command__bad_response(mocker):
    """
    Given:
        - Arguments with no relevant indicators.

    When:
        - Running threatfox-get-indicators command.

    Then:
        - An exception is thrown.
    """
    from FeedThreatFox import threatfox_get_indicators_command
    from CommonServerPython import DemistoException

    mocker.patch.object(CLIENT, "_http_request", return_value={"query_status": "not okay", "data": "details about the problem"})
    with pytest.raises(DemistoException):
        threatfox_get_indicators_command(CLIENT, {"tag": "bla"})


def test_threatfox_get_indicators_command(mocker):
    """
    Given:
        - Arguments.

    When:
        - Running threatfox-get-indicators command.

    Then:
        - The http request is called with the right argument.
    """
    from FeedThreatFox import threatfox_get_indicators_command

    http = mocker.patch.object(CLIENT, "_http_request", return_value={"query_status": "ok", "data": {}})
    threatfox_get_indicators_command(CLIENT, {"id": "41"})
    assert http.call_args.kwargs["json_data"] == {"query": "ioc", "id": 41}


indicator_data = [
    (
        {
            "id": "123",
            "ioc": "1.1.1.1:80",
            "threat_type_desc": "bla1",  # case tags and reporter
            "ioc_type": "ip:port",
            "malware": "bla2",
            "malware_printable": "bla3",
            "malware_alias": "bla4",
            "confidence_level": 100,
            "first_seen": "2024-08-04 07:31:49 UTC",
            "last_seen": "2024-07-03T05:11:35Z UTC",
            "reference": "bla5",
            "reporter": "bla6",
            "tags": ["bla7", "bla8"],
        },
        [
            {
                "ID": "123",
                "Value": "1.1.1.1",
                "Description": "bla1",
                "MalwareFamilyTags": "bla3",  # expected
                "AliasesTags": "bla4",
                "FirstSeenBySource": "2024-08-04 07:31:49 UTC",
                "LastSeenBySource": "2024-07-03T05:11:35Z UTC",
                "ReportedBy": "bla6",
                "Tags": ["bla3", "bla4", "bla7", "bla8", "port: 80"],
                "Confidence": "100",
                "Publications": [{"link": "bla5", "title": "bla3", "source": "ThreatFox"}],
            }
        ],
        ["bla3", "bla4", "bla7", "bla8", "port: 80"],
    ),
    (
        [
            {
                "id": "456",
                "ioc": "habdvhbkj",  # case no tags and no reporter
                "threat_type_desc": "bla1",
                "ioc_type": "sha1_hash",
                "malware": "bla2",
                "malware_printable": "bla3",
                "malware_alias": "bla4",
                "confidence_level": 100,
                "first_seen": "2024-08-04 07:31:49 UTC",
                "last_seen": "2024-07-03T05:11:35Z UTC",
            }
        ],
        [
            {
                "ID": "456",
                "Value": "habdvhbkj",
                "Description": "bla1",
                "MalwareFamilyTags": "bla3",  # expected
                "AliasesTags": "bla4",
                "FirstSeenBySource": "2024-08-04 07:31:49 UTC",
                "LastSeenBySource": "2024-07-03T05:11:35Z UTC",
                "Tags": ["bla3", "bla4"],
                "Confidence": "100",
            }
        ],
        ["bla3", "bla4"],
    ),
]


@pytest.mark.parametrize("indicators, expected, tags", indicator_data)
def test_parse_indicators_for_get_command(mocker, indicators, expected, tags):
    """
    Given:
        - The raw response of an indicator.

    When:
        - Running parse_indicators_for_get_command func.

    Then:
        - The indicator returned is parsed correctly.
    """
    from FeedThreatFox import parse_indicators_for_get_command

    mocker.patch("FeedThreatFox.tags", return_value=tags)
    res = parse_indicators_for_get_command(indicators)
    assert res == expected


types_data = [
    ({"ioc_type": "domain"}, FeedIndicatorType.FQDN),
    ({"ioc_type": "url"}, FeedIndicatorType.URL),
    ({"ioc_type": "ip:port"}, FeedIndicatorType.IP),
    ({"ioc_type": "envelope_from"}, FeedIndicatorType.Email),
    ({"ioc_type": "body_from"}, FeedIndicatorType.Email),
    ({"ioc_type": "sha1_hash"}, FeedIndicatorType.File),
]


@pytest.mark.parametrize("indicator, expected_type", types_data)
def test_indicator_type(indicator, expected_type):
    """
    Given:
        - An indicator.

    When:
        - Running indicator_type func.

    Then:
        - The right indicator type is returned.
    """
    from FeedThreatFox import indicator_type

    type = indicator_type(indicator)
    assert type == expected_type


publications_data = [
    ({}, None),  # case no reference field
    (
        {"reference": "bla", "malware_printable": "Unknown malware"},  # case malware_printable in unknown
        [{"link": "bla", "title": "Malware", "source": "ThreatFox"}],
    ),
    (
        {"reference": "bla", "malware_printable": "bla2"},  # case there is malware_printable
        [{"link": "bla", "title": "bla2", "source": "ThreatFox"}],
    ),
    (
        {"reference": "bla"},  # case no malware_printable field
        [{"link": "bla", "title": "Malware", "source": "ThreatFox"}],
    ),
]


@pytest.mark.parametrize("indicator, expected", publications_data)
def test_publications(indicator, expected):
    """
    Given:
        - An indicator.

    When:
        - Running publications func.

    Then:
        - The right publications list is returned.
    """
    from FeedThreatFox import publications

    publications = publications(indicator)
    assert publications == expected


date_data = [("2024-07-03T05:11:35 UTC", "2024-07-03T05:11:35Z"), (None, None)]


@pytest.mark.parametrize("given_date, expected", date_data)
def test_date(given_date, expected):
    """
    Given:
        - A date from raw response.

    When:
        - Running date func.

    Then:
        - The date is parsed correctly.
    """
    from FeedThreatFox import to_date

    res_date = to_date(given_date)
    assert res_date == expected


tags_data = [
    (
        {
            "malware_alias": "bla2",
            "threat_type": "bla3",  # case ip and malware_alias and threat_type
            "ioc_type": "ip:port",
            "ioc": "1.1.1.1:80",
            "tags": ["bla6"],
        },
        True,
        ["bla2", "bla3", "port: 80", "bla6"],
    ),  # expected
    (
        {"malware_printable": "bla1", "tags": ["bla4", "bla5"]},
        False,  # case malware_printable and tags
        ["bla1", "bla5", "bla4"],
    ),  # expected
    (
        {"malware_printable": "Unknown malware"},
        False,  # case malware_printable in unknown
        [],
    ),  # expected
]


@pytest.mark.parametrize("indicator, with_ports, expected_tags", tags_data)
def test_tags(indicator, with_ports, expected_tags):
    """
    Given:
        - The raw json of an indicator and a with_ports boolean argument.

    When:
        - Running tags func.

    Then:
        - The right list of tags to add to the indicator is returned.
    """
    from FeedThreatFox import tags

    tags = tags(indicator, with_ports)
    assert set(tags) == set(expected_tags)


value_data = [({"ioc_type": "ip:port", "ioc": "1.1.1.1:80"}, "1.1.1.1"), ({"ioc_type": "url", "ioc": "www..."}, "www...")]


@pytest.mark.parametrize("indicator, expected_value", value_data)
def test_value(indicator, expected_value):
    """
    Given:
        - The raw json of an indicator.

    When:
        - Running value func.

    Then:
        - The value of the indicator is given, when the value is an ip and port then the port is dumped.
    """
    from FeedThreatFox import get_value

    value = get_value(indicator)
    assert value == expected_value


relationships_data = [
    (
        "bla1",
        "bla2",
        None,
        FeedIndicatorType.Email,  # case no related_malware field
        [],
    ),  # case no relationships
    (
        "bla3",
        "domain",
        "bla4",
        FeedIndicatorType.FQDN,  # case indicator type is domain
        [
            {
                "name": "communicated-by",
                "reverseName": "communicated-with",  # expected communicated-by relationship
                "type": "IndicatorToIndicator",
                "entityA": "bla3",
                "entityAFamily": "Indicator",
                "entityAType": "Domain",
                "entityB": "bla4",
                "entityBFamily": "Indicator",
                "entityBType": "Malware",
                "fields": {},
            }
        ],
    ),
    (
        "bla5",
        "sha1_hash",
        "bla6",
        FeedIndicatorType.File,  # case indicator type is file
        [
            {
                "name": "related-to",
                "reverseName": "related-to",
                "type": "IndicatorToIndicator",  # expected related-to relationship
                "entityA": "bla5",
                "entityAFamily": "Indicator",
                "entityAType": "File",
                "entityB": "bla6",
                "entityBFamily": "Indicator",
                "entityBType": "Malware",
                "fields": {},
            }
        ],
    ),
]


@pytest.mark.parametrize("value, type, related_malware, demisto_ioc_type, expected", relationships_data)
def test_create_relationships(value, type, related_malware, demisto_ioc_type, expected):
    """
    Given:
        - A value, type and related_malware fields of an indicator.

    When:
        - Running create_relationships func.

    Then:
        - The right relationships are returned from the function.
    """
    from FeedThreatFox import create_relationships

    relationships = create_relationships(value, type, related_malware, demisto_ioc_type)
    assert relationships == expected


parse_fetch_data = [
    (
        {
            "id": "123",
            "ioc": "www...",
            "threat_type": "bla1",  # case without relationships and malware_printable is unknown
            "threat_type_desc": "bla2",
            "ioc_type": "url",
            "ioc_type_desc": "bla3",
            "malware": "bla4",
            "malware_printable": "Unknown malware",
            "malware_alias": "bla6",
            "malware_malpedia": "bla7",
            "confidence_level": 100,
            "first_seen": "2024-08-04 01:50:15 UTC",
            "last_seen": "2024-08-05 01:50:15 UTC",
            "reference": "bla8",
            "reporter": "bla9",
            "tags": ["bla10"],
        },
        True,
        False,
        "CLEAR",
        {
            "value": "www...",
            "type": "URL",
            "fields": {
                "indicatoridentification": "123",
                "description": "bla2",  # expected
                "aliases": "bla6",
                "firstseenbysource": "2024-08-04T01:50:15Z",
                "lastseenbysource": "2024-08-05T01:50:15Z",
                "reportedby": "bla9",
                "Tags": ["bla6", "bla1", "bla10"],
                "publications": [{"link": "bla8", "title": "Malware", "source": "ThreatFox"}],
                "confidence": 100,
                "trafficlightprotocol": "CLEAR",
            },
            "rawJSON": {
                "id": "123",
                "ioc": "www...",
                "threat_type": "bla1",
                "threat_type_desc": "bla2",
                "ioc_type": "url",
                "ioc_type_desc": "bla3",
                "malware": "bla4",
                "malware_printable": "Unknown malware",
                "malware_alias": "bla6",
                "malware_malpedia": "bla7",
                "confidence_level": 100,
                "first_seen": "2024-08-04 01:50:15 UTC",
                "last_seen": "2024-08-05 01:50:15 UTC",
                "reference": "bla8",
                "reporter": "bla9",
                "tags": ["bla10"],
            },
        },
        ["bla6", "bla1", "bla10"],
    ),
    (
        {
            "id": "123",
            "ioc": "www...",
            "threat_type": "bla1",  # case with relationships and there is malware_printable
            "threat_type_desc": "bla2",
            "ioc_type": "url",
            "ioc_type_desc": "bla3",
            "malware": "bla4",
            "malware_printable": "bla11",
            "malware_alias": "bla6",
            "malware_malpedia": "bla7",
            "confidence_level": 100,
            "first_seen": "2024-08-04 01:50:15 UTC",
            "last_seen": "2024-08-05 01:50:15 UTC",
            "reference": "bla8",
            "reporter": "bla9",
            "tags": ["bla10"],
        },
        True,
        True,
        "CLEAR",
        {
            "value": "www...",
            "type": "URL",
            "fields": {
                "indicatoridentification": "123",
                "description": "bla2",  # expected
                "malwarefamily": "bla11",
                "aliases": "bla6",
                "firstseenbysource": "2024-08-04T01:50:15Z",
                "lastseenbysource": "2024-08-05T01:50:15Z",
                "reportedby": "bla9",
                "Tags": ["bla11", "bla6", "bla1", "bla10"],
                "publications": [{"link": "bla8", "title": "bla11", "source": "ThreatFox"}],
                "confidence": 100,
                "trafficlightprotocol": "CLEAR",
            },
            "relationships": [
                {
                    "name": "communicated-by",
                    "reverseName": "communicated-with",
                    "type": "IndicatorToIndicator",
                    "entityA": "www...",
                    "entityAFamily": "Indicator",
                    "entityAType": "URL",
                    "entityB": "bla11",
                    "entityBFamily": "Indicator",
                    "entityBType": "Malware",
                    "fields": {},
                }
            ],
            "rawJSON": {
                "id": "123",
                "ioc": "www...",
                "threat_type": "bla1",
                "threat_type_desc": "bla2",
                "ioc_type": "url",
                "ioc_type_desc": "bla3",
                "malware": "bla4",
                "malware_printable": "bla11",
                "malware_alias": "bla6",
                "malware_malpedia": "bla7",
                "confidence_level": 100,
                "first_seen": "2024-08-04 01:50:15 UTC",
                "last_seen": "2024-08-05 01:50:15 UTC",
                "reference": "bla8",
                "reporter": "bla9",
                "tags": ["bla10"],
            },
        },
        ["bla11", "bla6", "bla1", "bla10"],
    ),
]


@pytest.mark.parametrize("indicator, with_ports, create_relationship, tlp_color, expected, tags", parse_fetch_data)
def test_parse_indicator_for_fetch(mocker, indicator, with_ports, create_relationship, tlp_color, expected, tags):
    """
    Given:
        - An indicator, with_ports, create_relationship, tlp_color arguments

    When:
        - Running parse_indicator_for_fetch func.

    Then:
        - The indicator is parsed correctly.
    """
    from FeedThreatFox import parse_indicator_for_fetch

    mocker.patch("FeedThreatFox.tags", return_value=tags)
    parsed_indicator = parse_indicator_for_fetch(indicator, with_ports, create_relationship, tlp_color)
    assert parsed_indicator == expected


first_run_data = [
    (
        True,
        80,
        True,
        1440,
        "CLEAR",
        None,  # case interval == 1
        {"query": "get_iocs", "days": 1},
    ),  # expected
    (
        True,
        80,
        True,
        2880,
        "CLEAR",
        None,  # case interval ==2
        {"query": "get_iocs", "days": 2},
    ),  # expected
]


@pytest.mark.parametrize(
    "with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run, expected", first_run_data
)
def test_fetch_indicators_command__first_run(
    mocker, with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run, expected
):
    """
    Given:
        - An arguments with no last_run

    When:
        - Running fetch_indicators_command func.

    Then:
        - The http request is called with the right number of days.
    """
    from FeedThreatFox import fetch_indicators_command

    http = mocker.patch.object(CLIENT, "_http_request", return_value={"query_status": "ok", "data": {}})
    fetch_indicators_command(CLIENT, with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run)
    assert http.call_args.kwargs["json_data"] == expected


second_run_data = [
    (
        True,
        80,
        True,
        1440,
        "CLEAR",
        {"last_successful_run": "2024-07-08T15:21:13Z"},  # case last run before 2 days
        {"query": "get_iocs", "days": 3},
    ),
    (
        True,
        80,
        True,
        2880,
        "CLEAR",
        {"last_successful_run": "2024-07-02T17:22:13Z"},  # case last run before more than 7 days
        {"query": "get_iocs", "days": 7},
    ),
]


@freeze_time("2024-07-10T15:21:13Z")
@pytest.mark.parametrize(
    "with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run, expected", second_run_data
)
def test_fetch_indicators_command__second_run(
    mocker, with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run, expected
):
    """
    Given:
        - An indicator, with_ports, create_relationship, tlp_color arguments

    When:
        - Running parse_indicator_for_fetch func.

    Then:
        - The indicator is parsed correctly.
    """
    from FeedThreatFox import fetch_indicators_command

    http = mocker.patch.object(CLIENT, "_http_request", return_value={"query_status": "ok", "data": {}})
    fetch_indicators_command(CLIENT, with_ports, confidence_threshold, create_relationship, interval, tlp_color, last_run)
    assert http.call_args.kwargs["json_data"] == expected


intervals = [1441, 11520, 10081]


@pytest.mark.parametrize("interval", intervals)
def test_validate_interval(interval):
    """
    Given:
        - An invalid interval.

    When:
        - Running validate_interval func.

    Then:
        - A DemistoException is raised.
    """
    from CommonServerPython import DemistoException
    from FeedThreatFox import validate_interval

    with pytest.raises(DemistoException):
        validate_interval(interval)
