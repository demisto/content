from ACTIIndicatorFeed import custom_build_iterator
import requests_mock
import pytest

from JSONFeedApiModule import Client

PARAMS = {
    "api_token": "test_api_key",
    "insecure": True,
    "indicator_type": ["IP", "Domain"],
    "feed_name_to_config": {
        "IP": {
            "extractor": "results",
            "indicator": "display_text",
            "insecure": True,
            "build_iterator_paging": custom_build_iterator,
            "filters": {},
            "url": "https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip",
            "indicator_type": "IP",
            "mapping": {
                "last_seen_as": "malwaretypes",
                "threat_types": "primarymotivation",
                "malware_family": "malwarefamily",
                "severity": "sourceoriginalseverity",
            },
        },
        "Domain": {
            "extractor": "wrong_extractor",
            "indicator": "display_text",
            "insecure": True,
            "build_iterator_paging": custom_build_iterator,
            "filters": {},
            "url": "https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain",
            "indicator_type": "Domain",
            "mapping": {
                "last_seen_as": "malwaretypes",
                "threat_types": "primarymotivation",
                "malware_family": "malwarefamily",
                "severity": "sourceoriginalseverity",
            },
        },
    },
    "headers": {"Content-Type": "application/json", "auth-token": "xxx"},
}


def test_build_iterator_paging():
    """
    Given:
        - feed configuration with no filters to fetch with

    When:
        - fetch indicators using jsonFeedApiModule with an api that his response method is pagination

    Then:
        - assert that results returned from 2 different pages

    """

    url_page1 = "https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip?page_size=200&page=1"
    status_code = 200
    json_data_page1 = {
        "results": [{"display_text": "2.2.2.2"}, {"display_text": "1.1.1.1"}],
        "total_size": 4,
        "page": 1,
        "page_size": 200,
        "more": True,
    }

    url_page2 = "https://api.intelgraph.idefense.com/rest/threatindicator/v0/ip?page_size=200&page=2"
    json_data_page2 = {
        "results": [{"display_text": "3.3.3.3"}, {"display_text": "4.4.4.4"}],
        "total_size": 4,
        "page": 2,
        "page_size": 200,
        "more": False,
    }

    with requests_mock.Mocker() as m:
        m.get(url_page1, status_code=status_code, json=json_data_page1)
        m.get(url_page2, status_code=status_code, json=json_data_page2)
        client = Client(**PARAMS)
        results = custom_build_iterator(client, PARAMS["feed_name_to_config"]["IP"], 0)
        assert len(results) == 4


def test_build_iterator_change_extractor():
    """
    Given:
        - feed configuration with wrong feed extractor

    When:
        - jmespath search for the given expression to be queried

    Then:
        - The json does not contain the given expression and TypeError raised

    """

    url_page1 = "https://api.intelgraph.idefense.com/rest/threatindicator/v0/domain?page_size=200&page=1"
    status_code = 200
    client = Client(**PARAMS)
    json_data = {"ccc": [{"display_text": "3.3.3.3"}], "total_size": 1, "page": 1, "page_size": 200, "more": False}
    with requests_mock.Mocker() as m:
        m.get(url_page1, status_code=status_code, json=json_data)
        with pytest.raises(TypeError) as e:
            custom_build_iterator(client, PARAMS["feed_name_to_config"]["Domain"], 0)
        if not e:
            raise AssertionError
