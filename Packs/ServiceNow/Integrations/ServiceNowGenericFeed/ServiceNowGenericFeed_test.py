import pytest
from pytest_mock import MockerFixture
from ServiceNowGenericFeed import OAUTH_URL, ServiceNowClient
from ServiceNowGenericFeed import records_list_command, create_indicator_object,add_indicators_to_TIM

CREATE_INDICATOR_PACK = [
    (
        [
            {
                "manufacturer.name": "Extreme Networks, Inc.",
                "ip_address": "198.51.100.0",
            },
        ],
        ["production", "network"],
        "ip_address",
        [
            {
                "value": "198.51.100.0",
                "type": "IP",
                "service": "Test Tag",
                "fields": {"tags": ["production", "network"]},
                "rawJSON": {
                    "manufacturer.name": "Extreme Networks, Inc.",
                    "ip_address": "198.51.100.0",
                },
            }
        ],
    ),
    (
        [
            {
                "manufacturer.name": "some network 1",
                "ip_address": "192.0.2.1",
            },
            {
                "manufacturer.name": "some networks 2",
                "ip_address": "198.51.100.255",
            },
        ],
        ["test"],
        "ip_address",
        [
            {
                "value": "192.0.2.1",
                "type": "IP",
                "service": "Test Tag",
                "fields": {"tags": ["test"]},
                "rawJSON": {
                    "manufacturer.name": "some network 1",
                    "ip_address": "192.0.2.1",
                },
            },
            {
                "value": "198.51.100.255",
                "type": "IP",
                "service": "Test Tag",
                "fields": {"tags": ["test"]},
                "rawJSON": {
                    "manufacturer.name": "some networks 2",
                    "ip_address": "198.51.100.255",
                },
            },
        ],
    ),
    (
        [],
        ["empty"],
        "ip_address",
        [],
    ),
]


@pytest.mark.parametrize(
    "indicator_list, feedtags, indicator_field, expected_result",
    CREATE_INDICATOR_PACK,
)
def test_create_indicator_object(indicator_list, feedtags, indicator_field, expected_result):
    """
    Given:
        A list of ServiceNow records, feed tags, and indicator field name
    When:
        Calling create_indicator_object
    Then:
        Returns properly formatted indicator objects with correct structure
    """
    result = create_indicator_object(
        indicator_list=indicator_list,
        feedtags=feedtags,
        indicator_field=indicator_field,
    )
    
    assert result == expected_result

ADD_INDICATORS_TO_TIM = [
    (
        [
            {
                "value": "192.0.2.1",
                "type": "IP",
                "service": "Test Tag",
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "rawJSON": {"manufacturer.name": "some network 1", "ip_address": "192.0.2.1"},
            },
            {
                "value": "198.51.100.255",
                "type": "IP",
                "service": "Test Tag",
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "rawJSON": {"manufacturer.name": "some networks 2", "ip_address": "198.51.100.255"},
            },
        ],
        "success",

        """
        [
            {
                "reliability": "F - Reliability cannot be judged",
                "fetchTime": "0001-01-01T00:00:00Z",
                "sourceBrand": "some integration",
                "sourceInstance": "some instance",
                "moduleId": "some ID",
                "expirationPolicy": "indicatorType",
                "expirationInterval": 20160,
                "bypassExclusionList": False,
                "score": 0,
                "classifierVersion": 0,
                "classifierId": "",
                "mapperVersion": 0,
                "mapperId": "",
                "type": "IP",
                "value": "192.0.2.1",
                "timestamp": "0001-01-01T00:00:00Z",
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "modifiedTime": "2026-02-10T17:05:54.763331909Z",
                "ExpirationSource": None,
                "rawJSON": {"ip_address": "192.0.2.1", "manufacturer.name": "some network 1"},
                "isEnrichment": False,
                "enrichmentExcluded": False,
            },
            {
                "reliability": "F - Reliability cannot be judged",
                "fetchTime": "0001-01-01T00:00:00Z",
                "sourceBrand": "some integration",
                "sourceInstance": "some instance",
                "moduleId": "some ID",
                "expirationPolicy": "indicatorType",
                "expirationInterval": 20160,
                "bypassExclusionList": False,
                "score": 0,
                "classifierVersion": 0,
                "classifierId": "",
                "mapperVersion": 0,
                "mapperId": "",
                "type": "IP",
                "value": "198.51.100.255",
                "timestamp": "0001-01-01T00:00:00Z",
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "modifiedTime": "2026-02-10T17:05:54.763331909Z",
                "ExpirationSource": None,
                "rawJSON": {"ip_address": "198.51.100.255", "manufacturer.name": "some networks 2"},
                "isEnrichment": False,
                "enrichmentExcluded": False,
            },
        ],
        """
    ),

    (
        [],
        [],
    ),
]


@pytest.mark.parametrize(
    "indicators_objs, expected_result",
    ADD_INDICATORS_TO_TIM,
)
def test_add_indicators_to_TIM(indicators_objs, expected_result):
    """
    Given:
        A list of Indicator objects with correct structure for the demisto.createIndicators command
    When:
        Calling add_indicators_to_TIM
    Then:
        Returns the output of the demisto.createIndicators command, which is a list of the successfully added indicators with their assigned IDs in the TIM system.
    """
    
    result = add_indicators_to_TIM(indicators=indicators_objs)
    
    assert result == expected_result

@pytest.mark.parametrize("enrichment_excluded", [True, False])
def test_records_list_command(requests_mock):
    """
    Given:
        A ServiceNow client and query parameters
    When:
        Calling records_list_command
    Then:
        The records are fetched via the client HTTP request
    """
    query_url = "https://service-now.com/api/now/cmdb_ci_ip_address"
    mock_response = {
        "result": [
            {"ip_address": "192.0.2.1", "manufacturer.name": "some network 1"},
            {"ip_address": "198.51.100.255", "manufacturer.name": "Juniper Networks"},
        ]
    }
    
    requests_mock.get(query_url, json=mock_response)
    
    client = ServiceNowClient(
        credentials={"identifier": "user", "password": "pass"},
        url="https://northdakota.service-now.com/",
        verify=False,
        proxy=False,
    )
    
    params = {"query_url": query_url}
    args = {"class": "cmdb_ci_ip_address"}
    
    human_readable, context, response = records_list_command(client, args, params)
    
    assert response.get("result") == mock_response["result"]