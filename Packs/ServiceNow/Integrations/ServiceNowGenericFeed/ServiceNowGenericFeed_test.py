import pytest
from ServiceNowGenericFeed import Client
from ServiceNowGenericFeed import records_list_command, create_indicator_object, add_indicators_to_TIM

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
                "ip_address": "some ip 2",
            },
        ],
        ["test"],
        "ip_address",
        [
            {
                "value": "192.0.2.1",
                "type": "IP",
                "fields": {"tags": ["test"]},
                "rawJSON": {
                    "manufacturer.name": "some network 1",
                    "ip_address": "192.0.2.1",
                },
            },
            {
                "value": "some ip 2",
                "type": "IP",
                "fields": {"tags": ["test"]},
                "rawJSON": {
                    "manufacturer.name": "some networks 2",
                    "ip_address": "some ip 2",
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
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "rawJSON": {"manufacturer.name": "some network 1", "ip_address": "192.0.2.1"},
            },
            {
                "value": "some ip 2",
                "type": "IP",
                "fields": {"tags": ["Tag 1", "Tag 2"]},
                "rawJSON": {"manufacturer.name": "some networks 2", "ip_address": "some ip 2"},
            },
        ],
        "success",
    ),
    (
        [],
        "Indicators do not exist",
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
        Returns the output of the add_indicators_to_TIM function.
    """

    result = add_indicators_to_TIM(indicators=indicators_objs)

    assert result == expected_result


def test_records_list_command(requests_mock):
    """
    Given:
        A ServiceNow client and query parameters
    When:
        Calling records_list_command
    Then:
        The records are fetched via the client HTTP request
    """
    base_url = "https://company.service-now.com/"
    query_url = "api/now/cmdb_ci_ip_address"
    full_url = f"{base_url}{query_url}"

    mock_response = {
        "result": [
            {"ip_address": "some ip 1", "manufacturer.name": "some network 1"},
            {"ip_address": "some ip 2", "manufacturer.name": "some network 2"},
        ]
    }

    requests_mock.get(full_url, json=mock_response)

    client = Client(
        credentials={"identifier": "user", "password": "pass"},
        url=base_url,
        verify=False,
        proxy=False,
    )

    params = {"query_url": query_url}
    args = {"class": "cmdb_ci_ip_address"}

    human_readable, response = records_list_command(client, args, params)

    assert response == mock_response
