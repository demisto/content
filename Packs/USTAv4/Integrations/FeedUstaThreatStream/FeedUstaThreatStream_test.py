from FeedUstaThreatStream import (
    Client,
    fetch_indicators_command,
    parse_phishing_sites,
    parse_malicious_urls,
    parse_malware_hashes,
    check_module,
    search_malware_hashes_command,
    search_malicious_urls_command,
    search_phishing_site_command,
    main
)
from CommonServerPython import tableToMarkdown

import json
import pytest
import demistomock as demisto  # noqa: F401


client = Client(base_url="", verify=False, headers={}, proxy=False)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def test_check_module(mocker):
    mock_response = util_load_json("test_data/auth_success_response.json")
    mocker.patch.object(client, "check_auth", return_value=mock_response)
    response = check_module(client)
    assert response == "ok"


def test_search_phishing_site_command(mocker):
    mock_response = json.loads(
        """
    {
        "count": 1,
        "next": null,
        "previous": null,
        "results": [
            {
                "id": 219286,
                "url": "https://phishingwebsite.org",
                "host": "phishingwebsite.org",
                "is_domain": true,
                "ip_addresses": [
                    "127.0.0.1"
                ],
                "country": null,
                "created": "2024-02-05T15:23:11.646011Z"
            }
        ]
    }"""
    )

    mocker.patch.object(client, "search_iterator_without_pagination", return_value=mock_response)
    args = {"limit": "10", "offset": "0", "indicator": "example.com"}
    response = search_phishing_site_command(client, args)
    human_readable = tableToMarkdown("Indicators from USTA Feed (phishing-sites):", mock_response["results"])
    assert response.raw_response == mock_response["results"]
    assert response.readable_output == human_readable
    assert len(response.raw_response) == 1


@pytest.mark.parametrize(
    "command, expected_output",
    [
        (search_phishing_site_command, "No entries."),
        (search_malware_hashes_command, "No entries."),
        (search_malicious_urls_command, "No entries."),
    ],
)
def test_search_commands_no_results_found(mocker, command, expected_output):
    mock_response = json.loads(
        """
        {
            "count": 0,
            "next": null,
            "previous": null,
            "results": []
        }"""
    )
    mocker.patch.object(client, "search_iterator_without_pagination", return_value=mock_response)
    args = {"limit": "10", "offset": "0", "indicator": "exampleurl.com"}
    response = command(client, args)
    assert response.raw_response == mock_response["results"]
    assert len(response.raw_response) == 0
    assert expected_output in response.readable_output


@pytest.mark.parametrize(
    "command, expected_output",
    [
        (search_phishing_site_command, "Indicators from USTA Feed (phishing-sites):"),
        (search_malware_hashes_command, "Indicators from USTA Feed (malware-hashes):"),
        (search_malicious_urls_command, "Indicators from USTA Feed (malicious-urls):"),
    ],
)
def test_search_commands_with_results(mocker, command, expected_output):
    mock_response = json.loads(
        """
        {
            "count": 1,
            "next": null,
            "previous": null,
            "results": [
                {
                    "id": 219286,
                    "url": "https://example.com",
                    "host": "example.com",
                    "is_domain": true,
                    "ip_addresses": [
                        "127.0.0.1"
                    ],
                    "country": null,
                    "created": "2024-02-05T15:23:11.646011Z"
                }
            ]
        }"""
    )
    mocker.patch.object(client, "search_iterator_without_pagination", return_value=mock_response)
    args = {"limit": "10", "offset": "0", "indicator": "example.com"}
    response = command(client, args)
    assert response.raw_response == mock_response["results"]
    assert len(response.raw_response) == 1
    assert expected_output in response.readable_output


@pytest.mark.parametrize(
    "parser_function, indicator_json",
    [
        (parse_phishing_sites, "test_data/fetch_indicators_phishing_sites.json"),
        (parse_malicious_urls, "test_data/fetch_indicators_malicious_urls.json"),
        (parse_malware_hashes, "test_data/fetch_indicators_malware_hashes.json"),
    ],
)
def test_parse_functions(mocker, parser_function, indicator_json):
    mock_response = util_load_json(indicator_json)
    for each in mock_response:
        expected_result = parser_function(each["rawJSON"])
        assert expected_result["rawJSON"] == each["rawJSON"]
        assert expected_result["value"] == each["value"]


@pytest.mark.parametrize(
    "ioc_type, indicator_json",
    [
        ('phishing-sites', "test_data/fetch_indicators_phishing_sites.json"),
        ('malicious-urls', "test_data/fetch_indicators_malicious_urls.json"),
        ('malware-hashes', "test_data/fetch_indicators_malware_hashes.json"),
    ],
)
def test_fetch_indicators_command(mocker, ioc_type, indicator_json):

    all_indicators = []
    for each in util_load_json(indicator_json):
        all_indicators.append(each["rawJSON"])

    mocker.patch.object(Client, "build_iterator", return_value=all_indicators)
    params = {
        'ioc_feed_type': ioc_type,
    }
    next_run, indicators = fetch_indicators_command(
        client=Client,
        last_run={
        },
        params=params
    )

    assert len(indicators) == len(all_indicators)
    assert next_run[ioc_type]['created'] == all_indicators[0]["created"]


def test_fetch_indicators_command_no_results(mocker):
    mocker.patch.object(Client, "build_iterator", return_value=[])
    params = {
        'ioc_feed_type': 'phishing-sites',
    }
    next_run, indicators = fetch_indicators_command(
        client=Client,
        last_run={
        },
        params=params
    )

    assert len(indicators) == 0
    assert next_run == {}


def test_main_cmd_fetch_indicators(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'url': 'https://example.com',
        'api_key': 'API_KEY',
        'insecure': True,
        'proxy': False,
        'first_fetch': '3 days',
        'status': 'open',
        'max_fetch': 50
    })

    Client(
        base_url='',
        verify=False,
        headers={},
        proxy=False
    )
    mocker.patch.object(client, "build_iterator", return_value=[{}])
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    mocker.patch.object(demisto, 'createIndicators')
    mocker.patch.object(demisto, 'setIntegrationContext')
    mocker.patch.object(demisto, 'setLastRun')
    main()
    demisto.setLastRun.assert_called_once()
