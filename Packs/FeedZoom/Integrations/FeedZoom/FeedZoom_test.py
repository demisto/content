import re
import pytest

from FeedZoom import Client, fetch_indicators_command
import demistomock as demisto


URL = "https://assets.zoom.us/docs/ipranges"


def test_build_iterator(mocker):
    """

    Given: zoom feed instance.

    When: Fetching indicators.

    Then: Build iterator of indicators from the API.

    """
    with open('test_data/zoom_endpoint.txt') as file:
        response = file.read()
    mocker.patch.object(Client, '_http_request', return_value=response)
    mocker.patch.object(demisto, 'params',
                        return_value={'zoom_clients_certificate_validation': 'crl3.digicert.com,crl4.digicert.com',
                                      'zoom_clients_user_browser': '*.zoom.us'})

    expected_cidr = '3.7.35.0/25'
    expected_glob = '*.zoom.us'
    expected_ipv4 = '1.2.3.4'
    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )

    indicators = client.build_iterator()
    cidr_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'CIDR'}
    ip_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'IP'}
    domain_glob_indicators = {indicator['value'] for indicator in indicators if indicator['type'] == 'DomainGlob'}
    assert expected_cidr in cidr_indicators
    assert expected_ipv4 in ip_indicators
    assert expected_glob in domain_glob_indicators


@pytest.mark.parametrize('enrichment_excluded', [True, False])
def test_fetch_indicators_command(mocker, requests_mock, enrichment_excluded):
    """
    Given:
        Parameters (zoom_clients_certificate_validation, zoom_clients_user_browser, enrichment_excluded) for fetching indicators
    When:
        Calling fetch_indicators_command
    Then:
        The indicators will be returned as expected, with enrichmentExcluded if requested
    """
    expected = [
        {
            'value': '3.7.35.0/25',
            'type': 'CIDR',
            'service': 'Zoom Feed',
            'rawJSON': {'value': '3.7.35.0/25', 'type': 'CIDR', 'FeedURL': 'https://assets.zoom.us/docs/ipranges'},
            'fields': {},
        },
        {
            'value': '1.2.3.4',
            'type': 'IP',
            'service': 'Zoom Feed',
            'rawJSON': {'value': '1.2.3.4', 'type': 'IP', 'FeedURL': 'https://assets.zoom.us/docs/ipranges'},
            'fields': {},
        },
        {
            'value': '*.zoom.us',
            'type': 'DomainGlob',
            'service': 'Zoom Feed',
            'rawJSON': {'value': '*.zoom.us', 'type': 'DomainGlob', 'FeedURL': 'https://assets.zoom.us/docs/ipranges'},
            'fields': {},
        },
        {
            'value': 'crl4.digicert.com',
            'type': 'Domain',
            'service': 'Zoom Feed',
            'rawJSON': {'value': 'crl4.digicert.com', 'type': 'Domain', 'FeedURL': 'https://assets.zoom.us/docs/ipranges'},
            'fields': {},
        },
        {
            'value': 'crl3.digicert.com',
            'type': 'Domain',
            'service': 'Zoom Feed',
            'rawJSON': {'value': 'crl3.digicert.com', 'type': 'Domain', 'FeedURL': 'https://assets.zoom.us/docs/ipranges'},
            'fields': {},
        }
    ]

    if enrichment_excluded:
        for ind in expected:
            ind['enrichmentExcluded'] = True

    with open('test_data/zoom_endpoint.txt') as file:
        response = file.read()
    requests_mock.register_uri('GET', re.compile(rf'{URL}.*'), text=response)

    mocker.patch.object(demisto, 'params',
                        return_value={'zoom_clients_certificate_validation': 'crl3.digicert.com,crl4.digicert.com',
                                      'zoom_clients_user_browser': '*.zoom.us',
                                      'enrichmentExcluded': enrichment_excluded})

    client = Client(
        base_url=URL,
        verify=False,
        proxy=False,
    )

    indicators = fetch_indicators_command(client, demisto.params())

    for ind in expected:
        assert ind in indicators
