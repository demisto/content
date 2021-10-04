import io
import json


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_indicator_generator(requests_mock):
    """
    Given:
        - an Expanse client
        - a valid API Key
    When
        - indicator generator is called
    Then
        - all 4 types of assets are retrieved from the API (IPs, Certificates, IPRanges and Domains)
        - Expanse assets are mapped into the appropriate fields
    """
    from FeedExpanse import Client, indicator_generator

    # load mock responses
    ipranges_mock_response = util_load_json('test_data/ipranges.json')
    certificates_mock_response = util_load_json('test_data/certificates.json')
    domains_mock_response = util_load_json('test_data/domains.json')
    ips0_mock_response = util_load_json('test_data/ips-page0.json')
    ips1_mock_response = util_load_json('test_data/ips-page1.json')

    # hook the mock responses in requests_mock
    requests_mock.get(
        'https://example.com/api/v2/ip-range',
        json=ipranges_mock_response
    )
    requests_mock.get(
        'https://example.com/api/v2/assets/certificates',
        json=certificates_mock_response
    )
    requests_mock.get(
        'https://example.com/api/v2/assets/domains',
        json=domains_mock_response
    )
    requests_mock.get(
        'https://example.com/api/v2/assets/ips',
        json=ips0_mock_response
    )
    requests_mock.get(
        ips0_mock_response['pagination']['next'],
        json=ips1_mock_response
    )

    client = Client(
        base_url='https://example.com/api',
        verify=True,
        api_key="FakeAPIKey",
        proxy=False
    )

    result = list(indicator_generator(
        client,
        max_indicators=2,
        tlp_color='Red',
        feed_tags='tag1'
    ))

    expected_result = util_load_json('./test_data/test_indicators_generator_result.json')

    assert result == expected_result
