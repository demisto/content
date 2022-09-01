import pytest
import json
import io

from HYASInsight import Client, get_passive_dns_records_by_indicator, get_dynamic_dns_records_by_indicator, \
    get_whois_records_by_indicator, get_whois_current_records_by_domain, get_malware_samples_records_by_indicator, \
    get_associated_ips_by_hash, get_associated_domains_by_hash, get_c2_attribution_record_by_indicator

client = Client(
    base_url="test.com",
    apikey="test",
)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


PASSIVE_DNS_RESPONSE = util_load_json('test_data/passivedns_response.json')
DYNAMIC_DNS_RESPONSE = util_load_json('test_data/dynamicdns_response.json')
WHOIS_RESPONSE = util_load_json('test_data/whois_response.json')
C2_ATTRIBUTION_RESPONSE = util_load_json(
    'test_data/c2_attribution_response.json')

WHOIS_CURRENT_RAW_RESPONSE1 = util_load_json('test_data/whoiscurrent_input.json')
WHOIS_CURRENT_RAW_RESPONSE2 = util_load_json('test_data/whoiscurrent_response.json')
MALWARE_SAMPLE_RESPONSE = util_load_json('test_data/malwaresample_response.json')
ASSOCIATED_IPS_INPUT = [{'ipv4': '8.8.8.8'}]
ASSOCIATED_DOMAINS_INPUT = [{'domain': 'butterfly.bigmoney.biz'}]
ASSOCIATED_IPS = {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d', 'ips': ['8.8.8.8']}
ASSOCIATED_DOMAINS = {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d', 'domains': ['butterfly.bigmoney.biz']}


@pytest.mark.parametrize('raw_response, expected', [(PASSIVE_DNS_RESPONSE, PASSIVE_DNS_RESPONSE)])
def test_get_passive_dns_records_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_ipv4 = get_passive_dns_records_by_indicator(client, {'indicator_type': 'ipv4',
                                                                         'indicator_value': '189.70.45.212',
                                                                         'limit': 1})
    command_results_domain = get_passive_dns_records_by_indicator(client, {'indicator_type': 'domain',
                                                                           'indicator_value': 'domain.org',
                                                                           'limit': 1})
    # results is CommandResults list
    context_ipv4 = command_results_ipv4.to_context()['Contents']
    context_domain = command_results_domain.to_context()['Contents']
    assert context_ipv4 == expected
    assert context_domain == expected

    with pytest.raises(ValueError):
        get_passive_dns_records_by_indicator(client, {'indicator_type': 'test',
                                                      'indicator_value': 'domain.org'})

    with pytest.raises(ValueError):
        get_passive_dns_records_by_indicator(client, {'indicator_type': 'ipv4',
                                                      'indicator_value': 'aaaaaa'})

    with pytest.raises(ValueError):
        get_passive_dns_records_by_indicator(client, {'indicator_type': 'domain',
                                                      'indicator_value': '344444'})


@pytest.mark.parametrize('raw_response, expected', [(DYNAMIC_DNS_RESPONSE, DYNAMIC_DNS_RESPONSE)])
def test_get_dynamic_dns_records_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 7)

    command_results_ip = get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'ip',
                                                                       'indicator_value': '4.4.4.4',
                                                                       'limit': 1})
    command_results_domain = get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'domain',
                                                                           'indicator_value': 'fluber12.duckdns.org',
                                                                           'limit': 1})

    command_results_email = get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'email',
                                                                          'indicator_value': 'comptrasfluber@gmail.com',
                                                                          'limit': 1})
    # results is CommandResults list
    context_ip = command_results_ip.to_context()['Contents']
    context_domain = command_results_domain.to_context()['Contents']
    context_email = command_results_email.to_context()['Contents']
    assert context_ip == expected
    assert context_domain == expected
    assert context_email == expected

    with pytest.raises(ValueError):
        get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'tttt', 'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'ip', 'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'domain', 'indicator_value': '3333'})
    with pytest.raises(ValueError):
        get_dynamic_dns_records_by_indicator(client, {'indicator_type': 'email', 'indicator_value': '33333'})


@pytest.mark.parametrize('raw_response, expected', [(WHOIS_RESPONSE, WHOIS_RESPONSE)])
def test_get_whois_records_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 7)
    command_results_phone = get_whois_records_by_indicator(client, {'indicator_type': 'phone',
                                                                    'indicator_value': '+84909095309',
                                                                    'limit': 1})

    command_results_domain = get_whois_records_by_indicator(client, {'indicator_type': 'domain',
                                                                     'indicator_value': 'domain.net',
                                                                     'limit': 1})

    command_results_email = get_whois_records_by_indicator(client, {'indicator_type': 'email',
                                                                    'indicator_value': 'viendongonline@gmail.com',
                                                                    'limit': 1})
    # results is CommandResults list
    context_domain = command_results_domain.to_context()['Contents']
    context_email = command_results_email.to_context()['Contents']
    context_phone = command_results_phone.to_context()['Contents']

    assert context_phone == expected
    assert context_domain == expected
    assert context_email == expected

    with pytest.raises(ValueError):
        get_whois_records_by_indicator(client, {'indicator_type': '5555',
                                                'indicator_value': '+84909095309'})
    with pytest.raises(ValueError):
        get_whois_records_by_indicator(client, {'indicator_type': 'phone',
                                                'indicator_value': 'aaaaa'})
    with pytest.raises(ValueError):
        get_whois_records_by_indicator(client, {'indicator_type': 'domain',
                                                'indicator_value': '+84909095309'})
    with pytest.raises(ValueError):
        get_whois_records_by_indicator(client, {'indicator_type': 'email',
                                                'indicator_value': '+84909095309'})


@pytest.mark.parametrize('raw_response, expected', [(WHOIS_CURRENT_RAW_RESPONSE1, WHOIS_CURRENT_RAW_RESPONSE2)])
def test_get_whois_current_records_by_domain(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 2)

    command_results_domain = get_whois_current_records_by_domain(client, {'domain': 'www.hyas.com'})

    # results is CommandResults list
    context_domain = command_results_domain.to_context()['Contents']
    assert context_domain == expected

    with pytest.raises(ValueError):
        get_whois_current_records_by_domain(client, {'domain': 'tytytyty'})


@pytest.mark.parametrize('raw_response, expected', [(MALWARE_SAMPLE_RESPONSE, MALWARE_SAMPLE_RESPONSE)])
def test_get_malware_samples_records_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 7)
    command_results_ipv4 = get_malware_samples_records_by_indicator(client, {'indicator_type': 'ipv4',
                                                                             'indicator_value': '106.187.43.98',
                                                                             'limit': 1})

    command_results_domain = get_malware_samples_records_by_indicator(client, {'indicator_type': 'domain',
                                                                               'indicator_value': 'butterfly.bigmoney.biz',
                                                                               'limit': 1})

    command_results_md5 = get_malware_samples_records_by_indicator(client, {'indicator_type': 'md5',
                                                                            'indicator_value':
                                                                                '1d0a97c41afe5540edd0a8c1fb9a0f2d',
                                                                            'limit': 1})

    # results is CommandResults list
    context_domain = command_results_domain.to_context()['Contents']
    context_ipv4 = command_results_ipv4.to_context()['Contents']
    context_hash = command_results_md5.to_context()['Contents']

    assert context_ipv4 == expected
    assert context_domain == expected
    assert context_hash == expected

    with pytest.raises(ValueError):
        get_malware_samples_records_by_indicator(client, {'indicator_type': '5555', 'indicator_value': '+84909095309'})
    with pytest.raises(ValueError):
        get_malware_samples_records_by_indicator(client, {'indicator_type': 'ipv4', 'indicator_value': 'aaaaa'})
    with pytest.raises(ValueError):
        get_malware_samples_records_by_indicator(client,
                                                 {'indicator_type': 'domain', 'indicator_value': '+84909095309'})
    with pytest.raises(ValueError):
        get_malware_samples_records_by_indicator(client, {'indicator_type': 'md5', 'indicator_value': '+84909095309'})


@pytest.mark.parametrize('raw_response, expected', [(ASSOCIATED_IPS_INPUT, ASSOCIATED_IPS)])
def test_get_associated_ips_by_hash(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 2)

    command_results = get_associated_ips_by_hash(client, {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d'})

    # results is CommandResults list
    context = command_results.to_context()['Contents']
    assert context == expected

    with pytest.raises(ValueError):
        get_associated_ips_by_hash(client, {'md5': 'ffff'})


@pytest.mark.parametrize('raw_response, expected', [(ASSOCIATED_DOMAINS_INPUT, ASSOCIATED_DOMAINS)])
def test_get_associated_domains_by_hash(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 2)

    command_results = get_associated_domains_by_hash(client, {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d'})

    # results is CommandResults list
    context = command_results.to_context()['Contents']
    assert context == expected

    with pytest.raises(ValueError):
        get_associated_domains_by_hash(client, {'md5': 'ffff'})


@pytest.mark.parametrize('raw_response, expected',
                         [(C2_ATTRIBUTION_RESPONSE, C2_ATTRIBUTION_RESPONSE)])
def test_get_c2_attribution_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 7)

    command_results_ip = get_c2_attribution_record_by_indicator(client, {
        'indicator_type': 'ip',
        'indicator_value': '197.210.84.34',
        'limit': 1})
    command_results_domain = get_c2_attribution_record_by_indicator(client, {
        'indicator_type': 'domain',
        'indicator_value': 'himionsa.com',
        'limit': 1})

    command_results_email = get_c2_attribution_record_by_indicator(client, {
        'indicator_type': 'email',
        'indicator_value': 'ip@allbayrak.com',
        'limit': 1})
    command_results_sha256 = get_c2_attribution_record_by_indicator(client, {
        'indicator_type': 'email',
        'indicator_value': 'ip@allbayrak.com',
        'limit': 1})
    # results is CommandResults list
    context_ip = command_results_ip.to_context()['Contents']
    context_domain = command_results_domain.to_context()['Contents']
    context_email = command_results_email.to_context()['Contents']
    context_sha256 = command_results_sha256.to_context()['Contents']
    assert context_ip == expected
    assert context_domain == expected
    assert context_email == expected
    assert context_sha256 == expected

    with pytest.raises(ValueError):
        get_c2_attribution_record_by_indicator(client,
                                               {'indicator_type': 'tttt',
                                                'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_c2_attribution_record_by_indicator(client, {'indicator_type': 'ip',
                                                        'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_c2_attribution_record_by_indicator(client,
                                               {'indicator_type': 'domain',
                                                'indicator_value': '3333'})
    with pytest.raises(ValueError):
        get_c2_attribution_record_by_indicator(client,
                                               {'indicator_type': 'email',
                                                'indicator_value': '33333'})
    with pytest.raises(ValueError):
        get_c2_attribution_record_by_indicator(client,
                                               {'indicator_type': 'sha256',
                                                'indicator_value': '33333'})
