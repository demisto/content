import pytest
import json

from HYASInsight import Client, get_passive_dns_records_by_indicator, get_dynamic_dns_records_by_indicator, \
    get_whois_records_by_indicator, get_whois_current_records_by_domain, get_malware_samples_records_by_indicator, \
    get_associated_ips_by_hash, get_associated_domains_by_hash, \
    get_c2attribution_records_by_indicator, \
    get_passive_hash_records_by_indicator,\
    get_ssl_certificate_records_by_indicator, \
    get_sinkhole_records_by_ipv4_address, get_malware_sample_information_by_hash,\
    get_opensource_indicator_records_by_indicator, get_device_geo_records_by_ip_address

client = Client(
    base_url="test.com",
    apikey="test",
)


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


PASSIVE_DNS_RESPONSE = util_load_json('test_data/passivedns_response.json')
DYNAMIC_DNS_RESPONSE = util_load_json('test_data/dynamicdns_response.json')
WHOIS_RESPONSE = util_load_json('test_data/whois_response.json')
C2_ATTRIBUTION_RESPONSE = util_load_json(
    'test_data/c2_attribution_response.json')

WHOIS_CURRENT_RAW_RESPONSE = util_load_json('test_data/whoiscurrent_input.json')
MALWARE_SAMPLE_RESPONSE = util_load_json('test_data/malwaresample_response.json')
PASSIVE_HASH_RESPONSE = util_load_json('test_data/passive_hash_response.json')
SSL_CERTIFICATE_RESPONSE = util_load_json('test_data/ssl_certificate_response.json')
DEVICE_GEO_RESPONSE = util_load_json('test_data/device_geo_repsponse.json')
OPEN_SOURCE_RESPONSE = util_load_json('test_data/open_source_response.json')
SINKHOLE_RESPONSE = util_load_json('test_data/sinkhole_response.json')
MALWARE_INFO_RESPONSE = util_load_json('test_data/malware_info_response.json')
ASSOCIATED_IPS_INPUT = [{'ipv4': '8.8.8.8'}]
ASSOCIATED_DOMAINS_INPUT = [{'domain': 'google.com'}]
ASSOCIATED_IPS = {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d', 'ips': ['8.8.8.8']}
ASSOCIATED_DOMAINS = {'md5': '1d0a97c41afe5540edd0a8c1fb9a0f2d', 'domains': ['google.com']}


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
                                                                           'indicator_value': 'google.com',
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


@pytest.mark.parametrize('raw_response, expected',
                         [(WHOIS_CURRENT_RAW_RESPONSE,
                           WHOIS_CURRENT_RAW_RESPONSE)])
def test_get_whois_current_records_by_domain(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response])

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
                                                                               'indicator_value': 'google.com',
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

    command_results_ip = get_c2attribution_records_by_indicator(client, {
        'indicator_type': 'ip',
        'indicator_value': '197.210.84.34',
        'limit': 1})
    command_results_domain = get_c2attribution_records_by_indicator(client, {
        'indicator_type': 'domain',
        'indicator_value': 'himionsa.com',
        'limit': 1})

    command_results_email = get_c2attribution_records_by_indicator(client, {
        'indicator_type': 'email',
        'indicator_value': 'ip@allbayrak.com',
        'limit': 1})
    command_results_sha256 = get_c2attribution_records_by_indicator(client, {
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
        get_c2attribution_records_by_indicator(client,
                                               {'indicator_type': 'tttt',
                                                'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_c2attribution_records_by_indicator(client, {'indicator_type': 'ip',
                                                        'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_c2attribution_records_by_indicator(client,
                                               {'indicator_type': 'domain',
                                                'indicator_value': '3333'})
    with pytest.raises(ValueError):
        get_c2attribution_records_by_indicator(client,
                                               {'indicator_type': 'email',
                                                'indicator_value': '33333'})
    with pytest.raises(ValueError):
        get_c2attribution_records_by_indicator(client,
                                               {'indicator_type': 'sha256',
                                                'indicator_value': '33333'})


@pytest.mark.parametrize('raw_response, expected',
                         [(PASSIVE_HASH_RESPONSE, PASSIVE_HASH_RESPONSE)])
def test_get_passive_hash_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_ipv4 = get_passive_hash_records_by_indicator(client, {
        'indicator_type': 'ipv4',
        'indicator_value': '4.4.4.4',
        'limit': 1})

    command_results_domain = get_passive_hash_records_by_indicator(client, {
        'indicator_type': 'domain',
        'indicator_value': 'chennaigastrosurgeon.com',
        'limit': 1})

    context_ip = command_results_ipv4.to_context()['Contents']
    context_domain = command_results_domain.to_context()['Contents']
    assert context_ip == expected
    assert context_domain == expected

    with pytest.raises(ValueError):
        get_passive_hash_records_by_indicator(client, {'indicator_type': 'tttt', 'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_passive_hash_records_by_indicator(client, {'indicator_type': 'ip', 'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_passive_hash_records_by_indicator(client, {'indicator_type': 'domain', 'indicator_value': '3333'})


@pytest.mark.parametrize('raw_response, expected',
                         [(SSL_CERTIFICATE_RESPONSE, SSL_CERTIFICATE_RESPONSE)])
def test_get_ssl_certificate_record_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_ipv4 = get_ssl_certificate_records_by_indicator(client, {
        'indicator_type': 'ip',
        'indicator_value': '4.4.4.4',
        'limit': 1})
    command_results_domain = get_ssl_certificate_records_by_indicator(client, {
        'indicator_type': 'domain',
        'indicator_value': 'chennaigastrosurgeon.com',
        'limit': 1})
    command_results_hash = get_ssl_certificate_records_by_indicator(client, {
        'indicator_type': 'sha1',
        'indicator_value': 'd1af9e1d6c892a56b34d88b1f75a84941252caff',
        'limit': 1})
    context_ip = command_results_ipv4.to_context()['Contents']
    context_domain = command_results_domain.to_context()['Contents']
    context_hash = command_results_hash.to_context()['Contents']
    assert context_ip == expected['ssl_certs']
    assert context_domain == expected['ssl_certs']
    assert context_hash == expected['ssl_certs']

    with pytest.raises(ValueError):
        get_ssl_certificate_records_by_indicator(client, {'indicator_type': 'tttt', 'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_ssl_certificate_records_by_indicator(client, {'indicator_type': 'ip', 'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_ssl_certificate_records_by_indicator(client, {'indicator_type': 'domain', 'indicator_value': '3333'})


@pytest.mark.parametrize('raw_response, expected',
                         [(OPEN_SOURCE_RESPONSE, OPEN_SOURCE_RESPONSE)])
def test_get_opensource_indicator_record_by_indicator(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)
    command_results_ipv4 = get_opensource_indicator_records_by_indicator(client, {
        'indicator_type': 'domain',
        'indicator_value': 'wgeupok.com',
        'limit': 1})
    context_ip = command_results_ipv4.to_context()['Contents']
    assert context_ip == expected

    with pytest.raises(ValueError):
        get_opensource_indicator_records_by_indicator(client, {'indicator_type': 'tttt', 'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_opensource_indicator_records_by_indicator(client, {'indicator_type': 'ipv4', 'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_opensource_indicator_records_by_indicator(client, {'indicator_type': 'domain', 'indicator_value': '3333'})


@pytest.mark.parametrize('raw_response, expected',
                         [(DEVICE_GEO_RESPONSE, DEVICE_GEO_RESPONSE)])
def test_get_device_geo_record_by_ip_address(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_ipv4 =\
        get_device_geo_records_by_ip_address(client, {'indicator_type': 'ipv4', 'indicator_value': '4.4.4.4', 'limit': 1})

    context_ip = command_results_ipv4.to_context()['Contents']
    assert context_ip == expected

    with pytest.raises(ValueError):
        get_device_geo_records_by_ip_address(client, {'indicator_type': 'tttt', 'indicator_value': '4.4.4.4'})
    with pytest.raises(ValueError):
        get_device_geo_records_by_ip_address(client, {'indicator_type': 'ipv4', 'indicator_value': 'gggg'})
    with pytest.raises(ValueError):
        get_device_geo_records_by_ip_address(client, {'indicator_type': 'domain', 'indicator_value': '3333'})


@pytest.mark.parametrize('raw_response, expected',
                         [(SINKHOLE_RESPONSE, SINKHOLE_RESPONSE)])
def test_get_sinkhole_record_by_ipv4_address(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_ipv4 = get_sinkhole_records_by_ipv4_address(client, {'ipv4': '4.4.4.4', 'limit': 1})

    context_ip = command_results_ipv4.to_context()['Contents']
    assert context_ip == expected

    with pytest.raises(ValueError):
        get_sinkhole_records_by_ipv4_address(client, {'ipv4': 'tttt'})


@pytest.mark.parametrize('raw_response, expected',
                         [(MALWARE_INFO_RESPONSE, MALWARE_INFO_RESPONSE)])
def test_get_malware_information_record_by_hash(mocker, raw_response, expected):
    mocker.patch.object(client, 'query', side_effect=[raw_response] * 5)

    command_results_hash =\
        get_malware_sample_information_by_hash(client, {'hash': '3e1811b957957ff27a15ef46c0a1dcf6', 'limit': 1})

    context_hash = command_results_hash.to_context()['Contents']
    assert context_hash == expected

    with pytest.raises(ValueError):
        get_malware_sample_information_by_hash(client, {'hash': 'tttt'})
