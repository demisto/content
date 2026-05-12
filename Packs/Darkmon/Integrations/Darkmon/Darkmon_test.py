"""
Comprehensive tests for the Darkmon XSOAR integration.

Each command has its own section with:
  * a realistic mock API response
  * an assertion on the URL/params the Client emits
  * an assertion on the outputs context structure
  * an assertion on the readable_output (the markdown shown to the user)
  * an empty-content case
  * validation cases where the command has guard clauses

Run:
    python -m pytest src_test.py -v
"""

import builtins
import importlib
import json
import os

import pytest
import yaml

src = importlib.import_module('Darkmon')


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_client():
    return src.Client(base_url='https://api.dev.darkmon.com/tip/2025.1', headers={'X-API-KEY': 'testkey'})


def patch_http(monkeypatch, response):
    """Patch Client._http_request and return a dict that captures the call."""
    calls = {}

    def fake(self, method, url_suffix='', params=None, **kwargs):
        calls['method'] = method
        calls['url_suffix'] = url_suffix
        calls['params'] = params
        calls['kwargs'] = kwargs
        return response

    monkeypatch.setattr(src.Client, '_http_request', fake)
    return calls


def page_obj(number=0, total_pages=1, total_elements=1):
    return {'number': number, 'totalPages': total_pages, 'totalElements': total_elements}


# ===========================================================================
# test-module
# ===========================================================================

def test_test_module_validates_via_test_api_key_endpoint(monkeypatch):
    calls = {}

    def fake(self, method, url_suffix='', resp_type=None, **kwargs):
        calls['method'] = method
        calls['url_suffix'] = url_suffix
        calls['resp_type'] = resp_type
        return 'The API key is valid!'

    monkeypatch.setattr(src.Client, '_http_request', fake)
    assert src.test_module(make_client()) == 'ok'
    assert calls['url_suffix'] == '/test-api-key'
    assert calls['method'] == 'GET'
    assert calls['resp_type'] == 'text'


def test_test_module_returns_error_on_invalid_key(monkeypatch):
    monkeypatch.setattr(src.Client, '_http_request',
                        lambda *_a, **_k: 'nope')
    with pytest.raises(builtins.DemistoException, match='Failed to validate API key'):
        src.test_module(make_client())


def test_test_module_swallows_http_exception(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError('connection refused')

    monkeypatch.setattr(src.Client, '_http_request', boom)
    with pytest.raises(builtins.DemistoException):
        src.test_module(make_client())


# ===========================================================================
# helpers: camel_case_to_underscore + extract_feature_value
# ===========================================================================

@pytest.mark.parametrize('inp, out', [
    ('camelCase', 'camel_case'),
    ('PascalCase', 'pascal_case'),
    ('lowercase', 'lowercase'),
    ('XMLParser', 'xml_parser'),
    ('simpleHTTP', 'simple_http'),
])
def test_camel_case_to_underscore(inp, out):
    assert src.camel_case_to_underscore(inp) == out


def test_extract_feature_value_finds_match():
    item = {
        'feature': [
            {'accessorKey': 'username', 'value': 'alice'},
            {'accessorKey': 'password', 'value': 'p@ss'},
        ]
    }
    assert src.extract_feature_value(item, 'username') == 'alice'
    assert src.extract_feature_value(item, 'password') == 'p@ss'
    assert src.extract_feature_value(item, 'missing') is None


def test_extract_feature_value_returns_none_when_no_features():
    assert src.extract_feature_value({}, 'k') is None
    assert src.extract_feature_value({'feature': []}, 'k') is None


# ===========================================================================
# helpers: extract_features_to_dict (per indicator type)
# ===========================================================================

def test_extract_features_to_dict_domain():
    item = {
        'id': 1, 'type': 'domain', 'value': 'evil.com',
        'eventId': 99, 'eventInfo': 'phishing', 'timestamp': '2026-01-01T00:00:00Z',
        'expired': False, 'name': 'evil.com', 'classification': 'malicious',
        'ips': ['1.2.3.4', '5.6.7.8'],
    }
    out = src.extract_features_to_dict(item)
    assert out['type'] == 'domain'
    assert out['value'] == 'evil.com'
    assert out['classification'] == 'malicious'
    assert out['ips'] == ['1.2.3.4', '5.6.7.8']
    assert 'md5' not in out  # type-specific fields shouldn't bleed across types


def test_extract_features_to_dict_file():
    item = {
        'id': 2, 'type': 'file', 'value': 'abc',
        'name': 'malware.exe', 'md5': 'm', 'sha1': 's1', 'sha256': 's2',
        'sha3_384': 's3', 'tlsh': 't', 'ssdeep': 'sd', 'size': 12345,
        'mimeType': 'application/x-dosexec',
    }
    out = src.extract_features_to_dict(item)
    assert out['md5'] == 'm'
    assert out['sha256'] == 's2'
    assert out['size'] == 12345
    assert out['mimeType'] == 'application/x-dosexec'


def test_extract_features_to_dict_vulnerability():
    item = {
        'id': 3, 'type': 'vulnerabilityioc', 'value': 'CVE-2026-0001',
        'vulnerabilityId': 'CVE-2026-0001', 'name': 'RCE', 'severity': 'CRITICAL',
        'cvssScore': 9.8, 'tags': ['rce', 'wormable'],
    }
    out = src.extract_features_to_dict(item)
    assert out['vulnerabilityId'] == 'CVE-2026-0001'
    assert out['severity'] == 'CRITICAL'
    assert out['cvssScore'] == 9.8
    assert out['tags'] == ['rce', 'wormable']


def test_extract_features_to_dict_strips_none_values():
    item = {'id': 1, 'type': 'ip', 'value': '8.8.8.8', 'ip': '8.8.8.8',
            'eventInfo': None, 'expired': None}
    out = src.extract_features_to_dict(item)
    assert 'eventInfo' not in out
    assert 'expired' not in out


# ===========================================================================
# dmontip-get-indicators
# ===========================================================================

INDICATORS_API_RESPONSE = {
    'iocObjects': [
        {
            'id': 'd1', 'type': 'domain', 'value': 'phish.example.com',
            'name': 'phish.example.com', 'classification': 'malicious',
            'ips': ['203.0.113.10'], 'eventInfo': 'Phishing kit hosted',
            'timestamp': '2026-04-29T12:00:00Z', 'expired': False,
        },
        {
            'id': 'h1', 'type': 'file', 'value': 'abc123',
            'name': 'dropper.exe', 'md5': 'm5', 'sha256': 's256',
            'size': 4096, 'mimeType': 'application/x-dosexec',
            'eventInfo': 'Dropper sample', 'timestamp': '2026-04-29T13:00:00Z',
        },
        {
            'id': 'i1', 'type': 'ip', 'value': '198.51.100.7', 'ip': '198.51.100.7',
            'eventInfo': 'C2 beacon', 'timestamp': '2026-04-29T14:00:00Z',
        },
    ]
}


def test_dmontip_get_indicators_calls_correct_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, INDICATORS_API_RESPONSE)
    src.dmontip_get_indicators_command(make_client(), {'size': '50'})
    assert calls['url_suffix'] == 'ioc-feed'
    assert calls['params'] == {'size': 50}


def test_dmontip_get_indicators_renders_grouped_tables(monkeypatch):
    patch_http(monkeypatch, INDICATORS_API_RESPONSE)
    result = src.dmontip_get_indicators_command(make_client(), {})

    assert 'Darkmon.Indicator(val.id == obj.id)' in result.outputs
    indicators = result.outputs['Darkmon.Indicator(val.id == obj.id)']
    ids = {i['id'] for i in indicators}
    assert ids == {'d1', 'h1', 'i1'}

    md = result.readable_output
    assert 'DOMAIN Indicators' in md
    assert 'FILE Indicators' in md
    assert 'IP Indicators' in md
    assert 'phish.example.com' in md
    assert 'dropper.exe' in md
    assert '198.51.100.7' in md


def test_dmontip_get_indicators_empty(monkeypatch):
    patch_http(monkeypatch, {'iocObjects': []})
    result = src.dmontip_get_indicators_command(make_client(), {})
    assert result.readable_output == 'No indicators found'
    assert result.outputs['Darkmon.Indicator(val.id == obj.id)'] == []


# ===========================================================================
# dmontip-global-search (and the per-type shortcuts: ip/url/domain/email/file)
# ===========================================================================

SEARCH_API_RESPONSE = {
    'content': [
        {
            'type': 'Domains',
            'feature': [
                {'accessorKey': 'id', 'displayName': 'ID', 'type': 'long', 'value': 42},
                {'accessorKey': 'name', 'displayName': 'Name', 'type': 'string',
                 'value': 'evil.com'},
                {'accessorKey': 'classification', 'displayName': 'Classification',
                 'type': 'string', 'value': 'malicious'},
                {'accessorKey': 'ips', 'displayName': 'IPs', 'type': 'list',
                 'value': ['203.0.113.1', '203.0.113.2']},
                {'accessorKey': 'eventInfo', 'displayName': 'Event Info',
                 'type': 'string', 'value': 'Phishing'},
            ],
        },
    ],
    'page': page_obj(number=0, total_pages=2, total_elements=15),
}


def test_dmontip_global_search_validates_query():
    with pytest.raises(ValueError, match='Query parameter is required'):
        src.dmontip_global_search_command(make_client(), {'type': 'Domain'})


def test_dmontip_global_search_rejects_invalid_type(monkeypatch):
    patch_http(monkeypatch, SEARCH_API_RESPONSE)
    with pytest.raises(ValueError, match='Invalid indicator type'):
        src.dmontip_global_search_command(
            make_client(), {'query': 'evil.com', 'type': 'BogusType'}
        )


def test_dmontip_global_search_formats_query_and_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, SEARCH_API_RESPONSE)
    src.dmontip_global_search_command(
        make_client(), {'query': 'evil.com', 'type': 'Domain', 'page': '1', 'size': '20'}
    )
    assert calls['url_suffix'] == 'search'
    assert calls['params']['query'] == 'Domain: "evil.com"'
    assert calls['params']['page'] == 0
    assert calls['params']['size'] == 20


def test_dmontip_global_search_renders_with_pagination(monkeypatch):
    patch_http(monkeypatch, SEARCH_API_RESPONSE)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'evil.com', 'type': 'Domain'}
    )
    md = result.readable_output
    assert 'Domains Information' in md  # uses TipFeature enum value
    assert 'malicious' in md
    assert 'evil.com' in md
    assert '203.0.113.1' in md
    assert 'Pagination' in md
    assert 'Page 1 of 2' in md
    assert '15 total items' in md


def test_dmontip_global_search_outputs_are_dynamic_from_cells(monkeypatch):
    """SearchResult context items contain whatever cells the backend sent - no hardcoding."""
    patch_http(monkeypatch, SEARCH_API_RESPONSE)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'evil.com', 'type': 'Domain'}
    )
    sr = result.outputs['Darkmon.SearchResult']
    assert len(sr) == 1
    item = sr[0]
    assert item['type'] == 'Domains'
    assert item['id'] == 42
    assert item['name'] == 'evil.com'
    assert item['classification'] == 'malicious'
    assert item['ips'] == ['203.0.113.1', '203.0.113.2']
    assert item['eventInfo'] == 'Phishing'


def test_global_search_handles_unknown_tipfeature_types_dynamically(monkeypatch):
    """A brand-new TipFeature type the integration has never seen should still work."""
    response = {
        'content': [
            {
                'type': 'ThreatActor',  # Python has never hardcoded this type
                'feature': [
                    {'accessorKey': 'name', 'displayName': 'Name',
                     'type': 'string', 'value': 'LockBit'},
                    {'accessorKey': 'origin', 'displayName': 'Origin',
                     'type': 'string', 'value': 'RU'},
                    {'accessorKey': 'aliases', 'displayName': 'Aliases',
                     'type': 'list', 'value': ['LB', 'Bitwise']},
                    {'accessorKey': 'firstSeen', 'displayName': 'First Seen',
                     'type': 'date', 'value': '2024-01-01'},
                ],
            },
            {
                'type': 'Telegram',  # also not hardcoded anywhere
                'feature': [
                    {'accessorKey': 'channel', 'displayName': 'Channel',
                     'type': 'string', 'value': '@bad_actor_chat'},
                    {'accessorKey': 'subscribers', 'displayName': 'Subscribers',
                     'type': 'long', 'value': 1500},
                ],
            },
        ],
        'page': page_obj(0, 1, 2),
    }
    patch_http(monkeypatch, response)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'lockbit', 'type': 'Source'}
    )
    md = result.readable_output
    assert 'ThreatActor Information' in md
    assert 'Telegram Information' in md
    assert 'LockBit' in md
    assert 'RU' in md
    assert 'LB, Bitwise' in md  # list flattened
    assert '@bad_actor_chat' in md
    assert '1500' in md

    sr = result.outputs['Darkmon.SearchResult']
    assert {x['type'] for x in sr} == {'ThreatActor', 'Telegram'}
    actor = next(x for x in sr if x['type'] == 'ThreatActor')
    assert actor['name'] == 'LockBit'
    assert actor['aliases'] == ['LB', 'Bitwise']
    tg = next(x for x in sr if x['type'] == 'Telegram')
    assert tg['channel'] == '@bad_actor_chat'
    assert tg['subscribers'] == 1500


def test_global_search_handles_brand_new_columns_without_code_changes(monkeypatch):
    """A new column on an existing type (e.g. Domains gets a 'reputation' field) should appear."""
    response = {
        'content': [
            {
                'type': 'Domains',
                'feature': [
                    {'accessorKey': 'name', 'displayName': 'Name',
                     'type': 'string', 'value': 'a.example'},
                    {'accessorKey': 'reputation', 'displayName': 'Reputation Score',
                     'type': 'number', 'value': 87},  # never seen before
                    {'accessorKey': 'whoisRegistrar', 'displayName': 'WHOIS Registrar',
                     'type': 'string', 'value': 'Namecheap'},  # also new
                ],
            },
        ],
        'page': {},
    }
    patch_http(monkeypatch, response)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'a.example', 'type': 'Domain'}
    )
    sr = result.outputs['Darkmon.SearchResult'][0]
    assert sr['reputation'] == 87
    assert sr['whoisRegistrar'] == 'Namecheap'
    assert 'Reputation Score' in result.readable_output
    assert 'WHOIS Registrar' in result.readable_output


def test_global_search_preserves_backend_column_order(monkeypatch):
    """Column order in the table should match the cell order from the backend, not alphabetical."""
    response = {
        'content': [
            {
                'type': 'Domains',
                'feature': [
                    {'accessorKey': 'zeta', 'displayName': 'Zeta',
                     'type': 'string', 'value': 'z'},
                    {'accessorKey': 'alpha', 'displayName': 'Alpha',
                     'type': 'string', 'value': 'a'},
                    {'accessorKey': 'middle', 'displayName': 'Middle',
                     'type': 'string', 'value': 'm'},
                ],
            },
        ],
        'page': {},
    }
    patch_http(monkeypatch, response)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'x', 'type': 'Domain'}
    )
    md = result.readable_output
    # The header row must list Zeta before Alpha before Middle (backend order),
    # not alphabetical (which would be Alpha, Middle, Zeta).
    z = md.index('Zeta')
    a = md.index('Alpha')
    m = md.index('Middle')
    assert z < a < m, f"column order broken: Zeta@{z}, Alpha@{a}, Middle@{m}"


def test_global_search_handles_missing_or_empty_feature_array(monkeypatch):
    """Items without a feature array should not break extraction or rendering."""
    response = {
        'content': [
            {'type': 'Domains'},  # no 'feature' key at all
            {'type': 'IPs', 'feature': []},  # empty
            {'type': 'Urls', 'feature': [
                {'accessorKey': 'url', 'displayName': 'URL',
                 'type': 'string', 'value': 'https://x.example'},
            ]},
        ],
        'page': {},
    }
    patch_http(monkeypatch, response)
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'x', 'type': 'Domain'}
    )
    sr = result.outputs['Darkmon.SearchResult']
    assert len(sr) == 3
    # First two contain only the type field
    assert sr[0] == {'type': 'Domains'}
    assert sr[1] == {'type': 'IPs'}
    # Third has the URL
    assert sr[2]['url'] == 'https://x.example'
    # Rendering should only show a Urls table
    md = result.readable_output
    assert 'Urls Information' in md
    assert 'https://x.example' in md


def test_global_search_handles_dict_value_in_cell(monkeypatch):
    """A cell whose value is a nested dict should be JSON-serialized in the table, preserved in context."""
    response = {
        'content': [
            {
                'type': 'IPs',
                'feature': [
                    {'accessorKey': 'address', 'displayName': 'Address',
                     'type': 'string', 'value': '1.2.3.4'},
                    {'accessorKey': 'geo', 'displayName': 'Geo',
                     'type': 'object',
                     'value': {'country': 'IT', 'lat': 41.9, 'lon': 12.5}},
                ],
            },
        ],
        'page': {},
    }
    patch_http(monkeypatch, response)
    result = src.dmontip_global_search_command(
        make_client(), {'query': '1.2.3.4', 'type': 'IP'}
    )
    sr = result.outputs['Darkmon.SearchResult'][0]
    # Context: dict preserved as-is
    assert sr['geo'] == {'country': 'IT', 'lat': 41.9, 'lon': 12.5}
    # Table: dict serialized to JSON-ish string with country
    assert '"country"' in result.readable_output


def test_extract_search_result_skips_none_values():
    item = {
        'type': 'Domains',
        'feature': [
            {'accessorKey': 'name', 'value': 'x.example'},
            {'accessorKey': 'classification', 'value': None},  # should be skipped
            {'accessorKey': 'ips', 'value': []},  # empty list IS preserved
        ],
    }
    out = src.extract_search_result(item)
    assert out == {'type': 'Domains', 'name': 'x.example', 'ips': []}


def test_extract_search_result_skips_cells_without_accessor_key():
    item = {
        'type': 'Domains',
        'feature': [
            {'accessorKey': 'name', 'value': 'x.example'},
            {'displayName': 'No Key', 'value': 'lost'},  # missing accessorKey
            {'accessorKey': '', 'value': 'also lost'},  # empty accessorKey
        ],
    }
    out = src.extract_search_result(item)
    assert out == {'type': 'Domains', 'name': 'x.example'}


def test_extract_search_result_handles_malformed_feature_field():
    """Defensive: feature being a string/dict instead of list shouldn't crash."""
    assert src.extract_search_result({'type': 'X', 'feature': 'not a list'}) == {'type': 'X'}
    assert src.extract_search_result({'type': 'X', 'feature': None}) == {'type': 'X'}
    assert src.extract_search_result({}) == {}


def test_dmontip_global_search_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': page_obj(0, 1, 0)})
    result = src.dmontip_global_search_command(
        make_client(), {'query': 'nothing', 'type': 'Domain'}
    )
    assert 'No data found' in result.readable_output


@pytest.mark.parametrize('cmd, arg_key, type_label', [
    (src.dmontip_search_ip_command, 'ip', 'IP'),
    (src.dmontip_search_url_command, 'url', 'URL'),
    (src.dmontip_search_domain_command, 'domain', 'Domain'),
    (src.dmontip_search_email_command, 'email', 'Email'),
    (src.dmontip_search_file_command, 'hash', 'Hash'),
])
def test_search_shortcut_commands_route_to_global_search(monkeypatch, cmd, arg_key, type_label):
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    cmd(make_client(), {arg_key: 'value-x'})
    assert calls['url_suffix'] == 'search'
    assert calls['params']['query'] == f'{type_label}: "value-x"'


@pytest.mark.parametrize('cmd, missing_msg', [
    (src.dmontip_search_ip_command, 'IP parameter is required'),
    (src.dmontip_search_url_command, 'URL parameter is required'),
    (src.dmontip_search_domain_command, 'Domain parameter is required'),
    (src.dmontip_search_email_command, 'Email parameter is required'),
    (src.dmontip_search_file_command, 'File hash parameter is required'),
])
def test_search_shortcut_commands_validate_required_arg(cmd, missing_msg):
    with pytest.raises(ValueError, match=missing_msg):
        cmd(make_client(), {})


# ===========================================================================
# dmontip-get-compromised (5 types)
# ===========================================================================

COMPROMISED_ACCOUNTS_RESPONSE = {
    'content': [{
        'id': 1, 'username': 'alice', 'password': 'hunter2',
        'url': 'https://login.example.com', 'firstSeen': '2026-04-01',
        'firstCompromiseDate': '2025-12-01', 'lastCompromiseDate': '2026-04-29',
        'state': 'NEW', 'valid': True, 'compromiseSourcesCount': 2,
        'countries': ['IT', 'US'], 'sources': ['darkforum'], 'stealers': ['redline'],
    }],
    'page': page_obj(0, 5, 100),
}


def test_compromised_requires_type():
    with pytest.raises(ValueError, match='type argument is required'):
        src.dmontip_get_compromised_command(make_client(), {})


def test_compromised_rejects_invalid_size():
    with pytest.raises(ValueError, match='size must be between 1 and 500'):
        src.dmontip_get_compromised_command(
            make_client(), {'type': 'accounts', 'size': '600'}
        )


def test_compromised_rejects_invalid_page():
    with pytest.raises(ValueError, match='page must be >= 1'):
        src.dmontip_get_compromised_command(
            make_client(), {'type': 'accounts', 'page': '-2'}
        )


def test_compromised_accounts_endpoint_and_output(monkeypatch):
    # redaction off so we can assert raw password presence in markdown
    monkeypatch.setattr(builtins.demisto, 'params',
                        lambda: {'redact_secrets': False})
    calls = patch_http(monkeypatch, COMPROMISED_ACCOUNTS_RESPONSE)
    result = src.dmontip_get_compromised_command(
        make_client(), {'type': 'accounts', 'page': '1', 'size': '20'}
    )
    assert calls['url_suffix'] == 'leaks/accounts'
    assert calls['params'] == {'page': 0, 'size': 20}

    assert 'Darkmon.Compromised.Account' in result.outputs
    assert result.outputs['Darkmon.Compromised.Account'][0]['username'] == 'alice'

    md = result.readable_output
    assert 'Compromised Account Data' in md
    assert 'alice' in md
    assert 'hunter2' in md
    assert 'IT, US' in md  # list flattened to comma-separated
    assert 'Page 1 / 5' in md
    assert 'Total Items: 100' in md


@pytest.mark.parametrize('data_type, suffix, prefix', [
    ('bank-cards', 'leaks/bank-cards', 'Darkmon.Compromised.BankCard'),
    ('combo-lists', 'leaks/combo-lists', 'Darkmon.Compromised.ComboList'),
    ('public-breaches', 'leaks/public-breaches', 'Darkmon.Compromised.PublicBreach'),
    ('employees', 'leaks/accounts/employees', 'Darkmon.Compromised.Employee'),
])
def test_compromised_other_types_route_correctly(monkeypatch, data_type, suffix, prefix):
    calls = patch_http(monkeypatch, {'content': [{'id': 1}], 'page': {}})
    result = src.dmontip_get_compromised_command(
        make_client(), {'type': data_type}
    )
    assert calls['url_suffix'] == suffix
    assert prefix in result.outputs


def test_compromised_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_compromised_command(
        make_client(), {'type': 'accounts'}
    )
    assert 'No compromised data found' in result.readable_output


# ===========================================================================
# dmontip-get-vpn
# ===========================================================================

VPN_RESPONSE = {
    'content': [{
        'id': 'v1', 'ip': '203.0.113.50', 'port': 1194,
        'name': 'NordVPN-IT', 'firstSeen': '2026-01-01',
        'lastUpdated': '2026-04-30',
    }],
    'page': page_obj(0, 3, 30),
}


def test_vpn_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, VPN_RESPONSE)
    src.dmontip_get_vpn_command(make_client(), {'page': '1', 'size': '50'})
    assert calls['url_suffix'] == 'vpn'
    assert calls['params']['page'] == 0
    assert calls['params']['size'] == 50


def test_vpn_rendering(monkeypatch):
    patch_http(monkeypatch, VPN_RESPONSE)
    result = src.dmontip_get_vpn_command(make_client(), {})
    md = result.readable_output
    assert 'VPN Exit Nodes' in md
    assert '203.0.113.50' in md
    assert '1194' in md
    assert 'NordVPN-IT' in md
    assert 'Page 1 / 3' in md
    assert 'Darkmon.VPN' in result.outputs


def test_vpn_size_bounds():
    with pytest.raises(ValueError, match='size must be between 1 and 100'):
        src.dmontip_get_vpn_command(make_client(), {'size': '500'})


def test_vpn_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_vpn_command(make_client(), {})
    assert 'No VPN data found' in result.readable_output


# ===========================================================================
# dmontip-get-proxy
# ===========================================================================

PROXY_RESPONSE = {
    'content': [{
        'id': 'p1', 'ip': '198.51.100.20', 'port': 8080, 'type': 'HTTP',
        'firstSeen': '2026-02-01', 'lastUpdated': '2026-04-29',
    }],
    'page': page_obj(0, 2, 25),
}


def test_proxy_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, PROXY_RESPONSE)
    src.dmontip_get_proxy_command(make_client(), {})
    assert calls['url_suffix'] == 'proxy'


def test_proxy_rendering(monkeypatch):
    patch_http(monkeypatch, PROXY_RESPONSE)
    result = src.dmontip_get_proxy_command(make_client(), {})
    md = result.readable_output
    assert 'Open Proxies' in md
    assert '198.51.100.20' in md
    assert 'HTTP' in md
    assert 'Darkmon.Proxy' in result.outputs


def test_proxy_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_proxy_command(make_client(), {})
    assert 'No proxy data found' in result.readable_output


# ===========================================================================
# dmontip-get-cve
# ===========================================================================

CVE_RESPONSE = {
    'content': [{
        'id': 'c1', 'name': 'CVE-2026-0001',
        'description': 'Remote code execution in libfoo',
        'cvssScore': 9.8, 'severity': 'CRITICAL',
        'published': '2026-04-15', 'lastModified': '2026-04-28',
        'sourceIdentifier': 'nvd@nist.gov', 'tags': ['rce', 'wormable'],
    }],
    'page': page_obj(0, 4, 50),
}


def test_cve_endpoint_uses_corrected_path(monkeypatch):
    calls = patch_http(monkeypatch, CVE_RESPONSE)
    src.dmontip_get_cve_command(make_client(), {})
    assert calls['url_suffix'] == 'vulnerabilities'  # was buggy "get/vulnerabilities"


def test_cve_rendering(monkeypatch):
    patch_http(monkeypatch, CVE_RESPONSE)
    result = src.dmontip_get_cve_command(make_client(), {'page': '1', 'size': '20'})
    md = result.readable_output
    assert 'Vulnerabilities' in md
    assert 'CVE-2026-0001' in md
    assert 'Remote code execution' in md
    assert '9.8' in md
    assert 'rce, wormable' in md
    assert 'Darkmon.CVE' in result.outputs


def test_cve_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_cve_command(make_client(), {})
    assert 'No vulnerability data found' in result.readable_output


# ===========================================================================
# dmontip-get-nrd (newly registered domains)
# ===========================================================================

NRD_RESPONSE = {
    'content': [{
        'id': 'n1', 'value': 'just-registered.xyz', 'type': 'domain',
        'timestamp': '2026-04-30T00:00:00Z',
    }],
    'page': page_obj(0, 10, 200),
}


def test_nrd_endpoint_and_filter(monkeypatch):
    calls = patch_http(monkeypatch, NRD_RESPONSE)
    src.dmontip_get_nrd_command(make_client(), {})
    assert calls['url_suffix'] == 'ioc'
    assert calls['params']['filter'] == '{"iocClassifications": ["NEWLY_REGISTERED_DOMAIN"]}'


def test_nrd_rendering(monkeypatch):
    patch_http(monkeypatch, NRD_RESPONSE)
    result = src.dmontip_get_nrd_command(make_client(), {})
    md = result.readable_output
    assert 'Newly Registered Domains' in md
    assert 'just-registered.xyz' in md
    assert 'Darkmon.NRD' in result.outputs


def test_nrd_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_nrd_command(make_client(), {})
    assert 'No newly-registered domains found' in result.readable_output


# ===========================================================================
# dmontip-get-tbf (telnet brute force)
# ===========================================================================

TBF_RESPONSE = {
    'content': [{
        'id': 't1', 'value': '192.0.2.55', 'type': 'ip',
        'timestamp': '2026-04-30T01:00:00Z',
    }],
    'page': page_obj(0, 1, 10),
}


def test_tbf_endpoint_and_filter(monkeypatch):
    calls = patch_http(monkeypatch, TBF_RESPONSE)
    src.dmontip_get_tbf_command(make_client(), {})
    assert calls['url_suffix'] == 'ioc'
    assert calls['params']['filter'] == '{"iocClassifications": ["TELNET_BRUTE_FORCE"]}'


def test_tbf_rendering(monkeypatch):
    patch_http(monkeypatch, TBF_RESPONSE)
    result = src.dmontip_get_tbf_command(make_client(), {})
    md = result.readable_output
    assert 'Telnet Brute Force IOCs' in md
    assert '192.0.2.55' in md
    assert 'Darkmon.TBF' in result.outputs


def test_tbf_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_tbf_command(make_client(), {})
    assert 'No Telnet Brute Force IOCs found' in result.readable_output


# ===========================================================================
# dmontip-get-ransomware (articles + mentions)
# ===========================================================================

RANSOMWARE_ARTICLES_RESPONSE = {
    'content': [{
        'id': 'r1', 'victimName': 'Acme Corp', 'victimDomain': 'acme.example',
        'threatActor': 'LockBit', 'description': 'Acme Corp listed on leak site',
        'publishedAt': '2026-04-28', 'updatedAt': '2026-04-29',
        'state': 'NEW', 'valid': True,
    }],
    'page': page_obj(0, 6, 60),
}


def test_ransomware_articles_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, RANSOMWARE_ARTICLES_RESPONSE)
    src.dmontip_get_ransomware_command(make_client(), {})
    assert calls['url_suffix'] == '/articles/ransomware'


def test_ransomware_mentions_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, RANSOMWARE_ARTICLES_RESPONSE)
    src.dmontip_get_ransomware_command(make_client(), {'type': 'mentions'})
    assert calls['url_suffix'] == '/mentions/ransomware'


def test_ransomware_articles_rendering(monkeypatch):
    patch_http(monkeypatch, RANSOMWARE_ARTICLES_RESPONSE)
    result = src.dmontip_get_ransomware_command(make_client(), {'page': '1'})
    md = result.readable_output
    assert 'Ransomware Articles' in md
    assert 'Acme Corp' in md
    assert 'LockBit' in md
    assert 'Page 1 / 6' in md
    assert 'Darkmon.Ransomware' in result.outputs


def test_ransomware_mentions_rendering(monkeypatch):
    patch_http(monkeypatch, RANSOMWARE_ARTICLES_RESPONSE)
    result = src.dmontip_get_ransomware_command(make_client(), {'type': 'mentions'})
    assert 'Ransomware Mentions' in result.readable_output


def test_ransomware_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_ransomware_command(make_client(), {})
    assert 'No ransomware articles found' in result.readable_output


# ===========================================================================
# dmontip-get-landscape (articles + mentions)
# ===========================================================================

LANDSCAPE_RESPONSE = {
    'content': [{
        'id': 'l1', 'title': 'New zero-day exploited in the wild',
        'link': 'https://news.example.com/zd',
        'publicationDate': '2026-04-29',
        'source': 'BleepingComputer', 'author': 'Lawrence Abrams',
        'categories': ['vulnerability', 'zero-day'],
        'matchedKeywords': ['zero-day', 'exploit'],
        'matchedKeywordsLength': 2,
        # `content` field is intentionally dropped by the renderer
        'content': 'Long article body that should not appear',
    }],
    'page': page_obj(0, 2, 12),
}


def test_landscape_articles_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, LANDSCAPE_RESPONSE)
    src.dmontip_get_landscape_command(make_client(), {})
    assert calls['url_suffix'] == '/articles/landscape-news'


def test_landscape_mentions_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, LANDSCAPE_RESPONSE)
    src.dmontip_get_landscape_command(make_client(), {'type': 'mentions'})
    assert calls['url_suffix'] == '/mentions/landscape-news'


def test_landscape_drops_content_body_from_table(monkeypatch):
    patch_http(monkeypatch, LANDSCAPE_RESPONSE)
    result = src.dmontip_get_landscape_command(make_client(), {})
    md = result.readable_output
    assert 'Landscape Articles' in md
    assert 'zero-day exploited' in md
    assert 'BleepingComputer' in md
    assert 'Long article body that should not appear' not in md
    assert 'Darkmon.Landscape' in result.outputs


def test_landscape_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_landscape_command(make_client(), {})
    assert 'No landscape articles found' in result.readable_output


# ===========================================================================
# dmontip-get-boardprotection (NEW: board-leak/request)
# ===========================================================================

BOARD_PROTECTION_RESPONSE = {
    'content': [
        {
            'id': 11, 'type': 'EMAIL', 'state': 'APPROVED',
            'value': 'ceo@victim.example', 'firstName': 'Jane',
            'middleName': '', 'lastName': 'Doe',
            'reason': 'C-suite monitoring', 'createdBy': 'analyst1',
            'createdAt': '2026-01-15T09:00:00Z',
            'updatedAt': '2026-04-01T09:00:00Z',
            'tokens': ['ceo@victim.example', 'jdoe@victim.example'],
        },
        {
            'id': 12, 'type': 'EMAIL', 'state': 'PENDING',
            'value': 'cto@victim.example',
            'firstName': 'John', 'lastName': 'Smith',
            'createdAt': '2026-04-20T09:00:00Z',
        },
    ],
    'page': page_obj(0, 1, 2),
}


def test_boardprotection_endpoint(monkeypatch):
    calls = patch_http(monkeypatch, BOARD_PROTECTION_RESPONSE)
    src.dmontip_get_boardprotection_command(make_client(), {'page': '1', 'size': '20'})
    assert calls['url_suffix'] == 'board-leak/request'
    assert calls['params'] == {'page': 0, 'size': 20}


def test_boardprotection_includes_term(monkeypatch):
    calls = patch_http(monkeypatch, BOARD_PROTECTION_RESPONSE)
    src.dmontip_get_boardprotection_command(make_client(), {'term': 'ceo'})
    assert calls['params']['term'] == 'ceo'


def test_boardprotection_term_omitted_when_blank(monkeypatch):
    calls = patch_http(monkeypatch, BOARD_PROTECTION_RESPONSE)
    src.dmontip_get_boardprotection_command(make_client(), {'term': '   '})
    assert 'term' not in calls['params']


def test_boardprotection_rendering(monkeypatch):
    patch_http(monkeypatch, BOARD_PROTECTION_RESPONSE)
    result = src.dmontip_get_boardprotection_command(make_client(), {})
    md = result.readable_output
    assert 'Board Protection Requests' in md
    assert 'ceo@victim.example' in md
    assert 'cto@victim.example' in md
    assert 'APPROVED' in md
    assert 'PENDING' in md
    assert 'ceo@victim.example, jdoe@victim.example' in md  # tokens flattened

    out = result.outputs['Darkmon.BoardProtection']
    assert {item['value'] for item in out} == {'ceo@victim.example', 'cto@victim.example'}


def test_boardprotection_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_boardprotection_command(make_client(), {})
    assert 'No board protection requests found' in result.readable_output


def test_boardprotection_size_bounds():
    with pytest.raises(ValueError, match='size must be between 1 and 100'):
        src.dmontip_get_boardprotection_command(make_client(), {'size': '500'})


# ===========================================================================
# dmontip-get-boardemails (board-leak/leaks/{accounts,comboLists,publicBreaches})
# ===========================================================================

BOARDLEAK_ACCOUNTS_RESPONSE = {
    'content': [{
        'email': 'victim@example.com', 'id': 1,
        'compromiseDate': '2026-01-15', 'username': 'victim',
        'password': 'hunter2', 'url': 'https://login.example.com',
        'machineUsername': 'WIN-DESKTOP\\victim',
        'ip': '203.0.113.5', 'country': 'IT',
        'stealer': 'redline', 'source': 'darkforum',
    }],
    'page': page_obj(0, 3, 60),
}

BOARDLEAK_COMBOS_RESPONSE = {
    'content': [{
        'email': 'victim@example.com', 'id': 2,
        'messageTime': '2026-03-01T12:00:00Z',
        'username': 'victim', 'password': 'pw2', 'source': 'tg-channel',
    }],
    'page': page_obj(0, 1, 1),
}

BOARDLEAK_BREACHES_RESPONSE = {
    'content': [{
        'email': 'victim@example.com', 'id': 3,
        'breachTime': '2026-02', 'source': 'BreachX',
        'name': 'Victim Real Name', 'username': 'vic_real',
        'password': 'old-password',
        'firstSeen': '2026-02-15T00:00:00Z',
        'firstSeenDate': '2026-02-15',
        'facebookUsername': 'fb-vic',
        'githubUsername': 'gh-vic',
    }],
    'page': page_obj(0, 1, 1),
}


@pytest.mark.parametrize('leak_type, suffix, response, prefix, key_field, key_value', [
    ('accounts', 'board-leak/leaks/accounts',
     BOARDLEAK_ACCOUNTS_RESPONSE, 'Darkmon.BoardLeak.Account', 'username', 'victim'),
    ('combo-lists', 'board-leak/leaks/comboLists',
     BOARDLEAK_COMBOS_RESPONSE, 'Darkmon.BoardLeak.ComboList', 'source', 'tg-channel'),
    ('public-breaches', 'board-leak/leaks/publicBreaches',
     BOARDLEAK_BREACHES_RESPONSE, 'Darkmon.BoardLeak.PublicBreach', 'name', 'Victim Real Name'),
])
def test_boardemails_routes_renders_and_outputs(monkeypatch, leak_type, suffix, response,
                                                prefix, key_field, key_value):
    calls = patch_http(monkeypatch, response)
    result = src.dmontip_get_boardemails_command(
        make_client(),
        {'type': leak_type, 'email': 'victim@example.com', 'page': '1', 'size': '20'},
    )

    assert calls['url_suffix'] == suffix
    assert calls['params']['email'] == 'victim@example.com'
    assert calls['params']['page'] == 0
    assert calls['params']['size'] == 20

    assert prefix in result.outputs
    assert result.outputs[prefix][0][key_field] == key_value
    assert key_value in result.readable_output


def test_boardemails_includes_term(monkeypatch):
    calls = patch_http(monkeypatch, BOARDLEAK_ACCOUNTS_RESPONSE)
    src.dmontip_get_boardemails_command(
        make_client(),
        {'type': 'accounts', 'email': 'victim@example.com', 'term': 'redline'},
    )
    assert calls['params']['term'] == 'redline'


def test_boardemails_requires_type():
    with pytest.raises(ValueError, match='type argument is required'):
        src.dmontip_get_boardemails_command(make_client(), {'email': 'a@b.com'})


def test_boardemails_requires_email():
    with pytest.raises(ValueError, match='email argument is required'):
        src.dmontip_get_boardemails_command(make_client(), {'type': 'accounts'})


def test_boardemails_size_bounds():
    with pytest.raises(ValueError, match='size must be between 1 and 100'):
        src.dmontip_get_boardemails_command(
            make_client(), {'type': 'accounts', 'email': 'a@b.com', 'size': '500'}
        )


def test_boardemails_empty(monkeypatch):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    result = src.dmontip_get_boardemails_command(
        make_client(), {'type': 'accounts', 'email': 'nobody@example.com'}
    )
    assert 'No board leak accounts found' in result.readable_output


def test_get_board_leaks_rejects_unknown_type(monkeypatch):
    patch_http(monkeypatch, {})
    with pytest.raises(ValueError, match='Unsupported board leak type'):
        make_client().get_board_leaks(leak_type='cards', email='a@b.com')


# ===========================================================================
# fetch-indicators
# ===========================================================================

FEED_RESPONSE = {
    'iocObjects': [
        {
            'id': 'd1', 'type': 'domain', 'value': 'phish.example.com',
            'name': 'phish.example.com', 'classification': 'malicious',
            'eventInfo': 'Phishing kit', 'timestamp': '2026-04-29T12:00:00Z',
        },
        {
            'id': 'h1', 'type': 'file', 'value': 's256-hash',
            'md5': 'm', 'sha1': 's1', 'sha256': 's2',
            'sha3_384': 's3', 'ssdeep': 'sd', 'size': 1024,
            'name': 'sample.exe',
            'eventInfo': 'Sample', 'timestamp': '2026-04-29T13:00:00Z',
        },
        {
            'id': 'v1', 'type': 'vulnerabilityioc', 'value': 'CVE-2026-0001',
            'cvssScore': 9.1, 'description': 'Critical RCE',
            'published': '2026-04-15', 'severity': 'CRITICAL',
        },
        {
            'id': 'i1', 'type': 'ip', 'value': '198.51.100.7',
            'eventInfo': 'C2',
        },
        {
            'id': 'skip-me', 'type': 'domain', 'value': '',  # skipped (empty value)
        },
    ]
}


def test_fetch_indicators_basic_mapping(monkeypatch):
    patch_http(monkeypatch, FEED_RESPONSE)
    indicators = src.fetch_indicators_command(make_client(), {})

    by_value = {i['value']: i for i in indicators}
    assert set(by_value.keys()) == {'phish.example.com', 's256-hash', 'CVE-2026-0001', '198.51.100.7'}

    domain = by_value['phish.example.com']
    assert domain['type'] == 'Domain'
    assert domain['service'] == 'Darkmon'
    assert domain['fields']['domainname'] == 'phish.example.com'
    assert domain['fields']['tags'] == ['malicious']
    assert domain['fields']['description'] == 'Phishing kit'

    file_ind = by_value['s256-hash']
    assert file_ind['type'] == 'File'
    assert file_ind['fields']['md5'] == 'm'
    assert file_ind['fields']['sha256'] == 's2'
    assert file_ind['fields']['size'] == 1024

    cve = by_value['CVE-2026-0001']
    assert cve['type'] == 'CVE'
    assert cve['fields']['cvssscore'] == 9.1
    assert 'CRITICAL' in cve['fields']['tags']

    ip = by_value['198.51.100.7']
    assert ip['type'] == 'IP'
    assert ip['fields']['description'] == 'C2'


def test_fetch_indicators_applies_tlp_and_feed_tags(monkeypatch):
    patch_http(monkeypatch, FEED_RESPONSE)
    indicators = src.fetch_indicators_command(
        make_client(),
        {'tlp_color': 'AMBER', 'feedTags': 'darkmon,threatfeed', 'limit': '100'},
    )
    for ind in indicators:
        assert ind['fields']['trafficlightprotocol'] == 'AMBER'
        assert 'darkmon' in ind['fields']['tags']
        assert 'threatfeed' in ind['fields']['tags']


def test_fetch_indicators_passes_limit_as_size(monkeypatch):
    calls = patch_http(monkeypatch, FEED_RESPONSE)
    src.fetch_indicators_command(make_client(), {'limit': '250'})
    assert calls['url_suffix'] == 'ioc-feed'
    assert calls['params'] == {'size': 250}


# ===========================================================================
# regression: dead methods + landscape rename
# ===========================================================================

def test_dead_methods_removed():
    assert not hasattr(src.Client, 'get_last_mentions')
    assert not hasattr(src.Client, 'get_ransomware_attacks')
    assert not hasattr(src.Client, 'get_board_emails')


def test_landscape_command_renamed():
    assert hasattr(src, 'dmontip_get_landscape_command')
    assert not hasattr(src, 'montip_get_landscape_command')


def test_get_compromised_data_rejects_unknown_type(monkeypatch):
    patch_http(monkeypatch, {})
    with pytest.raises(ValueError, match='Unsupported compromised data type'):
        make_client().get_compromised_data(data_type='unknown')


# ===========================================================================
# default sort behavior (newest-first by sensible field per command)
# ===========================================================================

@pytest.mark.parametrize('cmd_func, args, expected_sort, expected_url', [
    (src.dmontip_get_vpn_command,    {},                              'firstSeen,desc',   'vpn'),
    (src.dmontip_get_proxy_command,  {},                              'firstSeen,desc',   'proxy'),
    (src.dmontip_get_nrd_command,    {},                              'timestamp,desc',   'ioc'),
    (src.dmontip_get_tbf_command,    {},                              'timestamp,desc',   'ioc'),
    (src.dmontip_get_ransomware_command, {},                          'publishedAt,desc', '/articles/ransomware'),
    (src.dmontip_get_ransomware_command, {'type': 'mentions'},        'publishedAt,desc', '/mentions/ransomware'),
])
def test_default_sort_is_applied_when_user_omits(monkeypatch, cmd_func, args, expected_sort, expected_url):
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    cmd_func(make_client(), args)
    assert calls['url_suffix'] == expected_url
    assert calls['params'].get('sort') == expected_sort


@pytest.mark.parametrize('cmd_func, args', [
    (src.dmontip_get_vpn_command,    {'sort': 'lastUpdated,asc'}),
    (src.dmontip_get_proxy_command,  {'sort': 'port,asc'}),
    (src.dmontip_get_nrd_command,    {'sort': 'value,asc'}),
    (src.dmontip_get_tbf_command,    {'sort': 'value,asc'}),
    (src.dmontip_get_ransomware_command, {'sort': 'updatedAt,asc'}),
])
def test_user_supplied_sort_overrides_default(monkeypatch, cmd_func, args):
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    cmd_func(make_client(), args)
    assert calls['params']['sort'] == args['sort']


def test_compromised_combo_lists_default_sort_is_first_seen_desc(monkeypatch):
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    src.dmontip_get_compromised_command(make_client(), {'type': 'combo-lists'})
    assert calls['url_suffix'] == 'leaks/combo-lists'
    assert calls['params'].get('sort') == 'firstSeen,desc'


@pytest.mark.parametrize('data_type, suffix', [
    ('accounts', 'leaks/accounts'),
    ('bank-cards', 'leaks/bank-cards'),
    ('public-breaches', 'leaks/public-breaches'),
    ('employees', 'leaks/accounts/employees'),
])
def test_compromised_other_types_have_no_default_sort(monkeypatch, data_type, suffix):
    """Only combo-lists has a default sort. The other 4 types use the backend's
    natural order so we don't impose an opinion the user might disagree with."""
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    src.dmontip_get_compromised_command(make_client(), {'type': data_type})
    assert calls['url_suffix'] == suffix
    assert 'sort' not in (calls['params'] or {})


def test_compromised_user_sort_overrides_combo_lists_default(monkeypatch):
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    src.dmontip_get_compromised_command(
        make_client(), {'type': 'combo-lists', 'sort': 'messageTime,asc'}
    )
    assert calls['params']['sort'] == 'messageTime,asc'


def test_compromised_user_sort_works_on_types_without_default(monkeypatch):
    """User can opt into sorting for types that don't have a default."""
    calls = patch_http(monkeypatch, {'content': [], 'page': {}})
    src.dmontip_get_compromised_command(
        make_client(), {'type': 'accounts', 'sort': 'lastCompromiseDate,desc'}
    )
    assert calls['params']['sort'] == 'lastCompromiseDate,desc'


@pytest.mark.parametrize('cmd_name, expected_default', [
    ('dmontip-get-vpn',        'firstSeen,desc'),
    ('dmontip-get-proxy',      'firstSeen,desc'),
    ('dmontip-get-nrd',        'timestamp,desc'),
    ('dmontip-get-tbf',        'timestamp,desc'),
    ('dmontip-get-ransomware', 'publishedAt,desc'),
])
def test_yaml_advertises_sort_arg_with_correct_default(yml, cmd_name, expected_default):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == cmd_name)
    sort_arg = next((a for a in cmd['arguments'] if a['name'] == 'sort'), None)
    assert sort_arg is not None, f"{cmd_name} YAML missing 'sort' argument"
    assert sort_arg.get('defaultValue') == expected_default, (
        f"{cmd_name}: YAML default sort {sort_arg.get('defaultValue')!r} != "
        f"expected {expected_default!r}"
    )


def test_yaml_compromised_advertises_sort_arg_without_default(yml):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == 'dmontip-get-compromised')
    sort_arg = next((a for a in cmd['arguments'] if a['name'] == 'sort'), None)
    assert sort_arg is not None
    # No defaultValue because the per-type default lives in Python
    # (combo-lists -> firstSeen,desc; others -> backend natural order)
    assert 'defaultValue' not in sort_arg or not sort_arg.get('defaultValue')


# ===========================================================================
# reputation shortcuts: isArray=true behavior (multiple values)
# ===========================================================================

@pytest.mark.parametrize('cmd, arg_key, type_label', [
    (src.dmontip_search_ip_command, 'ip', 'IP'),
    (src.dmontip_search_url_command, 'url', 'URL'),
    (src.dmontip_search_domain_command, 'domain', 'Domain'),
    (src.dmontip_search_email_command, 'email', 'Email'),
    (src.dmontip_search_file_command, 'hash', 'Hash'),
])
def test_reputation_shortcut_returns_list_for_single_value(monkeypatch, cmd, arg_key, type_label):
    patch_http(monkeypatch, {'content': [], 'page': {}})
    out = cmd(make_client(), {arg_key: 'one-value'})
    assert isinstance(out, list)
    assert len(out) == 1


@pytest.mark.parametrize('cmd, arg_key, type_label', [
    (src.dmontip_search_ip_command, 'ip', 'IP'),
    (src.dmontip_search_url_command, 'url', 'URL'),
    (src.dmontip_search_domain_command, 'domain', 'Domain'),
    (src.dmontip_search_email_command, 'email', 'Email'),
    (src.dmontip_search_file_command, 'hash', 'Hash'),
])
def test_reputation_shortcut_handles_csv_string(monkeypatch, cmd, arg_key, type_label):
    queries = []

    def fake(self, method, url_suffix='', params=None, **kwargs):
        queries.append(params['query'])
        return {'content': [], 'page': {}}

    monkeypatch.setattr(src.Client, '_http_request', fake)
    out = cmd(make_client(), {arg_key: 'a,b,c'})
    assert isinstance(out, list) and len(out) == 3
    assert queries == [f'{type_label}: "a"', f'{type_label}: "b"', f'{type_label}: "c"']


@pytest.mark.parametrize('cmd, arg_key, type_label', [
    (src.dmontip_search_ip_command, 'ip', 'IP'),
    (src.dmontip_search_url_command, 'url', 'URL'),
    (src.dmontip_search_domain_command, 'domain', 'Domain'),
    (src.dmontip_search_email_command, 'email', 'Email'),
    (src.dmontip_search_file_command, 'hash', 'Hash'),
])
def test_reputation_shortcut_handles_python_list(monkeypatch, cmd, arg_key, type_label):
    queries = []

    def fake(self, method, url_suffix='', params=None, **kwargs):
        queries.append(params['query'])
        return {'content': [], 'page': {}}

    monkeypatch.setattr(src.Client, '_http_request', fake)
    cmd(make_client(), {arg_key: ['x', 'y']})
    assert queries == [f'{type_label}: "x"', f'{type_label}: "y"']


# ===========================================================================
# YAML <-> Python consistency
# ===========================================================================


_YAML_PATH = os.path.join(os.path.dirname(__file__), 'Darkmon.yml')
_PY_PATH = os.path.join(os.path.dirname(__file__), 'Darkmon.py')


@pytest.fixture(scope='module')
def yml():
    with open(_YAML_PATH, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def _yaml_command_names(yml):
    return {c['name'] for c in yml['script']['commands']}


def _python_dispatched_commands():
    """Extract command strings from main()'s dispatcher by reflection of the source."""
    import inspect
    src_text = inspect.getsource(src.main)
    import re
    return set(re.findall(r"command == '([^']+)'", src_text))


def test_yaml_commands_match_python_dispatcher(yml):
    yaml_cmds = _yaml_command_names(yml)
    py_cmds = _python_dispatched_commands()
    # XSOAR built-ins handled by Python but not always in YAML commands list:
    # - 'fetch-indicators' is implicit when feed: true
    # - 'test-module' may or may not appear in YAML
    py_only = py_cmds - yaml_cmds - {'fetch-indicators'}
    yaml_only = yaml_cmds - py_cmds - {'test-module'}
    assert py_only == set(), f"Commands dispatched in main() but missing from YAML: {py_only}"
    assert yaml_only == set(), f"Commands declared in YAML but not dispatched in main(): {yaml_only}"


def test_yaml_compromised_predefined_matches_python(yml):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == 'dmontip-get-compromised')
    yaml_types = {p for a in cmd['arguments'] if a['name'] == 'type' for p in a['predefined']}
    # Python endpoint_map keys
    expected = {'accounts', 'bank-cards', 'combo-lists', 'public-breaches', 'employees'}
    assert yaml_types == expected


def test_yaml_boardemails_predefined_matches_python(yml):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == 'dmontip-get-boardemails')
    yaml_types = {p for a in cmd['arguments'] if a['name'] == 'type' for p in a['predefined']}
    expected = {'accounts', 'combo-lists', 'public-breaches'}
    assert yaml_types == expected


def test_yaml_boardemails_requires_email_and_type(yml):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == 'dmontip-get-boardemails')
    required = {a['name'] for a in cmd['arguments'] if a.get('required')}
    assert {'type', 'email'} <= required


def test_yaml_reputation_args_have_default_and_isarray(yml):
    rep_commands = {'ip': 'ip', 'url': 'url', 'domain': 'domain',
                    'email': 'email', 'file': 'hash'}
    for cmd_name, arg_name in rep_commands.items():
        cmd = next(c for c in yml['script']['commands'] if c['name'] == cmd_name)
        arg = next(a for a in cmd['arguments'] if a['name'] == arg_name)
        assert arg.get('default') is True, f"{cmd_name}: {arg_name} missing default: true"
        assert arg.get('isArray') is True, f"{cmd_name}: {arg_name} missing isArray: true"


def test_yaml_feed_config_has_required_params(yml):
    config_names = {c['name'] for c in yml['configuration']}
    required_for_feed = {
        'feed', 'feedReputation', 'feedReliability', 'feedExpirationPolicy',
        'feedExpirationInterval', 'feedFetchInterval', 'feedBypassExclusionList',
        'tlp_color', 'feedTags', 'limit',
    }
    missing = required_for_feed - config_names
    assert not missing, f"Feed config missing: {missing}"


# ===========================================================================
# Tier 0: DBotScore + Common.<Type> contract for reputation commands
# ===========================================================================

@pytest.mark.parametrize('classification, expected_score', [
    ('malicious', 3), ('phishing', 3), ('ransomware', 3), ('c2', 3), ('botnet', 3),
    ('malware', 3), ('exploit', 3),
    ('suspicious', 2),
    ('clean', 1), ('benign', 1), ('safe', 1), ('whitelisted', 1),
    ('MALICIOUS', 3),  # case-insensitive
    ('  suspicious  ', 2),  # trimmed
    ('unknown', 0), ('something-new', 0), ('', 0), (None, 0),
])
def test_classification_to_dbot_score_mapping(classification, expected_score):
    assert src.classification_to_dbot_score(classification) == expected_score


def _search_response_with_classification(classification):
    return {
        'content': [
            {
                'type': 'Domains',
                'feature': [
                    {'accessorKey': 'classification', 'displayName': 'Classification',
                     'type': 'string', 'value': classification},
                ],
            },
        ],
        'page': {},
    }


def test_ip_reputation_emits_dbot_score_and_common_ip(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params',
                        lambda: {'feedReliability': 'B - Usually reliable'})
    patch_http(monkeypatch, _search_response_with_classification('malicious'))

    out = src.dmontip_search_ip_command(make_client(), {'ip': '203.0.113.5'})
    assert isinstance(out, list) and len(out) == 1
    o = out[0].outputs

    dbot = o['DBotScore']
    assert dbot == {
        'Indicator': '203.0.113.5',
        'Type': 'ip',
        'Vendor': 'Darkmon',
        'Score': 3,
        'Reliability': 'B - Usually reliable',
    }

    ip_key = next(k for k in o if k.startswith('Common.IP'))
    common_ip = o[ip_key]
    assert common_ip['Address'] == '203.0.113.5'
    assert common_ip['Malicious'] == {
        'Vendor': 'Darkmon',
        'Description': 'Darkmon classified as malicious',
    }


def test_domain_reputation_score_2_no_malicious_block(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, _search_response_with_classification('suspicious'))

    out = src.dmontip_search_domain_command(make_client(), {'domain': 'evil.example'})
    o = out[0].outputs
    assert o['DBotScore']['Score'] == 2
    domain_key = next(k for k in o if k.startswith('Common.Domain'))
    assert o[domain_key]['Name'] == 'evil.example'
    assert 'Malicious' not in o[domain_key]


def test_url_reputation_score_0_when_no_classification(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, {'content': [], 'page': {}})

    out = src.dmontip_search_url_command(make_client(), {'url': 'https://x.example/a'})
    o = out[0].outputs
    assert o['DBotScore']['Score'] == 0
    url_key = next(k for k in o if k.startswith('Common.URL'))
    assert o[url_key]['Data'] == 'https://x.example/a'
    assert 'Malicious' not in o[url_key]


def test_email_reputation_uses_address_field(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, _search_response_with_classification('malicious'))

    out = src.dmontip_search_email_command(make_client(), {'email': 'bad@example.com'})
    o = out[0].outputs
    common = next(o[k] for k in o if k.startswith('Common.EMAIL'))
    assert common['Address'] == 'bad@example.com'
    assert common['Malicious']['Vendor'] == 'Darkmon'


@pytest.mark.parametrize('hash_value, expected_field', [
    ('a' * 32, 'MD5'),
    ('A' * 32, 'MD5'),  # case-insensitive
    ('a' * 40, 'SHA1'),
    ('a' * 64, 'SHA256'),
    ('not-a-hash', 'MD5'),  # fallback
])
def test_file_reputation_detects_hash_type(monkeypatch, hash_value, expected_field):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, {'content': [], 'page': {}})

    out = src.dmontip_search_file_command(make_client(), {'hash': hash_value})
    o = out[0].outputs
    common = next(o[k] for k in o if k.startswith('Common.File'))
    assert common[expected_field] == hash_value


def test_dbot_reliability_falls_back_to_F(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})  # no feedReliability
    patch_http(monkeypatch, {'content': [], 'page': {}})

    out = src.dmontip_search_ip_command(make_client(), {'ip': '1.1.1.1'})
    assert out[0].outputs['DBotScore']['Reliability'] == 'F - Reliability cannot be judged'


def test_reputation_array_input_produces_dbot_per_value(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, _search_response_with_classification('malicious'))

    out = src.dmontip_search_ip_command(make_client(), {'ip': '1.2.3.4,5.6.7.8'})
    assert len(out) == 2
    assert out[0].outputs['DBotScore']['Indicator'] == '1.2.3.4'
    assert out[1].outputs['DBotScore']['Indicator'] == '5.6.7.8'


# ===========================================================================
# Tier 0: redact_secrets behavior
# ===========================================================================

def test_redact_rows_replaces_password_when_on():
    rows = [{'username': 'alice', 'password': 'hunter2', 'url': 'https://x'}]
    out = src._redact_rows(rows, redact=True)
    assert out[0] == {'username': 'alice', 'password': '***', 'url': 'https://x'}


def test_redact_rows_passthrough_when_off():
    rows = [{'username': 'alice', 'password': 'hunter2'}]
    out = src._redact_rows(rows, redact=False)
    assert out[0]['password'] == 'hunter2'


def test_redact_rows_skips_empty_secrets():
    """Don't replace empty-string passwords with *** - that would lie about presence."""
    rows = [{'password': '', 'cardNumber': None}]
    out = src._redact_rows(rows, redact=True)
    assert out[0]['password'] == ''
    assert out[0]['cardNumber'] is None


def test_compromised_table_redacts_password_by_default(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})  # default True
    patch_http(monkeypatch, COMPROMISED_ACCOUNTS_RESPONSE)
    out = src.dmontip_get_compromised_command(
        make_client(), {'type': 'accounts', 'page': '1', 'size': '20'}
    )
    assert 'hunter2' not in out.readable_output
    assert '***' in out.readable_output
    # context retains the raw value for playbook automation
    assert out.outputs['Darkmon.Compromised.Account'][0]['password'] == 'hunter2'


def test_compromised_table_keeps_password_when_redaction_off(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params',
                        lambda: {'redact_secrets': False})
    patch_http(monkeypatch, COMPROMISED_ACCOUNTS_RESPONSE)
    out = src.dmontip_get_compromised_command(
        make_client(), {'type': 'accounts'}
    )
    assert 'hunter2' in out.readable_output


def test_boardemails_accounts_redacts_password_by_default(monkeypatch):
    monkeypatch.setattr(builtins.demisto, 'params', lambda: {})
    patch_http(monkeypatch, BOARDLEAK_ACCOUNTS_RESPONSE)
    out = src.dmontip_get_boardemails_command(
        make_client(), {'type': 'accounts', 'email': 'victim@example.com'}
    )
    assert 'hunter2' not in out.readable_output
    assert '***' in out.readable_output


# ===========================================================================
# Tier 0: fetch_indicators table-driven mapping
# ===========================================================================

def test_fetch_indicators_handles_unknown_ioc_type_gracefully(monkeypatch):
    """A new ioc_type Darkmon adds in the future shouldn't crash the feed."""
    response = {
        'iocObjects': [
            {'id': 'x1', 'type': 'something_new', 'value': 'whatever',
             'eventInfo': 'novel kind'},
        ]
    }
    patch_http(monkeypatch, response)
    inds = src.fetch_indicators_command(make_client(), {})
    assert len(inds) == 1
    assert inds[0]['value'] == 'whatever'
    # type passes through (no FeedIndicatorType match, but doesn't crash)
    assert inds[0]['type'] == 'something_new'
    # description still applied from common section
    assert inds[0]['fields']['description'] == 'novel kind'


def test_fetch_indicators_field_mapping_is_table_driven(monkeypatch):
    """The IOC_FIELD_MAP is the authoritative source for per-type field mapping."""
    assert 'domain' in src.IOC_FIELD_MAP
    assert 'file' in src.IOC_FIELD_MAP
    assert 'vulnerabilityioc' in src.IOC_FIELD_MAP
    # Adding a column in the table should be the only edit needed
    assert any(s['src'] == 'sha256' and s['dst'] == 'sha256'
               for s in src.IOC_FIELD_MAP['file'])


# ===========================================================================
# YAML: DBotScore + Common.* outputs are declared on reputation commands
# ===========================================================================

@pytest.mark.parametrize('cmd_name, expected_common_prefix', [
    ('ip',     'IP.'),
    ('url',    'URL.'),
    ('domain', 'Domain.'),
    ('email',  'Account.Email.'),
    ('file',   'File.'),
])
def test_yaml_reputation_command_declares_dbot_and_common(yml, cmd_name, expected_common_prefix):
    cmd = next(c for c in yml['script']['commands'] if c['name'] == cmd_name)
    paths = {o['contextPath'] for o in cmd.get('outputs', [])}
    assert any(p.startswith('DBotScore.') for p in paths), f"{cmd_name} missing DBotScore.* outputs"
    assert any(p.startswith(expected_common_prefix) for p in paths), (
        f"{cmd_name} missing {expected_common_prefix}* outputs"
    )


def test_yaml_has_redact_secrets_param(yml):
    p = next((c for c in yml['configuration'] if c['name'] == 'redact_secrets'), None)
    assert p is not None
    assert p.get('type') == 8  # boolean
    assert p.get('defaultvalue') == 'true'


def test_yaml_has_base_url_with_prod_default(yml):
    """The Marketplace pack ships pointing at production. Dev team overrides per-instance."""
    base = next((c for c in yml['configuration'] if c['name'] == 'base_url'), None)
    assert base is not None, "configuration must expose 'base_url'"
    assert base.get('defaultvalue') == 'https://api.darkmon.com/tip/2025.1', (
        "Production default expected; do not ship the marketplace pack with the .dev URL"
    )
    assert base.get('required') is False


def test_yaml_has_insecure_and_proxy_toggles(yml):
    names = {c['name'] for c in yml['configuration']}
    assert 'insecure' in names
    assert 'proxy' in names


def test_python_main_reads_base_url_from_params():
    """main() must build the Client from params['base_url'], not a hardcoded constant."""
    import inspect
    src_text = inspect.getsource(src.main)
    assert "params.get('base_url'" in src_text, (
        "main() should read base_url from demisto.params() so the same code can "
        "target dev or prod via configuration."
    )


def test_pack_version_bumped():
    assert src.CONSTANT_PACK_VERSION != '0.0.1', "Bump CONSTANT_PACK_VERSION before release."


def test_yaml_credential_field_matches_python(yml):
    """Python reads params.get('X-API-KEY', {}).get('password') so YAML must expose that name."""
    config_names = {c['name'] for c in yml['configuration']}
    assert 'X-API-KEY' in config_names


# ===========================================================================
# Tier 1: pack content validation (IndicatorFields, Layouts, Playbooks, TPB)
# ===========================================================================

_PACK_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def _list_json(subdir):
    d = os.path.join(_PACK_ROOT, subdir)
    if not os.path.isdir(d):
        return []
    return sorted(
        os.path.join(d, f) for f in os.listdir(d)
        if f.endswith('.json')
    )


def _list_yaml(subdir):
    d = os.path.join(_PACK_ROOT, subdir)
    if not os.path.isdir(d):
        return []
    return sorted(
        os.path.join(d, f) for f in os.listdir(d)
        if f.endswith('.yml') or f.endswith('.yaml')
    )


# ---- Indicator fields ----

EXPECTED_INDICATOR_FIELD_CLINAMES = {
    'darkmonclassification',
    'darkmoncompromisesources',
    'darkmonstealers',
    'darkmonfirstcompromise',
    'darkmonlastcompromise',
}


def test_indicator_fields_files_present():
    paths = _list_json('IndicatorFields')
    assert len(paths) == len(EXPECTED_INDICATOR_FIELD_CLINAMES), (
        f"Expected {len(EXPECTED_INDICATOR_FIELD_CLINAMES)} indicator field files, got {len(paths)}"
    )


@pytest.mark.parametrize('path', _list_json('IndicatorFields'))
def test_indicator_field_schema(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Core required fields
    for k in ('id', 'cliName', 'name', 'type', 'description', 'fromVersion',
              'marketplaces', 'associatedTypes'):
        assert k in data, f"{os.path.basename(path)}: missing '{k}'"

    assert data['cliName'] in EXPECTED_INDICATOR_FIELD_CLINAMES
    assert data['cliName'].islower(), "cliName must be lowercase"
    assert data['cliName'].isalnum(), "cliName must be alphanumeric"
    assert data['id'] == f"indicator_{data['cliName']}"
    assert data['type'] in {'shortText', 'longText', 'multiSelect', 'singleSelect',
                            'date', 'number', 'boolean', 'tagsSelect'}
    assert data['fromVersion'] == '6.5.0'
    assert set(data['marketplaces']) == {'xsoar', 'marketplacev2'}
    assert isinstance(data['associatedTypes'], list) and data['associatedTypes']


# ---- Indicator layouts ----

EXPECTED_LAYOUT_NAMES = {
    'Darkmon IP', 'Darkmon Domain', 'Darkmon URL', 'Darkmon File', 'Darkmon Email',
}


def _indicator_layout_paths():
    out = []
    for p in _list_json('Layouts'):
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        if d.get('group') == 'indicator':
            out.append(p)
    return out


def _incident_layout_paths():
    out = []
    for p in _list_json('Layouts'):
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        if d.get('group') == 'incident':
            out.append(p)
    return out


def _all_indicator_field_ids():
    ids = set()
    for p in _list_json('IndicatorFields'):
        with open(p, 'r', encoding='utf-8') as f:
            ids.add(json.load(f)['id'])
    return ids


def _all_incident_field_ids():
    ids = set()
    for p in _list_json('IncidentFields'):
        with open(p, 'r', encoding='utf-8') as f:
            ids.add(json.load(f)['id'])
    return ids


def test_indicator_layouts_present():
    names = {json.load(open(p, 'r', encoding='utf-8'))['name']
             for p in _indicator_layout_paths()}
    assert names == EXPECTED_LAYOUT_NAMES


@pytest.mark.parametrize('path', _indicator_layout_paths())
def test_indicator_layout_schema_and_field_references(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for k in ('id', 'name', 'group', 'fromVersion', 'marketplaces',
              'indicatorsDetails'):
        assert k in data, f"{os.path.basename(path)}: missing '{k}'"
    assert data['group'] == 'indicator'
    assert data['fromVersion'] == '6.5.0'
    assert data['name'] in EXPECTED_LAYOUT_NAMES

    referenced = set()
    for tab in data['indicatorsDetails'].get('tabs', []):
        for section in tab.get('sections', []) or []:
            for item in section.get('items', []) or []:
                if item.get('sectionItemType') == 'field':
                    referenced.add(item['fieldId'])

    unknown = referenced - _all_indicator_field_ids()
    assert not unknown, (
        f"{os.path.basename(path)} references unknown indicator fieldIds: {unknown}"
    )


EXPECTED_INCIDENT_LAYOUT_NAMES = {
    'Darkmon Compromised Credential', 'Darkmon VIP Email Leak',
    'Darkmon Compromised Employee', 'Darkmon Ransomware Mention',
    'Darkmon Typosquatting Threat', 'Darkmon Critical CVE',
}


def test_incident_layouts_present():
    names = {json.load(open(p, 'r', encoding='utf-8'))['name']
             for p in _incident_layout_paths()}
    assert names == EXPECTED_INCIDENT_LAYOUT_NAMES


@pytest.mark.parametrize('path', _incident_layout_paths())
def test_incident_layout_schema_and_field_references(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    for k in ('id', 'name', 'group', 'fromVersion', 'marketplaces',
              'detailsV2'):
        assert k in data, f"{os.path.basename(path)}: missing '{k}'"
    assert data['group'] == 'incident'
    assert data['fromVersion'] == '6.5.0'
    assert data['name'] in EXPECTED_INCIDENT_LAYOUT_NAMES

    referenced = set()
    for tab in data['detailsV2'].get('tabs', []):
        for section in tab.get('sections', []) or []:
            for item in section.get('items', []) or []:
                if item.get('sectionItemType') == 'field':
                    referenced.add(item['fieldId'])

    unknown = referenced - _all_incident_field_ids()
    assert not unknown, (
        f"{os.path.basename(path)} references unknown incident fieldIds: {unknown}"
    )


# ---- Enrichment sub-playbooks ----

EXPECTED_PLAYBOOK_NAMES = {
    'Darkmon - Enrich IP', 'Darkmon - Enrich Domain', 'Darkmon - Enrich URL',
    'Darkmon - Enrich File', 'Darkmon - Enrich Email',
}


def _enrichment_playbook_paths():
    paths = []
    for p in _list_yaml('Playbooks'):
        with open(p, 'r', encoding='utf-8') as f:
            d = yaml.safe_load(f)
        if d.get('name', '').startswith('Darkmon - Enrich '):
            paths.append(p)
    return paths


def test_enrichment_playbooks_present():
    names = set()
    for path in _enrichment_playbook_paths():
        with open(path, 'r', encoding='utf-8') as f:
            names.add(yaml.safe_load(f)['name'])
    assert names == EXPECTED_PLAYBOOK_NAMES


@pytest.mark.parametrize('path', _enrichment_playbook_paths())
def test_enrichment_playbook_schema(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    for k in ('id', 'name', 'description', 'fromversion', 'marketplaces',
              'starttaskid', 'tasks', 'inputs', 'outputs'):
        assert k in data, f"{os.path.basename(path)}: missing '{k}'"

    assert data['fromversion'] == '6.5.0'
    assert set(data['marketplaces']) == {'xsoar', 'marketplacev2'}
    assert data['name'] in EXPECTED_PLAYBOOK_NAMES
    assert data['id'] == data['name']
    assert data['starttaskid'] == '0'
    assert isinstance(data['tasks'], dict) and '0' in data['tasks']

    # Exactly one input
    assert isinstance(data['inputs'], list) and len(data['inputs']) == 1
    inp = data['inputs'][0]
    assert inp['required'] is True
    assert 'value' in inp and 'complex' in inp['value']

    # Outputs declare DBotScore + the matching Common.<Type>
    outputs = {o['contextPath'] for o in data['outputs']}
    assert any(p.startswith('DBotScore.') for p in outputs)
    assert 'DBotScore.Score' in outputs
    assert 'DBotScore.Vendor' in outputs
    assert any(p.endswith('.Malicious.Vendor') for p in outputs)


def test_enrichment_playbook_calls_correct_command():
    expected = {
        'Darkmon - Enrich IP':     'ip',
        'Darkmon - Enrich Domain': 'domain',
        'Darkmon - Enrich URL':    'url',
        'Darkmon - Enrich File':   'file',
        'Darkmon - Enrich Email':  'email',
    }
    for path in _enrichment_playbook_paths():
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        cmd_task = data['tasks']['1']['task']
        assert cmd_task['brand'] == 'Darkmon'
        assert cmd_task['script'] == f"Darkmon|||{expected[data['name']]}"


def test_playbook_commands_exist_in_integration_yaml(yml):
    """Every Darkmon|||<cmd> reference across all playbooks must be declared."""
    integration_cmds = {c['name'] for c in yml['script']['commands']}
    bad = []
    for path in _list_yaml('Playbooks'):
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        for tid, t in data['tasks'].items():
            if t['type'] != 'regular' or not t['task'].get('iscommand'):
                continue
            script = t['task'].get('script', '')
            if not script.startswith('Darkmon|||'):
                continue  # external command (send-mail, ad-disable-account, etc.)
            cmd = script.split('|||')[-1]
            if cmd not in integration_cmds:
                bad.append((os.path.basename(path), cmd))
    assert not bad, f"Playbook tasks reference unknown Darkmon commands: {bad}"


# ---- Test playbook ----

def test_test_playbook_present():
    paths = _list_yaml('TestPlaybooks')
    assert len(paths) == 1
    with open(paths[0], 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    assert data['name'] == 'Darkmon - Test'
    assert data['fromversion'] == '6.5.0'


def test_test_playbook_invokes_each_reputation_command(yml):
    paths = _list_yaml('TestPlaybooks')
    with open(paths[0], 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    invoked = set()
    for t in data['tasks'].values():
        if t['type'] == 'regular' and t['task'].get('iscommand'):
            invoked.add(t['task']['script'].split('|||')[-1])

    # Smoke set: 5 reputation commands + dmontip-get-indicators
    expected = {'ip', 'url', 'domain', 'email', 'file', 'dmontip-get-indicators'}
    missing = expected - invoked
    assert not missing, f"Test playbook missing tasks for commands: {missing}"


# ---- Pack metadata + layout/file completeness ----

def test_pack_metadata_present_and_valid():
    pmd = os.path.join(_PACK_ROOT, 'pack_metadata.json')
    with open(pmd, 'r', encoding='utf-8') as f:
        data = json.load(f)
    for k in ('name', 'description', 'support', 'currentVersion', 'author',
              'url', 'email', 'categories', 'useCases', 'marketplaces',
              'devEmail'):
        assert k in data, f"pack_metadata.json missing '{k}'"
    assert data['support'] == 'developer'
    assert 'certification' not in data, \
        "'certification' is reserved for Cortex XSOAR; developer-supported packs must omit it"
    assert data['currentVersion'] == '1.0.0'


def test_yaml_embedded_script_matches_python_source(yml):
    """The XSOAR runtime executes the script embedded in the YAML, NOT Darkmon.py.

    Whenever Darkmon.py is edited, the YAML's script: block must be re-synced or
    the deployed integration will silently run stale code. This test asserts
    perfect equivalence so drift is caught before deploy.
    """
    embedded = yml['script']['script']
    with open(_PY_PATH, 'r', encoding='utf-8') as f:
        src_text = f.read()

    emb_lines = embedded.rstrip('\n').splitlines()
    src_lines = src_text.rstrip('\n').splitlines()

    assert len(emb_lines) == len(src_lines), (
        f"Line count drift: YAML embedded={len(emb_lines)}, Darkmon.py={len(src_lines)}. "
        "Run sync_yaml.py to re-sync."
    )
    for i, (a, b) in enumerate(zip(emb_lines, src_lines), start=1):
        assert a == b, (
            f"YAML/Darkmon.py drift at line {i}:\n"
            f"  YAML embedded: {a!r}\n"
            f"  Darkmon.py:    {b!r}\n"
            "Run sync_yaml.py to re-sync."
        )


def test_yaml_has_fromversion(yml):
    assert yml.get('fromversion'), "fromversion missing - XSOAR feed integrations should set 6.5.0+"


def test_yaml_all_user_facing_commands_have_descriptions(yml):
    missing = [c['name'] for c in yml['script']['commands']
               if c['name'] != 'test-module' and not c.get('description')]
    assert not missing, f"Commands missing description: {missing}"


def test_yaml_all_user_facing_commands_have_outputs(yml):
    missing = [c['name'] for c in yml['script']['commands']
               if c['name'] != 'test-module' and not c.get('outputs')]
    assert not missing, f"Commands missing outputs: {missing}"


def test_yaml_output_paths_appear_in_python(yml):
    """Every contextPath declared in YAML should map to something Python emits.

    Acceptance rules:
      - Literal full path appears in the Python source, OR
      - Two-segment root (e.g. "Darkmon.Compromised") appears (covers f-string
        constructions like f'Darkmon.Compromised.{singular}'), OR
      - Path is rooted in an XSOAR-mandatory standard prefix (DBotScore, IP, URL,
        Domain, Account, File). These are produced by build_dbot_outputs() via
        dict construction, so the literal path string never appears in source -
        we still verify the helper exists and the leaf field is constructed.
    """
    import inspect
    src_text = inspect.getsource(src)

    XSOAR_STANDARD_PREFIXES = {'DBotScore', 'IP', 'URL', 'Domain', 'Account', 'File'}
    # If the integration emits these, build_dbot_outputs must exist:
    assert 'def build_dbot_outputs' in src_text

    bad = []
    for cmd in yml['script']['commands']:
        for out in (cmd.get('outputs') or []):
            path = out['contextPath']
            parts = path.split('.')
            if path in src_text:
                continue
            if len(parts) >= 2 and '.'.join(parts[:2]) in src_text:
                continue
            if parts[0] in XSOAR_STANDARD_PREFIXES:
                continue  # XSOAR-mandatory standard, validated by separate tests
            bad.append((cmd['name'], path))
    assert not bad, (
        "YAML outputs declare contextPaths not produced by Python: "
        + ', '.join(f'{c}: {p}' for c, p in bad)
    )


def test_yaml_global_search_predefined_matches_python_allowed_types(yml):
    """The dropdown in YAML must be a subset of the types Python's global_search accepts."""
    cmd = next(c for c in yml['script']['commands'] if c['name'] == 'dmontip-global-search')
    yaml_types = {p for a in cmd['arguments'] if a['name'] == 'type' for p in a['predefined']}

    # Reflect Python's allowed_types from global_search
    import inspect
    src_text = inspect.getsource(src.Client.global_search)
    import re
    m = re.search(r'allowed_types\s*=\s*\[([^\]]+)\]', src_text, re.DOTALL)
    assert m, "Could not locate allowed_types literal in Client.global_search"
    py_types = set(re.findall(r'"([^"]+)"', m.group(1)))

    # Anything in YAML that Python rejects = silent runtime failure for the user
    drift = yaml_types - py_types
    assert drift == set(), (
        f"YAML predefined types not accepted by Python global_search: {drift}. "
        f"Python allows: {py_types}. Either add them to allowed_types or drop them from YAML."
    )
