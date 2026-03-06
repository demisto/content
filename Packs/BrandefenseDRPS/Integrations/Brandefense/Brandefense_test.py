"""Unit tests for the Brandefense XSOAR Integration.

These tests use mocked API responses to validate command logic,
severity mapping, caching, and output formatting without requiring
a live Brandefense API connection.
"""
import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Import integration modules (these run inside XSOAR's environment)
# For local testing, mock the demisto/CommonServerPython imports first.


# ===== Test Data =====

MOCK_IOC_IP_RESPONSE = json.dumps([{
    "data": "192.168.1.100",
    "type": "ip_address",
    "severity": "HIGH",
    "category": "Botnet C2",
    "module": "THREAT_INTELLIGENCE",
    "first_seen": "2026-01-15T10:00:00Z",
    "last_seen": "2026-02-20T15:30:00Z",
    "data_source_type": "AUTOMATED"
}])

MOCK_IOC_DOMAIN_RESPONSE = json.dumps([{
    "data": "evil-domain.com",
    "type": "domain",
    "severity": "MEDIUM",
    "category": "Phishing",
    "module": "PHISHING_MONITORING",
    "first_seen": "2026-02-01T08:00:00Z",
    "last_seen": "2026-02-20T12:00:00Z",
    "data_source_type": "MANUAL"
}])

MOCK_IOC_HASH_RESPONSE = json.dumps([{
    "data": "d41d8cd98f00b204e9800998ecf8427e",
    "type": "hash",
    "severity": "CRITICAL",
    "category": "Malware",
    "module": "MALICIOUS_FILES",
    "first_seen": "2026-02-10T06:00:00Z",
    "last_seen": "2026-02-20T18:00:00Z",
    "data_source_type": "AUTOMATED"
}])

MOCK_IOC_URL_RESPONSE = json.dumps([{
    "data": "https://phishing-site.com/login",
    "type": "url",
    "severity": "HIGH",
    "category": "Phishing URL",
    "module": "PHISHING_MONITORING",
    "first_seen": "2026-02-15T09:00:00Z",
    "last_seen": "2026-02-20T14:00:00Z",
    "data_source_type": "AUTOMATED"
}])

MOCK_IOC_EMPTY_RESPONSE = json.dumps([])

MOCK_INCIDENT_LIST = {
    "results": [
        {
            "id": 1001,
            "code": "INC-2026-001",
            "title": "Compromised Account Detected",
            "created_at": "2026-02-20T10:00:00Z",
            "status": "OPEN",
            "severity": "HIGH",
            "indicators": []
        },
        {
            "id": 1002,
            "code": "INC-2026-002",
            "title": "Phishing Campaign Targeting Executives",
            "created_at": "2026-02-19T08:00:00Z",
            "status": "IN_PROGRESS",
            "severity": "CRITICAL",
            "indicators": []
        }
    ]
}

MOCK_INCIDENT_DETAIL = {
    "code": "INC-2026-001",
    "title": "Compromised Account Detected",
    "description": "Employee credentials found on dark web marketplace.",
    "severity": "HIGH",
    "status": "OPEN",
    "created_at": "2026-02-20T10:00:00Z",
    "module": "BREACH_MONITORING",
    "module_category": "BRAND_MONITORING",
    "indicators": [
        {"type": "email", "value": "user@company.com"},
        {"type": "password_hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99"}
    ]
}

MOCK_INTELLIGENCE_LIST = {
    "results": [
        {
            "code": "INT-2026-001",
            "title": "New Ransomware Variant Targeting Financial Sector",
            "severity": "CRITICAL",
            "created_at": "2026-02-18T12:00:00Z",
            "category": "THREAT_REPORTS"
        }
    ]
}


# ===== Severity Mapping Tests =====

class TestSeverityMapping:
    """Test Brandefense severity to XSOAR severity conversion."""

    def test_critical_severity(self):
        """CRITICAL should map to XSOAR severity 4 (Critical)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('CRITICAL') == 4

    def test_high_severity(self):
        """HIGH should map to XSOAR severity 3 (High)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('HIGH') == 3

    def test_medium_severity(self):
        """MEDIUM should map to XSOAR severity 2 (Medium)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('MEDIUM') == 2

    def test_low_severity(self):
        """LOW should map to XSOAR severity 1 (Low)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('LOW') == 1

    def test_info_severity(self):
        """INFO should map to XSOAR severity 0.5 (Info)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('INFO') == 0.5

    def test_unknown_severity(self):
        """Unknown severity should map to XSOAR severity 0 (Unknown)."""
        from Brandefense import convert_to_demisto_severity
        assert convert_to_demisto_severity('SOMETHING_ELSE') == 0


class TestDBotScoreMapping:
    """Test Brandefense severity to DBot score mapping."""

    def test_high_maps_to_bad(self):
        """HIGH severity should produce DBotScore 3 (Bad/Malicious)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('HIGH') == 3

    def test_critical_maps_to_bad(self):
        """CRITICAL severity should produce DBotScore 3 (Bad/Malicious)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('CRITICAL') == 3

    def test_medium_maps_to_suspicious(self):
        """MEDIUM severity should produce DBotScore 2 (Suspicious)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('MEDIUM') == 2

    def test_low_maps_to_good(self):
        """LOW severity should produce DBotScore 1 (Good)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('LOW') == 1

    def test_info_maps_to_good(self):
        """INFO severity should produce DBotScore 1 (Good)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('INFO') == 1

    def test_none_maps_to_unknown(self):
        """None severity should produce DBotScore 0 (Unknown)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score(None) == 0

    def test_empty_string_maps_to_unknown(self):
        """Empty string severity should produce DBotScore 0 (Unknown)."""
        from Brandefense import severity_to_dbot_score
        assert severity_to_dbot_score('') == 0


# ===== Helper Function Tests =====

class TestHelperFunctions:
    """Test utility/helper functions."""

    def test_list_to_comma_separated_string_with_list(self):
        """Should convert list to comma-separated string."""
        from Brandefense import list_to_comma_separated_string
        assert list_to_comma_separated_string(['a', 'b', 'c']) == 'a,b,c'

    def test_list_to_comma_separated_string_with_string(self):
        """Should return string as-is."""
        from Brandefense import list_to_comma_separated_string
        assert list_to_comma_separated_string('already,string') == 'already,string'

    def test_list_to_comma_separated_string_with_empty(self):
        """Should return empty string for empty input."""
        from Brandefense import list_to_comma_separated_string
        assert list_to_comma_separated_string([]) == ''
        assert list_to_comma_separated_string(None) == ''

    def test_convert_rules_to_ids(self):
        """Should convert known rule names to their IDs."""
        from Brandefense import convert_rules_to_ids
        result = convert_rules_to_ids(['Compromised Employee Account Detection'])
        assert result == '1'

    def test_convert_rules_to_ids_empty(self):
        """Should return empty string for empty rules."""
        from Brandefense import convert_rules_to_ids
        assert convert_rules_to_ids([]) == ''
        assert convert_rules_to_ids(None) == ''

    def test_convert_rules_unknown_rule(self):
        """Unknown rules should be silently skipped."""
        from Brandefense import convert_rules_to_ids
        result = convert_rules_to_ids(['NonExistentRule'])
        assert result == ''

    def test_hours_ago_from_epoch(self):
        """Should calculate correct hours difference."""
        from Brandefense import hours_ago_from_epoch
        # Use a timestamp from about 24 hours ago
        now = int(datetime.now(timezone.utc).timestamp())
        twenty_four_hours_ago = now - (24 * 3600)
        result = hours_ago_from_epoch(twenty_four_hours_ago)
        assert 23 <= result <= 25  # Allow small variance


# ===== IoC Cache Tests =====

class TestIoCCache:
    """Test IoC caching mechanism."""

    @patch('Brandefense.demisto')
    def test_cache_miss_returns_none(self, mock_demisto):
        """Cache miss should return None."""
        from Brandefense import lookup_ioc_cache
        mock_demisto.getIntegrationContext.return_value = {}
        result = lookup_ioc_cache('ip_address', '1.2.3.4')
        assert result is None

    @patch('Brandefense.demisto')
    def test_cache_hit_returns_result(self, mock_demisto):
        """Cache hit should return the stored result."""
        from Brandefense import lookup_ioc_cache
        now = int(datetime.now(timezone.utc).timestamp())
        mock_demisto.getIntegrationContext.return_value = {
            'ioc_cache': {
                'ip_address:1.2.3.4': {
                    'result': {'data': '1.2.3.4', 'severity': 'HIGH'},
                    'cached_at': now - 100  # 100 seconds ago — still valid
                }
            }
        }
        result = lookup_ioc_cache('ip_address', '1.2.3.4')
        assert result is not None
        assert result['data'] == '1.2.3.4'

    @patch('Brandefense.demisto')
    def test_cache_expired_returns_none(self, mock_demisto):
        """Expired cache entry should return None."""
        from Brandefense import lookup_ioc_cache, IOC_CACHE_TTL
        now = int(datetime.now(timezone.utc).timestamp())
        mock_demisto.getIntegrationContext.return_value = {
            'ioc_cache': {
                'ip_address:1.2.3.4': {
                    'result': {'data': '1.2.3.4', 'severity': 'HIGH'},
                    'cached_at': now - IOC_CACHE_TTL - 100  # Expired
                }
            }
        }
        result = lookup_ioc_cache('ip_address', '1.2.3.4')
        assert result is None

    @patch('Brandefense.demisto')
    def test_cache_stores_result(self, mock_demisto):
        """update_ioc_cache should store result in integration context."""
        from Brandefense import update_ioc_cache
        mock_demisto.getIntegrationContext.return_value = {}
        update_ioc_cache('ip_address', '1.2.3.4', {'data': '1.2.3.4', 'severity': 'HIGH'})
        mock_demisto.setIntegrationContext.assert_called_once()
        call_args = mock_demisto.setIntegrationContext.call_args[0][0]
        assert 'ioc_cache' in call_args
        assert 'ip_address:1.2.3.4' in call_args['ioc_cache']


# ===== Command Tests =====

class TestSearchIPCommand:
    """Test the search_ip_command function."""

    @patch('Brandefense.cached_ioc_lookup')
    def test_ip_found_returns_bad_score(self, mock_lookup):
        """When IoC found with HIGH severity, DBotScore should be 3 (Bad)."""
        from Brandefense import search_ip_command
        mock_lookup.return_value = {
            'data': '192.168.1.100',
            'severity': 'HIGH',
            'category': 'Botnet C2',
            'first_seen': '2026-01-15T10:00:00Z',
            'last_seen': '2026-02-20T15:30:00Z'
        }
        client = MagicMock()
        results = search_ip_command(client, {'ip': '192.168.1.100'})
        assert len(results) == 1
        assert results[0].indicator.address == '192.168.1.100'
        assert results[0].indicator.dbot_score.score == 3

    @patch('Brandefense.cached_ioc_lookup')
    def test_ip_not_found_returns_none_score(self, mock_lookup):
        """When IoC not found, DBotScore should be 0 (Unknown)."""
        from Brandefense import search_ip_command
        mock_lookup.return_value = {}
        client = MagicMock()
        results = search_ip_command(client, {'ip': '10.0.0.1'})
        assert len(results) == 1
        assert results[0].indicator.dbot_score.score == 0


class TestSearchDomainCommand:
    """Test the search_domain_command function."""

    @patch('Brandefense.cached_ioc_lookup')
    def test_domain_found_returns_suspicious(self, mock_lookup):
        """MEDIUM severity domain should return DBotScore 2 (Suspicious)."""
        from Brandefense import search_domain_command
        mock_lookup.return_value = {
            'data': 'evil-domain.com',
            'severity': 'MEDIUM',
            'category': 'Phishing',
            'first_seen': '2026-02-01T08:00:00Z',
            'last_seen': '2026-02-20T12:00:00Z'
        }
        client = MagicMock()
        results = search_domain_command(client, {'domain': 'evil-domain.com'})
        assert len(results) == 1
        assert results[0].indicator.dbot_score.score == 2


class TestSearchHashCommand:
    """Test the search_hash_command function."""

    @patch('Brandefense.cached_ioc_lookup')
    def test_hash_found_returns_bad(self, mock_lookup):
        """CRITICAL severity hash should return DBotScore 3 (Bad)."""
        from Brandefense import search_hash_command
        mock_lookup.return_value = {
            'data': 'd41d8cd98f00b204e9800998ecf8427e',
            'severity': 'CRITICAL',
            'category': 'Malware',
            'first_seen': '2026-02-10T06:00:00Z',
            'last_seen': '2026-02-20T18:00:00Z'
        }
        client = MagicMock()
        results = search_hash_command(client, {'file': 'd41d8cd98f00b204e9800998ecf8427e'})
        assert len(results) == 1
        assert results[0].indicator.dbot_score.score == 3


class TestSearchURLCommand:
    """Test the search_url_command function."""

    @patch('Brandefense.cached_ioc_lookup')
    def test_url_found_returns_bad(self, mock_lookup):
        """HIGH severity URL should return DBotScore 3 (Bad)."""
        from Brandefense import search_url_command
        mock_lookup.return_value = {
            'data': 'https://phishing-site.com/login',
            'severity': 'HIGH',
            'category': 'Phishing URL',
            'first_seen': '2026-02-15T09:00:00Z',
            'last_seen': '2026-02-20T14:00:00Z'
        }
        client = MagicMock()
        results = search_url_command(client, {'url': 'https://phishing-site.com/login'})
        assert len(results) == 1
        assert results[0].indicator.dbot_score.score == 3


class TestGetIoCListCommand:
    """Test the brandefense_get_ioc_list command."""

    @patch('Brandefense.Client')
    def test_returns_consolidated_list(self, MockClient):
        """Should consolidate IoCs from all types into a single list."""
        from Brandefense import get_ioc_list_command
        client = MockClient()
        client.get_iocs.return_value = {
            'results': [
                {'data': '1.2.3.4', 'severity': 'HIGH'},
                {'data': '5.6.7.8', 'severity': 'MEDIUM'},
            ]
        }
        result = get_ioc_list_command(client, {'days': '7', 'limit': '100'})
        assert result.outputs is not None
        assert len(result.outputs) > 0


# ===== Throttle Tests =====

class TestClientThrottle:
    """Test client request throttling."""

    def test_throttle_delays_requests(self):
        """Throttle should enforce minimum delay between calls."""
        from Brandefense import Client
        import time
        client = Client.__new__(Client)
        client._request_delay = 0.1
        client._last_request_time = time.time()
        start = time.time()
        client._throttle()
        elapsed = time.time() - start
        # Should have waited approximately 0.1 seconds
        assert elapsed >= 0.05  # Allow some tolerance

    def test_throttle_no_delay_first_call(self):
        """First call should not be delayed."""
        from Brandefense import Client
        import time
        client = Client.__new__(Client)
        client._request_delay = 0.5
        client._last_request_time = 0.0
        start = time.time()
        client._throttle()
        elapsed = time.time() - start
        # Should be nearly instant
        assert elapsed < 0.1
