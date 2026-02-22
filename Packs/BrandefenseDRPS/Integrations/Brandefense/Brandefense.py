import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
import time
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
MAX_INCIDENTS_TO_FETCH = 200
DEFAULT_PAGE_SIZE = 100
IOC_CACHE_TTL = 6 * 3600  # 6 hours in seconds — how long cached IoC results stay valid
IOC_CACHE_MAX_SIZE = 5000  # Maximum number of cached IoC entries
REQUEST_DELAY_SECONDS = 0.3  # 300ms delay between sequential API calls

SEVERITY_MAP = {
    'INFO': IncidentSeverity.INFO,
    'LOW': IncidentSeverity.LOW,
    'MEDIUM': IncidentSeverity.MEDIUM,
    'HIGH': IncidentSeverity.HIGH,
    'CRITICAL': IncidentSeverity.CRITICAL,
}

RULES_DICT = {
    "Compromised Employee Account Detection": 1,
    "Compromised Client Account Detection": 2,
    "Executive Person Email Leak": 3,
    "Compromised Device Detection": 4,
    "Confirmed Phishing Address": 5,
    "Potential Phishing Address": 6,
    "Dark Web Intelligence": 7,
    "Sensitive File Disclosure": 8,
    "Confirmed Impersonated Account": 9,
    "Potential Impersonated Account": 10,
    "Vulnerable Technology Assessment": 13,
    "Stolen Credit/Debit Card Detection": 14,
    "Attack Surface": 15,
    "Custom Investigation": 16,
    "Malware Analysis": 17,
    "Fraud Protection": 18,
    "Other": 19,
    "SSL/TLS Vulnerability Detection": 20,
    "Vulnerability Detection": 21,
    "Insecure Redirect Protocol (HTTP) Detection": 22,
    "SSL/TLS Certificate Missing Domain Inclusion": 23,
    "SSL/TLS Weak Cipher & Algorithm Detection": 24,
    "Executive's Cyber Risk Assessment": 25,
    "Open DNS Resolver Detection": 26,
    "Malicious File Detection": 27,
    "Unsecure Login Page Detection": 28,
    "Exposed Redis Server": 29,
    "Exposed Memcached System": 30,
    "Vulnerable SSH Protocol Detection": 31,
    "Externally Exploitable Vulnerability Detection": 32,
    "DNS Server Allows Cache Snooping": 35,
    "Disclosure of Important Technology Information": 37,
    "Compromised Supply Chain Device": 38,
    "Security Scan": 40,
    "SMTP Open Relay Detection for Supplier Systems": 41,
    "Expired Supply Chain Domain Detection": 42,
    "Detection of Torrent Download Activity": 44,
    "Potentially Exposed SCADA Services": 45,
    "Credit Card": 46,
    "Potentially Vulnerable Exposed Technology": 47,
    "Domain Registrar Transfer Protection Not Enabled": 48,
    "Suspected Dark Web Exposure of Organization Asset": 49,
    "Data Sale Detection of Brand Accounts": 50,
    "Your Company Attacked by a Ransomware Group": 51,
    "Ransomware Attack Detected for Related Supply Chain Asset": 52,
    "Daily Discovered Entity Updates": 53,
    "Suspected Dark Web Exposure of Supply Chain Asset": 55,
    "Entity Found in Threat Intelligence Feeds": 56,
    "Malicious File Identified on Compromised Device": 57,
    "Compromised Employee Accounts via Botnet Attack": 58,
    "Unidentified Management Port Detection": 59,
    "Filtered Statused Management Port Exposure": 60,
    "Sensitive File Disclosure on GitHub Repositories": 61,
    "Sensitive File Disclosure on Postman Collections": 62,
    "Misconfigured AWS S3 Bucket Leading to Data Exposure": 63,
    "Misconfigured Azure Blob Storage Container Leading to Data Exposure": 64,
    "Misconfigured Google Cloud Storage Bucket Leading to Data Exposure": 65,
    "Misconfigured IBM Cloud Object Storage Leading to Data Exposure": 66,
    "Misconfigured Alibaba Cloud OSS Leading to Data Exposure": 67,
    "Misconfigured Backblaze B2 Bucket Leading to Data Exposure": 68,
    "Misconfigured DigitalOcean Space Leading to Data Exposure": 69,
    "Misconfigured Oracle Cloud Object Storage Leading to Data Exposure": 70,
    "DNS Zone Transfer Detection": 281,
    "DNSSEC Not Found": 282,
    "Shared Hosting Detection": 284,
    "SPF Misconfiguration": 285,
    "DMARC Not Found": 286,
    "DMARC Policy Not Configured": 287,
    "Domain Expires in 30 Days": 288,
    "Expired Domain Detection": 289,
    "SSL Expires in 30 Days": 290,
    "LDAP Server Allows Anonymous Bindings": 291,
    "Anonymous FTP Detection": 292,
    "SSH Supports Weak MAC Algorithms": 293,
    "SSH Supports Weak Ciphers": 294,
    "Expired SSL/TLS Detection": 295,
    "Blacklisted IP Address Detection": 296,
    "Blacklisted Domain Address Detection": 297,
    "Vulnerable HTTP Security Headers Detection": 299,
    "SMTP Open Relay Detection": 300,
    "Subdomain Takeover Detection": 301,
    "Private IP Address Exposure": 302,
    "Management Port Detection": 303,
    "Hacker Search Engine Monitoring Detection": 304,
}


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    """Maps Brandefense severity to Cortex XSOAR severity.

    Args:
        severity: Severity string from Brandefense API.

    Returns:
        Cortex XSOAR Severity (0 to 4).
    """
    return SEVERITY_MAP.get(severity, IncidentSeverity.UNKNOWN)


def list_to_comma_separated_string(lst: Any) -> str:
    """Convert a list to comma-separated string.

    Args:
        lst: Input list or string.

    Returns:
        Comma-separated string.
    """
    if isinstance(lst, str):
        return lst
    if not lst:
        return ''
    return ','.join(str(element) for element in lst)


def convert_rules_to_ids(rules: List[str]) -> str:
    """Convert rule names to their corresponding IDs.

    Args:
        rules: List of rule name strings.

    Returns:
        Comma-separated string of rule IDs.
    """
    if not rules:
        return ''
    ids = [str(RULES_DICT[key]) for key in rules if key in RULES_DICT]
    return ','.join(ids)


TIME_RANGE_DAYS = {
    'Last 24 Hours': 1,
    'Last 7 Days': 7,
    'Last 30 Days': 30,
    'Last 90 Days': 90,
    'Last 6 Months': 180,
    'Last 1 Year': 365,
}


def resolve_time_range(args: Dict[str, Any], custom_field: str = 'created_at_range',
                       fmt: str = '%Y-%m-%d') -> Optional[str]:
    """Resolve a time_range dropdown or custom date field into a date range string.

    Args:
        args: Command arguments dict.
        custom_field: The name of the custom date range argument (fallback).
        fmt: strftime format for the dates.

    Returns:
        A comma-separated date range string (e.g. '2025-01-01,2026-02-22') or None.
    """
    time_range = args.get('time_range')
    if time_range and time_range != 'Custom':
        days = TIME_RANGE_DAYS.get(time_range)
        if days:
            today = datetime.now(timezone.utc).strftime(fmt)
            start_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(fmt)
            return f'{start_date},{today}'
    custom_value = args.get(custom_field)
    if custom_value:
        return custom_value
    return None


def hours_ago_from_epoch(epoch_time: int) -> int:
    """Calculate hours elapsed since a given epoch timestamp.

    Args:
        epoch_time: Unix epoch timestamp.

    Returns:
        Number of hours elapsed.
    """
    current_time = datetime.now(timezone.utc)
    past_time = datetime.fromtimestamp(epoch_time, timezone.utc)
    time_difference = current_time - past_time
    return int(time_difference.total_seconds() / 3600)


def get_first_time_fetch(first_fetch: str) -> Optional[int]:
    """Parse first fetch time string to epoch timestamp.

    Args:
        first_fetch: Human-readable time string (e.g., '3 days').

    Returns:
        Epoch timestamp or None.
    """
    first_fetch_time = arg_to_datetime(
        arg=first_fetch if first_fetch else '3 days',
        arg_name='First fetch time',
        required=True
    )
    return int(first_fetch_time.timestamp()) if first_fetch_time else None


def get_ioc_cache() -> Dict[str, Any]:
    """Retrieve the IoC cache from integration context.

    Returns:
        Dictionary with cached IoC results keyed by 'type:value'.
    """
    ctx = demisto.getIntegrationContext()
    return ctx.get('ioc_cache', {})


def set_ioc_cache(cache: Dict[str, Any]) -> None:
    """Save the IoC cache to integration context.

    Trims to IOC_CACHE_MAX_SIZE if needed, removing oldest entries first.

    Args:
        cache: Dictionary of IoC cache entries.
    """
    # Trim cache if it exceeds max size — keep newest entries
    if len(cache) > IOC_CACHE_MAX_SIZE:
        sorted_keys = sorted(
            cache.keys(),
            key=lambda k: cache[k].get('cached_at', 0)
        )
        keys_to_remove = sorted_keys[:len(cache) - IOC_CACHE_MAX_SIZE]
        for key in keys_to_remove:
            del cache[key]

    ctx = demisto.getIntegrationContext()
    ctx['ioc_cache'] = cache
    demisto.setIntegrationContext(ctx)


def lookup_ioc_cache(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
    """Look up an IoC in the cache.

    Returns the cached result if found and not expired (within TTL).

    Args:
        ioc_type: Type of IoC (ip_address, domain, url, hash).
        value: The IoC value to look up.

    Returns:
        Cached result dict if valid, None if not found or expired.
    """
    cache = get_ioc_cache()
    cache_key = f'{ioc_type}:{value}'
    entry = cache.get(cache_key)

    if not entry:
        return None

    cached_at = entry.get('cached_at', 0)
    now = int(datetime.now(timezone.utc).timestamp())

    if now - cached_at > IOC_CACHE_TTL:
        # Expired — remove from cache
        del cache[cache_key]
        set_ioc_cache(cache)
        demisto.debug(f'IoC cache expired for {cache_key}')
        return None

    demisto.debug(f'IoC cache HIT for {cache_key}')
    return entry.get('result')


def update_ioc_cache(ioc_type: str, value: str, result: Dict[str, Any]) -> None:
    """Store an IoC lookup result in the cache.

    Args:
        ioc_type: Type of IoC.
        value: The IoC value.
        result: The API response to cache.
    """
    cache = get_ioc_cache()
    cache_key = f'{ioc_type}:{value}'
    cache[cache_key] = {
        'result': result,
        'cached_at': int(datetime.now(timezone.utc).timestamp())
    }
    set_ioc_cache(cache)
    demisto.debug(f'IoC cache SET for {cache_key}')


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the Brandefense API.

    Inherits from BaseClient which handles proxy, SSL verification, etc.
    Includes request throttling to prevent rate limit issues.
    """

    def __init__(self, *args, request_delay: float = REQUEST_DELAY_SECONDS, **kwargs):
        """Initialize the client with optional request throttling.

        Args:
            request_delay: Seconds to wait between sequential API calls.
        """
        super().__init__(*args, **kwargs)
        self._request_delay = request_delay
        self._last_request_time = 0.0

    def _throttle(self) -> None:
        """Enforce minimum delay between API requests."""
        if self._request_delay > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self._request_delay:
                sleep_time = self._request_delay - elapsed
                time.sleep(sleep_time)
            self._last_request_time = time.time()

    def search_ioc(self, param: dict) -> str:
        """Search for Indicators of Compromise.

        Args:
            param: Query parameters including ioc_type and query.

        Returns:
            Raw text response from the API.
        """
        self._throttle()
        return self._http_request(
            method='GET',
            params=param,
            url_suffix='/threat-intelligence/iocs/search',
            resp_type='text'
        )

    def api_request(self, url: str, method: str, params: dict = None,
                    data: dict = None) -> Dict[str, Any]:
        """Make a generic API request with throttling.

        Args:
            url: API endpoint URL suffix.
            method: HTTP method (GET, POST, PATCH, etc.).
            params: Query parameters.
            data: Request body data.

        Returns:
            JSON response as dictionary.
        """
        self._throttle()
        kwargs: Dict[str, Any] = {
            'method': method,
            'url_suffix': url,
            'resp_type': 'json',
        }
        if params:
            kwargs['params'] = params
        if data:
            kwargs['json_data'] = data
        return self._http_request(**kwargs)

    def get_incidents_list(self, params: dict) -> Dict[str, Any]:
        """Get list of incidents with pagination support.

        Args:
            params: Query parameters for filtering.

        Returns:
            Paginated response with results.
        """
        return self.api_request(url='/incidents', method='GET', params=params)

    def get_incident_detail(self, code: str) -> Dict[str, Any]:
        """Get detailed information for a specific incident.

        Args:
            code: Incident code identifier.

        Returns:
            Incident details dictionary.
        """
        return self.api_request(url=f'/incidents/{code}', method='GET')

    def get_incident_indicators(self, code: str, params: dict = None) -> Dict[str, Any]:
        """Get indicators associated with an incident.

        Args:
            code: Incident code identifier.
            params: Optional pagination parameters.

        Returns:
            Paginated response with indicator results.
        """
        return self.api_request(url=f'/incidents/{code}/indicators', method='GET', params=params)

    def get_incident_relatives(self, code: str) -> Dict[str, Any]:
        """Get related incidents.

        Args:
            code: Incident code identifier.

        Returns:
            Related incidents data.
        """
        return self.api_request(url=f'/incidents/{code}/relatives', method='GET')

    def change_incident_status(self, code: str, status: str) -> Dict[str, Any]:
        """Change the status of an incident.

        Args:
            code: Incident code identifier.
            status: New status value.

        Returns:
            Updated incident data.
        """
        return self.api_request(
            url=f'/incidents/{code}/change-status',
            method='PATCH',
            data={'status': status}
        )

    def get_intelligences_list(self, params: dict) -> Dict[str, Any]:
        """Get list of intelligence reports.

        Args:
            params: Query parameters for filtering.

        Returns:
            Paginated response with results.
        """
        return self.api_request(url='/intelligences', method='GET', params=params)

    def get_intelligence_detail(self, code: str) -> Dict[str, Any]:
        """Get detailed information for a specific intelligence report.

        Args:
            code: Intelligence code identifier.

        Returns:
            Intelligence details dictionary.
        """
        return self.api_request(url=f'/intelligences/{code}', method='GET')

    def get_intelligence_indicators(self, code: str, params: dict = None) -> Dict[str, Any]:
        """Get indicators associated with an intelligence report.

        Args:
            code: Intelligence code identifier.
            params: Optional pagination parameters.

        Returns:
            Indicator results.
        """
        return self.api_request(url=f'/intelligences/{code}/indicators', method='GET', params=params)

    def get_intelligence_rules(self, code: str) -> Dict[str, Any]:
        """Get rules associated with an intelligence report.

        Args:
            code: Intelligence code identifier.

        Returns:
            Rules data.
        """
        return self.api_request(url=f'/intelligences/{code}/rules', method='GET')

    def create_threat_search(self, value: str) -> Dict[str, Any]:
        """Create a new threat search request.

        Args:
            value: Search value (domain, IP, hash, etc.).

        Returns:
            Response with UUID for tracking.
        """
        return self.api_request(url='/cti/threat-search', method='POST', data={'value': value})

    def get_threat_search_result(self, uuid: str) -> Dict[str, Any]:
        """Get result of a threat search by UUID.

        Args:
            uuid: Threat search UUID.

        Returns:
            Threat search result.
        """
        return self.api_request(url=f'/cti/threat-search/{uuid}', method='GET')

    def get_assets(self, params: dict = None) -> Dict[str, Any]:
        """Get list of assets.

        Args:
            params: Query parameters for filtering.

        Returns:
            Paginated asset list.
        """
        return self.api_request(url='/assets', method='GET', params=params)

    def get_asset_detail(self, asset_id: str) -> Dict[str, Any]:
        """Get detail for a specific asset.

        Args:
            asset_id: Asset identifier.

        Returns:
            Asset details.
        """
        return self.api_request(url=f'/assets/{asset_id}', method='GET')

    def get_iocs(self, params: dict) -> Dict[str, Any]:
        """Get Indicators of Compromise from threat intelligence.

        Args:
            params: Query parameters including ioc_type.

        Returns:
            IoC list response.
        """
        return self.api_request(url='/threat-intelligence/iocs', method='GET', params=params)

    def get_cti_rules(self, params: dict = None) -> Dict[str, Any]:
        """Get CTI rules.

        Args:
            params: Query parameters for filtering.

        Returns:
            CTI rules list.
        """
        return self.api_request(url='/threat-intelligence/rules', method='GET', params=params)

    def get_audit_logs(self, params: dict = None) -> Dict[str, Any]:
        """Get audit log entries.

        Args:
            params: Query parameters for filtering.

        Returns:
            Paginated audit logs.
        """
        return self.api_request(url='/audit-logs', method='GET', params=params)

    def get_compromised_devices(self, params: dict = None) -> Dict[str, Any]:
        """Get compromised devices list.

        Args:
            params: Query parameters.

        Returns:
            Compromised devices data.
        """
        return self.api_request(url='/compromised-devices', method='GET', params=params)

    def get_compromised_device_detail(self, botnet_id: str) -> Dict[str, Any]:
        """Get detail for a specific compromised device.

        Args:
            botnet_id: Botnet/compromised device identifier.

        Returns:
            Device details.
        """
        return self.api_request(url=f'/compromised-devices/{botnet_id}', method='GET')

    def create_confirmed_phishing(self, data: dict) -> Dict[str, Any]:
        """Create a confirmed phishing address incident.

        Args:
            data: Phishing incident data.

        Returns:
            Created incident response.
        """
        return self.api_request(
            url='/incidents/confirmed-phishing-address',
            method='POST',
            data=data
        )

    def takedown_request(self, data: dict) -> Dict[str, Any]:
        """Request takedown for a confirmed phishing address.

        Args:
            data: Takedown request data containing URL.

        Returns:
            Takedown request response.
        """
        return self.api_request(
            url='/indicators/confirmed-phishing-address/takedown-request',
            method='POST',
            data=data
        )

    def get_domain_risk_assessments(self, params: dict = None) -> Dict[str, Any]:
        """Get third-party domain risk assessments.

        Args:
            params: Query parameters.

        Returns:
            Risk assessment list.
        """
        return self.api_request(url='/third-party-risk-management', method='GET', params=params)

    def get_domain_risk_assessment_detail(self, uuid: str) -> Dict[str, Any]:
        """Get detail for a specific domain risk assessment.

        Args:
            uuid: Assessment UUID.

        Returns:
            Assessment details.
        """
        return self.api_request(url=f'/third-party-risk-management/{uuid}', method='GET')

    def get_indicators(self, params: dict = None) -> Dict[str, Any]:
        """Get indicators by type from the Brandefense Indicators endpoint.

        Supports indicator types: leak, phishing_site, credit_card, cve,
        social_media, sensitive_file_disclosure, malicious-file, malicious_ads.

        Args:
            params: Query parameters including indicator_type (required)
                    and organization__code__in (required).

        Returns:
            Paginated indicator results.
        """
        return self.api_request(url='/indicators', method='GET', params=params)

    def create_confirmed_phishing(self, data: dict) -> Dict[str, Any]:
        """Create a confirmed phishing address incident.

        Args:
            data: Phishing address data.

        Returns:
            Created incident response.
        """
        return self.api_request(
            url='/incidents/confirmed-phishing-address',
            method='POST',
            data=data
        )


''' PAGINATION '''


def paginate(client: Client, url: str, method: str, params: dict = None,
             data: dict = None, max_results: int = DEFAULT_PAGE_SIZE) -> List[Dict[str, Any]]:
    """Generic pagination function for Brandefense API.

    Follows cursor-based pagination using the 'next' field.

    Args:
        client: Brandefense API client.
        url: API endpoint URL suffix.
        method: HTTP method.
        params: Query parameters.
        data: Request body data.
        max_results: Maximum number of results to return.

    Returns:
        List of result items.
    """
    if not params:
        params = {
            'page_size': DEFAULT_PAGE_SIZE,
            'page': 1,
        }

    all_results: List[Dict[str, Any]] = []
    has_more = True

    while has_more:
        response = client.api_request(url=url, method=method, params=params, data=data)
        if not response or 'results' not in response:
            break

        results = response.get('results', [])
        if not results:
            break

        all_results.extend(results)

        if len(all_results) >= max_results:
            break

        next_url = response.get('next')
        if next_url:
            params['page'] = params.get('page', 1) + 1
        else:
            has_more = False

    return all_results[:max_results]


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Args:
        client: Brandefense API client.

    Returns:
        'ok' if test passed.
    """
    try:
        params = {'ioc_type': 'ip_address', 'period': '24h'}
        client.get_iocs(params=params)
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or '403' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        elif '401' in str(e):
            return 'Authorization Error: invalid API key'
        else:
            raise e


VENDOR_NAME = 'Brandefense'
DEFAULT_RELIABILITY = DBotScoreReliability.B  # Usually reliable


def severity_to_dbot_score(severity: Optional[str]) -> int:
    """Map Brandefense severity to DBot score.

    Args:
        severity: Brandefense severity string.

    Returns:
        DBot score: 0 (Unknown), 1 (Good), 2 (Suspicious), 3 (Malicious).
    """
    if not severity:
        return Common.DBotScore.NONE
    severity_upper = severity.upper()
    if severity_upper in ('HIGH', 'CRITICAL'):
        return Common.DBotScore.BAD
    elif severity_upper in ('MEDIUM',):
        return Common.DBotScore.SUSPICIOUS
    elif severity_upper in ('LOW', 'INFO'):
        return Common.DBotScore.GOOD
    return Common.DBotScore.NONE


def cached_ioc_lookup(client: Client, ioc_type: str, value: str) -> Dict[str, Any]:
    """Look up an IoC with caching to prevent redundant API calls.

    Checks the integration context cache first. On miss, queries the API
    and stores the result for future lookups (TTL: 6 hours).

    Args:
        client: Brandefense API client.
        ioc_type: IoC type (ip_address, domain, url, hash).
        value: The indicator value to look up.

    Returns:
        The IoC result dict (may be empty if not found).
    """
    # Check cache first
    cached = lookup_ioc_cache(ioc_type, value)
    if cached is not None:
        return cached

    # Cache miss — call the API
    param = {'query': value, 'ioc_type': ioc_type}
    raw_response = client.search_ioc(param=param)
    results = json.loads(raw_response) if raw_response else []

    if results and isinstance(results, list) and len(results) > 0:
        result = results[0]
    else:
        result = {}

    # Store in cache for future lookups
    update_ioc_cache(ioc_type, value, result)
    return result


def search_ip_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Search for malicious IP addresses in Brandefense threat intelligence.

    Returns proper DBotScore and IP standard context so XSOAR auto-enrichment
    includes Brandefense in all TI lookups.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'ip'.

    Returns:
        List of CommandResults with DBotScore and IP indicator.
    """
    ips = argToList(args.get('ip'))
    reliability = args.get('reliability', DEFAULT_RELIABILITY)
    command_results: List[CommandResults] = []

    for ip_value in ips:
        result = cached_ioc_lookup(client, 'ip_address', ip_value)

        if result:
            severity = result.get('severity')
            score = severity_to_dbot_score(severity)
            description = result.get('category', 'Found in Brandefense threat intelligence')
        else:
            result = {}
            score = Common.DBotScore.NONE
            description = None

        dbot_score = Common.DBotScore(
            indicator=ip_value,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=score,
            reliability=reliability,
            message=description
        )

        ip_indicator = Common.IP(
            ip=ip_value,
            dbot_score=dbot_score,
        )

        readable_output = tableToMarkdown(
            f'Brandefense IP Reputation - {ip_value}',
            {
                'IP': ip_value,
                'Score': score,
                'Severity': result.get('severity', 'N/A'),
                'Category': result.get('category', 'N/A'),
                'First Seen': result.get('first_seen', 'N/A'),
                'Last Seen': result.get('last_seen', 'N/A'),
            }
        )

        command_results.append(CommandResults(
            readable_output=readable_output,
            indicator=ip_indicator,
            outputs_prefix='Brandefense.IP',
            outputs_key_field='data',
            outputs=result if result else None,
            raw_response=result
        ))

    return command_results


def search_domain_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Search for malicious domains in Brandefense threat intelligence.

    Returns proper DBotScore and Domain standard context so XSOAR auto-enrichment
    includes Brandefense in all TI lookups.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'domain'.

    Returns:
        List of CommandResults with DBotScore and Domain indicator.
    """
    domains = argToList(args.get('domain'))
    reliability = args.get('reliability', DEFAULT_RELIABILITY)
    command_results: List[CommandResults] = []

    for domain_value in domains:
        result = cached_ioc_lookup(client, 'domain', domain_value)

        if result:
            severity = result.get('severity')
            score = severity_to_dbot_score(severity)
            description = result.get('category', 'Found in Brandefense threat intelligence')
        else:
            result = {}
            score = Common.DBotScore.NONE
            description = None

        dbot_score = Common.DBotScore(
            indicator=domain_value,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=score,
            reliability=reliability,
            message=description
        )

        domain_indicator = Common.Domain(
            domain=domain_value,
            dbot_score=dbot_score,
        )

        readable_output = tableToMarkdown(
            f'Brandefense Domain Reputation - {domain_value}',
            {
                'Domain': domain_value,
                'Score': score,
                'Severity': result.get('severity', 'N/A'),
                'Category': result.get('category', 'N/A'),
                'First Seen': result.get('first_seen', 'N/A'),
                'Last Seen': result.get('last_seen', 'N/A'),
            }
        )

        command_results.append(CommandResults(
            readable_output=readable_output,
            indicator=domain_indicator,
            outputs_prefix='Brandefense.Domain',
            outputs_key_field='data',
            outputs=result if result else None,
            raw_response=result
        ))

    return command_results


def search_hash_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Search for malware file hashes in Brandefense threat intelligence.

    Returns proper DBotScore and File standard context so XSOAR auto-enrichment
    includes Brandefense in all TI lookups.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'file' (hash).

    Returns:
        List of CommandResults with DBotScore and File indicator.
    """
    file_hashes = argToList(args.get('file', args.get('hash', '')))
    reliability = args.get('reliability', DEFAULT_RELIABILITY)
    command_results: List[CommandResults] = []

    for file_hash in file_hashes:
        result = cached_ioc_lookup(client, 'hash', file_hash)

        if result:
            severity = result.get('severity')
            score = severity_to_dbot_score(severity)
            description = result.get('category', 'Found in Brandefense threat intelligence')
        else:
            result = {}
            score = Common.DBotScore.NONE
            description = None

        dbot_score = Common.DBotScore(
            indicator=file_hash,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=score,
            reliability=reliability,
            message=description
        )

        # Determine hash type by length
        hash_type_kwargs: Dict[str, Any] = {'dbot_score': dbot_score}
        if len(file_hash) == 32:
            hash_type_kwargs['md5'] = file_hash
        elif len(file_hash) == 40:
            hash_type_kwargs['sha1'] = file_hash
        elif len(file_hash) == 64:
            hash_type_kwargs['sha256'] = file_hash

        file_indicator = Common.File(**hash_type_kwargs)

        readable_output = tableToMarkdown(
            f'Brandefense File Reputation - {file_hash}',
            {
                'Hash': file_hash,
                'Score': score,
                'Severity': result.get('severity', 'N/A'),
                'Category': result.get('category', 'N/A'),
                'First Seen': result.get('first_seen', 'N/A'),
                'Last Seen': result.get('last_seen', 'N/A'),
            }
        )

        command_results.append(CommandResults(
            readable_output=readable_output,
            indicator=file_indicator,
            outputs_prefix='Brandefense.File',
            outputs_key_field='data',
            outputs=result if result else None,
            raw_response=result
        ))

    return command_results


def search_url_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Search for malicious URLs in Brandefense threat intelligence.

    Returns proper DBotScore and URL standard context so XSOAR auto-enrichment
    includes Brandefense in all TI lookups.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'url'.

    Returns:
        List of CommandResults with DBotScore and URL indicator.
    """
    urls = argToList(args.get('url'))
    reliability = args.get('reliability', DEFAULT_RELIABILITY)
    command_results: List[CommandResults] = []

    for url_value in urls:
        result = cached_ioc_lookup(client, 'url', url_value)

        if result:
            severity = result.get('severity')
            score = severity_to_dbot_score(severity)
            description = result.get('category', 'Found in Brandefense threat intelligence')
        else:
            result = {}
            score = Common.DBotScore.NONE
            description = None

        dbot_score = Common.DBotScore(
            indicator=url_value,
            indicator_type=DBotScoreType.URL,
            integration_name=VENDOR_NAME,
            score=score,
            reliability=reliability,
            message=description
        )

        url_indicator = Common.URL(
            url=url_value,
            dbot_score=dbot_score,
        )

        readable_output = tableToMarkdown(
            f'Brandefense URL Reputation - {url_value}',
            {
                'URL': url_value,
                'Score': score,
                'Severity': result.get('severity', 'N/A'),
                'Category': result.get('category', 'N/A'),
                'First Seen': result.get('first_seen', 'N/A'),
                'Last Seen': result.get('last_seen', 'N/A'),
            }
        )

        command_results.append(CommandResults(
            readable_output=readable_output,
            indicator=url_indicator,
            outputs_prefix='Brandefense.URL',
            outputs_key_field='data',
            outputs=result if result else None,
            raw_response=result
        ))

    return command_results


def get_incidents_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get Brandefense incidents with optional filtering.

    Args:
        client: Brandefense API client.
        args: Command arguments for filtering.

    Returns:
        CommandResults with incident list.
    """
    incident_category = list_to_comma_separated_string(args.get('module_category'))
    incident_module = list_to_comma_separated_string(args.get('module'))
    incident_rules = args.get('IncidentRules')
    status = list_to_comma_separated_string(args.get('status', 'OPEN'))
    period = int(args.get('period', 1))
    max_results = int(args.get('MaxResults', DEFAULT_PAGE_SIZE))

    template_ids = convert_rules_to_ids(incident_rules) if incident_rules else ''

    # Resolve time range: dropdown > custom date > period (hours) fallback
    date_range = resolve_time_range(args, fmt='%Y-%m-%d %H:%M:%S')
    if not date_range:
        current_datetime = datetime.now()
        start_datetime = current_datetime - timedelta(hours=period)
        date_range = f'{start_datetime.strftime("%Y-%m-%d %H:%M:%S")},{current_datetime.strftime("%Y-%m-%d %H:%M:%S")}'

    params = {
        'page_size': DEFAULT_PAGE_SIZE,
        'created_at__range': date_range,
        'status': status.upper() if status else 'OPEN',
        'page': 1,
    }
    if incident_module:
        params['module'] = incident_module
    if incident_category:
        params['module_category'] = incident_category
    if template_ids:
        params['template_id__in'] = template_ids
    if args.get('search'):
        params['search'] = args['search']
    if args.get('severity'):
        params['severity'] = args['severity']
    if args.get('tags'):
        params['tags'] = args['tags']
    if args.get('network_type'):
        params['network_type'] = args['network_type']
    if args.get('mitre_tactics'):
        params['mitre_tactics'] = args['mitre_tactics']
    if args.get('ordering'):
        params['ordering'] = args['ordering']
    if args.get('has_indicator'):
        params['has_indicator'] = args['has_indicator']
    if args.get('has_attachment'):
        params['has_attachment'] = args['has_attachment']
    if args.get('type'):
        params['type'] = args['type']

    incidents = paginate(client, url='/incidents', method='GET', params=params, max_results=max_results)

    incident_details = []
    for _incident in incidents:
        code = _incident.get('code')
        if code:
            details = client.get_incident_detail(code)
            details['indicators'] = paginate(
                client, url=f'/incidents/{code}/indicators', method='GET'
            )
            details['reference_url'] = f'https://app.brandefense.io/issues/incidents/all/{code}'
            incident_details.append(details)

    readable_output = tableToMarkdown(
        'Brandefense Incidents',
        incident_details,
        headers=['code', 'title', 'severity', 'status', 'created_at', 'reference_url'],
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Incident',
        outputs_key_field='code',
        outputs=incident_details
    )


def get_incident_detail_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get detailed information for a specific Brandefense incident.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with incident details.
    """
    code = args.get('code')
    incident = client.get_incident_detail(code)
    incident['reference_url'] = f'https://app.brandefense.io/issues/incidents/all/{code}'

    readable_output = tableToMarkdown('Incident Details', incident)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.IncidentDetail',
        outputs_key_field='code',
        outputs=incident
    )


def get_incident_indicators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get indicators associated with a Brandefense incident.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with indicator list.
    """
    code = args.get('code')
    indicators = paginate(client, url=f'/incidents/{code}/indicators', method='GET')

    readable_output = tableToMarkdown('Incident Indicators', indicators, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Incident.Indicators',
        outputs_key_field='code',
        outputs=indicators
    )


def get_incident_relatives_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get related incidents for a Brandefense incident.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with related incidents.
    """
    code = args.get('code')
    relatives = client.get_incident_relatives(code)

    readable_output = tableToMarkdown('Related Incidents', relatives)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Incident.Relatives',
        outputs=relatives
    )


def change_incident_status_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Change the status of a Brandefense incident.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code' and 'status'.

    Returns:
        CommandResults with updated incident.
    """
    code = args.get('code')
    status = args.get('status', '').upper()

    valid_statuses = ['OPEN', 'IN_PROGRESS', 'CLOSED', 'RISK_ACCEPTED', 'REJECTED']
    if status not in valid_statuses:
        raise ValueError(f'Invalid status "{status}". Must be one of: {", ".join(valid_statuses)}')

    result = client.change_incident_status(code, status)
    readable_output = tableToMarkdown('Incident Status Updated', result)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.ChangingStatus',
        outputs=result
    )


def get_intelligence_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get Brandefense intelligence reports with optional filtering.

    Args:
        client: Brandefense API client.
        args: Command arguments for filtering.

    Returns:
        CommandResults with intelligence list.
    """
    category = list_to_comma_separated_string(args.get('category'))
    search_term = args.get('search', '')
    period = int(args.get('period', 24))
    max_results = int(args.get('MaxResults', DEFAULT_PAGE_SIZE))

    # Resolve time range: dropdown > custom date > period (hours) fallback
    date_range = resolve_time_range(args, fmt='%Y-%m-%d %H:%M:%S')
    if not date_range:
        current_datetime = datetime.now()
        start_datetime = current_datetime - timedelta(hours=period)
        date_range = f'{start_datetime.strftime("%Y-%m-%d %H:%M:%S")},{current_datetime.strftime("%Y-%m-%d %H:%M:%S")}'

    params = {
        'page_size': DEFAULT_PAGE_SIZE,
        'created_at__range': date_range,
        'page': 1,
    }
    if category:
        params['category__in'] = category

    intelligence_list = paginate(client, url='/intelligences', method='GET', params=params, max_results=max_results)

    # Filter by search term in tags if provided
    if search_term:
        intelligence_list = [
            item for item in intelligence_list
            if any(search_term.lower() in tag.lower() for tag in item.get('tags', []))
        ]

    intelligence_details = []
    for intel in intelligence_list:
        code = intel.get('code')
        if code:
            details = client.get_intelligence_detail(code)
            ind_resp = client.get_intelligence_indicators(code)
            if isinstance(ind_resp, list):
                details['indicators'] = ind_resp
            elif isinstance(ind_resp, dict):
                details['indicators'] = ind_resp.get('results', [])
            else:
                details['indicators'] = []
            details['reference_url'] = f'https://app.brandefense.io/issues/intelligence/all/{code}'
            intelligence_details.append(details)

    readable_output = tableToMarkdown(
        'Brandefense Intelligence',
        intelligence_details,
        headers=['code', 'title', 'severity', 'created_at', 'reference_url'],
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Intelligence',
        outputs_key_field='code',
        outputs=intelligence_details
    )


def get_intelligence_detail_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get detailed information for a specific intelligence report.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with intelligence details.
    """
    code = args.get('code')
    intelligence = client.get_intelligence_detail(code)
    intelligence['reference_url'] = f'https://app.brandefense.io/issues/intelligence/all/{code}'

    readable_output = tableToMarkdown('Intelligence Details', intelligence)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.IntelligenceDetail',
        outputs_key_field='code',
        outputs=intelligence
    )


def get_intelligence_indicators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get indicators associated with an intelligence report.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with indicator list.
    """
    code = args.get('code')
    response = client.get_intelligence_indicators(code)
    # API may return a list directly or a paginated dict
    if isinstance(response, list):
        indicators = response
    elif isinstance(response, dict):
        indicators = response.get('results', [])
    else:
        indicators = []

    readable_output = tableToMarkdown('Intelligence Indicators', indicators, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Intelligence.Indicators',
        outputs_key_field='code',
        outputs=indicators
    )


def get_intelligence_rules_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get rules associated with an intelligence report.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'code'.

    Returns:
        CommandResults with rules data.
    """
    code = args.get('code')
    rules = client.get_intelligence_rules(code)

    readable_output = tableToMarkdown('Intelligence Rules', rules)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Intelligence.Rules',
        outputs=rules
    )


def threat_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Perform a threat search and wait for results.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'value' and optional 'waitingtime'.

    Returns:
        CommandResults with threat search results.
    """
    value = args.get('value')
    waiting_time = int(args.get('waitingtime', 20))

    # Create the threat search
    response = client.create_threat_search(value)
    uuid = response.get('uuid')

    if not uuid:
        raise DemistoException('Failed to create threat search: no UUID returned')

    # Poll for results
    result = None
    max_attempts = 30  # Safety limit
    attempts = 0

    while not result and attempts < max_attempts:
        response = client.get_threat_search_result(uuid)
        result = response.get('result')
        if not result:
            time.sleep(waiting_time)
            attempts += 1

    if not result:
        raise DemistoException(f'Threat search timed out after {max_attempts * waiting_time} seconds')

    # Flatten results
    extras = result.pop('results', {})
    for key, value_data in extras.items():
        if isinstance(value_data, list) and len(value_data) > 0:
            if isinstance(value_data[0], dict):
                for k, v in value_data[0].items():
                    response[k] = v
            else:
                response[key] = value_data[0]
        else:
            response[key] = value_data

    readable_output = tableToMarkdown('Threat Search Results', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.ThreatSearch',
        outputs_key_field='uuid',
        outputs=response
    )


def get_assets_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get Brandefense assets list.

    Args:
        client: Brandefense API client.
        args: Command arguments for filtering.

    Returns:
        CommandResults with asset list.
    """
    params: Dict[str, Any] = {}
    if args.get('type'):
        params['type__in'] = args['type']
    if args.get('severity'):
        params['severity__in'] = args['severity']
    if args.get('status'):
        params['status__in'] = args['status']
    if args.get('search'):
        params['search'] = args['search']
    if args.get('module'):
        params['module__code__in'] = args['module']
    if args.get('ordering'):
        params['ordering'] = args['ordering']
    date_range = resolve_time_range(args)
    if date_range:
        params['created_at_range'] = date_range
    if args.get('threat_type'):
        params['threat_type'] = args['threat_type']
    if args.get('asset_ilike'):
        params['asset__ilike'] = args['asset_ilike']
    if args.get('organization'):
        params['organization__code__in'] = args['organization']
    max_results = int(args.get('max_results', 50))

    params['page_size'] = DEFAULT_PAGE_SIZE
    params['page'] = 1

    assets = paginate(client, url='/assets', method='GET', params=params, max_results=max_results)

    readable_output = tableToMarkdown(
        'Brandefense Assets',
        assets,
        headers=['id', 'asset', 'type', 'severity', 'status'],
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Asset',
        outputs_key_field='id',
        outputs=assets
    )


def get_iocs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get Indicators of Compromise from Brandefense threat intelligence.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'ioc_type'.

    Returns:
        CommandResults with IoC list.
    """
    ioc_type = args.get('ioc_type')
    period = args.get('period', '24h')
    params: Dict[str, Any] = {'ioc_type': ioc_type}
    if period:
        params['period'] = period
    if args.get('exclude_country'):
        params['exclude_country'] = args['exclude_country']
    if args.get('include_country'):
        params['include_country'] = args['include_country']
    if args.get('module'):
        params['module'] = args['module']

    response = client.get_iocs(params=params)
    results = response.get('results', []) if isinstance(response, dict) else response

    readable_output = tableToMarkdown(
        f'Brandefense IoCs ({ioc_type})',
        results,
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.IOC',
        outputs_key_field='data',
        outputs=results
    )


def get_ioc_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Fetch and consolidate all IoCs from the last N days (default 30).

    Pulls IoCs of all 4 types (ip_address, domain, url, hash) and merges
    them into a single list. Useful for building a local threat feed or
    exporting to a SIEM/EDR.

    Args:
        client: Brandefense API client.
        args: Command arguments.
            - days: Number of days to look back (default: 30, max: 90).
            - ioc_type: Optional, filter to specific type(s).
            - limit: Maximum total results to return (default: 5000).

    Returns:
        CommandResults with consolidated IoC list.
    """
    days = min(int(args.get('days', 30)), 90)
    limit = int(args.get('limit', 5000))
    requested_types = argToList(args.get('ioc_type', 'ip_address,domain,url,hash'))

    all_iocs: List[Dict[str, Any]] = []
    period = f'{days * 24}h'  # Convert days to hours

    ioc_type_map = {
        'ip_address': 'IP Address',
        'ip': 'IP Address',
        'domain': 'Domain',
        'url': 'URL',
        'hash': 'File Hash',
    }

    for ioc_type in requested_types:
        # Normalize type name
        normalized_type = ioc_type.lower().strip()
        if normalized_type == 'ip':
            normalized_type = 'ip_address'

        try:
            params: Dict[str, Any] = {'ioc_type': normalized_type, 'period': period}
            response = client.get_iocs(params=params)
            results = response.get('results', []) if isinstance(response, dict) else response

            if isinstance(results, list):
                for item in results:
                    item['ioc_type'] = normalized_type
                    item['ioc_type_display'] = ioc_type_map.get(normalized_type, normalized_type)
                all_iocs.extend(results)
        except Exception as e:
            demisto.debug(f'Error fetching IoCs of type {normalized_type}: {str(e)}')
            continue

        if len(all_iocs) >= limit:
            break

    # Trim to limit
    all_iocs = all_iocs[:limit]

    # Summary stats
    type_counts: Dict[str, int] = {}
    for ioc in all_iocs:
        t = ioc.get('ioc_type_display', 'Unknown')
        type_counts[t] = type_counts.get(t, 0) + 1

    summary_rows = [{'Type': k, 'Count': v} for k, v in type_counts.items()]
    summary_rows.append({'Type': '**Total**', 'Count': len(all_iocs)})

    readable_output = tableToMarkdown(
        f'Brandefense IoC List (Last {days} Days)',
        summary_rows,
        headers=['Type', 'Count']
    )
    readable_output += '\n\n'
    readable_output += tableToMarkdown(
        'IoC Details (showing first 50)',
        all_iocs[:50],
        headers=['ioc_type_display', 'data', 'severity', 'first_seen', 'last_seen'],
        headerTransform=lambda h: {'ioc_type_display': 'Type', 'data': 'Value',
                                    'severity': 'Severity', 'first_seen': 'First Seen',
                                    'last_seen': 'Last Seen'}.get(h, h),
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.IOCList',
        outputs_key_field='data',
        outputs=all_iocs
    )


def get_indicators_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get indicators from Brandefense Indicators endpoint.

    Retrieves Consolidated Data and Incident indicators filtered by type
    and organization, with optional date range and status filters.

    Args:
        client: Brandefense API client.
        args: Command arguments.
            - indicator_type: Required. One of: leak, phishing_site, credit_card,
              cve, social_media, sensitive_file_disclosure, malicious-file, malicious_ads.
            - organization_code: Required. Organization code(s), comma-separated.
            - created_at_range: Date range filter (e.g., 2020-10-10,2023-10-10).
            - incident_status: Filter by incident status(es), comma-separated.
            - page: Page number.
            - page_size: Results per page.
            - limit: Maximum total results to return (default 50).

    Returns:
        CommandResults with indicator list.
    """
    indicator_type = args.get('indicator_type')
    if not indicator_type:
        raise ValueError('indicator_type is a required argument.')

    params: Dict[str, Any] = {
        'indicator_type': indicator_type,
    }

    if args.get('organization_code'):
        params['organization__code__in'] = args['organization_code']

    date_range = resolve_time_range(args)
    if date_range:
        params['created_at__range'] = date_range

    if args.get('incident_status'):
        params['incident__status__in'] = args['incident_status']

    page = args.get('page')
    page_size = args.get('page_size')
    limit = int(args.get('limit', 50))

    if page:
        params['page'] = int(page)
    if page_size:
        params['page_size'] = int(page_size)
    if not page_size and not page:
        params['page_size'] = min(limit, 100)

    response = client.get_indicators(params=params)

    if isinstance(response, dict):
        results = response.get('results', [])
        total_count = response.get('count', len(results))
    elif isinstance(response, list):
        results = response
        total_count = len(results)
    else:
        results = []
        total_count = 0

    # Truncate to limit
    results = results[:limit]

    # Build readable output
    # Flatten content_object fields into top-level for display
    display_rows = []
    for item in results:
        row: Dict[str, Any] = {'id': item.get('id'), 'created_at': item.get('created_at')}
        content_obj = item.get('content_object', {})
        if isinstance(content_obj, dict):
            for key, val in content_obj.items():
                row[key] = val
        # Add threat/incident info
        threats = item.get('threats', [])
        if threats:
            incident_codes = []
            for threat in threats:
                for inc in threat.get('incidents', []):
                    incident_codes.append(inc.get('code', ''))
            row['incidents'] = ', '.join(incident_codes)
            row['threat_title'] = threats[0].get('title', '')
        display_rows.append(row)

    readable_output = tableToMarkdown(
        f'Brandefense Indicators ({indicator_type}) - {total_count} total',
        display_rows,
        removeNull=True
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.Indicator',
        outputs_key_field='id',
        outputs=results,
        raw_response=response
    )


def get_compromised_devices_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get compromised devices from Brandefense.

    Args:
        client: Brandefense API client.
        args: Command arguments.

    Returns:
        CommandResults with compromised devices list.
    """
    botnet_id = args.get('botnet_id')

    if botnet_id:
        result = client.get_compromised_device_detail(botnet_id)
        results = [result] if isinstance(result, dict) else result
    else:
        max_results = int(args.get('max_results', 10))
        params: Dict[str, Any] = {'page_size': 10, 'page': 1}
        if args.get('username'):
            params['username__contains'] = args['username']
        date_range = resolve_time_range(args, custom_field='detection_date_range')
        if date_range:
            params['detection_date__range'] = date_range
        if args.get('search'):
            params['search'] = args['search']
        if args.get('ordering'):
            params['ordering'] = args['ordering']
        results = paginate(client, url='/compromised-devices', method='GET',
                           params=params, max_results=max_results)

    readable_output = tableToMarkdown('Compromised Devices', results, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.CompromisedDevice',
        outputs_key_field='id',
        outputs=results
    )


def get_audit_logs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get audit log entries from Brandefense.

    Args:
        client: Brandefense API client.
        args: Command arguments for filtering.

    Returns:
        CommandResults with audit logs.
    """
    params: Dict[str, Any] = {'page_size': DEFAULT_PAGE_SIZE, 'page': 1}
    if args.get('type'):
        params['type'] = args['type']
    if args.get('search'):
        params['search'] = args['search']
    date_range = resolve_time_range(args)
    if date_range:
        params['created_at__range'] = date_range
    if args.get('actor_object_id'):
        params['actor_object_id__in'] = args['actor_object_id']
    if args.get('ip_address'):
        params['ip_address'] = args['ip_address']
    if args.get('ordering'):
        params['ordering'] = args['ordering']
    max_results = int(args.get('max_results', 50))

    logs = paginate(client, url='/audit-logs', method='GET', params=params, max_results=max_results)

    readable_output = tableToMarkdown('Audit Logs', logs, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.AuditLog',
        outputs_key_field='id',
        outputs=logs
    )


def create_confirmed_phishing_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Create a confirmed phishing address incident.

    Args:
        client: Brandefense API client.
        args: Command arguments.

    Returns:
        CommandResults with created incident data.
    """
    data: Dict[str, Any] = {
        'data': args.get('url'),
    }
    if args.get('title'):
        data['title'] = args['title']
    if args.get('network_type'):
        data['network_type'] = args['network_type']
    if args.get('severity'):
        data['severity'] = args['severity']
    if args.get('tags'):
        data['tags'] = argToList(args['tags'])
    if args.get('status'):
        data['status'] = args['status']
    if args.get('asset_ids'):
        data['asset_ids'] = [int(i) for i in argToList(args['asset_ids'])]
    if args.get('data_source'):
        data['data_source'] = args['data_source']

    response = client.create_confirmed_phishing(data)
    readable_output = tableToMarkdown('Created Confirmed Phishing Incident', response, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.ConfirmedPhishing',
        outputs=response
    )


def takedown_request_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Request takedown for a confirmed phishing address.

    Args:
        client: Brandefense API client.
        args: Command arguments containing 'url'.

    Returns:
        CommandResults with takedown request response.
    """
    url_value = args.get('url')
    data = {'data': url_value}

    response = client.takedown_request(data)
    readable_output = tableToMarkdown('Takedown Request', response, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.TakedownRequest',
        outputs=response
    )


def get_domain_risk_assessment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get third-party domain risk assessments.

    Args:
        client: Brandefense API client.
        args: Command arguments.

    Returns:
        CommandResults with risk assessment data.
    """
    uuid = args.get('uuid')

    if uuid:
        result = client.get_domain_risk_assessment_detail(uuid)
        results = [result] if isinstance(result, dict) else result
    else:
        response = client.get_domain_risk_assessments()
        results = response.get('results', []) if isinstance(response, dict) else response

    readable_output = tableToMarkdown('Domain Risk Assessments', results, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brandefense.DomainRiskAssessment',
        outputs_key_field='uuid',
        outputs=results
    )


''' FETCH INCIDENTS '''


def get_brandefense_incidents_for_fetch(client: Client, args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Internal function to fetch incidents for the fetch-incidents command.

    Args:
        client: Brandefense API client.
        args: Parameters for filtering.

    Returns:
        List of incident details with indicators.
    """
    incident_category = list_to_comma_separated_string(args.get('IncidentCategory'))
    incident_module = list_to_comma_separated_string(args.get('IncidentModule'))
    incident_rules = args.get('IncidentRules')
    status = list_to_comma_separated_string(args.get('status', 'OPEN'))
    period = int(args.get('period', 1))
    max_results = int(args.get('MaxResults', DEFAULT_PAGE_SIZE))

    template_ids = convert_rules_to_ids(incident_rules) if incident_rules else ''

    current_datetime = datetime.now()
    start_datetime = current_datetime - timedelta(hours=period)

    params = {
        'page_size': DEFAULT_PAGE_SIZE,
        'created_at__range': f'{start_datetime.strftime("%Y-%m-%d %H:%M:%S")},{current_datetime.strftime("%Y-%m-%d %H:%M:%S")}',
        'status': status.upper() if status else 'OPEN',
        'page': 1,
    }
    if incident_module:
        params['module'] = incident_module
    if incident_category:
        params['module_category'] = incident_category
    if template_ids:
        params['template_id__in'] = template_ids

    incidents = paginate(client, url='/incidents', method='GET', params=params, max_results=max_results)

    incident_details = []
    for _incident in incidents:
        code = _incident.get('code')
        if code:
            details = client.get_incident_detail(code)
            details['indicators'] = paginate(
                client, url=f'/incidents/{code}/indicators', method='GET'
            )
            details['reference_url'] = f'https://app.brandefense.io/issues/incidents/all/{code}'
            incident_details.append(details)

    return incident_details


def get_brandefense_intelligence_for_fetch(client: Client, args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Internal function to fetch intelligence for the fetch-incidents command.

    Args:
        client: Brandefense API client.
        args: Parameters for filtering.

    Returns:
        List of intelligence details with indicators.
    """
    category = list_to_comma_separated_string(args.get('IntelligenceCategory'))
    search_term = args.get('IntelligenceSearch', '')
    period = int(args.get('period', 24))
    max_results = int(args.get('MaxResults', DEFAULT_PAGE_SIZE))

    current_datetime = datetime.now()
    start_datetime = current_datetime - timedelta(hours=period)

    params = {
        'page_size': DEFAULT_PAGE_SIZE,
        'created_at__range': f'{start_datetime.strftime("%Y-%m-%d %H:%M:%S")},{current_datetime.strftime("%Y-%m-%d %H:%M:%S")}',
        'page': 1,
    }
    if category:
        params['category__in'] = category

    intelligence_list = paginate(client, url='/intelligences', method='GET', params=params, max_results=max_results)

    # Filter by search term in tags
    if search_term:
        intelligence_list = [
            item for item in intelligence_list
            if any(search_term.lower() in tag.lower() for tag in item.get('tags', []))
        ]

    intelligence_details = []
    for intel in intelligence_list:
        code = intel.get('code')
        if code:
            details = client.get_intelligence_detail(code)
            ind_resp = client.get_intelligence_indicators(code)
            if isinstance(ind_resp, list):
                details['indicators'] = ind_resp
            elif isinstance(ind_resp, dict):
                details['indicators'] = ind_resp.get('results', [])
            else:
                details['indicators'] = []
            details['reference_url'] = f'https://app.brandefense.io/issues/intelligence/all/{code}'
            intelligence_details.append(details)

    return intelligence_details


def fetch_incidents(client: Client, last_run: Dict[str, Any],
                    first_fetch_time: Optional[int],
                    incident_category: List, incident_module: List,
                    incident_status: List, fetching_issue_types: List,
                    intelligence_category: List, intelligence_search: Any,
                    incident_rules: List, max_results: int) -> Tuple[Dict[str, Any], List[Dict]]:
    """Fetch incidents from Brandefense with deduplication.

    Uses a dual-check deduplication strategy:
    1. Timestamp-based: Only process items newer than or equal to last fetch time.
    2. Code-based: Track seen incident/intelligence codes in last_run to prevent
       duplicates when multiple items share the same created_at timestamp.

    The seen_codes list is stored in last_run and bounded to the last 1000 codes
    to prevent unlimited memory growth.

    Args:
        client: Brandefense API client.
        last_run: Dict containing 'last_fetch' timestamp and 'seen_codes' list.
        first_fetch_time: If last_run is None then fetch all incidents since this time.
        incident_category: Filter by incident category.
        incident_module: Filter by incident module.
        incident_status: Filter by incident status.
        fetching_issue_types: Types to fetch (Incident, Intelligence).
        intelligence_category: Filter by intelligence category.
        intelligence_search: Search term for intelligence filtering.
        incident_rules: Filter by incident rules.
        max_results: Maximum number of results to fetch.

    Returns:
        Tuple of (next_run dict, list of XSOAR incidents).
    """
    MAX_SEEN_CODES = 1000  # Prevent unbounded growth of seen codes list

    args: Dict[str, Any] = {
        'IncidentCategory': incident_category,
        'IncidentModule': incident_module,
        'status': incident_status,
        'IntelligenceCategory': intelligence_category,
        'IntelligenceSearch': intelligence_search,
        'IncidentRules': incident_rules,
        'MaxResults': max_results,
    }

    fetch_functions = {
        'Incident': get_brandefense_incidents_for_fetch,
        'Intelligence': get_brandefense_intelligence_for_fetch,
    }

    # Get the last fetch time and previously seen codes
    last_fetch = last_run.get('last_fetch', None)
    seen_codes: set = set(last_run.get('seen_codes', []))

    if not last_fetch:
        args['period'] = hours_ago_from_epoch(first_fetch_time)
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = int(last_fetch)

    # Fetch items from configured sources
    items: List[Dict[str, Any]] = []
    for fetch_type in (fetching_issue_types or ['Incident']):
        fetch_fn = fetch_functions.get(fetch_type)
        if fetch_fn:
            items.extend(fetch_fn(client, args))

    incidents: List[Dict] = []
    new_seen_codes: set = set()

    if items:
        # Sort by created_at
        items = sorted(
            items,
            key=lambda x: datetime.strptime(x.get('created_at', ''), DATETIME_FORMAT)
        )

        for item in items:
            code = item.get('code', '')
            severity = item.get('severity', 'HIGH')
            created_at = item.get('created_at', '')

            try:
                incident_created_time = int(
                    datetime.fromisoformat(created_at[:-1] + '+00:00').timestamp()
                )
            except (ValueError, IndexError):
                demisto.debug(f'Skipping item with invalid created_at: {created_at}')
                continue

            # DEDUPLICATION: Skip if we've already seen this code
            if code in seen_codes:
                demisto.debug(f'Skipping duplicate item with code: {code}')
                continue

            # Only process items newer than or equal to the last fetch time
            if incident_created_time >= latest_created_time:
                # Add a fetch_type marker for the classifier
                fetch_type_marker = 'Incident' if 'module' in item else 'Intelligence'
                item['brandefense_type'] = fetch_type_marker
                # Preserve original type and set classifier key
                if 'type' in item:
                    item['brandefense_original_type'] = item['type']
                item['type'] = fetch_type_marker

                title = item.get('title', code)
                incident_xsoar = {
                    'name': f'{title}: {code}',
                    'occurred': timestamp_to_datestring(incident_created_time * 1000),
                    'rawJSON': json.dumps(item),
                    'severity': convert_to_demisto_severity(severity),
                }
                incidents.append(incident_xsoar)
                new_seen_codes.add(code)

        # Update latest timestamp to the most recent item
        if incidents:
            try:
                latest_created_time = int(
                    datetime.fromisoformat(items[-1]['created_at'][:-1] + '+00:00').timestamp()
                )
            except (ValueError, IndexError, KeyError):
                pass

    # Merge seen codes: keep existing + new, bounded to MAX_SEEN_CODES
    all_seen_codes = seen_codes | new_seen_codes
    # Keep only the most recent codes if we exceed the limit
    all_seen_codes_list = list(all_seen_codes)[-MAX_SEEN_CODES:]

    next_run = {
        'last_fetch': latest_created_time,
        'seen_codes': all_seen_codes_list,
    }

    demisto.debug(f'Fetched {len(incidents)} new incidents/intelligence. '
                  f'Tracking {len(all_seen_codes_list)} seen codes. '
                  f'Latest timestamp: {latest_created_time}')

    return next_run, incidents


''' MAIN '''


def main() -> None:
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    api_key = params.get('apikey')
    base_url = urljoin(params['url'], '/api/v1')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')

    first_fetch_time = get_first_time_fetch(params.get('first_fetch'))

    try:
        headers = {
            'authorization': f'Bearer {api_key}'
        }

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
        )

        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            result = test_module(client)
            demisto.results(result)

        elif command == 'fetch-incidents':
            incident_category = params.get('IncidentCategory')
            incident_module = params.get('IncidentModule')
            incident_status = params.get('IncidentStatus')
            intelligence_category = params.get('IntelligenceCategory')
            intelligence_search = params.get('IntelligenceSearch')
            fetching_issue_types = params.get('FetchingIssueTypes')
            incident_rules = params.get('IncidentRules')
            max_results = int(params.get('MaxResults', 30))

            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                incident_category=incident_category,
                incident_module=incident_module,
                incident_status=incident_status,
                fetching_issue_types=fetching_issue_types,
                intelligence_category=intelligence_category,
                intelligence_search=intelligence_search,
                incident_rules=incident_rules,
                max_results=max_results
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'ip':
            return_results(search_ip_command(client, args))
        elif command == 'domain':
            return_results(search_domain_command(client, args))
        elif command == 'file':
            return_results(search_hash_command(client, args))
        elif command == 'url':
            return_results(search_url_command(client, args))
        elif command == 'brandefense_get_incidents':
            return_results(get_incidents_command(client, args))
        elif command == 'brandefense_get_incident_detail':
            return_results(get_incident_detail_command(client, args))
        elif command == 'brandefense_incident_indicators':
            return_results(get_incident_indicators_command(client, args))
        elif command == 'brandefense_get_incident_relatives':
            return_results(get_incident_relatives_command(client, args))
        elif command == 'brandefense_change_incident_status':
            return_results(change_incident_status_command(client, args))
        elif command == 'brandefense_get_intelligences':
            return_results(get_intelligence_command(client, args))
        elif command == 'brandefense_get_intelligence_detail':
            return_results(get_intelligence_detail_command(client, args))
        elif command == 'brandefense_intelligence_indicators':
            return_results(get_intelligence_indicators_command(client, args))
        elif command == 'brandefense_get_intelligence_rules':
            return_results(get_intelligence_rules_command(client, args))
        elif command == 'threat_search':
            return_results(threat_search_command(client, args))
        elif command == 'brandefense_get_assets':
            return_results(get_assets_command(client, args))
        elif command == 'brandefense_get_iocs':
            return_results(get_iocs_command(client, args))
        elif command == 'brandefense_get_compromised_devices':
            return_results(get_compromised_devices_command(client, args))
        elif command == 'brandefense_get_audit_logs':
            return_results(get_audit_logs_command(client, args))
        elif command == 'brandefense_get_domain_risk_assessment':
            return_results(get_domain_risk_assessment_command(client, args))
        elif command == 'brandefense_get_ioc_list':
            return_results(get_ioc_list_command(client, args))
        elif command == 'brandefense_create_confirmed_phishing':
            return_results(create_confirmed_phishing_command(client, args))
        elif command == 'brandefense_takedown_request':
            return_results(takedown_request_command(client, args))
        elif command == 'brandefense_get_indicators':
            return_results(get_indicators_command(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
