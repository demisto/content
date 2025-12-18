import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""IMPORTS"""
import urllib3
from base64 import b64decode
from typing import Dict, Any, Optional

# Disable insecure warnings
urllib3.disable_warnings()

"""CONSTANTS"""
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# V2 API Endpoints
ENDPOINTS = {
    'ip_reputation': '/v2/ip-reputation',
    'domain_reputation': '/v2/domain-reputation',
    'url_reputation': '/v2/url-reputation',
    'dns_lookup': '/v2/dns-lookup',
    'ssl_info': '/v2/ssl-info',
    'email_verify': '/v2/email-verify',
    'parked_domain': '/v2/parked-domain',
    'domain_age': '/v2/domain-age',
    'screenshot': '/v2/screenshot',
    'url_to_pdf': '/v2/url-to-pdf',
    'site_trustworthiness': '/v2/site-trust'
}


class Client(BaseClient):
    """
    APIVoid V2 Client - handles all API requests with V2 authentication
    """

    def __init__(self, base_url: str, apikey: str, verify: bool, proxy: bool):
        headers = {
            'X-API-Key': apikey,
            'Content-Type': 'application/json'
        }
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def api_request(self, endpoint: str, json_data: dict) -> dict:
        """Generic V2 API request method"""
        return self._http_request(
            method='POST',
            url_suffix=endpoint,
            json_data=json_data
        )


def calculate_dbot_score(engines_count: int, detections: int, good_threshold: int,
                         suspicious_threshold: int, bad_threshold: int) -> int:
    """
    Calculate DBot score based on detection rate
    
    Args:
        engines_count: Total number of engines
        detections: Number of positive detections
        good_threshold: Threshold for good reputation (%)
        suspicious_threshold: Threshold for suspicious reputation (%)
        bad_threshold: Threshold for bad reputation (%)
    
    Returns:
        DBot score (0-3)
    """
    if engines_count == 0:
        return Common.DBotScore.NONE

    detection_rate = (detections / engines_count) * 100

    if detection_rate < good_threshold:
        return Common.DBotScore.GOOD
    elif detection_rate < suspicious_threshold:
        return Common.DBotScore.GOOD
    elif detection_rate < bad_threshold:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.BAD


def ip_reputation_command(client: Client, args: dict, reputation_only: bool,
                          thresholds: dict, reliability: str) -> CommandResults:
    """
    Get IP reputation from APIVoid V2 API
    
    Args:
        client: APIVoid client instance
        args: Command arguments
        reputation_only: If True, return only standard IP context
        thresholds: Dict with 'good', 'suspicious', 'bad' thresholds
        reliability: Source reliability level
    
    Returns:
        CommandResults object
    """
    ip = args.get('ip')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['ip_reputation'], {'ip': ip})
    except Exception as e:
        raise DemistoException(f'Failed to get IP reputation: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error checking IP {ip}: {response.get("error")}',
            raw_response=response
        )

    # Extract data
    blacklists = response.get('blacklists', {})
    information = response.get('information', {})
    engines_count = blacklists.get('engines_count', 0)
    detections = blacklists.get('detections', 0)

    # Calculate DBot score
    score = calculate_dbot_score(
        engines_count,
        detections,
        thresholds['good'],
        thresholds['suspicious'],
        thresholds['bad']
    )

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name='APIVoid',
        score=score,
        reliability=reliability
    )

    # Create IP indicator with standard context
    lat = information.get('latitude')
    lng = information.get('longitude')

    ip_indicator = Common.IP(
        ip=ip,
        detection_engines=engines_count,
        positive_engines=detections,
        dbot_score=dbot_score,
        hostname=information.get('reverse_dns'),
        geo_country=information.get('country_name'),
        geo_description=information.get('isp'),
        geo_latitude=lat,
        geo_longitude=lng
    )

    # Build custom context outputs
    outputs = {} if reputation_only else response

    # Create readable output
    readable_data = {
        'IP': ip,
        'Detections': f'{detections}/{engines_count}',
        'Detection Rate': blacklists.get('detection_rate', 'N/A'),
        'Risk Score': response.get('risk_score', {}).get('result', 'N/A'),
        'Country': information.get('country_name', 'N/A'),
        'ISP': information.get('isp', 'N/A'),
        'Reverse DNS': information.get('reverse_dns', 'N/A')
    }

    readable_output = tableToMarkdown(
        f'APIVoid IP Reputation for {ip}',
        readable_data
    )

    return CommandResults(
        outputs_prefix="APIVoid.IP",
        outputs_key_field="ip",
        outputs=outputs,
        indicator=ip_indicator,
        readable_output=readable_output,
        raw_response=response
    )


def domain_reputation_command(client: Client, args: dict, reputation_only: bool,
                               thresholds: dict, reliability: str) -> CommandResults:
    """
    Get Domain reputation from APIVoid V2 API
    
    Args:
        client: APIVoid client instance
        args: Command arguments
        reputation_only: If True, return only standard Domain context
        thresholds: Dict with 'good', 'suspicious', 'bad' thresholds
        reliability: Source reliability level
    
    Returns:
        CommandResults object
    """
    domain = args.get('domain')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['domain_reputation'], {'host': domain})
    except Exception as e:
        raise DemistoException(f'Failed to get domain reputation: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error checking domain {domain}: {response.get("error")}',
            raw_response=response
        )

    # Map V2 response to V1 field names for YML compatibility
    if 'server_details' in response:
        response['server'] = response.pop('server_details')

    # Extract data
    blacklists = response.get('blacklists', {})
    engines_count = blacklists.get('engines_count', 0)
    detections = blacklists.get('detections', 0)

    # Calculate DBot score
    score = calculate_dbot_score(
        engines_count,
        detections,
        thresholds['good'],
        thresholds['suspicious'],
        thresholds['bad']
    )

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name='APIVoid',
        score=score,
        reliability=reliability
    )

    # Create Domain indicator
    domain_indicator = Common.Domain(
        domain=domain,
        dbot_score=dbot_score,
        detection_engines=engines_count,
        positive_detections=detections
    )

    # Build custom context outputs
    outputs = {}
    if not reputation_only:
        outputs['APIVoid.Domain(val.host && val.host == obj.host)'] = response

    # Create readable output
    readable_data = {
        'Domain': domain,
        'Detections': f'{detections}/{engines_count}',
        'Detection Rate': blacklists.get('detection_rate', 'N/A'),
        'Risk Score': response.get('risk_score', {}).get('result', 'N/A')
    }

    readable_output = tableToMarkdown(
        f'APIVoid Domain Reputation for {domain}',
        readable_data
    )

    return CommandResults(
        outputs=outputs,
        indicator=domain_indicator,
        readable_output=readable_output,
        raw_response=response
    )


def url_reputation_command(client: Client, args: dict, reputation_only: bool,
                           thresholds: dict, reliability: str) -> CommandResults:
    """
    Get URL reputation from APIVoid V2 API
    
    Args:
        client: APIVoid client instance
        args: Command arguments
        reputation_only: If True, return only standard URL context
        thresholds: Dict with 'good', 'suspicious', 'bad' thresholds
        reliability: Source reliability level
    
    Returns:
        CommandResults object
    """
    url = args.get('url')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['url_reputation'], {'url': url})
    except Exception as e:
        raise DemistoException(f'Failed to get URL reputation: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error checking URL {url}: {response.get("error")}',
            raw_response=response
        )

    # Add url to response for context
    response['url'] = url

    # Map V2 response to V1 field names for YML compatibility
    if 'html_info' in response:
        response['web_page'] = response.pop('html_info')

    # Extract data
    domain_blacklist = response.get('domain_blacklist', {})
    engines_count = domain_blacklist.get('engines_count', 0)
    detections = domain_blacklist.get('detections', 0)

    # Calculate DBot score
    score = calculate_dbot_score(
        engines_count,
        detections,
        thresholds['good'],
        thresholds['suspicious'],
        thresholds['bad']
    )

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name='APIVoid',
        score=score,
        reliability=reliability
    )

    # Create URL indicator
    url_indicator = Common.URL(
        url=url,
        dbot_score=dbot_score,
        detection_engines=engines_count,
        positive_detections=detections
    )

    # Build custom context outputs
    outputs = {}
    if not reputation_only:
        outputs['APIVoid.URL(val.url && val.url == obj.url)'] = response

    # Create readable output
    readable_data = {
        'URL': url,
        'Detections': f'{detections}/{engines_count}',
        'Risk Score': response.get('risk_score', {}).get('result', 'N/A')
    }

    readable_output = tableToMarkdown(
        f'APIVoid URL Reputation for {url}',
        readable_data
    )

    return CommandResults(
        outputs=outputs,
        indicator=url_indicator,
        readable_output=readable_output,
        raw_response=response
    )


def dns_lookup_command(client: Client, args: dict) -> list:
    """
    Get DNS records for a host
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        List of entry objects
    """
    host = args.get('host')
    dns_type = args.get('type', 'A')

    # Make API request
    try:
        response = client.api_request(
            ENDPOINTS['dns_lookup'],
            {'host': host, 'action': f'dns-{dns_type.lower()}'}
        )
    except Exception as e:
        raise DemistoException(f'Failed to get DNS records: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return [CommandResults(
            readable_output=f'Error looking up DNS for {host}: {response.get("error")}',
            raw_response=response
        )]

    records = response.get('records', {})
    entries = []

    if records:
        records['host'] = host
        records['type'] = dns_type

        md_data = dict(records)
        md_data['Host'] = host
        md_data['Type'] = dns_type

        ec = {
            'APIVoid.DNS(val.host && val.type && val.host == obj.host && val.type == obj.type)': records
        }

        md = tableToMarkdown(f'APIVoid DNS-{dns_type} information for {host}:', md_data)
        entries.append({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': ec,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })

        # Add individual record entries
        for item in records.get('items', []):
            item_type = item.get('type', dns_type)
            md = tableToMarkdown(f'Information of {item_type} record from {host}:', item)
            entries.append({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': item,
                'HumanReadable': md,
                'ReadableContentsFormat': formats['markdown']
            })

    return entries


def ssl_info_command(client: Client, args: dict) -> CommandResults:
    """
    Get SSL certificate information for a host
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        CommandResults object
    """
    host = args.get('host')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['ssl_info'], {'host': host})
    except Exception as e:
        raise DemistoException(f'Failed to get SSL info: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error getting SSL info for {host}: {response.get("error")}',
            raw_response=response
        )

    certificate = response.get('certificate', {})
    if certificate:
        md_data = dict(certificate)
        if 'details' in md_data:
            del md_data['details']

        certificate['host'] = host
        ec = {
            'APIVoid.SSL(val.host && val.host == obj.host)': certificate
        }
        md = tableToMarkdown(f'APIVoid SSL Information for {host}:', md_data)
    else:
        ec = {}
        md = f'## No SSL information for {host}'

    return CommandResults(
        outputs=ec,
        readable_output=md,
        raw_response=response
    )


def email_verify_command(client: Client, args: dict) -> CommandResults:
    """
    Verify an email address
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        CommandResults object
    """
    email = args.get('email')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['email_verify'], {'email': email})
    except Exception as e:
        raise DemistoException(f'Failed to verify email: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error verifying email {email}: {response.get("error")}',
            raw_response=response
        )

    if response:
        # Create user-friendly readable output
        valid_format = response.get('valid_format', False)
        disposable = response.get('disposable', False)
        free_email = response.get('free_email', False)
        role_address = response.get('role_address', False)
        should_block = response.get('should_block', False)
        
        # Determine overall status
        if should_block:
            status = '❌ Should Block'
        elif valid_format and not disposable:
            status = '✅ Valid'
        elif valid_format:
            status = '⚠️ Valid but Risky'
        else:
            status = '❌ Invalid'
        
        # Build main summary table
        readable_data = {
            'Email': email,
            'Status': status,
            'Valid Format': '✅ Yes' if valid_format else '❌ No',
            'Disposable': '⚠️ Yes' if disposable else '✅ No',
            'Free Email': 'ℹ️ Yes' if free_email else 'No',
            'Role Address': 'ℹ️ Yes' if role_address else 'No',
            'Domain': response.get('domain', 'N/A'),
            'Risk Score': response.get('score', 'N/A')
        }
        
        md = tableToMarkdown(f'APIVoid Email Verification for {email}', readable_data)
        
        # Add DNS/SMTP findings
        dns_findings = []
        if response.get('has_mx_records'):
            dns_findings.append('✅ MX records found')
        else:
            dns_findings.append('❌ No MX records')
        
        if response.get('has_a_records'):
            dns_findings.append('✅ A records found')
        
        if response.get('has_spf_records'):
            dns_findings.append('✅ SPF configured')
        
        if response.get('dmarc_configured'):
            if response.get('dmarc_enforced'):
                dns_findings.append('✅ DMARC enforced')
            else:
                dns_findings.append('ℹ️ DMARC configured but not enforced')
        
        if response.get('is_spoofable'):
            dns_findings.append('⚠️ Email spoofing possible')
        
        if dns_findings:
            md += '\n### DNS & SMTP Configuration\n' + '\n'.join(f'- {finding}' for finding in dns_findings)
        
        # Add security concerns
        security_concerns = []
        if disposable:
            security_concerns.append('⚠️ Disposable/temporary email service')
        if response.get('suspicious_email'):
            security_concerns.append('⚠️ Suspicious email pattern detected')
        if response.get('suspicious_username'):
            security_concerns.append('⚠️ Suspicious username pattern')
        if response.get('dirty_words_username'):
            security_concerns.append('⚠️ Inappropriate words in username')
        if response.get('suspicious_domain'):
            security_concerns.append('⚠️ Suspicious domain')
        if response.get('dirty_words_domain'):
            security_concerns.append('⚠️ Inappropriate words in domain')
        if response.get('risky_tld'):
            security_concerns.append('⚠️ Risky top-level domain')
        if response.get('email_forwarder'):
            security_concerns.append('ℹ️ Email forwarding service')
        
        # Add positive indicators
        if response.get('domain_popular'):
            security_concerns.append('✅ Popular domain')
        if response.get('valid_tld'):
            security_concerns.append('✅ Valid TLD')
        
        # Add special domain types
        if response.get('government_domain'):
            security_concerns.append('ℹ️ Government domain')
        if response.get('educational_domain'):
            security_concerns.append('ℹ️ Educational domain')
        if response.get('police_domain'):
            security_concerns.append('ℹ️ Police/law enforcement domain')

        
        if security_concerns:
            md += '\n### Security & Domain Analysis\n' + '\n'.join(f'- {concern}' for concern in security_concerns)
        
        # Add suggestion if available
        did_you_mean = response.get('did_you_mean', '')
        if did_you_mean:
            md += f'\n### Suggestion\n- Did you mean: **{did_you_mean}**?'
    else:
        md = f'## No information for {email}'

    return CommandResults(
        outputs_prefix="APIVoid.Email",
        outputs_key_field="email",
        outputs=response,
        readable_output=md,
        raw_response=response
    )


def parked_domain_command(client: Client, args: dict) -> CommandResults:
    """
    Check if a domain is parked
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        CommandResults object
    """
    domain = args.get('domain')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['parked_domain'], {'domain': domain})
    except Exception as e:
        raise DemistoException(f'Failed to check parked domain: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error checking parked domain {domain}: {response.get("error")}',
            raw_response=response
        )

    if response:
        ec = {
            'APIVoid.ParkedDomain(val.host && val.host == obj.host)': response,
            'Domain': {'Name': domain}
        }
        md = tableToMarkdown(f'APIVoid Parked Domain Information for {domain}:', response)
    else:
        ec = {}
        md = f'## No information for {domain}'

    return CommandResults(
        outputs=ec,
        readable_output=md,
        raw_response=response
    )


def domain_age_command(client: Client, args: dict) -> CommandResults:
    """
    Get domain age information
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        CommandResults object
    """
    domain = args.get('domain')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['domain_age'], {'domain': domain})
    except Exception as e:
        raise DemistoException(f'Failed to get domain age: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error getting domain age for {domain}: {response.get("error")}',
            raw_response=response
        )

    if response:
        ec = {
            'APIVoid.DomainAge(val.host && val.host == obj.host)': response,
            'Domain': {
                'Name': domain,
                'CreationDate': response.get('domain_creation_date')
            }
        }
        md = tableToMarkdown(f'APIVoid Domain Age Information for {domain}:', response)
    else:
        ec = {}
        md = f'## No information for {domain}'

    return CommandResults(
        outputs=ec,
        readable_output=md,
        raw_response=response
    )


def screenshot_command(client: Client, args: dict) -> dict:
    """
    Capture a screenshot of a URL
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        File result dict
    """
    url = args.get('url', '')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['screenshot'], {'url': url})
    except Exception as e:
        raise DemistoException(f'Failed to capture screenshot: {str(e)}')

    # Handle API errors
    if 'error' in response:
        raise DemistoException(f'Error capturing screenshot for {url}: {response.get("error")}')

    data = response.get('base64_file')
    if data:
        # Create file name
        file_name = url.replace('https', '').replace('http', '').replace('://', '').replace('.', '_')
        file_name += '_capture.png'
        return fileResult(file_name, b64decode(data))
    else:
        raise DemistoException(f'No screenshot data returned for {url}')


def url_to_pdf_command(client: Client, args: dict) -> dict:
    """
    Convert a URL to PDF
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        File result dict
    """
    url = args.get('url', '')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['url_to_pdf'], {'url': url})
    except Exception as e:
        raise DemistoException(f'Failed to convert URL to PDF: {str(e)}')

    # Handle API errors
    if 'error' in response:
        raise DemistoException(f'Error converting URL to PDF for {url}: {response.get("error")}')

    data = response.get('base64_file')
    if data:
        # Create file name
        file_name = url.replace('https', '').replace('http', '').replace('://', '').replace('.', '_')
        file_name += '_capture.pdf'
        return fileResult(file_name, b64decode(data))
    else:
        raise DemistoException(f'No PDF data returned for {url}')


def site_trustworthiness_command(client: Client, args: dict) -> CommandResults:
    """
    Get site trustworthiness information
    
    Args:
        client: APIVoid client instance
        args: Command arguments
    
    Returns:
        CommandResults object
    """
    host = args.get('host')

    # Make API request
    try:
        response = client.api_request(ENDPOINTS['site_trustworthiness'], {'host': host})
    except Exception as e:
        raise DemistoException(f'Failed to get site trustworthiness: {str(e)}')

    # Handle API errors
    if 'error' in response:
        return CommandResults(
            readable_output=f'Error getting site trustworthiness for {host}: {response.get("error")}',
            raw_response=response
        )

    # Build outputs - following YML structure
    outputs = {}
    if response:
        response['host'] = host
        
        # Map security_checks domain age fields to domain_age structure for YML compatibility
        # The YML expects APIVoid.SiteTrust.domain_age.* fields
        security_checks = response.get('security_checks', {})
        if security_checks:
            # Create domain_age object from security_checks fields
            domain_age = {}
            if 'domain_creation_date' in security_checks:
                domain_age['domain_creation_date'] = security_checks.get('domain_creation_date')
                domain_age['found'] = True
            if 'domain_age_in_days' in security_checks:
                domain_age['domain_age_in_days'] = security_checks.get('domain_age_in_days')
            if 'domain_age_in_months' in security_checks:
                domain_age['domain_age_in_months'] = security_checks.get('domain_age_in_months')
            if 'domain_age_in_years' in security_checks:
                domain_age['domain_age_in_years'] = security_checks.get('domain_age_in_years')
            
            if domain_age:
                response['domain_age'] = domain_age
        
        outputs = response
        
        # Create user-friendly readable output
        trust_score = response.get('trust_score', {}).get('result', 'N/A')
        domain_blacklist = response.get('domain_blacklist', {})
        blacklist_detections = domain_blacklist.get('detections', 0)
        blacklist_engines = domain_blacklist.get('engines_count', 0)
        server_details = response.get('server_details', {})
        
        # Build main summary table
        readable_data = {
            'Host': host,
            'Trust Score': trust_score,
            'Blacklist Detections': f'{blacklist_detections}/{blacklist_engines}',
            'Domain Age': f"{security_checks.get('domain_age_in_years', 'N/A')} years" if security_checks.get('domain_age_in_years') else 'N/A',
            'Creation Date': security_checks.get('domain_creation_date', 'N/A'),
            'Server IP': server_details.get('ip', 'N/A'),
            'Country': server_details.get('country_name', 'N/A'),
            'ISP': server_details.get('isp', 'N/A')
        }
        
        md = tableToMarkdown(f'APIVoid Site Trustworthiness for {host}', readable_data)
        
        # Add key security findings
        security_findings = []
        if security_checks:
            if security_checks.get('is_domain_blacklisted'):
                security_findings.append('⚠️ Domain is blacklisted')
            if security_checks.get('is_suspicious_domain'):
                security_findings.append('⚠️ Suspicious domain detected')
            if security_checks.get('is_sinkholed_domain'):
                security_findings.append('⚠️ Sinkholed domain')
            if security_checks.get('is_domain_recent') == 'yes':
                security_findings.append('⚠️ Recently created domain')
            if not security_checks.get('is_valid_https'):
                security_findings.append('⚠️ Invalid HTTPS configuration')
            if security_checks.get('is_ssl_blacklisted'):
                security_findings.append('⚠️ SSL certificate blacklisted')
            if not security_checks.get('is_hsts_header'):
                security_findings.append('ℹ️ Missing HSTS header')
            if security_checks.get('is_email_spoofable'):
                security_findings.append('ℹ️ Email spoofing possible')
            if not security_checks.get('is_dmarc_enforced'):
                security_findings.append('ℹ️ DMARC not enforced')
            if security_checks.get('is_risky_geo_location'):
                security_findings.append('⚠️ Risky geographic location')
            
            # Positive indicators
            if security_checks.get('is_website_popular'):
                security_findings.append('✅ Popular website')
            if security_checks.get('is_valid_https'):
                security_findings.append('✅ Valid HTTPS')
            if security_checks.get('is_hsts_header'):
                security_findings.append('✅ HSTS enabled')
        
        if security_findings:
            md += '\n### Security Findings\n' + '\n'.join(f'- {finding}' for finding in security_findings)
        
        # Add DNS summary if available
        dns_records = response.get('dns_records', {})
        if dns_records:
            dns_summary = []
            ns_records = dns_records.get('ns', [])
            mx_records = dns_records.get('mx', [])
            
            if ns_records:
                dns_summary.append(f"**NS Records:** {len(ns_records)} nameserver(s)")
            if mx_records:
                dns_summary.append(f"**MX Records:** {len(mx_records)} mail server(s)")
            
            if dns_summary:
                md += '\n### DNS Information\n' + '\n'.join(f'- {item}' for item in dns_summary)
    else:
        md = f'## No information for {host}'

    return CommandResults(
        outputs_prefix="APIVoid.SiteTrust",
        outputs_key_field="host",
        outputs=outputs,
        readable_output=md,
        raw_response=response
    )


def test_module(client: Client) -> str:
    """
    Test the integration by making a simple API call
    
    Args:
        client: APIVoid client instance
    
    Returns:
        'ok' if successful, error message otherwise
    """
    try:
        # Use IP reputation endpoint with a known IP for testing
        response = client.api_request(ENDPOINTS['ip_reputation'], {'ip': '8.8.8.8'})
        if 'error' in response:
            return f'Test Failed: {response.get("error")}'
        return 'ok'
    except Exception as e:
        return f'Test Failed: {str(e)}'


def main():
    """Main execution function"""

    # Get parameters once
    params = demisto.params()
    base_url = 'https://api.apivoid.com'
    apikey = params.get('credentials', {}).get('password') or params.get('apikey', '')
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('integrationReliability', 'C - Fairly reliable')

    # Threshold configuration
    thresholds = {
        'good': arg_to_number(params.get('good', 10)),
        'suspicious': arg_to_number(params.get('suspicious', 30)),
        'bad': arg_to_number(params.get('bad', 60))
    }

    # Create client
    client = Client(base_url, apikey, verify, proxy)

    # Get command and args
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        # Command routing
        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command in ['ip', 'apivoid-ip']:
            reputation_only = (command == 'ip')
            result = ip_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command in ['domain', 'apivoid-domain']:
            reputation_only = (command == 'domain')
            result = domain_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command in ['url', 'apivoid-url']:
            reputation_only = (command == 'url')
            result = url_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command == 'apivoid-dns-lookup':
            results = dns_lookup_command(client, args)
            demisto.results(results)

        elif command == 'apivoid-ssl-info':
            result = ssl_info_command(client, args)
            return_results(result)

        elif command == 'apivoid-email-verify':
            result = email_verify_command(client, args)
            return_results(result)

        elif command == 'apivoid-parked-domain':
            result = parked_domain_command(client, args)
            return_results(result)

        elif command == 'apivoid-domain-age':
            result = domain_age_command(client, args)
            return_results(result)

        elif command == 'apivoid-url-to-image':
            result = screenshot_command(client, args)
            demisto.results(result)

        elif command == 'apivoid-url-to-pdf':
            result = url_to_pdf_command(client, args)
            demisto.results(result)

        elif command == 'apivoid-site-trustworthiness':
            result = site_trustworthiness_command(client, args)
            return_results(result)

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
