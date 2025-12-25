import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

"""IMPORTS"""
import urllib3
from base64 import b64decode
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

"""CONSTANTS"""
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# V2 API Endpoints
ENDPOINTS = {
    "ip_reputation": "/v2/ip-reputation",
    "domain_reputation": "/v2/domain-reputation",
    "url_reputation": "/v2/url-reputation",
    "dns_lookup": "/v2/dns-lookup",
    "ssl_info": "/v2/ssl-info",
    "email_verify": "/v2/email-verify",
    "parked_domain": "/v2/parked-domain",
    "domain_age": "/v2/domain-age",
    "screenshot": "/v2/screenshot",
    "url_to_pdf": "/v2/url-to-pdf",
    "site_trustworthiness": "/v2/site-trust",
}

# Global field mapping - maps API V2 field names to YML expected field names
# This mapping is applied recursively to all response data
FIELD_MAPPING = {
    "elapsed_ms": "elapsed",
    "name": "engine",
    "calling_code": "country_calling_code",
    "currency": "country_currency",
    "scan_time_ms": "scantime",
    "html_info": "web_page",
    "fingerprint_sha1": "fingerprint",
}


class Client(BaseClient):
    """
    APIVoid V2 Client - handles all API requests with V2 authentication
    """

    def __init__(self, base_url: str, apikey: str, verify: bool, proxy: bool):
        headers = {"X-API-Key": apikey, "Content-Type": "application/json"}
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers)

    def api_request(self, endpoint: str, json_data: dict) -> dict:
        """Generic V2 API request method"""
        demisto.debug(f"APIVoid: Making API request to {endpoint} with data: {json_data}")

        response = self._http_request(method="POST", url_suffix=endpoint, json_data=json_data)
        demisto.debug(f"APIVoid: Received response with {len(response)} fields")
        return response


def map_fields(data: Any, exclude_mappings: list | None = None) -> Any:
    """
    Recursively map field names in a data structure according to FIELD_MAPPING.
    Works on dictionaries, lists, and nested structures.

    Args:
        data: Data structure to map (dict, list, or any other type)
        exclude_mappings: Optional list of field names to exclude from mapping

    Returns:
        Data structure with mapped field names
    """
    if isinstance(data, dict):
        # Create a new dict to avoid modifying during iteration
        result = {}
        for key, value in data.items():
            # Map the key if it exists in the global mapping and is not excluded
            if exclude_mappings and key in exclude_mappings:
                new_key = key
            else:
                new_key = FIELD_MAPPING.get(key, key)
            # Recursively process the value
            result[new_key] = map_fields(value, exclude_mappings)
        return result
    elif isinstance(data, list):
        # Recursively process each item in the list
        return [map_fields(item, exclude_mappings) for item in data]
    else:
        # Return primitive types as-is
        return data


def calculate_dbot_score(engines_count: int, detections: int, thresholds: dict) -> int:
    """
    Calculate DBot score based on detection rate

    Args:
        engines_count: Total number of engines
        detections: Number of positive detections
        thresholds: Dict with 'suspicious', 'bad' thresholds (%)

    Returns:
        DBot score (0-3)
    """
    if engines_count == 0:
        return Common.DBotScore.NONE

    detection_rate = (detections / engines_count) * 100

    if detection_rate > thresholds["bad"]:
        return Common.DBotScore.BAD
    if detection_rate > thresholds["suspicious"]:
        return Common.DBotScore.SUSPICIOUS

    return Common.DBotScore.GOOD


def ip_reputation_command(
    client: Client, args: dict, reputation_only: bool, thresholds: dict, reliability: str
) -> CommandResults:
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
    ip = args.get("ip")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["ip_reputation"], {"ip": ip})
    except Exception as e:
        raise DemistoException(f"Failed to get IP reputation: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error checking IP {ip}: {response.get("error")}')

    # Extract data
    blacklists = response.get("blacklists", {})
    information = response.get("information", {})
    engines_count = blacklists.get("engines_count", 0)
    detections = blacklists.get("detections", 0)

    # Convert engines dict to list for YML compatibility
    if "engines" in blacklists:
        engines_dict = blacklists["engines"]
        if isinstance(engines_dict, dict):
            engines_list = list(engines_dict.values())
            response["blacklists"]["engines"] = engines_list

    # Apply field mapping recursively to entire response
    response = map_fields(response)

    # Calculate DBot score
    score = calculate_dbot_score(engines_count, detections, thresholds)

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name="APIVoid",
        score=score,
        reliability=reliability,
        malicious_description=f"Detection rate of {detections}/{engines_count}",
    )

    # Create IP indicator with standard context
    lat = information.get("latitude")
    lng = information.get("longitude")

    ip_indicator = Common.IP(
        ip=ip,
        detection_engines=engines_count,
        positive_engines=detections,
        dbot_score=dbot_score,
        hostname=information.get("reverse_dns"),
        geo_country=information.get("country_name"),
        geo_description=information.get("isp"),
        geo_latitude=lat,
        geo_longitude=lng,
    )

    # Build custom context outputs
    outputs = None if reputation_only else response

    readable_data = {
        "Address": ip,
        "Hostname": information.get("reverse_dns"),
        "Geo": {
            "Location": f"{lat}:{lng}" if lat and lng else None,
            "Country": information.get("country_name"),
            "Description": information.get("isp"),
        },
        "DetectionEngines": engines_count,
        "PositiveDetections": detections,
    }

    readable_output = tableToMarkdown(f"APIVoid information for {ip}:", readable_data)

    return CommandResults(
        outputs_prefix="APIVoid.IP",
        outputs_key_field="ip",
        outputs=outputs,
        indicator=ip_indicator,
        readable_output=readable_output,
        raw_response=response,
    )


def domain_reputation_command(
    client: Client, args: dict, reputation_only: bool, thresholds: dict, reliability: str
) -> CommandResults:
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
    domain = args.get("domain")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["domain_reputation"], {"host": domain})
    except Exception as e:
        raise DemistoException(f"Failed to get domain reputation: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error checking domain {domain}: {response.get("error")}')

    # Map V2 response to V1 field names for YML compatibility
    if "server_details" in response:
        response["server"] = response.pop("server_details")

    # Extract data
    blacklists = response.get("blacklists", {})
    engines_count = blacklists.get("engines_count", 0)
    detections = blacklists.get("detections", 0)

    # Convert engines dict to list for YML compatibility
    if "engines" in blacklists:
        engines_dict = blacklists["engines"]
        if isinstance(engines_dict, dict):
            engines_list = list(engines_dict.values())
            response["blacklists"]["engines"] = engines_list

    # Apply field mapping recursively to entire response
    response = map_fields(response)

    # Calculate DBot score
    score = calculate_dbot_score(engines_count, detections, thresholds)

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name="APIVoid",
        score=score,
        reliability=reliability,
        malicious_description=f"Detection rate of {detections}/{engines_count}",
    )

    # Create Domain indicator
    domain_indicator = Common.Domain(
        domain=domain, dbot_score=dbot_score, detection_engines=engines_count, positive_detections=detections
    )

    # Build custom context outputs
    outputs = None if reputation_only else response

    readable_data = {"Name": domain, "DNS": domain, "DetectionEngines": engines_count, "PositiveDetections": detections}

    readable_output = tableToMarkdown(f"APIVoid information for {domain}:", readable_data)

    return CommandResults(
        outputs_prefix="APIVoid.Domain",
        outputs_key_field="host",
        outputs=outputs,
        indicator=domain_indicator,
        readable_output=readable_output,
        raw_response=response,
    )


def url_reputation_command(
    client: Client, args: dict, reputation_only: bool, thresholds: dict, reliability: str
) -> CommandResults:
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
    url = args.get("url")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["url_reputation"], {"url": url})
    except Exception as e:
        raise DemistoException(f"Failed to get URL reputation: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error checking URL {url}: {response.get("error")}')

    # Add url to response for context
    response["url"] = url

    # Apply field mapping recursively to entire response
    response = map_fields(response, exclude_mappings=["name"])

    # Extract data
    domain_blacklist = response.get("domain_blacklist", {})
    engines_count = domain_blacklist.get("engines_count", 0)
    detections = domain_blacklist.get("detections", 0)
    for key in ["ns", "mx"]:
        dns_records_inner_data = demisto.get(response, f"dns_records.{key}", {})
        if dns_records_inner_data:
            response["dns_records"][key] = {"records": dns_records_inner_data}  # Backward Competability

    # Calculate DBot score
    score = calculate_dbot_score(engines_count, detections, thresholds)

    # Create DBot score object
    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name="APIVoid",
        score=score,
        reliability=reliability,
        malicious_description=f"Detection rate of {detections}/{engines_count}",
    )

    # Create URL indicator
    url_indicator = Common.URL(url=url, dbot_score=dbot_score, detection_engines=engines_count, positive_detections=detections)

    # Build custom context outputs
    outputs = None if reputation_only else response

    readable_data = {"Data": url, "DetectionEngines": engines_count, "PositiveDetections": detections}

    readable_output = tableToMarkdown(f"APIVoid information for {url}:", readable_data)

    return CommandResults(
        outputs_prefix="APIVoid.URL",
        outputs_key_field="url",
        outputs=outputs,
        indicator=url_indicator,
        readable_output=readable_output,
        raw_response=response,
    )


def dns_lookup_command(client: Client, args: dict) -> CommandResults:
    """
    Get DNS records for a host

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        CommandResults object
    """
    host = args.get("host")
    dns_type = args.get("type", "A")  # Required parameter with default

    request_data = {"host": host, "dns_types": dns_type}

    try:
        response = client.api_request(ENDPOINTS["dns_lookup"], request_data)
    except Exception as e:
        raise DemistoException(f"Failed to get DNS records: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error looking up DNS for {host}: {response.get("error")}')

    response = map_fields(response)

    records = response.get("records", {})

    if records:
        # Build outputs with host and type
        outputs = {
            "host": host,
            "type": dns_type,
        }

        # Build readable output - check for the requested type in lowercase
        dns_type_lower = dns_type.lower()

        # Check if the requested type exists in records
        if dns_type_lower in records and records[dns_type_lower]:
            type_records = records[dns_type_lower]
            outputs["items"] = type_records
            md = tableToMarkdown(f"APIVoid DNS {dns_type.upper()} records for {host}:", type_records)
        else:
            md = f"## No {dns_type.upper()} records found for {host}"

        return CommandResults(
            outputs_prefix="APIVoid.DNS", outputs_key_field="host", outputs=outputs, readable_output=md, raw_response=response
        )
    else:
        return CommandResults(readable_output=f"## No DNS records found for {host}", raw_response=response)


def ssl_info_command(client: Client, args: dict) -> CommandResults:
    """
    Get SSL certificate information for a host

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        CommandResults object
    """
    host = args.get("host")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["ssl_info"], {"host": host})
    except Exception as e:
        raise DemistoException(f"Failed to get SSL info: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error getting SSL info for {host}: {response.get("error")}')

    response = map_fields(response, exclude_mappings=["name"])

    certificate = response.get("certificate", {})
    if certificate:
        md_data = dict(certificate)
        if "details" in md_data:
            del md_data["details"]

        certificate["host"] = host
        md = tableToMarkdown(f"APIVoid SSL Information for {host}:", md_data)
    else:
        md = f"## No SSL information for {host}"
    outputs = certificate if certificate else None

    return CommandResults(
        outputs_prefix="APIVoid.SSL", outputs_key_field="host", outputs=outputs, readable_output=md, raw_response=response
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
    email = args.get("email")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["email_verify"], {"email": email})
    except Exception as e:
        raise DemistoException(f"Failed to verify email: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error verifying email {email}: {response.get("error")}')

    if response:
        # Create simple table
        md = tableToMarkdown(f"APIVoid Email Information for {email}:", response)
    else:
        md = f"## No information for {email}"

    return CommandResults(
        outputs_prefix="APIVoid.Email", outputs_key_field="email", outputs=response, readable_output=md, raw_response=response
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
    domain = args.get("domain")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["parked_domain"], {"domain": domain})
    except Exception as e:
        raise DemistoException(f"Failed to check parked domain: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error checking parked domain {domain}: {response.get("error")}')

    if response:
        ec = {"APIVoid.ParkedDomain(val.host && val.host == obj.host)": response, "Domain": {"Name": domain}}
        md = tableToMarkdown(f"APIVoid Parked Domain Information for {domain}:", response)
    else:
        ec = {}
        md = f"## No information for {domain}"

    return CommandResults(outputs=ec, readable_output=md, raw_response=response)


def domain_age_command(client: Client, args: dict) -> CommandResults:
    """
    Get domain age information

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        CommandResults object
    """
    domain = args.get("domain")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["domain_age"], {"domain": domain})
    except Exception as e:
        raise DemistoException(f"Failed to get domain age: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error getting domain age for {domain}: {response.get("error")}')

    if response:
        ec = {
            "APIVoid.DomainAge(val.host && val.host == obj.host)": response,
            "Domain": {"Name": domain, "CreationDate": response.get("domain_creation_date")},
        }
        md = tableToMarkdown(f"APIVoid Domain Age Information for {domain}:", response)
    else:
        ec = {}
        md = f"## No information for {domain}"

    return CommandResults(outputs=ec, readable_output=md, raw_response=response)


def screenshot_command(client: Client, args: dict) -> dict:
    """
    Capture a screenshot of a URL

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        File result dict
    """
    url = args.get("url", "")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["screenshot"], {"url": url})
    except Exception as e:
        raise DemistoException(f"Failed to capture screenshot: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error capturing screenshot for {url}: {response.get("error")}')

    data = response.get("base64_file")
    if data:
        # Create file name
        file_name = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        file_name += "_capture.png"
        return fileResult(file_name, b64decode(data))
    else:
        raise DemistoException(f"No screenshot data returned for {url}")


def url_to_pdf_command(client: Client, args: dict) -> dict:
    """
    Convert a URL to PDF

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        File result dict
    """
    url = args.get("url", "")
    demisto.debug(f"APIVoid: url_to_pdf_command called with url={url}")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["url_to_pdf"], {"url": url})
    except Exception as e:
        raise DemistoException(f"Failed to convert URL to PDF: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error converting URL to PDF for {url}: {response.get("error")}')

    data = response.get("base64_file")
    if data:
        # Create file name
        file_name = url.replace("https", "").replace("http", "").replace("://", "").replace(".", "_")
        file_name += "_capture.pdf"
        return fileResult(file_name, b64decode(data))
    else:
        raise DemistoException(f"No PDF data returned for {url}")


def site_trustworthiness_command(client: Client, args: dict) -> CommandResults:
    """
    Get site trustworthiness information

    Args:
        client: APIVoid client instance
        args: Command arguments

    Returns:
        CommandResults object
    """
    host = args.get("host")
    demisto.debug(f"APIVoid: site_trustworthiness_command called with host={host}")

    # Make API request
    try:
        response = client.api_request(ENDPOINTS["site_trustworthiness"], {"host": host})
    except Exception as e:
        raise DemistoException(f"Failed to get site trustworthiness: {str(e)}")

    # Handle API errors
    if "error" in response:
        raise DemistoException(f'Error getting site trustworthiness for {host}: {response.get("error")}')

    response = map_fields(response, exclude_mappings=["name"])

    # Build outputs - following YML structure
    outputs = {}
    if response:
        response["host"] = host

        # Map security_checks domain age fields to domain_age structure for YML compatibility
        # The YML expects APIVoid.SiteTrust.domain_age.* fields
        security_checks = response.get("security_checks", {})
        if security_checks:
            # Create domain_age object from security_checks fields
            domain_age = {}
            if "domain_creation_date" in security_checks:
                domain_age["domain_creation_date"] = security_checks.get("domain_creation_date")
                domain_age["found"] = True
            if "domain_age_in_days" in security_checks:
                domain_age["domain_age_in_days"] = security_checks.get("domain_age_in_days")
            if "domain_age_in_months" in security_checks:
                domain_age["domain_age_in_months"] = security_checks.get("domain_age_in_months")
            if "domain_age_in_years" in security_checks:
                domain_age["domain_age_in_years"] = security_checks.get("domain_age_in_years")

            if domain_age:
                response["domain_age"] = domain_age

        outputs = response

        # Create simple table
        md = tableToMarkdown(f"APIVoid Site Trustworthiness for {host}:", response)
    else:
        md = f"## No information for {host}"

    return CommandResults(
        outputs_prefix="APIVoid.SiteTrust", outputs_key_field="host", outputs=outputs, readable_output=md, raw_response=response
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
        response = client.api_request(ENDPOINTS["ip_reputation"], {"ip": "8.8.8.8"})
        if "error" in response:
            return f'Test Failed: {response.get("error")}'
        return "ok"
    except Exception as e:
        return f"Test Failed: {str(e)}"


def main():
    """Main execution function"""

    # Get parameters once
    params = demisto.params()
    base_url = params.get("url", "https://api.apivoid.com")
    apikey = params.get("credentials", {}).get("password") or params.get("apikey", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("integrationReliability", "C - Fairly reliable")

    # Threshold configuration
    thresholds = {
        "suspicious": arg_to_number(params.get("suspicious", 30)),
        "bad": arg_to_number(params.get("bad", 60)),
    }

    demisto.debug(f"APIVoid: Initialized with base_url={base_url}, verify={verify}, proxy={proxy}, reliability={reliability}")
    demisto.debug(
        f'APIVoid: Thresholds configured - '
        f'suspicious={thresholds["suspicious"]}%, bad={thresholds["bad"]}%'
    )

    # Create client
    client = Client(base_url, apikey, verify, proxy)

    # Get command and args
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"APIVoid: Command being called is {command}")

    try:
        result: None | str | CommandResults | dict[str, Any] = None
        # Command routing
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command in ["ip", "apivoid-ip"]:
            reputation_only = command == "ip"
            result = ip_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command in ["domain", "apivoid-domain"]:
            reputation_only = command == "domain"
            result = domain_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command in ["url", "apivoid-url"]:
            reputation_only = command == "url"
            result = url_reputation_command(client, args, reputation_only, thresholds, reliability)
            return_results(result)

        elif command == "apivoid-dns-lookup":
            result = dns_lookup_command(client, args)
            return_results(result)

        elif command == "apivoid-ssl-info":
            result = ssl_info_command(client, args)
            return_results(result)

        elif command == "apivoid-email-verify":
            result = email_verify_command(client, args)
            return_results(result)

        elif command == "apivoid-parked-domain":
            result = parked_domain_command(client, args)
            return_results(result)

        elif command == "apivoid-domain-age":
            result = domain_age_command(client, args)
            return_results(result)

        elif command == "apivoid-url-to-image":
            result = screenshot_command(client, args)
            return_results(result)

        elif command == "apivoid-url-to-pdf":
            result = url_to_pdf_command(client, args)
            return_results(result)

        elif command == "apivoid-site-trustworthiness":
            result = site_trustworthiness_command(client, args)
            return_results(result)

        elif command in ["apivoid-threatlog", "apivoid-url-to-html"]:
            raise DemistoException(f"Command {command} is not supported in API V2")
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
