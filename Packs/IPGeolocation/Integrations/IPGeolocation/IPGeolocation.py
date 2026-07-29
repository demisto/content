"""Cortex XSOAR integration for the IPGeolocation.io v3 APIs.

Implements the following documented v3 endpoints only:
    * GET /v3/ipgeo    - IP Geolocation API (unified lookup)
    * GET /v3/security - IP Security API
    * GET /v3/abuse    - IP Abuse Contact API
    * GET /v3/asn      - ASN API

Every response field mapped by this module is documented at
https://ipgeolocation.io/documentation.html. No undocumented endpoint,
query parameter or response field is referenced.
"""

import ipaddress
import re
from collections.abc import Callable
from typing import Any

import requests

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

from CommonServerUserPython import *  # noqa: F401,F403

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INTEGRATION_NAME = "IPGeolocation.io"
DEFAULT_BASE_URL = "https://api.ipgeolocation.io"
DEFAULT_TIMEOUT = 30
MIN_TIMEOUT = 1
MAX_TIMEOUT = 300

ENDPOINT_IPGEO = "/v3/ipgeo"
ENDPOINT_SECURITY = "/v3/security"
ENDPOINT_ABUSE = "/v3/abuse"
ENDPOINT_ASN = "/v3/asn"

# IP used by test-module. Chosen because it is a stable, public, non-bogon address.
TEST_MODULE_IP = "8.8.8.8"

SCORE_MIN = 0
SCORE_MAX = 100
DEFAULT_MALICIOUS_THRESHOLD = 70
DEFAULT_SUSPICIOUS_THRESHOLD = 40

# Documented values for the `include` parameter of GET /v3/ipgeo.
IPGEO_INCLUDE_VALUES = {
    "*",
    "abuse",
    "dma_code",
    "geo_accuracy",
    "hostname",
    "hostnameFallbackLive",
    "liveHostname",
    "security",
    "user_agent",
}

# Documented values for the `include` parameter of GET /v3/asn.
ASN_INCLUDE_VALUES = {"downstreams", "peers", "routes", "upstreams", "whois_response"}

# Documented values for the `lang` parameter of GET /v3/ipgeo.
IPGEO_LANGUAGES = {"ar", "cn", "cs", "de", "en", "es", "fa", "fr", "it", "ja", "ko", "pt", "ru"}

ASN_ARGUMENT_PATTERN = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
# Conservative hostname/domain shape check (RFC 1123 labels, at least one dot).
DOMAIN_PATTERN = re.compile(r"^(?=.{4,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

# HTTP status codes documented by IPGeolocation.io, mapped to analyst-facing text.
# 403 is not part of the documented v3 error tables but is handled defensively
# because reverse proxies and origin restrictions can surface it.
HTTP_STATUS_MESSAGES: dict[int, str] = {
    400: (
        "Bad Request. The supplied IP address, domain name or ASN is invalid, or the request contained "
        "an unsupported character or an unsupported value for the lang parameter."
    ),
    401: (
        "Unauthorized. The API key is missing or invalid, the subscription is paused, expired or "
        "disabled, or the requested data requires a paid subscription. The security, abuse, "
        "geo_accuracy, dma_code, user_agent and hostname modules, domain lookups and non-English "
        "responses are not available on the Free plan."
    ),
    403: (
        "Forbidden. The request was rejected before it reached the API. Verify the server URL, any "
        "Request Origin restrictions configured for the API key, and outbound proxy rules."
    ),
    404: (
        "Not Found. The requested IP address, domain name or ASN does not exist in the "
        "IPGeolocation.io database, or the configured server URL points at a non-existent endpoint."
    ),
    405: "Method Not Allowed. The endpoint was called with an unsupported HTTP method.",
    413: "Content Too Large. The request payload exceeded the limit accepted by the API.",
    415: "Unsupported Media Type. The API rejected the Content-Type of the request.",
    423: (
        "Locked. The supplied IP address belongs to a bogon range or a private network, so "
        "IPGeolocation.io cannot return data for it."
    ),
    429: (
        "Too Many Requests. The subscription quota or surcharge limit has been reached, or the "
        "subscription status is past due, deleted or trial expired. Review the usage in the "
        "IPGeolocation.io billing dashboard before retrying."
    ),
    499: (
        "Client Closed Request. IPGeolocation.io closed the request because the configured timeout "
        "was too short. Increase the HTTP timeout in the integration configuration."
    ),
}

SERVER_ERROR_MESSAGE = (
    "IPGeolocation.io reported a server side error. This indicates a problem on the provider side. "
    "Retry the command and contact support@ipgeolocation.io if the error persists."
)


# ---------------------------------------------------------------------------
# Context key mappings
#
# Each mapping translates the documented snake_case API field names to stable
# PascalCase Cortex XSOAR context keys. Mapping values are either a destination
# key, or a (destination key, transform) tuple for nested structures.
# ---------------------------------------------------------------------------

MappingValue = Any
Mapping = dict[str, MappingValue]


def _sub(mapping: Mapping) -> Callable[[Any], Any]:
    """Build a transform that remaps a nested JSON object.

    :param mapping: Mapping applied to the nested object.
    :return: Callable that remaps a dictionary and passes any other type through.
    """

    def transform(value: Any) -> Any:
        return remap_keys(value, mapping) if isinstance(value, dict) else value

    return transform


def _sub_list(mapping: Mapping) -> Callable[[Any], Any]:
    """Build a transform that remaps every object of a nested JSON array.

    :param mapping: Mapping applied to each array item.
    :return: Callable that remaps a list of dictionaries and passes any other type through.
    """

    def transform(value: Any) -> Any:
        if not isinstance(value, list):
            return value
        return [remap_keys(item, mapping) if isinstance(item, dict) else item for item in value]

    return transform


LOCATION_MAPPING: Mapping = {
    "continent_code": "ContinentCode",
    "continent_name": "ContinentName",
    "country_code2": "CountryCode2",
    "country_code3": "CountryCode3",
    "country_name": "CountryName",
    "country_name_official": "CountryNameOfficial",
    "country_capital": "CountryCapital",
    "state_prov": "StateProv",
    "state_code": "StateCode",
    "district": "District",
    "city": "City",
    "locality": "Locality",
    "accuracy_radius": "AccuracyRadius",
    "confidence": "Confidence",
    "dma_code": "DMACode",
    "zipcode": "Zipcode",
    "latitude": "Latitude",
    "longitude": "Longitude",
    "is_eu": "IsEU",
    "country_flag": "CountryFlag",
    "geoname_id": "GeonameID",
    "country_emoji": "CountryEmoji",
}

COUNTRY_METADATA_MAPPING: Mapping = {
    "calling_code": "CallingCode",
    "tld": "TLD",
    "languages": "Languages",
}

CURRENCY_MAPPING: Mapping = {
    "code": "Code",
    "name": "Name",
    "symbol": "Symbol",
}

NETWORK_MAPPING: Mapping = {
    "connection_type": "ConnectionType",
    "route": "Route",
    "is_anycast": "IsAnycast",
}

COMPANY_MAPPING: Mapping = {
    "name": "Name",
    "type": "Type",
    "domain": "Domain",
}

ASN_RELATION_MAPPING: Mapping = {
    "as_number": "ASNumber",
    "description": "Description",
    "country": "Country",
}

ASN_MAPPING: Mapping = {
    "as_number": "ASNumber",
    "organization": "Organization",
    "country": "Country",
    "type": "Type",
    "domain": "Domain",
    "date_allocated": "DateAllocated",
    "rir": "RIR",
    "asn_name": "ASNName",
    "allocation_status": "AllocationStatus",
    "num_of_ipv4_routes": "NumOfIPv4Routes",
    "num_of_ipv6_routes": "NumOfIPv6Routes",
    "routes": "Routes",
    "peers": ("Peers", _sub_list(ASN_RELATION_MAPPING)),
    "upstreams": ("Upstreams", _sub_list(ASN_RELATION_MAPPING)),
    "downstreams": ("Downstreams", _sub_list(ASN_RELATION_MAPPING)),
    "whois_response": "WhoisResponse",
}

DST_TRANSITION_MAPPING: Mapping = {
    "utc_time": "UTCTime",
    "duration": "Duration",
    "gap": "Gap",
    "date_time_after": "DateTimeAfter",
    "date_time_before": "DateTimeBefore",
    "overlap": "Overlap",
}

TIME_ZONE_MAPPING: Mapping = {
    "name": "Name",
    "offset": "Offset",
    "offset_with_dst": "OffsetWithDST",
    "current_time": "CurrentTime",
    "current_time_unix": "CurrentTimeUnix",
    "current_tz_abbreviation": "CurrentTZAbbreviation",
    "current_tz_full_name": "CurrentTZFullName",
    "standard_tz_abbreviation": "StandardTZAbbreviation",
    "standard_tz_full_name": "StandardTZFullName",
    "is_dst": "IsDST",
    "dst_savings": "DSTSavings",
    "dst_exists": "DSTExists",
    "dst_tz_abbreviation": "DSTTZAbbreviation",
    "dst_tz_full_name": "DSTTZFullName",
    "dst_start": ("DSTStart", _sub(DST_TRANSITION_MAPPING)),
    "dst_end": ("DSTEnd", _sub(DST_TRANSITION_MAPPING)),
}

SECURITY_MAPPING: Mapping = {
    "threat_score": "ThreatScore",
    "is_tor": "IsTor",
    "is_proxy": "IsProxy",
    "proxy_provider_names": "ProxyProviderNames",
    "proxy_confidence_score": "ProxyConfidenceScore",
    "proxy_last_seen": "ProxyLastSeen",
    "is_residential_proxy": "IsResidentialProxy",
    "is_vpn": "IsVPN",
    "vpn_provider_names": "VPNProviderNames",
    "vpn_confidence_score": "VPNConfidenceScore",
    "vpn_last_seen": "VPNLastSeen",
    "is_relay": "IsRelay",
    "relay_provider_name": "RelayProviderName",
    "is_anonymous": "IsAnonymous",
    "is_known_attacker": "IsKnownAttacker",
    "is_bot": "IsBot",
    "is_spam": "IsSpam",
    "is_cloud_provider": "IsCloudProvider",
    "cloud_provider_name": "CloudProviderName",
}

ABUSE_MAPPING: Mapping = {
    "route": "Route",
    "country": "Country",
    "name": "Name",
    "organization": "Organization",
    "kind": "Kind",
    "address": "Address",
    "emails": "Emails",
    "phone_numbers": "PhoneNumbers",
}

USER_AGENT_DEVICE_MAPPING: Mapping = {
    "name": "Name",
    "type": "Type",
    "brand": "Brand",
    "cpu": "CPU",
}

USER_AGENT_ENGINE_MAPPING: Mapping = {
    "name": "Name",
    "type": "Type",
    "version": "Version",
    "version_major": "VersionMajor",
}

USER_AGENT_OS_MAPPING: Mapping = {
    "name": "Name",
    "type": "Type",
    "version": "Version",
    "version_major": "VersionMajor",
    "build": "Build",
}

USER_AGENT_MAPPING: Mapping = {
    "user_agent_string": "UserAgentString",
    "name": "Name",
    "type": "Type",
    "version": "Version",
    "version_major": "VersionMajor",
    "device": ("Device", _sub(USER_AGENT_DEVICE_MAPPING)),
    "engine": ("Engine", _sub(USER_AGENT_ENGINE_MAPPING)),
    "operating_system": ("OperatingSystem", _sub(USER_AGENT_OS_MAPPING)),
}

IPGEO_MAPPING: Mapping = {
    "ip": "IP",
    "domain": "Domain",
    "hostname": "Hostname",
    "location": ("Location", _sub(LOCATION_MAPPING)),
    "country_metadata": ("CountryMetadata", _sub(COUNTRY_METADATA_MAPPING)),
    "currency": ("Currency", _sub(CURRENCY_MAPPING)),
    "network": ("Network", _sub(NETWORK_MAPPING)),
    "asn": ("ASN", _sub(ASN_MAPPING)),
    "company": ("Company", _sub(COMPANY_MAPPING)),
    "time_zone": ("TimeZone", _sub(TIME_ZONE_MAPPING)),
    "security": ("Security", _sub(SECURITY_MAPPING)),
    "abuse": ("Abuse", _sub(ABUSE_MAPPING)),
    "user_agent": ("UserAgent", _sub(USER_AGENT_MAPPING)),
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def remap_keys(source: dict[str, Any], mapping: Mapping) -> dict[str, Any]:
    """Translate documented API field names into Cortex XSOAR context keys.

    Keys that are absent from the API response are omitted rather than set to
    ``None``, so the resulting context reflects exactly what the API returned.

    :param source: Raw API object.
    :param mapping: Mapping of API field name to context key or (context key, transform).
    :return: Remapped dictionary.
    """
    remapped: dict[str, Any] = {}
    for api_key, target in mapping.items():
        if api_key not in source:
            continue
        value = source[api_key]
        if isinstance(target, tuple):
            context_key, transform = target
            value = transform(value)
        else:
            context_key = target
        remapped[context_key] = value
    return remapped


def prune_empty(value: Any) -> Any:
    """Recursively drop ``None``, empty strings, lists and dictionaries.

    Boolean ``False`` and numeric ``0`` are preserved because the IP Security API
    relies on them to express negative detections and zero confidence scores.

    :param value: Value to clean.
    :return: Cleaned value.
    """
    if isinstance(value, dict):
        cleaned_dict = {key: prune_empty(item) for key, item in value.items()}
        return {key: item for key, item in cleaned_dict.items() if not _is_empty(item)}
    if isinstance(value, list):
        cleaned_list = [prune_empty(item) for item in value]
        return [item for item in cleaned_list if not _is_empty(item)]
    return value


def _is_empty(value: Any) -> bool:
    """Report whether a value carries no information.

    :param value: Value to inspect.
    :return: ``True`` for ``None``, empty string, empty list and empty dictionary.
    """
    if value is None:
        return True
    if isinstance(value, (str, list, dict, tuple)):
        return len(value) == 0
    return False


def yes_no(value: Any) -> str:
    """Render a boolean detection flag for a human readable table.

    :param value: Value returned by the API.
    :return: ``yes``, ``no`` or ``n/a``.
    """
    if value is None:
        return "n/a"
    return "yes" if value else "no"


def join_values(value: Any) -> str:
    """Render a list of strings as a comma separated value.

    :param value: Value returned by the API.
    :return: Comma separated representation, or the stringified value.
    """
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return "" if value is None else str(value)


def validate_ip(ip: str) -> str:
    """Validate that an argument is a public IPv4 or IPv6 address.

    :param ip: Raw argument value.
    :return: The trimmed IP address.
    :raises DemistoException: If the value is not a valid IP address.
    """
    candidate = (ip or "").strip()
    if not candidate:
        raise DemistoException('The "ip" argument must not be empty.')
    if not is_ip_valid(candidate, accept_v6_ips=True):
        raise DemistoException(f'"{candidate}" is not a valid IPv4 or IPv6 address.')
    return candidate


def validate_ip_or_domain(value: str) -> str:
    """Validate an argument accepted by GET /v3/ipgeo, which supports domains.

    :param value: Raw argument value.
    :return: The trimmed IP address or domain name.
    :raises DemistoException: If the value is neither an IP address nor a domain name.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise DemistoException('The "ip" argument must not be empty.')
    if is_ip_valid(candidate, accept_v6_ips=True) or DOMAIN_PATTERN.match(candidate):
        return candidate
    raise DemistoException(f'"{candidate}" is not a valid IPv4 address, IPv6 address or domain name.')


def is_private_ip(ip: str) -> bool:
    """Report whether an IP address is private, loopback, link local or reserved.

    IPGeolocation.io answers such addresses with HTTP 423, so the check saves a
    round trip and an unhelpful error for the analyst.

    :param ip: IP address to inspect.
    :return: ``True`` when the address is not globally routable.
    """
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def normalize_asn(asn: str) -> str:
    """Normalize an ASN argument to the digits expected by GET /v3/asn.

    Both ``AS24940`` and ``24940`` are accepted from the analyst.

    :param asn: Raw argument value.
    :return: ASN as a numeric string.
    :raises DemistoException: If the value is not a valid ASN.
    """
    candidate = (asn or "").strip()
    match = ASN_ARGUMENT_PATTERN.match(candidate)
    if not match:
        raise DemistoException(f'"{candidate}" is not a valid ASN. Supply a number such as 24940 or AS24940.')
    return match.group(1)


def validate_choices(values: list[str], allowed: set[str], argument_name: str) -> str | None:
    """Validate a comma separated argument against the documented values.

    :param values: Parsed argument values.
    :param allowed: Documented values for the argument.
    :param argument_name: Argument name, used in the error message.
    :return: Comma separated value to send to the API, or ``None`` when empty.
    :raises DemistoException: If any value is not documented.
    """
    if not values:
        return None
    unsupported = [value for value in values if value not in allowed]
    if unsupported:
        raise DemistoException(
            f'Unsupported value(s) {", ".join(sorted(unsupported))} for the "{argument_name}" argument. '
            f'Supported values are: {", ".join(sorted(allowed))}.'
        )
    return ",".join(values)


def to_int(value: Any, name: str) -> int | None:
    """Coerce a configuration value to an integer, raising a Cortex XSOAR error.

    ``arg_to_number`` raises ``ValueError`` for non numeric input, which would
    reach the analyst as an unhelpful stack trace.

    :param value: Value to coerce.
    :param name: Parameter name, used in the error message.
    :return: Integer value, or ``None`` when the value is empty.
    :raises DemistoException: If the value is not numeric.
    """
    try:
        return arg_to_number(value, arg_name=name, required=True)
    except ValueError as exception:
        raise DemistoException(f'"{name}" must be a whole number. Received "{value}".') from exception


def validate_threshold(value: Any, name: str, default: int) -> int:
    """Validate a threat score threshold taken from the integration configuration.

    :param value: Configured value.
    :param name: Parameter name, used in the error message.
    :param default: Value applied when the parameter is not configured.
    :return: Validated threshold.
    :raises DemistoException: If the value is not an integer between 0 and 100.
    """
    if value in (None, ""):
        return default
    threshold = to_int(value, name)
    if threshold is None or not SCORE_MIN <= threshold <= SCORE_MAX:
        raise DemistoException(f'"{name}" must be an integer between {SCORE_MIN} and {SCORE_MAX}.')
    return threshold


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


def extract_api_message(response: Any) -> str:
    """Extract the descriptive ``message`` field returned by failing requests.

    :param response: ``requests.Response`` object.
    :return: Provider supplied message, or an empty string.
    """
    try:
        payload = response.json()
    except (ValueError, AttributeError):
        return ""
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, str):
            return message.strip()
    return ""


def http_error_handler(response: Any) -> None:
    """Convert an unsuccessful HTTP response into a meaningful Cortex XSOAR error.

    :param response: ``requests.Response`` object.
    :raises DemistoException: Always.
    """
    status_code = response.status_code
    if status_code in HTTP_STATUS_MESSAGES:
        description = HTTP_STATUS_MESSAGES[status_code]
    elif status_code >= 500:
        description = SERVER_ERROR_MESSAGE
    else:
        description = "The request to IPGeolocation.io failed."

    api_message = extract_api_message(response)
    error = f"{INTEGRATION_NAME} request failed [HTTP {status_code}]. {description}"
    if api_message:
        error = f"{error} API message: {api_message}"
    raise DemistoException(error, res=response)


class Client(BaseClient):
    """HTTP client for the IPGeolocation.io v3 APIs."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        verify: bool = True,
        proxy: bool = False,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        """Initialize the client.

        :param base_url: API base URL, without the version path.
        :param api_key: IPGeolocation.io API key.
        :param verify: Whether to verify the TLS certificate.
        :param proxy: Whether to use the system proxy settings.
        :param timeout: Per request timeout, in seconds.
        """
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy)
        self._api_key = api_key
        self._timeout = timeout

    def _request(self, url_suffix: str, params: dict[str, Any]) -> dict[str, Any]:
        """Perform an authenticated GET request and return the decoded payload.

        The API key is sent as the documented ``apiKey`` query parameter. Cortex
        XSOAR masks configured credentials in logs, so the key is never written
        out by this integration.

        :param url_suffix: Endpoint path.
        :param params: Query parameters, excluding the API key.
        :return: Decoded JSON object.
        :raises DemistoException: On HTTP, transport or payload errors.
        """
        query: dict[str, Any] = {"apiKey": self._api_key}
        query.update({key: value for key, value in params.items() if value not in (None, "")})

        try:
            response = self._http_request(
                method="GET",
                url_suffix=url_suffix,
                params=query,
                timeout=self._timeout,
                resp_type="response",
                error_handler=http_error_handler,
            )
        except requests.exceptions.Timeout as exception:
            # BaseClient converts connect timeouts on its own. A read timeout
            # reaches this point and is reported with the actionable setting.
            raise DemistoException(
                f"The request to {INTEGRATION_NAME} timed out after {self._timeout} seconds. "
                f"Increase the HTTP timeout in the integration configuration or check network latency."
            ) from exception
        return self._decode(response, url_suffix)

    @staticmethod
    def _decode(response: Any, url_suffix: str) -> dict[str, Any]:
        """Decode a successful response and reject unusable payloads.

        :param response: ``requests.Response`` object.
        :param url_suffix: Endpoint path, used in error messages.
        :return: Decoded JSON object.
        :raises DemistoException: If the body is empty, not JSON, or not an object.
        """
        body = response.text or ""
        if not body.strip():
            raise DemistoException(
                f"{INTEGRATION_NAME} returned an empty response for {url_suffix}. "
                f"Retry the command and contact IPGeolocation.io support if the response stays empty."
            )
        try:
            payload = response.json()
        except ValueError:
            raise DemistoException(
                f"{INTEGRATION_NAME} returned a response for {url_suffix} that is not valid JSON. "
                f"Verify that the server URL points at the IPGeolocation.io API and that no proxy is "
                f"rewriting the response."
            )
        if not isinstance(payload, dict):
            raise DemistoException(
                f"{INTEGRATION_NAME} returned an unexpected JSON structure for {url_suffix}. "
                f"A JSON object was expected but {type(payload).__name__} was received."
            )
        if set(payload) == {"message"}:
            raise DemistoException(f"{INTEGRATION_NAME} could not process the request: {payload['message']}")
        return payload

    def get_ip_geolocation(
        self,
        ip: str,
        include: str | None = None,
        fields: str | None = None,
        excludes: str | None = None,
        lang: str | None = None,
    ) -> dict[str, Any]:
        """Call GET /v3/ipgeo.

        :param ip: IPv4 address, IPv6 address or domain name.
        :param include: Comma separated optional modules.
        :param fields: Comma separated response fields to return.
        :param excludes: Comma separated response fields to omit.
        :param lang: Response language code.
        :return: Decoded JSON object.
        """
        return self._request(
            ENDPOINT_IPGEO,
            {"ip": ip, "include": include, "fields": fields, "excludes": excludes, "lang": lang},
        )

    def get_ip_security(
        self,
        ip: str,
        fields: str | None = None,
        excludes: str | None = None,
    ) -> dict[str, Any]:
        """Call GET /v3/security.

        :param ip: IPv4 or IPv6 address.
        :param fields: Comma separated response fields to return.
        :param excludes: Comma separated response fields to omit.
        :return: Decoded JSON object.
        """
        return self._request(ENDPOINT_SECURITY, {"ip": ip, "fields": fields, "excludes": excludes})

    def get_abuse_contact(
        self,
        ip: str,
        fields: str | None = None,
        excludes: str | None = None,
    ) -> dict[str, Any]:
        """Call GET /v3/abuse.

        :param ip: IPv4 or IPv6 address.
        :param fields: Comma separated response fields to return.
        :param excludes: Comma separated response fields to omit.
        :return: Decoded JSON object.
        """
        return self._request(ENDPOINT_ABUSE, {"ip": ip, "fields": fields, "excludes": excludes})

    def get_asn(
        self,
        ip: str | None = None,
        asn: str | None = None,
        include: str | None = None,
        fields: str | None = None,
        excludes: str | None = None,
    ) -> dict[str, Any]:
        """Call GET /v3/asn.

        :param ip: IPv4 or IPv6 address to resolve to an ASN.
        :param asn: ASN to look up, as digits.
        :param include: Comma separated optional objects.
        :param fields: Comma separated response fields to return.
        :param excludes: Comma separated response fields to omit.
        :return: Decoded JSON object.
        """
        return self._request(
            ENDPOINT_ASN,
            {"ip": ip, "asn": asn, "include": include, "fields": fields, "excludes": excludes},
        )


# ---------------------------------------------------------------------------
# Reputation scoring
# ---------------------------------------------------------------------------


class ReputationConfig:
    """Configuration that drives the DBotScore of the ``ip`` command."""

    def __init__(self, params: dict[str, Any]) -> None:
        """Read and validate the reputation settings.

        :param params: Integration configuration parameters.
        :raises DemistoException: If the configured thresholds are inconsistent.
        """
        self.malicious_threshold = validate_threshold(
            params.get("malicious_threshold"), "Malicious threat score threshold", DEFAULT_MALICIOUS_THRESHOLD
        )
        self.suspicious_threshold = validate_threshold(
            params.get("suspicious_threshold"), "Suspicious threat score threshold", DEFAULT_SUSPICIOUS_THRESHOLD
        )
        if self.suspicious_threshold > self.malicious_threshold:
            raise DemistoException(
                "The suspicious threat score threshold must be lower than or equal to the malicious "
                "threat score threshold."
            )
        self.malicious_on_known_attacker = argToBoolean(params.get("malicious_on_known_attacker", True))
        self.suspicious_on_anonymizer = argToBoolean(params.get("suspicious_on_anonymizer", True))
        self.suspicious_on_bot_or_spam = argToBoolean(params.get("suspicious_on_bot_or_spam", True))
        self.reliability = params.get("integrationReliability") or DBotScoreReliability.B


def score_security(security: dict[str, Any] | None, config: ReputationConfig) -> tuple[int, str]:
    """Derive a DBotScore from the IP Security API signals.

    :param security: ``security`` object returned by the API, if present.
    :param config: Reputation configuration.
    :return: Tuple of DBotScore and a human readable justification.
    """
    if not security:
        return (
            Common.DBotScore.NONE,
            "No security data was returned for this IP address. IP Security data requires a paid "
            "IPGeolocation.io subscription, so no reputation could be determined.",
        )

    threat_score = arg_to_number(security.get("threat_score"))
    malicious_reasons: list[str] = []
    suspicious_reasons: list[str] = []

    if threat_score is not None and threat_score >= config.malicious_threshold:
        malicious_reasons.append(
            f"threat score {threat_score} is at or above the malicious threshold {config.malicious_threshold}"
        )
    elif threat_score is not None and threat_score >= config.suspicious_threshold:
        suspicious_reasons.append(
            f"threat score {threat_score} is at or above the suspicious threshold {config.suspicious_threshold}"
        )

    if config.malicious_on_known_attacker and security.get("is_known_attacker"):
        malicious_reasons.append("the IP address is flagged as a known attacker")

    if config.suspicious_on_bot_or_spam:
        if security.get("is_bot"):
            suspicious_reasons.append("the IP address is associated with bot activity")
        if security.get("is_spam"):
            suspicious_reasons.append("the IP address is associated with spam activity")

    if config.suspicious_on_anonymizer:
        anonymizers = [
            ("is_tor", "a Tor exit node"),
            ("is_vpn", "a VPN network"),
            ("is_proxy", "a proxy network"),
            ("is_residential_proxy", "a residential proxy network"),
            ("is_relay", "a relay network"),
        ]
        detected = [label for flag, label in anonymizers if security.get(flag)]
        if detected:
            suspicious_reasons.append(f'the IP address is associated with {", ".join(detected)}')

    if malicious_reasons:
        return Common.DBotScore.BAD, f'Assessed as malicious because {"; ".join(malicious_reasons)}.'
    if suspicious_reasons:
        return Common.DBotScore.SUSPICIOUS, f'Assessed as suspicious because {"; ".join(suspicious_reasons)}.'

    detail = f" The reported threat score is {threat_score}." if threat_score is not None else ""
    return Common.DBotScore.GOOD, f"No adverse security signals were reported for this IP address.{detail}"


# ---------------------------------------------------------------------------
# Human readable output builders
# ---------------------------------------------------------------------------


def build_overview_table(raw: dict[str, Any]) -> str:
    """Build the summary table of a GET /v3/ipgeo result.

    :param raw: Raw API response.
    :return: Markdown table.
    """
    location = raw.get("location") or {}
    asn = raw.get("asn") or {}
    company = raw.get("company") or {}
    network = raw.get("network") or {}
    time_zone = raw.get("time_zone") or {}

    row = {
        "IP Address": raw.get("ip"),
        "Domain": raw.get("domain"),
        "Hostname": raw.get("hostname"),
        "City": location.get("city"),
        "State / Province": location.get("state_prov"),
        "Country": location.get("country_name"),
        "Country Code": location.get("country_code2"),
        "Continent": location.get("continent_name"),
        "Postal Code": location.get("zipcode"),
        "Latitude": location.get("latitude"),
        "Longitude": location.get("longitude"),
        "Accuracy Radius (km)": location.get("accuracy_radius"),
        "Location Confidence": location.get("confidence"),
        "Time Zone": time_zone.get("name"),
        "Local Time": time_zone.get("current_time"),
        "ASN": asn.get("as_number"),
        "AS Organization": asn.get("organization"),
        "AS Type": asn.get("type"),
        "Company": company.get("name"),
        "Route": network.get("route"),
        "Connection Type": network.get("connection_type"),
        "Anycast": yes_no(network.get("is_anycast")) if "is_anycast" in network else None,
    }
    row = {key: value for key, value in row.items() if not _is_empty(value)}
    title = f'IPGeolocation.io IP Geolocation for {raw.get("ip") or "the requested address"}'
    return tableToMarkdown(title, row, headers=list(row), sort_headers=False)


def build_security_table(ip: str | None, security: dict[str, Any]) -> str:
    """Build the security signals table.

    :param ip: IP address the signals belong to.
    :param security: ``security`` object returned by the API.
    :return: Markdown table.
    """
    row = {
        "IP Address": ip,
        "Threat Score": security.get("threat_score"),
        "Anonymous": yes_no(security.get("is_anonymous")),
        "Known Attacker": yes_no(security.get("is_known_attacker")),
        "Tor Exit Node": yes_no(security.get("is_tor")),
        "VPN": yes_no(security.get("is_vpn")),
        "VPN Providers": join_values(security.get("vpn_provider_names")),
        "VPN Confidence": security.get("vpn_confidence_score"),
        "VPN Last Seen": security.get("vpn_last_seen"),
        "Proxy": yes_no(security.get("is_proxy")),
        "Proxy Providers": join_values(security.get("proxy_provider_names")),
        "Proxy Confidence": security.get("proxy_confidence_score"),
        "Proxy Last Seen": security.get("proxy_last_seen"),
        "Residential Proxy": yes_no(security.get("is_residential_proxy")),
        "Relay": yes_no(security.get("is_relay")),
        "Relay Provider": security.get("relay_provider_name"),
        "Bot": yes_no(security.get("is_bot")),
        "Spam": yes_no(security.get("is_spam")),
        "Cloud Provider": yes_no(security.get("is_cloud_provider")),
        "Cloud Provider Name": security.get("cloud_provider_name"),
    }
    row = {key: value for key, value in row.items() if not _is_empty(value)}
    title = f'IPGeolocation.io IP Security for {ip or "the requested address"}'
    return tableToMarkdown(title, row, headers=list(row), sort_headers=False)


def build_abuse_table(ip: str | None, abuse: dict[str, Any]) -> str:
    """Build the abuse contact table.

    :param ip: IP address the contact belongs to.
    :param abuse: ``abuse`` object returned by the API.
    :return: Markdown table.
    """
    row = {
        "IP Address": ip,
        "Abuse Contact Name": abuse.get("name"),
        "Organization": abuse.get("organization"),
        "Contact Type": abuse.get("kind"),
        "Emails": join_values(abuse.get("emails")),
        "Phone Numbers": join_values(abuse.get("phone_numbers")),
        "Route": abuse.get("route"),
        "Country": abuse.get("country"),
        "Registered Address": (abuse.get("address") or "").replace("\n", ", ") or None,
    }
    row = {key: value for key, value in row.items() if not _is_empty(value)}
    title = f'IPGeolocation.io Abuse Contact for {ip or "the requested address"}'
    return tableToMarkdown(title, row, headers=list(row), sort_headers=False)


def build_user_agent_table(user_agent: dict[str, Any]) -> str:
    """Build the parsed user agent table.

    :param user_agent: ``user_agent`` object returned by the API.
    :return: Markdown table.
    """
    device = user_agent.get("device") or {}
    engine = user_agent.get("engine") or {}
    operating_system = user_agent.get("operating_system") or {}
    row = {
        "User Agent": user_agent.get("user_agent_string"),
        "Name": user_agent.get("name"),
        "Type": user_agent.get("type"),
        "Version": user_agent.get("version"),
        "Device": device.get("name"),
        "Device Type": device.get("type"),
        "Device Brand": device.get("brand"),
        "Engine": engine.get("name"),
        "Engine Version": engine.get("version"),
        "Operating System": operating_system.get("name"),
        "OS Version": operating_system.get("version"),
    }
    row = {key: value for key, value in row.items() if not _is_empty(value)}
    return tableToMarkdown("Parsed User Agent", row, headers=list(row), sort_headers=False)


def build_asn_output(raw: dict[str, Any]) -> str:
    """Build the human readable output of a GET /v3/asn result.

    :param raw: Raw API response.
    :return: Markdown tables.
    """
    asn = raw.get("asn") or {}
    row = {
        "IP Address": raw.get("ip"),
        "ASN": asn.get("as_number"),
        "AS Name": asn.get("asn_name"),
        "Organization": asn.get("organization"),
        "Type": asn.get("type"),
        "Domain": asn.get("domain"),
        "Country": asn.get("country"),
        "RIR": asn.get("rir"),
        "Date Allocated": asn.get("date_allocated"),
        "Allocation Status": asn.get("allocation_status"),
        "IPv4 Routes": asn.get("num_of_ipv4_routes"),
        "IPv6 Routes": asn.get("num_of_ipv6_routes"),
    }
    row = {key: value for key, value in row.items() if not _is_empty(value)}
    identifier = asn.get("as_number") or raw.get("ip") or "the requested ASN"
    sections = [tableToMarkdown(f"IPGeolocation.io ASN Details for {identifier}", row, headers=list(row), sort_headers=False)]

    relation_titles = {"peers": "Peers", "upstreams": "Upstreams", "downstreams": "Downstreams"}
    for key, title in relation_titles.items():
        relations = asn.get(key)
        if not relations:
            continue
        rows = [
            {
                "ASN": item.get("as_number"),
                "Description": item.get("description"),
                "Country": item.get("country"),
            }
            for item in relations
            if isinstance(item, dict)
        ]
        sections.append(tableToMarkdown(title, rows, headers=["ASN", "Description", "Country"], sort_headers=False))

    routes = asn.get("routes")
    if routes:
        rows = [{"Prefix": route} for route in routes]
        sections.append(tableToMarkdown("Announced Routes", rows, headers=["Prefix"], sort_headers=False))

    whois_response = asn.get("whois_response")
    if whois_response:
        sections.append(f"### WHOIS Record\n```\n{whois_response.strip()}\n```")

    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Indicator builders
# ---------------------------------------------------------------------------


def build_ip_indicator(raw: dict[str, Any], dbot_score: Common.DBotScore) -> Common.IP:
    """Build a standard IP indicator from a GET /v3/ipgeo or GET /v3/security result.

    :param raw: Raw API response.
    :param dbot_score: Reputation attached to the indicator.
    :return: Standard IP indicator.
    """
    location = raw.get("location") or {}
    asn = raw.get("asn") or {}
    company = raw.get("company") or {}
    security = raw.get("security") or {}
    abuse = raw.get("abuse") or {}

    tags = [label for flag, label in (
        ("is_tor", "tor"),
        ("is_vpn", "vpn"),
        ("is_proxy", "proxy"),
        ("is_residential_proxy", "residential-proxy"),
        ("is_relay", "relay"),
        ("is_bot", "bot"),
        ("is_spam", "spam"),
        ("is_known_attacker", "known-attacker"),
        ("is_cloud_provider", "cloud-provider"),
    ) if security.get(flag)]

    geo_description_parts = [
        part for part in (location.get("city"), location.get("state_prov"), location.get("country_name")) if part
    ]

    return Common.IP(
        ip=raw.get("ip"),
        dbot_score=dbot_score,
        asn=asn.get("as_number"),
        as_owner=asn.get("organization"),
        hostname=raw.get("hostname") or None,
        geo_country=location.get("country_code2") or None,
        geo_latitude=location.get("latitude") or None,
        geo_longitude=location.get("longitude") or None,
        geo_description=", ".join(geo_description_parts) or None,
        region=location.get("state_prov") or None,
        organization_name=company.get("name") or None,
        organization_type=company.get("type") or None,
        registrar_abuse_name=abuse.get("name") or None,
        registrar_abuse_address=abuse.get("address") or None,
        registrar_abuse_country=abuse.get("country") or None,
        registrar_abuse_network=abuse.get("route") or None,
        registrar_abuse_email=join_values(abuse.get("emails")) or None,
        registrar_abuse_phone=join_values(abuse.get("phone_numbers")) or None,
        tags=tags or None,
    )


def build_dbot_score(ip: str, score: int, reliability: str, message: str) -> Common.DBotScore:
    """Build a DBotScore for an IP indicator.

    :param ip: Indicator value.
    :param score: DBotScore value.
    :param reliability: Configured source reliability.
    :param message: Justification for the score.
    :return: DBotScore object.
    """
    return Common.DBotScore(
        indicator=ip,
        indicator_type=DBotScoreType.IP,
        integration_name=INTEGRATION_NAME,
        score=score,
        reliability=reliability,
        malicious_description=message if score == Common.DBotScore.BAD else None,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def run_test_module(client: Client) -> str:
    """Verify connectivity and authentication with a single documented lookup.

    :param client: Configured client.
    :return: ``ok`` when the credentials are valid.
    """
    client.get_ip_geolocation(ip=TEST_MODULE_IP)
    return "ok"


def ip_lookup_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Run ``ipgeolocation-ip-lookup`` against GET /v3/ipgeo.

    :param client: Configured client.
    :param args: Command arguments.
    :return: One CommandResults per requested address.
    """
    targets = argToList(args.get("ip"))
    if not targets:
        raise DemistoException('The "ip" argument is required.')

    include = validate_choices(argToList(args.get("include")), IPGEO_INCLUDE_VALUES, "include")
    lang = validate_choices(argToList(args.get("lang")), IPGEO_LANGUAGES, "lang")
    fields = ",".join(argToList(args.get("fields"))) or None
    excludes = ",".join(argToList(args.get("excludes"))) or None

    results: list[CommandResults] = []
    for target in targets:
        validated = validate_ip_or_domain(target)
        try:
            raw = client.get_ip_geolocation(
                ip=validated, include=include, fields=fields, excludes=excludes, lang=lang
            )
        except DemistoException as error:
            results.append(build_failure_entry(validated, error))
            continue

        readable = build_overview_table(raw)
        if raw.get("security"):
            readable = f'{readable}\n{build_security_table(raw.get("ip"), raw["security"])}'
        if raw.get("abuse"):
            readable = f'{readable}\n{build_abuse_table(raw.get("ip"), raw["abuse"])}'
        if raw.get("user_agent"):
            readable = f'{readable}\n{build_user_agent_table(raw["user_agent"])}'

        results.append(
            CommandResults(
                outputs_prefix="IPGeolocation.IP",
                outputs_key_field="IP",
                outputs=prune_empty(remap_keys(raw, IPGEO_MAPPING)),
                readable_output=readable,
                raw_response=raw,
            )
        )
    return results


def ip_security_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Run ``ipgeolocation-ip-security`` against GET /v3/security.

    :param client: Configured client.
    :param args: Command arguments.
    :return: One CommandResults per requested address.
    """
    targets = argToList(args.get("ip"))
    if not targets:
        raise DemistoException('The "ip" argument is required.')

    fields = ",".join(argToList(args.get("fields"))) or None
    excludes = ",".join(argToList(args.get("excludes"))) or None

    results: list[CommandResults] = []
    for target in targets:
        validated = validate_ip(target)
        try:
            raw = client.get_ip_security(ip=validated, fields=fields, excludes=excludes)
        except DemistoException as error:
            results.append(build_failure_entry(validated, error))
            continue

        results.append(
            CommandResults(
                outputs_prefix="IPGeolocation.IP",
                outputs_key_field="IP",
                outputs=prune_empty(remap_keys(raw, IPGEO_MAPPING)),
                readable_output=build_security_table(raw.get("ip"), raw.get("security") or {}),
                raw_response=raw,
            )
        )
    return results


def abuse_contact_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Run ``ipgeolocation-abuse-contact`` against GET /v3/abuse.

    :param client: Configured client.
    :param args: Command arguments.
    :return: One CommandResults per requested address.
    """
    targets = argToList(args.get("ip"))
    if not targets:
        raise DemistoException('The "ip" argument is required.')

    fields = ",".join(argToList(args.get("fields"))) or None
    excludes = ",".join(argToList(args.get("excludes"))) or None
    reliability = demisto.params().get("integrationReliability") or DBotScoreReliability.B

    results: list[CommandResults] = []
    for target in targets:
        validated = validate_ip(target)
        try:
            raw = client.get_abuse_contact(ip=validated, fields=fields, excludes=excludes)
        except DemistoException as error:
            results.append(build_failure_entry(validated, error))
            continue

        # An abuse contact lookup carries no verdict, so the indicator is
        # published with an unknown reputation and the registrar abuse fields.
        dbot_score = build_dbot_score(
            raw.get("ip") or validated,
            Common.DBotScore.NONE,
            reliability,
            "Abuse contact enrichment does not produce a reputation verdict.",
        )
        results.append(
            CommandResults(
                outputs_prefix="IPGeolocation.IP",
                outputs_key_field="IP",
                outputs=prune_empty(remap_keys(raw, IPGEO_MAPPING)),
                readable_output=build_abuse_table(raw.get("ip"), raw.get("abuse") or {}),
                raw_response=raw,
                indicator=build_ip_indicator(raw, dbot_score),
            )
        )
    return results


def asn_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    """Run ``ipgeolocation-asn`` against GET /v3/asn.

    :param client: Configured client.
    :param args: Command arguments.
    :return: One CommandResults per requested ASN or address.
    """
    ip_targets = argToList(args.get("ip"))
    asn_targets = argToList(args.get("asn"))
    if not ip_targets and not asn_targets:
        raise DemistoException('Either the "ip" or the "asn" argument must be provided.')
    if ip_targets and asn_targets:
        raise DemistoException('Provide either the "ip" or the "asn" argument, not both.')

    include = validate_choices(argToList(args.get("include")), ASN_INCLUDE_VALUES, "include")
    fields = ",".join(argToList(args.get("fields"))) or None
    excludes = ",".join(argToList(args.get("excludes"))) or None

    results: list[CommandResults] = []
    for target in ip_targets or asn_targets:
        by_ip = bool(ip_targets)
        validated = validate_ip(target) if by_ip else normalize_asn(target)
        try:
            raw = client.get_asn(
                ip=validated if by_ip else None,
                asn=None if by_ip else validated,
                include=include,
                fields=fields,
                excludes=excludes,
            )
        except DemistoException as error:
            results.append(build_failure_entry(validated, error))
            continue

        outputs = prune_empty(remap_keys(raw.get("asn") or {}, ASN_MAPPING))
        if raw.get("ip"):
            outputs["IP"] = raw["ip"]
        results.append(
            CommandResults(
                outputs_prefix="IPGeolocation.ASN",
                outputs_key_field="ASNumber",
                outputs=outputs,
                readable_output=build_asn_output(raw),
                raw_response=raw,
            )
        )
    return results


def ip_reputation_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> list[CommandResults]:
    """Run the generic ``ip`` reputation command.

    Security data drives the DBotScore. When geolocation context is enabled the
    unified GET /v3/ipgeo endpoint is used with ``include=security``, otherwise
    the dedicated GET /v3/security endpoint is used.

    :param client: Configured client.
    :param args: Command arguments.
    :param params: Integration configuration parameters.
    :return: One CommandResults per requested address.
    """
    targets = argToList(args.get("ip"))
    if not targets:
        raise DemistoException('The "ip" argument is required.')

    config = ReputationConfig(params)
    with_geolocation = argToBoolean(params.get("reputation_with_geolocation", True))

    results: list[CommandResults] = []
    for target in targets:
        validated = validate_ip(target)
        if is_private_ip(validated):
            results.append(build_failure_entry(validated, DemistoException(HTTP_STATUS_MESSAGES[423])))
            continue
        try:
            if with_geolocation:
                raw = client.get_ip_geolocation(ip=validated, include="security")
            else:
                raw = client.get_ip_security(ip=validated)
        except DemistoException as error:
            results.append(build_failure_entry(validated, error))
            continue

        score, message = score_security(raw.get("security"), config)
        dbot_score = build_dbot_score(raw.get("ip") or validated, score, config.reliability, message)

        readable = build_security_table(raw.get("ip"), raw.get("security") or {})
        if with_geolocation:
            readable = f"{build_overview_table(raw)}\n{readable}"
        readable = f"{readable}\n**Reputation:** {message}"

        results.append(
            CommandResults(
                outputs_prefix="IPGeolocation.IP",
                outputs_key_field="IP",
                outputs=prune_empty(remap_keys(raw, IPGEO_MAPPING)),
                readable_output=readable,
                raw_response=raw,
                indicator=build_ip_indicator(raw, dbot_score),
            )
        )
    return results


def build_failure_entry(target: str, error: DemistoException) -> CommandResults:
    """Report a single failed lookup without aborting the remaining ones.

    Batch friendly behaviour keeps a playbook running when one indicator in a
    list cannot be enriched, for example a bogon address.

    :param target: Value that could not be looked up.
    :param error: Error raised for that value.
    :return: Warning entry for the analyst.
    """
    return CommandResults(
        readable_output=f"Could not retrieve IPGeolocation.io data for {target}. {error}",
        entry_type=EntryType.WARNING,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_client(params: dict[str, Any]) -> Client:
    """Create a client from the integration configuration.

    :param params: Integration configuration parameters.
    :return: Configured client.
    :raises DemistoException: If the API key is missing or the timeout is invalid.
    """
    api_key = (params.get("credentials") or {}).get("password")
    if not api_key:
        raise DemistoException("An IPGeolocation.io API key is required. Add it in the integration configuration.")

    timeout = to_int(params.get("timeout") or DEFAULT_TIMEOUT, "HTTP timeout")
    if timeout is None or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise DemistoException(f"The HTTP timeout must be an integer between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")

    return Client(
        base_url=params.get("url") or DEFAULT_BASE_URL,
        api_key=api_key,
        verify=not argToBoolean(params.get("insecure", False)),
        proxy=argToBoolean(params.get("proxy", False)),
        timeout=timeout,
    )


def main() -> None:
    """Parse the invocation and dispatch it to the matching command."""
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        client = build_client(params)

        if command == "test-module":
            return_results(run_test_module(client))
        elif command == "ip":
            return_results(ip_reputation_command(client, args, params))
        elif command == "ipgeolocation-ip-lookup":
            return_results(ip_lookup_command(client, args))
        elif command == "ipgeolocation-ip-security":
            return_results(ip_security_command(client, args))
        elif command == "ipgeolocation-abuse-contact":
            return_results(abuse_contact_command(client, args))
        elif command == "ipgeolocation-asn":
            return_results(asn_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented by {INTEGRATION_NAME}.")
    except Exception as error:
        return_error(f"Failed to execute {command} command.\nError:\n{error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
