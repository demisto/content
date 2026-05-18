import base64
import hashlib
import hmac
import json
import time
import urllib.parse
import uuid
from collections.abc import Callable
from datetime import datetime, UTC
from http import HTTPStatus
from typing import Any, cast

import dateparser
import demistomock as demisto
import requests
import urllib3
from CommonServerPython import *

from CommonServerUserPython import *


def is_valid_uuid(uuid_string):
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False


# register_module_line("CTIX v3", "start", __line__())
# Uncomment while development=


"""IMPORTS"""


# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS"""

domain_regex = (
    "([a-z¡-\uffff0-9](?:[a-z¡-\uffff0-9-]{0,61}"
    "[a-z¡-\uffff0-9])?(?:\\.(?!-)[a-z¡-\uffff0-9-]{1,63}(?<!-))*"
    "\\.(?!-)(?!(jpg|jpeg|exif|tiff|tif|png|gif|otf|ttf|fnt|dtd|xhtml|css"
    "|html)$)(?:[a-z¡-\uffff-]{2,63}|xn--[a-z0-9]{1,59})(?<!-)\\.?$"
    "|localhost)"
)

tag_colors = {
    "blue": "#0068FA",
    "purple": "#5236E2",
    "orange": "#EB9C00",
    "red": "#FF5330",
    "green": "#27865F",
    "yellow": "#C4C81D",
    "turquoise": "#00A2C2",
    "pink": "#C341E7",
    "light-red": "#AD6B76",
    "grey": "#95A1B1",
}

CTIX_DBOT_MAP = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "MD5": "file",
    "SHA-1": "file",
    "SHA-224": "file",
    "SHA-256": "file",
    "SHA-384": "file",
    "SHA-512": "file",
    "SSDEEP": "file",
    "domain-name": "domain",
    "domain": "domain",
    "email-addr": "email",
    "email-message": "email",
    "artifact": "custom",
    "network-traffic": "custom",
    "user-agent": "custom",
    "windows-registry-key": "custom",
    "directory": "custom",
    "process": "custom",
    "software": "custom",
    "user-account": "custom",
    "mac-addr": "custom",
    "mutex": "custom",
    "autonomous-system": "custom",
    "cidr": "custom",
    "certificate": "x509-certificate",
    "url": "url",
}

REGEX_MAP = {
    "url": re.compile(urlRegex, regexFlags),
    "domain": re.compile(domain_regex, regexFlags),
    "hash": re.compile(hashRegex, regexFlags),
}

"""
Canonical map for indicator type -> XSOAR type
"""
INDICATOR_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain-name": FeedIndicatorType.Domain,
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "email-addr": FeedIndicatorType.Email,
    "email-message": FeedIndicatorType.Email,
    "MD5": FeedIndicatorType.File,
    "SHA-1": FeedIndicatorType.File,
    "SHA-224": FeedIndicatorType.File,
    "SHA-256": FeedIndicatorType.File,
    "SHA-384": FeedIndicatorType.File,
    "SHA-512": FeedIndicatorType.File,
    "SSDEEP": FeedIndicatorType.SSDeep,
    "autonomous-system": FeedIndicatorType.AS,
    "cidr": FeedIndicatorType.CIDR,
    "certificate": FeedIndicatorType.X509,
    "user-agent": "User Agent",
    "windows-registry-key": FeedIndicatorType.Registry,
    "mutex": FeedIndicatorType.MUTEX,
    "mac-addr": "MAC Address",
    "network-traffic": "Network Traffic",
    "artifact": "Artifact",
    "directory": "Directory",
    "process": "Process",
    "software": FeedIndicatorType.Software,
    "user-account": FeedIndicatorType.Account,
}
CYWARE_TYPE_NORMALIZATION: dict[str, str] = {
    "ip": INDICATOR_TYPE_MAP.get("ipv4-addr", FeedIndicatorType.IP),
    "ipv4": INDICATOR_TYPE_MAP.get("ipv4-addr", FeedIndicatorType.IP),
    "ipv4-addr": INDICATOR_TYPE_MAP.get("ipv4-addr", FeedIndicatorType.IP),
    "ipv6": INDICATOR_TYPE_MAP.get("ipv6-addr", FeedIndicatorType.IPv6),
    "ipv6-addr": INDICATOR_TYPE_MAP.get("ipv6-addr", FeedIndicatorType.IPv6),
    "domain": INDICATOR_TYPE_MAP.get("domain", FeedIndicatorType.Domain),
    "domain-name": INDICATOR_TYPE_MAP.get("domain", FeedIndicatorType.Domain),
    "url": INDICATOR_TYPE_MAP.get("url", FeedIndicatorType.URL),
    "email": INDICATOR_TYPE_MAP.get("email-addr", FeedIndicatorType.Email),
    "email-addr": INDICATOR_TYPE_MAP.get("email-addr", FeedIndicatorType.Email),
    "hash_md5": INDICATOR_TYPE_MAP.get("MD5", FeedIndicatorType.File),
    "hash_sha1": INDICATOR_TYPE_MAP.get("SHA-1", FeedIndicatorType.File),
    "hash_sha256": INDICATOR_TYPE_MAP.get("SHA-256", FeedIndicatorType.File),
    "md5": INDICATOR_TYPE_MAP.get("MD5", FeedIndicatorType.File),
    "sha-1": INDICATOR_TYPE_MAP.get("SHA-1", FeedIndicatorType.File),
    "sha-256": INDICATOR_TYPE_MAP.get("SHA-256", FeedIndicatorType.File),
    "sha1": INDICATOR_TYPE_MAP.get("SHA-1", FeedIndicatorType.File),
    "sha256": INDICATOR_TYPE_MAP.get("SHA-256", FeedIndicatorType.File),
    "ssdeep": INDICATOR_TYPE_MAP.get("SSDEEP", FeedIndicatorType.SSDeep),
    "file": FeedIndicatorType.File,
}

# Maps raw Cyware/CTIX IOC type strings → the XSOAR hash field name to populate
_HASH_TYPE_TO_FIELD: dict[str, str] = {
    # MD5
    "hash_md5": "md5",
    "md5": "md5",
    "MD5": "md5",
    # SHA-1
    "hash_sha1": "sha1",
    "sha1": "sha1",
    "sha-1": "sha1",
    "SHA-1": "sha1",
    # SHA-256
    "hash_sha256": "sha256",
    "sha256": "sha256",
    "sha-256": "sha256",
    "SHA-256": "sha256",
    # SHA-224 / SHA-384 / SHA-512
    "SHA-224": "sha224",
    "sha-224": "sha224",
    "SHA-384": "sha384",
    "sha-384": "sha384",
    "SHA-512": "sha512",
    "sha-512": "sha512",
    # SSDEEP
    "SSDEEP": "ssdeep",
    "ssdeep": "ssdeep",
}

_STIX_SDO_TO_XSOAR_ENTITY_TYPE: dict[str, str] = {
    # ── Standard indicator / observable types ──────────────────────────────────
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain-name": FeedIndicatorType.Domain,
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "email-addr": FeedIndicatorType.Email,
    "email-message": FeedIndicatorType.Email,
    "file": FeedIndicatorType.File,
    "MD5": FeedIndicatorType.File,
    "SHA-1": FeedIndicatorType.File,
    "SHA-224": FeedIndicatorType.File,
    "SHA-256": FeedIndicatorType.File,
    "SHA-384": FeedIndicatorType.File,
    "SHA-512": FeedIndicatorType.File,
    "SSDEEP": FeedIndicatorType.SSDeep,
    "autonomous-system": FeedIndicatorType.AS,
    "cidr": FeedIndicatorType.CIDR,
    "windows-registry-key": FeedIndicatorType.Registry,
    "mutex": FeedIndicatorType.MUTEX,
    "certificate": FeedIndicatorType.X509,
    "x509-certificate": FeedIndicatorType.X509,
    "software": FeedIndicatorType.Software,
    "user-account": FeedIndicatorType.Account,
    "user-agent": "User Agent",
    "mac-addr": "MAC Address",
    "network-traffic": "Network Traffic",
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    "vulnerability": FeedIndicatorType.CVE,
    "indicator": "Indicator",
    "observable": "Indicator",
    "identity": "Identity",
    "location": "Location",
}

ENRICHMENT_BATCH_SIZE = 100
BULK_LOOKUP_PAGE_SIZE = 100
# Max ``next`` pages to follow per bulk IOC lookup batch (safety cap)
BULK_LOOKUP_MAX_PAGES = 100
FETCH_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DELTA_TIME_DIFF = 2
FIRST_FETCH_DEFAULT_MINUTES = 4320

# API page-size limits (per CTIX API documentation)
PAGE_SIZE = 100
PAGE_SIZE_THREAT_DATA = 2000

# LastRun state keys (instance namespaced)
FETCH_INCIDENTS_STATE_PREFIX = "fetch_incidents"
FETCH_INDICATORS_STATE_PREFIX = "fetch_indicators"

RATE_LIMIT_STATUS_ERR = "status-> 429"
RETRY_COUNT = 0
""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the CTIX integration. Overrides BaseClient
    """

    def __init__(
        self,
        base_url: str,
        access_id: str,
        secret_key: str,
        timeout: int,
        verify: bool,
        proxies: dict,
    ) -> None:
        self.base_url = base_url
        self.access_id = access_id
        self.secret_key = secret_key
        self.timeout = timeout
        self.verify = verify
        self.proxies = proxies

    def signature(self, expires: int):
        """
        Signature Generation

        :param int expires: Epoch time in which time when signature will expire
        :return str signature : signature queryset
        """
        to_sign = f"{self.access_id}\n{expires}"
        return base64.b64encode(hmac.new(self.secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1).digest()).decode(
            "utf-8"
        )

    def add_common_params(self, params: dict):
        """
        Add Common Params

        :param dict params: Paramters to be added in request
        :return dict: Params dictionary with AccessID, Expires and Signature
        """
        expires = int(time.time() + 15)
        params["AccessID"] = self.access_id
        params["Expires"] = expires
        params["Signature"] = self.signature(expires)
        return params

    def get_http_request(self, full_url: str, payload: dict = None, fallback_full_url: str = None, params: dict = None, **kwargs):
        """
        GET HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :param str fallback_full_url: URL to be called if the first 404s, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        kwargs = self.add_common_params(kwargs)
        params and kwargs.update(params)
        separator = "&" if "?" in full_url else "?"
        full_url = full_url + separator + urllib.parse.urlencode(kwargs)

        headers = {"content-type": "application/json"}
        resp = requests.get(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            timeout=self.timeout,
            headers=headers,
            json=payload,
        )
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status code
            response = {"data": resp.json(), "status": status_code}
            return response
        except requests.exceptions.HTTPError:
            if status_code == HTTPStatus.NOT_FOUND:
                if fallback_full_url:
                    # try again with the fallback url
                    return self.get_http_request(fallback_full_url, payload, **kwargs)
                else:
                    return_error("Your CTIX version does not support this command.")
            else:
                raise DemistoException(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def post_http_request(self, full_url: str, payload: dict, params: dict, fallback_full_url: str = None):
        """
        POST HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :param str fallback_full_url: URL to be called if the first 404s, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        headers = {"content-type": "application/json"}
        params = self.add_common_params(params)
        separator = "&" if "?" in full_url else "?"
        full_url = full_url + separator + urllib.parse.urlencode(params)
        resp = requests.post(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status code
            response = {"data": resp.json(), "status": status_code}
            return response
        except requests.exceptions.HTTPError:
            if status_code == HTTPStatus.NOT_FOUND:
                if fallback_full_url:
                    # try again with the fallback url
                    return self.post_http_request(fallback_full_url, payload, params)
                else:
                    return_error("Your CTIX version does not support this command.")
            else:
                raise DemistoException(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def put_http_request(self, full_url: str, payload: dict, params: dict):
        """
        PUT HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        headers = {"content-type": "application/json"}
        params = self.add_common_params(params)
        separator = "&" if "?" in full_url else "?"
        full_url = full_url + separator + urllib.parse.urlencode(params)
        resp = requests.put(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status codeg
            response = {"data": resp.json(), "status": status_code}
            return response
        except requests.exceptions.HTTPError:
            if status_code == HTTPStatus.NOT_FOUND:
                return_error("Your CTIX version does not support this command.")
            else:
                raise DemistoException(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def delete_http_request(self, full_url: str, payload: dict = None, params: dict = None, **kwargs):
        """
        DELETE HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        kwargs = self.add_common_params(kwargs)
        params and kwargs.update(params)
        separator = "&" if "?" in full_url else "?"
        full_url = full_url + separator + urllib.parse.urlencode(kwargs)
        headers = {"content-type": "application/json"}
        resp = requests.delete(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            timeout=self.timeout,
            headers=headers,
            json=payload,
        )
        status_code = resp.status_code
        try:
            resp.raise_for_status()  # Raising an exception for non-200 status code
            response = {"data": resp.json(), "status": status_code}
            return response
        except requests.exceptions.HTTPError:
            if status_code == HTTPStatus.BAD_REQUEST:
                response = {"data": {}, "status": status_code}
                return response

            raise DemistoException(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def follow_next_page(
        self,
        next_url: str,
        payload: dict | None = None,
        method: str = "GET",
    ) -> dict | None:
        """Follow a pagination ``next`` URL returned by the CTIX API.

        The ``next`` value is a relative path with embedded query params,
        e.g. ``ingestion/rules/save_result_set/?page=2&page_size=100&...``.
        Auth params (AccessID, Expires, Signature) are appended automatically
        by the underlying HTTP helpers.

        :param str next_url: Relative URL path (must not be empty)
        :param dict payload: Request body – required for POST-based endpoints
        :param str method: ``"GET"`` (default) or ``"POST"``
        :return: Standard ``{"data": ..., "status": ...}`` response dict
        """
        if not next_url:
            return None
        full_url = self.base_url + next_url
        if method.upper() == "POST":
            return self.post_http_request(full_url, payload or {}, {})
        return self.get_http_request(full_url, payload)

    def test_auth(self):
        """
        Test authentication

        :return dict: Returns result for ping
        """
        client_url = self.base_url + "ping/"
        return self.get_http_request(client_url)

    def create_tag(self, name: str, color_code: str):
        """Creates a tag in ctix platform
        :type name: ``str``
        :param name: Name of the tag

        :type color_code: ``str``
        :param color_code: Hex color code of the tag e.g #111111

        :return: dict containing the details of newly created tag
        :rtype: ``Dict[str, Any]``
        """
        url_suffix = "ingestion/tags/"
        client_url = self.base_url + url_suffix
        payload = {"name": name, "color_code": color_code}
        return self.post_http_request(full_url=client_url, payload=payload, params={})

    def get_tags(self, page: int, page_size: int, q: str):
        """Paginated list of tags from ctix platform using page_number and page_size
        :type page: int
        :param page: page number for the pagination for list api

        :type page_size: int
        :param page_size: page size for the pagination for list api

        :type q: str
        :param q: search query string for the list api
        """
        url_suffix = "ingestion/tags/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q  # type: ignore
        return self.get_http_request(client_url, params)

    def disable_or_enable_tag(self, tag_ids: list, action: str):
        """Enables or Disables a tag from the ctix instance
        :type tag_ids: ``list``
        :param tag_ids: id of the tag to be disabled or enabled
        :type action: ``str``
        :param action: Action to be performed. Possible values are 'enabled' and 'disabled'
        """
        url_suffix = "ingestion/tags/bulk-actions/"
        client_url = self.base_url + url_suffix
        return self.post_http_request(client_url, {"ids": tag_ids, "action": action}, {"component": "tags"})

    def whitelist_iocs(self, ioc_type, values, reason):
        url_suffix = "conversion/allowed_indicators/"  # for CTIX >= 3.6
        fallback_url_suffix = "conversion/whitelist/"  # for CTIX < 3.6
        client_url = self.base_url + url_suffix
        fallback_client_url = self.base_url + fallback_url_suffix
        payload = {"type": ioc_type, "values": values, "reason": reason}
        return self.post_http_request(client_url, payload, {}, fallback_full_url=fallback_client_url)

    def get_whitelist_iocs(self, page: int, page_size: int, q: str):
        """Paginated list of tags from ctix platform using page_number and page_size
        :type page: int
        :param page: page number for the pagination for list api

        :type page_size: int
        :param page_size: page size for the pagination for list api

        :type q: str
        :param q: search query string for the list api
        """
        url_suffix = "conversion/allowed_indicators/"  # for CTIX >= 3.6
        fallback_url_suffix = "conversion/whitelist/"  # for CTIX < 3.6
        client_url = self.base_url + url_suffix
        fallback_client_url = self.base_url + fallback_url_suffix
        params = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q  # type: ignore
        return self.get_http_request(client_url, {}, fallback_full_url=fallback_client_url, params=params)

    def remove_whitelisted_ioc(self, whitelist_id: str):
        """Removes whitelisted ioc with given `whitelist_id`
        :type whitelist_id: str
        :param whitelist_id: id of the whitelisted ioc to be removed
        """
        url_suffix = "conversion/allowed_indicators/bulk-actions/"
        payload = {
            "ids": whitelist_id,
            "action": "delete",
        }
        client_url = self.base_url + url_suffix
        return self.post_http_request(full_url=client_url, payload=payload, params={})

    def get_threat_data(self, page: int, page_size: int, query: str):
        """
        Get Threat Data

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str query: CQL query for polling specific result
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/list/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        payload = {"query": query}
        return self.post_http_request(client_url, payload=payload, params=params)

    def get_saved_searches(self, page: int, page_size: int):
        """
        Get Saved Searches

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/saved-searches/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, None, params=params)

    def get_server_collections(self, page: int, page_size: int):
        """
        Get Server Collections

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        """
        url_suffix = "publishing/collection/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, params=params)

    def get_actions(self, page: int, page_size: int, params: dict[str, Any]):
        """
        Get Actions

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param Dict[str, Any] params: Params to be send with request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/actions/"
        client_url = self.base_url + url_suffix
        params["page"] = page
        params["page_size"] = page_size
        return self.get_http_request(client_url, params=params)

    def add_indicator_as_false_positive(self, object_ids: List[str], object_type: str):
        """
        Add Indicator as False Positive

        :param list[str] object_ids: Object IDs of the IOCs
        :param str object_type: Object type of the IOCs
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/bulk-action/false_positive/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def add_ioc_to_manual_review(self, object_ids: List[str], object_type: str):
        """
        Add IOC to Manual Review

        :param list[str] object_ids: Object IDs of the IOCs
        :param str object_type: Object type of the IOCs
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/bulk-action/manual_review/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def deprecate_ioc(self, object_ids: str, object_type: str):
        """
        Deprecate IOC

        :param str object_ids: Object ID of the IOC
        :param str object_type: Object type of the IOC
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/bulk-action/deprecate/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def add_analyst_tlp(self, object_id: str, object_type: str, data):
        """
        Add Analyst TLP

        :param str object_id: Object ID of the IOCs
        :param str object_type: _Object type of the IOCs
        :param dict data: data to be send over POST request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/action/analyst_tlp/"
        client_url = self.base_url + url_suffix
        payload = {"object_id": object_id, "object_type": object_type, "data": data}

        return self.post_http_request(client_url, payload, {})

    def add_analyst_score(self, object_id: str, object_type, data):
        """
        Add Analyst Score

        :param str object_id: Object ID of the IOCs
        :param str object_type: Object type of the IOCs
        :param dict data: Request body to be send over POST request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/action/analyst_score/"
        client_url = self.base_url + url_suffix
        payload = {"object_id": object_id, "object_type": object_type, "data": data}

        return self.post_http_request(client_url, payload, {})

    def saved_result_set(
        self,
        page: int,
        page_size: int,
        label_name: str = None,
        version: str = None,
        from_timestamp: int | None = None,
        to_timestamp: int | None = None,
    ):
        """
        Saved Result Set

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str label_name: Label name used to get the data from the rule
        :param str version: Saved Result Set version
        :param int from_timestamp: Filter results from this epoch timestamp
        :param int to_timestamp: Filter results until this epoch timestamp
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/rules/save_result_set/"
        client_url = self.base_url + url_suffix
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if version:
            params["version"] = version
        if label_name:
            params["label_name"] = label_name
        if from_timestamp:
            params["from_timestamp"] = from_timestamp
        if to_timestamp:
            params["to_timestamp"] = to_timestamp
        return self.get_http_request(client_url, {}, params=params)

    def tag_indicator_updation(
        self,
        q: str,
        page: int,
        page_size: int,
        object_id: str,
        object_type: str,
        tag_id: str,
        operation: str,
    ):
        """
        Tag Indicator Updation

        :param str q: query to be send
        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str object_id: Object ID of the IOCs
        :param str object_type: Object type of the IOCs
        :param str tag_id: Tag ID that will be removed or added
        :param str operation: Addition or Removal of tag operation
        :return dict: Returns response for query
        """
        tags_data = self.get_indicator_tags(object_type, object_id, {"page": page, "page_size": page_size})["data"]
        tags = [_["id"] for _ in tags_data["tags"]]
        data = {}
        url_suffix = ""
        if operation == "add_tag_indicator":
            url_suffix = "ingestion/threat-data/bulk-action/add_tag/"
            tags.extend([_.strip() for _ in tag_id.split(",")])
            data = {"tag_id": list(set(tags))}
        elif operation == "remove_tag_from_indicator":
            url_suffix = "ingestion/threat-data/bulk-action/remove_tag/"
            tags = [_.strip() for _ in tag_id.split(",")]
            data = {"tag_id": list(set(tags))}
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size, "q": q}
        payload = {
            "object_ids": [object_id],
            "object_type": object_type,
            "data": data,
        }
        return self.post_http_request(client_url, payload, params)

    def search_for_tag(self, params: dict):
        """
        Search for tag

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/tags/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_details(self, object_type: str, object_id: str, params: dict):
        """
        Get Indicator Details

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/basic/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_tags(self, object_type: str, object_id: str, params: dict):
        """
        Get Indicator Tags

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/quick-actions/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_relations(self, object_type: str, object_id: str, params: dict):
        """
        Get Indicator Relations

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/relations/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_observations(self, params: dict):
        """
        Get Indicator Observations

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/source-references/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_conversion_feed_source(self, params: dict):
        """
        Get Conversion Feed Source

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = "conversion/feed-sources/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_lookup_threat_data(self, object_type: str, ioc_type: list, object_names: list, params: dict):
        """
        Get Lookup Threat Data

        :param str object_type: (SDO) Object type of the IOCs
        :param list ioc_type: the IOC type of the Indicator (eg. URL, MD5, IPv4)
        :param list object_names: Indicator/IOCs names
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/list/"
        query = f"type={object_type}"

        if len(ioc_type) == 1:
            query += f" AND ioc_type IN ('{ioc_type[0]}')"
        elif len(ioc_type) > 1:
            query += f" AND ioc_type IN {tuple(ioc_type)}"

        if len(object_names) == 1:
            query += f" AND value IN ('{object_names[0]}')"
        else:
            query += f" AND value IN {tuple(object_names)}"

        payload = {"query": query}
        client_url = self.base_url + url_suffix
        return self.post_http_request(client_url, payload, params)

    def bulk_lookup_and_create_data(self, object_names, source, collection, page_size):
        url_suffix = "ingestion/threat-data/bulk-lookup-and-create/"
        client_url = self.base_url + url_suffix
        params = {"create": "true", "page_size": page_size}

        payload = {
            "ioc_values": object_names,
            "metadata": {"tlp": "AMBER", "confidence": 100, "tags": []},
            "source": {"source_name": source},
            "collection": {"collection_name": collection},
        }

        return self.post_http_request(client_url, payload, params)

    def bulk_ioc_lookup_advanced(
        self,
        object_type: str,
        values: list,
        object_ids: list,
        enrichment_data: bool,
        relation_data: bool,
        enrichment_tools: str | None = None,
        fields: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ):
        """
        Bulk IOC Lookup (Advanced)

        :param str object_type: SDO object type to lookup (path param)
        :param list values: list of indicator values to lookup
        :param list object_ids: list of object ids to lookup
        :param bool enrichment_data: pass True to include the latest enrichment data objects
        :param bool relation_data: pass True to include the latest relation details
        :param str enrichment_tools: optional comma-separated enrichment tool names
        :param str fields: optional comma-separated field names to retrieve
        :param int page: optional page number for paginated bulk lookups
        :param int page_size: optional page size for paginated bulk lookups
        :return: response dict
        """
        payload: dict[str, Any] = {}
        url_suffix = f"ingestion/openapi/bulk-lookup/{object_type}/"
        client_url = self.base_url + url_suffix
        params: dict[str, Any] = {
            "enrichment_data": enrichment_data,
            "relation_data": relation_data,
        }
        if enrichment_tools:
            params["enrichment_tools"] = enrichment_tools
        if fields:
            params["fields"] = fields
        if page is not None:
            params["page"] = page
        if page_size is not None:
            params["page_size"] = page_size
        if values:
            payload.update({"value": values})
        elif object_ids:
            payload.update({"object_id": object_ids})
        else:
            return_error("Either values or object_ids must be provided for bulk IOC lookup.")
        return self.post_http_request(client_url, payload, params)

    def get_vulnerability_product_details(self, obj_id: str, page: int, page_size: int):
        """
        Get Vulnerability Product Details

        :param str obj_id: The ID of the vulnerability to get the product details for
        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/vulnerability/{obj_id}/product-details/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, None, params=params)

    def get_vulnerability_cvss_score(self, obj_id: str, page: int, page_size: int):
        """
        Get Vulnerability CVSS Score

        :param str obj_id: The ID of the vulnerability to get the product details for
        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/vulnerability/{obj_id}/cvss-score/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, None, params=params)

    def get_vulnerability_source_description(self, obj_id: str, source_id: str, page: int, page_size: int):
        """
        Get Vulnerability Source Description

        :param str obj_id: The ID of the vulnerability to get the source description for
        :param str source_id: The ID of the source to get the description for
        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        """
        url_suffix = f"ingestion/threat-data/vulnerability/{obj_id}/source-description/"
        client_url = self.base_url + url_suffix
        params = {"source_id": source_id, "page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, None, params=params)


""" HELPER FUNCTIONS """


def execute_with_retry(func: Callable, *args, **kwargs) -> Any:
    """
    Executes a function with a single retry after 60 seconds if it fails.
    """
    global RETRY_COUNT
    try:
        return func(*args, **kwargs)
    except DemistoException as e:
        if "429" not in str(e):
            raise e
        RETRY_COUNT += 1
        if RETRY_COUNT > 3:
            demisto.error(f"CTIX: RETRY_COUNT exceeded {RETRY_COUNT}. Error: {e}")
            raise e
        demisto.error(f"CTIX: Hit an error: {e}. Waiting 60 seconds before retrying... (Retry {RETRY_COUNT})")
        time.sleep(60)  # pylint: disable=E9003
        return func(*args, **kwargs)


def to_dbot_score(ctix_score: int) -> int:
    """
    Maps CTIX Score to DBotScore
    """
    if isinstance(ctix_score, str):
        try:
            ctix_score = int(ctix_score)
        except (ValueError, TypeError):
            ctix_score = 0
    if ctix_score == 0:
        dbot_score = Common.DBotScore.NONE  # unknown
    elif ctix_score <= 30:
        dbot_score = Common.DBotScore.GOOD  # good
    elif ctix_score <= 70:
        dbot_score = Common.DBotScore.SUSPICIOUS  # suspicious
    else:
        dbot_score = Common.DBotScore.BAD
    return dbot_score


def no_result_found(data: Any):
    if data in ("", " ", None, [], {}):
        result = CommandResults(
            readable_output="No results were found",
            outputs=None,
            raw_response=None,
        )
    else:
        result = data
    return result


def check_for_empty_variable(value: str, default: Any):
    return value if value not in ("", " ", None) else default


def iter_dbot_score(
    data: list,
    score_key: str,
    type_key: str,
    table_name: str,
    output_prefix: str,
    outputs_key_field: str,
    reliability: str = None,
):
    final_data = []
    for value in data:
        if value[type_key] is not None:
            indicator_type = CTIX_DBOT_MAP[value[type_key]]
            score = to_dbot_score(value.get(score_key, 0))
            if indicator_type == "ip":
                dbot_score = Common.DBotScore(
                    indicator=value.get("name"),
                    indicator_type=DBotScoreType.IP,
                    integration_name="CTIX",
                    score=score,
                    reliability=reliability,
                )
                ip_standard_context = Common.IP(ip=value.get("name"), asn=value.get("asn"), dbot_score=dbot_score)
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        indicator=ip_standard_context,
                        raw_response=value,
                    )
                )
            elif indicator_type == "file":
                dbot_score = Common.DBotScore(
                    indicator=value.get("name"),
                    indicator_type=DBotScoreType.FILE,
                    integration_name="CTIX",
                    score=score,
                    reliability=reliability,
                )
                file_standard_context = Common.File(name=value.get("name"), dbot_score=dbot_score)
                file_key = value.get("name")
                hash_type = value.get("attribute_field", "Unknown").lower()
                if hash_type == "md5":
                    file_standard_context.md5 = file_key
                elif hash_type == "sha-1":
                    file_standard_context.sha1 = file_key
                elif hash_type == "sha-256":
                    file_standard_context.sha256 = file_key
                elif hash_type == "sha-512":
                    file_standard_context.sha512 = file_key

                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        indicator=file_standard_context,
                        raw_response=value,
                    )
                )
            elif indicator_type == "domain":
                dbot_score = Common.DBotScore(
                    indicator=value.get("name"),
                    indicator_type=DBotScoreType.DOMAIN,
                    integration_name="CTIX",
                    score=score,
                    reliability=reliability,
                )
                domain_standard_context = Common.Domain(domain=value.get("name"), dbot_score=dbot_score)
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        indicator=domain_standard_context,
                        raw_response=value,
                    )
                )
            elif indicator_type == "email":
                dbot_score = Common.DBotScore(
                    indicator=value.get("name"),
                    indicator_type=DBotScoreType.EMAIL,
                    integration_name="CTIX",
                    score=score,
                    reliability=reliability,
                )
                email_standard_context = Common.Domain(domain=value.get("name"), dbot_score=dbot_score)
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        indicator=email_standard_context,
                        raw_response=value,
                    )
                )
            elif indicator_type == "url":
                dbot_score = Common.DBotScore(
                    indicator=value.get("name"),
                    indicator_type=DBotScoreType.URL,
                    integration_name="CTIX",
                    score=score,
                    reliability=reliability,
                )
                url_standard_context = Common.URL(url=value.get("name"), dbot_score=dbot_score)
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        indicator=url_standard_context,
                        raw_response=value,
                    )
                )
            else:  # indicator_type == 'custom'
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(table_name, value, removeNull=True),
                        outputs_prefix=output_prefix,
                        outputs_key_field=outputs_key_field,
                        outputs=value,
                        raw_response=value,
                    )
                )
        else:
            final_data.append(
                CommandResults(
                    readable_output=tableToMarkdown(table_name, value, removeNull=True),
                    outputs_prefix=output_prefix,
                    outputs_key_field=outputs_key_field,
                    outputs=value,
                    raw_response=value,
                )
            )
    return final_data


def _normalize_timestamp_to_iso(ts: Any) -> str | None:
    """Convert a timestamp value to ISO8601 format.

    Handles epoch int/float, ISO strings, and other common date string formats.
    Returns None if the value cannot be parsed.
    """
    if ts is None:
        return None
    # Epoch int/float
    if isinstance(ts, int | float) and ts > 0:
        return datetime.fromtimestamp(ts, tz=UTC).strftime(FETCH_DATE_FORMAT)
    # Already a string – try to parse
    if isinstance(ts, str) and ts.strip():
        parsed = dateparser.parse(ts)
        if parsed:
            return parsed.strftime(FETCH_DATE_FORMAT)
    return None


def _normalize_cyware_indicator_type(raw_type: str | None) -> str:
    """Normalize a Cyware indicator type string to Cortex XSOAR type."""
    DEFAULT_INDICATOR = "Indicator"
    if not raw_type:
        return DEFAULT_INDICATOR
    lookup = raw_type.strip().lower().replace(" ", "_")
    return CYWARE_TYPE_NORMALIZATION.get(
        lookup, INDICATOR_TYPE_MAP.get(raw_type, _STIX_SDO_TO_XSOAR_ENTITY_TYPE.get(raw_type, DEFAULT_INDICATOR))
    )


def confidence_to_dbot_score(confidence: Any) -> int:
    """Map CTIX confidence score to DBotScore.

    confidence >= 80 -> Malicious (3)
    confidence 50-79 -> Suspicious (2)
    confidence < 50  -> Unknown (1)
    None / non-numeric -> None (0)
    """
    if confidence is None:
        return Common.DBotScore.NONE
    if isinstance(confidence, str):
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            return Common.DBotScore.NONE
    if confidence >= 80:
        return Common.DBotScore.BAD
    if confidence >= 50:
        return Common.DBotScore.SUSPICIOUS
    return Common.DBotScore.NONE


def normalize_indicator_type(ctix_ioc_type: str | None) -> str:
    """Normalize CTIX IOC type to XSOAR FeedIndicatorType."""
    if not ctix_ioc_type:
        return "Custom Indicator"
    return INDICATOR_TYPE_MAP.get(ctix_ioc_type, "Custom Indicator")


def map_report_severity(report: dict) -> int:
    """Convert CTIX report severity/confidence to XSOAR severity (1-4)."""
    severity_str = (report.get("risk_severity") or "").upper()
    severity_map = {
        "LOW": IncidentSeverity.LOW,
        "MEDIUM": IncidentSeverity.MEDIUM,
        "HIGH": IncidentSeverity.HIGH,
        "CRITICAL": IncidentSeverity.CRITICAL,
    }
    if severity_str in severity_map:
        return severity_map[severity_str]

    confidence = report.get("confidence_score")
    if isinstance(confidence, str):
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = None
    if isinstance(confidence, int | float):
        if confidence >= 80:
            return IncidentSeverity.HIGH
        if confidence >= 50:
            return IncidentSeverity.MEDIUM
        if confidence >= 20:
            return IncidentSeverity.LOW

    return IncidentSeverity.UNKNOWN


def map_report_to_incident(report: dict, relations: dict | None = None, source_reliability: str = "") -> dict:
    """Map a CTIX report object to an XSOAR incident dict."""
    report_id = report.get("id", "")
    title = report.get("name")
    created_ts = report.get("created")
    occurred = ""
    if isinstance(created_ts, int | float) and created_ts > 0:
        occurred = datetime.fromtimestamp(created_ts, tz=UTC).strftime(FETCH_DATE_FORMAT)

    tags = report.get("tags", [])
    labels = []
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict):
                labels.append({"type": "Tag", "value": tag.get("name", "")})
            elif isinstance(tag, str):
                labels.append({"type": "Tag", "value": tag})

    # Build XSOAR relationships from the fetched relations dict
    relationships: list[dict] = []
    if relations and isinstance(relations, dict):
        relationships = _build_relationships(
            indicator_value=title or report_id,
            xsoar_type=ThreatIntel.ObjectsNames.REPORT,
            relations=relations,
            source_reliability=source_reliability,
        )

    # Build per-field CustomFields mapping
    custom_fields: dict[str, Any] = {}
    if report.get("custom_scores"):
        custom_fields["ctixcustomscores"] = json.dumps(report["custom_scores"])
    if report.get("custom_attributes"):
        custom_attribute_data = {
            "custom_attributes": report.get("custom_attributes", []),
            "custom_scores": report.get("custom_scores", {}),
        }
        custom_fields["ctixcustomattributes"] = json.dumps(custom_attribute_data)
    if relations:
        custom_fields["ctixrelations"] = json.dumps(relations)

    incident: dict[str, Any] = {
        "name": f"CTIX Intel: {title}",
        "occurred": occurred,
        "severity": map_report_severity(report),
        "labels": labels,
        "dbotMirrorId": report_id,
        "rawJSON": json.dumps(report),
        "CustomFields": custom_fields,
    }
    if relationships:
        incident["relationships"] = relationships
    return incident


def _severity_to_dbot_score(severity: str | None) -> int:
    """Translate Cyware severity string to XSOAR DBot score.

    Mapping:
        HIGH / CRITICAL -> 3 (Bad)
        MEDIUM          -> 2 (Suspicious)
        LOW / UNKNOWN   -> 1 (Good)
        None / other    -> 0 (None)
    """
    if not severity:
        return Common.DBotScore.NONE
    severity_upper = severity.strip().upper()
    if severity_upper in ("HIGH", "CRITICAL"):
        return Common.DBotScore.BAD
    if severity_upper == "MEDIUM":
        return Common.DBotScore.SUSPICIOUS
    if severity_upper in ("LOW", "UNKNOWN"):
        return Common.DBotScore.GOOD
    return Common.DBotScore.NONE


def _extract_tag_names(tags: Any) -> list[str]:
    """Extract a flat list of tag name strings from various tag formats."""
    tag_names: list[str] = []
    if not isinstance(tags, list):
        return tag_names
    for tag in tags:
        if isinstance(tag, dict):
            name = tag.get("name", "")
            if name:
                tag_names.append(name)
        elif isinstance(tag, str) and tag:
            tag_names.append(tag)
    return tag_names


def _extract_source_names(sources: Any) -> list[str]:
    """Extract a flat list of source name strings."""
    source_names: list[str] = []
    if not isinstance(sources, list):
        return source_names
    for src in sources:
        if isinstance(src, dict):
            name = src.get("name", "")
            if name:
                source_names.append(name)
        elif isinstance(src, str) and src:
            source_names.append(src)
    return source_names


def _build_relationships(
    indicator_value: str,
    xsoar_type: str,
    relations: Any,
    source_reliability: str = "",
) -> list[dict]:
    """Build XSOAR relationship dicts from Cyware relations payload.

    CTIX returns two relation formats depending on the source:

    1. **Enrichment / dict format** — key is the relationship verb, value items are dicts:
       ``{"related-to": [{"name": "evil.com", "type": "domain-name"}]}``

    2. **Base / string format** — key is the STIX target object type, value items are names:
       ``{"malware": ["Adaptix"], "report": ["Feed 6"], "threat-actor": ["APT29"]}``

    In format (2) the key is NOT a valid XSOAR relationship name, so we always use
    ``"related-to"`` as the relationship verb and derive entity_b_type from the key.

    Args:
        indicator_value: The indicator value (entity_a).
        xsoar_type: The XSOAR type of entity_a.
        relations: Relations dict as described above.
        source_reliability: Source reliability string from integration params.

    Returns:
        List of relationship dicts produced by EntityRelationship.to_indicator().
    """
    relationships: list[dict] = []
    if not isinstance(relations, dict):
        return relationships
    for rel_type, rel_list in relations.items():
        if not isinstance(rel_list, list):
            continue
        for rel in rel_list:
            if isinstance(rel, dict):
                # Enrichment format: the dict key IS the relationship verb.
                # Validate it; fall back to "related-to" for any unknown verbs.
                rel_name = rel.get("name", "")
                raw_target_type = rel.get("type", "")
                rel_target_type = _STIX_SDO_TO_XSOAR_ENTITY_TYPE.get(
                    raw_target_type,
                    _normalize_cyware_indicator_type(raw_target_type),
                )
                relationship_verb = (
                    rel_type
                    if EntityRelationship.Relationships.is_valid(rel_type)
                    else EntityRelationship.Relationships.RELATED_TO
                )
            else:
                # Base format: the dict key is the STIX object TYPE of the target
                # (e.g. "malware", "report"), NOT a relationship verb.
                # Always use "related-to" and derive entity_b_type from the key.
                rel_name = str(rel)
                rel_target_type = _STIX_SDO_TO_XSOAR_ENTITY_TYPE.get(rel_type, "Indicator")
                relationship_verb = EntityRelationship.Relationships.RELATED_TO
            if not rel_name:
                continue
            relationships.append(
                EntityRelationship(
                    name=relationship_verb,
                    entity_a=indicator_value,
                    entity_a_type=xsoar_type,
                    entity_b=rel_name,
                    entity_b_type=rel_target_type,
                    source_reliability=source_reliability,
                    brand="Cyware Intel Exchange",
                ).to_indicator()
            )
    return relationships


def _hash_field_name(raw_type: str, attribute_field: str = "") -> str | None:
    """Return the XSOAR hash field name ('md5', 'sha1', 'sha256', …) for a raw type string.

    Checks ``_HASH_TYPE_TO_FIELD`` by exact key first, then by a normalised lowercase
    key, then falls back to ``attribute_field`` (used by the saved-result-set schema
    where ``indicator_type`` is a dict carrying the real attribute name).
    Returns ``None`` when the type is not a file hash.
    """
    if raw_type in _HASH_TYPE_TO_FIELD:
        return _HASH_TYPE_TO_FIELD[raw_type]
    normalised = (raw_type or "").strip().lower().replace(" ", "_")
    if normalised in _HASH_TYPE_TO_FIELD:
        return _HASH_TYPE_TO_FIELD[normalised]
    if attribute_field:
        attr_norm = attribute_field.strip().lower().replace("-", "").replace("_", "")
        return _HASH_TYPE_TO_FIELD.get(attr_norm)
    return None


def parse_cyware_indicator(
    cyware_data: dict, source_reliability: str = "", feed_tags: list | None = None, tlp_color: str = ""
) -> dict:
    """Map a single Cyware/CTIX indicator dict to an XSOAR feed indicator object.

    Strict mapping (per requirements):
        first_seen / first seen  -> fields.firstseenbysource
        last_seen / last seen    -> fields.lastseenbysource
        tags / Tags              -> fields.tags  (list[str])
        tlp / TLP / source_tlp   -> fields.trafficlightprotocol
        confidence_score / ctix_score / Confidence Score -> fields.confidence (int)
        severity                 -> fields.threatassessscore AND top-level score
        custom_attributes        -> fields.cywarecustomattribute<name>
        relations                -> relationships (via EntityRelationship.to_indicator())
        rawJSON                  -> combined raw dict (base + enrichment)
    """
    indicator_value: str = cyware_data.get("name") or cyware_data.get("sdo_name") or ""
    raw_type = cyware_data.get("ioc_type") or cyware_data.get("indicator_type", "")
    if isinstance(raw_type, dict):
        raw_type = raw_type.get("type", "")
    xsoar_type = _normalize_cyware_indicator_type(raw_type)
    severity = cyware_data.get("severity")
    dbot_score = (
        _severity_to_dbot_score(severity)
        if severity
        else confidence_to_dbot_score(cyware_data.get("confidence_score") or cyware_data.get("ctix_score"))
    )
    confidence = cyware_data.get("confidence_score") or cyware_data.get("ctix_score")
    if isinstance(confidence, str):
        try:
            confidence = float(confidence)
        except (ValueError, TypeError):
            confidence = None
    tag_names = _extract_tag_names(cyware_data.get("tags"))
    if feed_tags:
        tag_names.extend(feed_tags)
    custom_fields = {}
    source_names = _extract_source_names(cyware_data.get("sources", []))
    relationships = _build_relationships(indicator_value, xsoar_type, cyware_data.get("relations", {}), source_reliability)
    custom_attributes = {
        "custom_attributes": cyware_data.get("custom_attributes", {}),
        "custom_scores": cyware_data.get("custom_scores", {}),
    }
    if custom_attributes["custom_attributes"] or custom_attributes["custom_scores"]:
        custom_fields = {"ctixcustomattributes": json.dumps(custom_attributes)}
    # _normalize_cyware_indicator_type already set xsoar_type to File for hash types;
    # _hash_field_name just tells us which specific field (md5/sha1/sha256) to populate.
    hash_field = _hash_field_name(raw_type)
    hash_fields: dict[str, str] = {hash_field: indicator_value} if hash_field else {}

    fields: dict[str, Any] = assign_params(
        firstseenbysource=_normalize_timestamp_to_iso(cyware_data.get("ctix_created")),
        lastseenbysource=_normalize_timestamp_to_iso(cyware_data.get("ctix_modified")),
        trafficlightprotocol=tlp_color
        or cyware_data.get("source_tlp")
        or cyware_data.get("ctix_tlp")
        or cyware_data.get("analyst_tlp"),
        tags=tag_names if tag_names else None,
        confidence=confidence,
        threatassessscore=cyware_data.get("severity"),
        description=cyware_data.get("description") or None,
        reportedby=", ".join(source_names) if source_names else None,
        ctixid=cyware_data.get("id") or None,
        isfalsepositive=cyware_data.get("is_false_positive"),
        isdeprecated=cyware_data.get("is_deprecated"),
        isreviewed=cyware_data.get("is_reviewed"),
        iswhitelisted=cyware_data.get("is_whitelisted"),
    )
    if hash_fields:
        fields.update(hash_fields)
    if cyware_data.get("custom_scores"):
        custom_fields["ctixcustomscores"] = json.dumps(cyware_data["custom_scores"])

    # --- enrichment extra data ---
    enrich_objects = cyware_data.get("enrichment_data", [])
    if isinstance(enrich_objects, list) and enrich_objects:
        custom_fields["ctixenrichment"] = json.dumps(enrich_objects)
    if custom_fields:
        fields.update(custom_fields)
    # --- build indicator object ---
    # rawJSON must always be a plain dict. XSOAR's Go runtime expects
    # map[string]interface{} and will raise a ValueError if it receives a
    # JSON-encoded string instead (e.g. if cyware_data were somehow a str).
    raw_json: dict = cyware_data if isinstance(cyware_data, dict) else {}
    xsoar_indicator: dict[str, Any] = assign_params(
        value=indicator_value,
        type=xsoar_type,
        score=dbot_score,
        rawJSON=raw_json,
        fields=fields,
        relationships=relationships if relationships else None,
    )
    return xsoar_indicator


def map_ctix_indicator_to_xsoar(indicator: dict, reliability: str, enrichment_data: dict | None = None) -> dict:
    """Backward-compatible wrapper around parse_cyware_indicator.

    Merges enrichment data into the indicator dict before parsing and threads
    the source reliability through to EntityRelationship construction.
    """
    if enrichment_data:
        merged = dict(indicator)
        # Merge enrichment fields that are missing in base data
        for key in (
            "description",
            "relations",
            "enrichment_data",
            "custom_attributes",
            "confidence_score",
            "tlp",
            "first_seen",
            "last_seen",
        ):
            if enrichment_data.get(key) and not merged.get(key):
                merged[key] = enrichment_data[key]
        return parse_cyware_indicator(merged, source_reliability=reliability)
    return parse_cyware_indicator(indicator, source_reliability=reliability)


""" FETCH FUNCTIONS """


def _state_key(prefix: str, key: str) -> str:
    """Build a namespaced LastRun key for multi-instance support."""
    instance_name = demisto.integrationInstance() or "default"
    return f"{prefix}_{key}_{instance_name}"


def _parse_fetch_interval_to_minutes(fetch_interval: Any) -> int:
    """Parse feed/fetch interval values into minutes, with safe fallbacks."""
    if fetch_interval in (None, "", " "):
        return 60

    if isinstance(fetch_interval, int | float):
        return max(1, int(fetch_interval))

    raw = str(fetch_interval).strip().lower()
    if raw.isdigit():
        return max(1, int(raw))

    interval_match = re.match(r"^(\d+)\s*([a-z]+)$", raw)
    if not interval_match:
        # Try dateparser for values like "12 hours"
        now = datetime.now(UTC)
        parsed = dateparser.parse(raw, settings={"RELATIVE_BASE": now})
        if parsed:
            delta_seconds = int((parsed - now).total_seconds())
            return max(1, delta_seconds // 60)
        return 60

    value = int(interval_match.group(1))
    unit = interval_match.group(2)
    if unit.startswith("min"):
        return max(1, value)
    if unit.startswith("hour"):
        return max(1, value * 60)
    if unit.startswith("day"):
        return max(1, value * 1440)
    return max(1, value)


def _derive_iteration_threshold(interval_minutes: int) -> int:
    """Derive max pages per run from interval, per design plan."""
    if interval_minutes < 60:
        return 5
    if interval_minutes < 300:
        return 10
    return 25


def _resolve_initial_fetch_from_timestamp(from_timestamp: int, page_number: int, params: dict) -> int:
    """When LastRun has no watermark (0) and we start at page 1, use first_fetch minutes from params."""
    if from_timestamp != 0 or page_number != 1:
        return from_timestamp
    minutes = arg_to_number(params.get("first_fetch"))
    if minutes is None or minutes <= 0:
        minutes = FIRST_FETCH_DEFAULT_MINUTES
    return int(datetime.now(UTC).timestamp()) - int(minutes) * 60


def _load_fetch_state(last_run: dict, prefix: str) -> tuple[int, int, dict]:
    """Read resumable pagination state from LastRun."""
    page_key = _state_key(prefix, "page_number")
    ts_key = _state_key(prefix, "last_run_date")

    from_timestamp = arg_to_number(last_run.get(ts_key))
    if from_timestamp is None:
        from_timestamp = arg_to_number(last_run.get("last_run_date"))

    page_number = arg_to_number(last_run.get(page_key))
    if page_number is None:
        page_number = arg_to_number(last_run.get("page_number"))
    if page_number in (None, 0):
        page_number = 1

    safe_from_timestamp = int(from_timestamp) if from_timestamp is not None else 0
    safe_page_number = int(page_number) if page_number is not None else 1
    return safe_from_timestamp, safe_page_number, {"page_key": page_key, "ts_key": ts_key}


def _store_partial_fetch_state(last_run: dict, keys: dict, page_number: int, from_timestamp: int) -> dict:
    """Store partial-run state and preserve unrelated LastRun keys."""
    next_run = dict(last_run)
    next_run[keys["page_key"]] = page_number
    next_run[keys["ts_key"]] = from_timestamp
    # Compatibility keys for easier troubleshooting.
    next_run["page_number"] = page_number
    next_run["last_run_date"] = from_timestamp
    if FETCH_INCIDENTS_STATE_PREFIX in keys["page_key"]:
        next_run["last_fetch_time"] = from_timestamp
    if FETCH_INDICATORS_STATE_PREFIX in keys["page_key"]:
        next_run["last_indicator_time"] = from_timestamp
    return next_run


def _store_completed_fetch_state(last_run: dict, keys: dict) -> dict:
    """Store full-sweep completion state."""
    next_run = dict(last_run)
    completed_ts = int(time.time()) - DELTA_TIME_DIFF
    next_run[keys["page_key"]] = 0
    next_run[keys["ts_key"]] = completed_ts
    # Compatibility keys for easier troubleshooting.
    next_run["page_number"] = 0
    next_run["last_run_date"] = completed_ts
    if FETCH_INCIDENTS_STATE_PREFIX in keys["page_key"]:
        next_run["last_fetch_time"] = completed_ts
    if FETCH_INDICATORS_STATE_PREFIX in keys["page_key"]:
        next_run["last_indicator_time"] = completed_ts
    return next_run


def fetch_incidents(client: Client, params: dict, last_run: dict) -> tuple[dict, list]:
    """Fetch CTIX reports as XSOAR incidents.

    :param Client client: CTIX API client
    :param dict params: Integration instance parameters
    :param dict last_run: Previous run state from demisto.getLastRun()
    :return tuple: (next_run dict, list of incident dicts)
    """
    source_reliability = params.get("integrationReliability", "")

    max_fetch = arg_to_number(params.get("max_fetch"))
    if max_fetch is None:
        max_fetch = 10
    max_fetch = min(max(1, int(max_fetch)), 200)

    from_timestamp, page_number, state_keys = _load_fetch_state(
        last_run=last_run,
        prefix=FETCH_INCIDENTS_STATE_PREFIX,
    )
    from_timestamp = _resolve_initial_fetch_from_timestamp(from_timestamp, page_number, params)

    demisto.debug(f"CTIX fetch_incidents: from_timestamp={from_timestamp}, page_number={page_number}, max_fetch={max_fetch}")

    incidents: list[dict] = []

    custom_query = (params.get("incident_fetch_query") or "").strip() or 'type = "report"'
    final_query = f'{custom_query} AND ctix_modified >= "{from_timestamp}"'
    report_query = final_query
    demisto.debug(f"CTIX fetch_incidents: using CQL query: {report_query}")

    try:
        response = execute_with_retry(client.get_threat_data, page=page_number, page_size=max_fetch, query=report_query)
    except DemistoException as e:
        demisto.error(f"CTIX fetch_incidents: DemistoException while fetching incidents: {e}")
        return _store_partial_fetch_state(last_run, state_keys, page_number, from_timestamp), incidents

    data = response.get("data", {}) if response else {}
    results = data.get("results", []) or []
    results = results[:max_fetch]
    next_page_val: str | None = data.get("next") if isinstance(data.get("next"), str) else None
    relation_enrichment_rate_limit_failure = False

    relations_by_id: dict[str, dict] = {}
    if results:
        type_groups: dict[str, list[str]] = {}
        for report in results:
            rid = report.get("id") or ""
            sdo_type = report.get("type")
            if rid and sdo_type:
                type_groups.setdefault(sdo_type, []).append(rid)

        try:
            for object_type, ids_list in type_groups.items():
                for i in range(0, len(ids_list), ENRICHMENT_BATCH_SIZE):
                    chunk = ids_list[i : i + ENRICHMENT_BATCH_SIZE]
                    enriched_rows = _bulk_ioc_lookup_advanced_collect_all_pages(
                        client,
                        object_type=object_type,
                        values=[],
                        object_ids=chunk,
                        enrichment_data=False,
                        relation_data=True,
                        enrichment_tools=None,
                        fields=None,
                    )
                    for row in enriched_rows:
                        oid = row.get("id", "")
                        if oid:
                            relations_by_id[oid] = row.get("relations") or {}
        except DemistoException as e:
            if RATE_LIMIT_STATUS_ERR in str(e):
                relation_enrichment_rate_limit_failure = True
                demisto.error(
                    f"CTIX fetch_incidents: Rate limit hit again after retry during relation enrichment: {e}. "
                    "Continuing with base threat-data results; incidents will be mapped without full relations."
                )
            else:
                demisto.debug(f"CTIX fetch_incidents: Bulk relations lookup failed: {e}")
        except Exception as e:
            demisto.debug(f"CTIX fetch_incidents: Bulk relations lookup failed: {e}")

        for report in results:
            report_id = report.get("id", "")
            relations_data = relations_by_id.get(report_id, {}) if report_id else {}
            incident = map_report_to_incident(report, relations=relations_data, source_reliability=source_reliability)
            incidents.append(incident)
    else:
        demisto.debug("CTIX fetch_incidents: No results on this page")

    if relation_enrichment_rate_limit_failure:
        if next_page_val:
            demisto.error(
                f"CTIX fetch_incidents: Relation enrichment failed (rate limit after retries). "
                f"Returning {len(incidents)} incident(s) from base fetch without full relations. "
                f"Checkpoint: threat-data page_number={page_number}, next run will use page_number={page_number + 1}."
            )
        else:
            demisto.error(
                f"CTIX fetch_incidents: Relation enrichment failed (rate limit after retries). "
                f"Returning {len(incidents)} incident(s) from base fetch without full relations. "
                f"Checkpoint: completing sweep for this interval (no further threat-data pages); LastRun will advance."
            )

    if next_page_val:
        return _store_partial_fetch_state(last_run, state_keys, page_number + 1, from_timestamp), incidents

    return _store_completed_fetch_state(last_run, state_keys), incidents


def _collect_saved_result_set_indicators(
    client: Client,
    from_timestamp: int,
    page_number: int,
    iteration_threshold: int,
    label_name: str | None,
    version: str | None,
    to_timestamp: int,
) -> tuple[list[dict], int, bool]:
    """Paginate through the saved result set endpoint and collect raw indicator dicts.

    Uses the existing ``client.saved_result_set()`` method.
    All object types returned by the API are collected; type normalisation into the
    correct XSOAR indicator type is handled downstream by ``parse_cyware_indicator``.
    Deduplication is intentionally delegated to ``demisto.createIndicators`` at submission time.
    """
    all_indicators: list[dict] = []
    page_size = PAGE_SIZE
    current_page_number = page_number
    pages_processed = 0

    try:
        response = execute_with_retry(
            client.saved_result_set,
            page=current_page_number,
            page_size=page_size,
            label_name=label_name,
            version=version,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
        )
    except DemistoException as e:
        demisto.error(f"CTIX fetch_indicators: Error at initial request: {e}")
        return all_indicators, current_page_number, False

    while response and pages_processed < iteration_threshold:
        data = response.get("data", {}) if response else {}
        result_sets = data.get("results", [])

        if not result_sets:
            demisto.debug("CTIX fetch_indicators: No more results")
            return all_indicators, current_page_number, True

        for result_set in result_sets:
            indicators_data = result_set.get("data", [])
            if not indicators_data:
                continue
            for ind in indicators_data:
                all_indicators.append(ind)

        # Move to the next page for pagination
        next_url = data.get("next")
        pages_processed += 1
        if not next_url:
            return all_indicators, current_page_number, True

        current_page_number += 1
        if pages_processed >= iteration_threshold:
            demisto.debug(
                f"CTIX fetch_indicators: Iteration threshold reached at page_number={current_page_number}, "
                "saving checkpoint for next run"
            )
            return all_indicators, current_page_number, False

        try:
            response = execute_with_retry(
                client.saved_result_set,
                page=current_page_number,
                page_size=page_size,
                label_name=label_name,
                version=version,
                from_timestamp=from_timestamp,
                to_timestamp=to_timestamp,
            )
        except DemistoException as e:
            if RATE_LIMIT_STATUS_ERR in str(e):
                demisto.error(f"CTIX fetch_indicators: Rate limit hit again during pagination: {e}")
                return all_indicators, current_page_number, False
            demisto.error(f"CTIX fetch_indicators: Error following next page: {e}")
            return all_indicators, current_page_number, False

    return all_indicators, current_page_number, False


def _merge_enrichment_into_indicators(
    base_indicators: list[dict],
    enrichment_map: dict[str, dict],
) -> list[dict]:
    """Merge enrichment data (custom_attributes, relations, etc.) into base indicator dicts.

    Returns a new list of merged dicts; original dicts are not mutated.
    """
    merged: list[dict] = []
    for ind in base_indicators:
        ind_id = ind.get("id") or ""
        enrich = enrichment_map.get(ind_id)
        if enrich:
            combined = dict(ind)
            # Merge keys from enrichment that add new information
            # Fill missing fields from enrichment; relations/custom_attributes handled below
            for key in (
                "description",
                "enrichment_data",
                "confidence_score",
                "tlp",
                "first_seen",
                "last_seen",
                "country",
            ):
                if enrich.get(key) and not combined.get(key):
                    combined[key] = enrich[key]
            # Always prefer enrichment relations/custom_attributes when present
            if enrich.get("relations"):
                combined["relations"] = enrich["relations"]
            if enrich.get("custom_attributes"):
                combined["custom_attributes"] = enrich["custom_attributes"]
            merged.append(combined)
        else:
            merged.append(ind)
    return merged


def fetch_indicators(client: Client, params: dict, last_run: dict) -> tuple[dict, list]:
    """Fetch indicators from CTIX saved result sets.

    Flow:
        1. Collect base IOC data via the existing ``client.saved_result_set()`` method.
        2. If ``retrieve_enriched_data`` (if_enrich) is True, enrich via bulk IOC lookup.
        3. Merge enrichment data back into the base IOC dicts.
        4. Map each merged dict to an XSOAR indicator via ``parse_cyware_indicator``.
        5. Return (next_run, indicators). Caller is responsible for ``demisto.createIndicators``.

    :param Client client: CTIX API client
    :param dict params: Integration instance parameters
    :param dict last_run: Previous run state from demisto.getLastRun()
    :return tuple: (next_run dict, list of XSOAR indicator dicts)
    """
    label_name = params.get("saved_result_set_label")
    version = params.get("saved_result_set_version")
    if_enrich: bool = argToBoolean(params.get("retrieve_enriched_data", False))
    feed_tags = argToList(params.get("feedTags"))
    tlp_color: str = params.get("tlp_color", "") or ""

    from_timestamp, page_number, state_keys = _load_fetch_state(
        last_run=last_run,
        prefix=FETCH_INDICATORS_STATE_PREFIX,
    )
    from_timestamp = _resolve_initial_fetch_from_timestamp(from_timestamp, page_number, params)
    fetch_interval_minutes = _parse_fetch_interval_to_minutes(params.get("feedFetchInterval"))
    iteration_threshold = _derive_iteration_threshold(fetch_interval_minutes)

    demisto.debug(
        f"CTIX fetch_indicators: from_timestamp={from_timestamp}, page_number={page_number}, "
        f"iteration_threshold={iteration_threshold}"
    )

    current_time = int(datetime.now(UTC).timestamp())

    # Step 1: Collect base IOC data using existing saved_result_set action
    all_indicators_raw, next_page_number, completed_sweep = _collect_saved_result_set_indicators(
        client=client,
        from_timestamp=from_timestamp,
        page_number=page_number,
        iteration_threshold=iteration_threshold,
        label_name=label_name,
        version=version,
        to_timestamp=current_time,
    )
    demisto.debug(f"CTIX fetch_indicators: Collected {len(all_indicators_raw)} raw indicators")

    # Step 2 & 3: Optionally enrich and merge
    if if_enrich and all_indicators_raw:
        enrichment_map = enrich_indicators_bulk(client, all_indicators_raw)
        if enrichment_map:
            all_indicators_raw = _merge_enrichment_into_indicators(all_indicators_raw, enrichment_map)
            demisto.debug(f"CTIX fetch_indicators: Enriched {len(enrichment_map)} indicators")

    # Step 4: Map to XSOAR indicator format
    xsoar_indicators: list[dict] = []
    source_reliability = params.get("feedReliability", "")
    for ind in all_indicators_raw:
        xsoar_ind = parse_cyware_indicator(ind, source_reliability=source_reliability, feed_tags=feed_tags, tlp_color=tlp_color)
        if xsoar_ind.get("value"):
            xsoar_indicators.append(xsoar_ind)

    demisto.debug(f"CTIX fetch_indicators: Mapped {len(xsoar_indicators)} indicators")

    if completed_sweep:
        next_run = _store_completed_fetch_state(last_run, state_keys)
    else:
        next_run = _store_partial_fetch_state(last_run, state_keys, next_page_number, from_timestamp)

    return next_run, xsoar_indicators


def _bulk_ioc_lookup_advanced_collect_all_pages(
    client: Client,
    object_type: str,
    values: list[str],
    object_ids: list[str],
    enrichment_data: bool,
    relation_data: bool,
    enrichment_tools: str | None = None,
    fields: str | None = None,
) -> list[dict]:
    """Call bulk IOC lookup advanced and increment page params until exhausted or max pages reached."""
    all_rows: list[dict] = []
    current_page = 1
    while current_page <= BULK_LOOKUP_MAX_PAGES:
        response = execute_with_retry(
            client.bulk_ioc_lookup_advanced,
            object_type=object_type,
            values=values,
            object_ids=object_ids,
            enrichment_data=enrichment_data,
            relation_data=relation_data,
            enrichment_tools=enrichment_tools,
            fields=fields,
            page=current_page,
            page_size=BULK_LOOKUP_PAGE_SIZE,
        )
        if not response:
            break
        data = response.get("data")
        if not isinstance(data, dict):
            break
        rows = data.get("results", [])
        if isinstance(rows, list):
            all_rows.extend(rows)
        next_url = data.get("next")
        if not next_url:
            break
        current_page += 1
    return all_rows


def enrich_indicators_bulk(client: Client, indicators: list[dict]) -> dict[str, dict]:
    """Enrich indicators via bulk IOC lookup advanced.

    Groups indicators by SDO type, batches up to ENRICHMENT_BATCH_SIZE per request,
    and returns a mapping of indicator_id -> enrichment_data.

    :param Client client: CTIX API client
    :param list indicators: List of raw indicator dicts
    :return dict: Mapping of indicator id to enrichment response
    """
    enrichment_map: dict[str, dict] = {}

    # Group by SDO object type
    type_groups: dict[str, list[str]] = {}
    for ind in indicators:
        ind_id = ind.get("id") or ""
        sdo_type = ind.get("sdo_type") or ind.get("type") or "indicator"
        if ind_id:
            type_groups.setdefault(sdo_type, []).append(ind_id)

    for object_type, object_ids in type_groups.items():
        # Batch into chunks of ENRICHMENT_BATCH_SIZE (100)
        for i in range(0, len(object_ids), ENRICHMENT_BATCH_SIZE):
            batch_object_ids = object_ids[i : i + ENRICHMENT_BATCH_SIZE]
            try:
                enriched_list = _bulk_ioc_lookup_advanced_collect_all_pages(
                    client,
                    object_type=object_type,
                    values=[],
                    object_ids=batch_object_ids,
                    enrichment_data=True,
                    relation_data=True,
                    enrichment_tools=None,
                    fields=None,
                )
                for enriched in enriched_list:
                    enriched_id = enriched.get("id") or ""
                    if enriched_id:
                        enrichment_map[enriched_id] = enriched
            except DemistoException as e:
                if RATE_LIMIT_STATUS_ERR in str(e):
                    demisto.error(
                        f"CTIX enrich_indicators_bulk: Rate limit hit again after retry. Returning partial results. Error: {e}"
                    )
                    return enrichment_map
                demisto.debug(f"CTIX enrich_indicators_bulk: Partial failure for batch of {object_type}: {e}")
                continue

    demisto.debug(f"CTIX enrich_indicators_bulk: Enriched {len(enrichment_map)} indicators")
    return enrichment_map


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Performs basic get request to get sample ip details.
    """
    client.test_auth()
    # test was successful
    demisto.results("ok")


def create_tag_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    create_tag command: Creates a new tag in the CTIX platform
    """
    name = args["tag_name"]
    color_name = args["color"]

    color_code = tag_colors[color_name]

    response = client.create_tag(name, color_code)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Tag Data", data, removeNull=True),
            outputs_prefix="CTIX.Tag",
            outputs_key_field="name",
            outputs=data,
            raw_response=data,
        )
        return results


def get_tags_command(client: Client, args=dict[str, Any]) -> List[CommandResults]:
    """
    get_tags commands: Returns paginated list of tags
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    query = args.get("q", "")
    response = client.get_tags(page, page_size, query)
    response_data = response.get("data", {})
    tags_list = response_data.get("results", [])
    tags_list = no_result_found(tags_list)
    if isinstance(tags_list, CommandResults):
        return [tags_list]
    else:
        results = []
        for tag in tags_list:
            results.append(
                CommandResults(
                    readable_output=tableToMarkdown("Tag Data", tag, removeNull=True),
                    outputs_prefix="CTIX.Tag",
                    outputs_key_field="name",
                    outputs=response_data,
                    raw_response=response,
                )
            )
        return results


def disable_or_enable_tags_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Disable/Enable Tags command

    :Description Disable or Enable tags in CTIX platform
    :param Dict[str, Any] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    tag_ids = argToList(args.get("tag_ids"))
    action = args.get("action") or "enabled"
    response = client.disable_or_enable_tag(tag_ids=tag_ids, action=action.lower())
    final_result = response.get("data", {})
    final_result = no_result_found(final_result)
    if isinstance(final_result, CommandResults):
        return final_result
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Tag Response", [final_result], removeNull=True),
            outputs_prefix="CTIX.TagAction",
            outputs_key_field="result",
            outputs=final_result,
            raw_response=final_result,
        )
        return results


def whitelist_iocs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Whitelist IOCs command

    :Description Whitelist IOCs for a given value
    :param Dict[str, Any] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    ioc_type = args.get("type")
    values = args.get("values")
    values = argToList(values)
    reason = args.get("reason")

    data = client.whitelist_iocs(ioc_type, values, reason).get("data", {}).get("details", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Whitelist IOC", data, removeNull=True),
            outputs_prefix="CTIX.AllowedIOC",
            outputs=data,
            raw_response=data,
        )
        return results


def get_whitelist_iocs_command(client: Client, args=dict[str, Any]) -> List[CommandResults]:
    """
    get_tags commands: Returns paginated list of tags
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    query = args.get("q")
    response = client.get_whitelist_iocs(page, page_size, query)
    response_data = response.get("data", {})
    ioc_list = response_data.get("results", [])
    ioc_list = no_result_found(ioc_list)
    if isinstance(ioc_list, CommandResults):
        return [ioc_list]
    else:
        results = []
        for ioc in ioc_list:
            results.append(
                CommandResults(
                    readable_output=tableToMarkdown("Whitelist IOC", ioc, removeNull=True),
                    outputs_prefix="CTIX.IOC",
                    outputs_key_field="value",
                    outputs=response_data,
                    raw_response=response,
                )
            )
        return results


def remove_whitelisted_ioc_command(client: Client, args=dict[str, Any]) -> CommandResults:
    """
    remove_whitelist_ioc: Deletes a whitelisted ioc with given id
    """
    whitelist_id = argToList(args.get("ids"))
    response = client.remove_whitelisted_ioc(whitelist_id)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Details", data, removeNull=True),
            outputs_prefix="CTIX.RemovedIOC",
            outputs_key_field="detail",
            outputs=data,
            raw_response=data,
        )
        return results


def get_threat_data_command(client: Client, args=dict[str, Any]) -> List[CommandResults]:
    """
    get_threat_data: List thread data and allow query
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    query = args.get("query", "type=indicator")
    response = client.get_threat_data(page, page_size, query)
    threat_data_list = response.get("data", {}).get("results", [])
    results = list(threat_data_list)
    results = no_result_found(results)
    reliability = args.get("reliability")

    if isinstance(results, CommandResults):
        return [results]
    else:
        result = iter_dbot_score(
            results,
            "confidence_score",
            "ioc_type",
            "Threat Data",
            "CTIX.ThreatData",
            "id",
            reliability,
        )
        return result


def get_saved_searches_command(client: Client, args=dict[str, Any]) -> CommandResults:
    """
    get_saved_searches: List saved search data
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    response = client.get_saved_searches(page, page_size)
    response_data = response.get("data", {})
    data_list = response_data.get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown("Saved Search", results, removeNull=True),
            outputs_prefix="CTIX.SavedSearch",
            outputs_key_field="id",
            outputs=response_data,
            raw_response=response_data,
        )
        return result


def get_server_collections_command(client: Client, args=dict[str, Any]) -> CommandResults:
    """
    get_server_collections: List server collections
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    response = client.get_server_collections(page, page_size)
    response_data = response.get("data", {})
    data_list = response_data.get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown("Server Collection", results, removeNull=True),
            outputs_prefix="CTIX.ServerCollection",
            outputs_key_field="id",
            outputs=response_data,
            raw_response=response_data,
        )
        return result


def get_actions_command(client: Client, args=dict[str, Any]) -> CommandResults:
    """
    get_actions: List Actions
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    object_type = args.get("object_type")
    action_type = args.get("actions_type")
    params = {}
    if action_type:
        params["action_type"] = action_type
    if object_type:
        params["object_type"] = object_type
    response = client.get_actions(page, page_size, params)
    response_data = response.get("data", {})
    data_list = response_data.get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown("Actions", results, removeNull=True),
            outputs_prefix="CTIX.Action",
            outputs_key_field="id",
            outputs=response_data,
            raw_response=response_data,
        )
        return result


def add_indicator_as_false_positive_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Add Indicator as False Positive Command

    :Description Add Indicator as False Positive for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_ids = args.get("object_ids")
    object_type = args.get("object_type", "indicator")
    object_ids = argToList(object_ids)
    response = client.add_indicator_as_false_positive(object_ids, object_type)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Indicator False Positive", data, removeNull=True),
            outputs_prefix="CTIX.IndicatorFalsePositive",
            outputs=data,
            raw_response=data,
        )

        return results


def add_ioc_manual_review_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add IOC for Manual Review Command

    :Description Add IOC for Manual Review for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_ids = args.get("object_ids")
    object_type = args.get("object_type", "indicator")
    object_ids = argToList(object_ids)
    response = client.add_ioc_to_manual_review(object_ids, object_type)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("IOC Manual Review", data, removeNull=True),
            outputs_prefix="CTIX.IOCManualReview",
            outputs=data,
            raw_response=data,
        )

        return results


def deprecate_ioc_command(client: Client, args: dict) -> CommandResults:
    """
    deprecate_ioc command: Deprecate indicators bulk api
    """
    object_ids = args.get("object_ids")
    object_type = args["object_type"]
    object_ids = argToList(object_ids)
    response = client.deprecate_ioc(object_ids, object_type)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Deprecate IOC", data, removeNull=True),
            outputs_prefix="CTIX.DeprecateIOC",
            outputs=data,
            raw_response=data,
        )

        return results


def add_analyst_tlp_command(client: Client, args: dict) -> CommandResults:
    """
    Add Analyst TLP Command

    :Description Add Analyst TLP for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_id = args["object_id"]
    object_type = args["object_type"]
    data = json.loads(args["data"])

    analyst_tlp = data.get("analyst_tlp")
    if not analyst_tlp:
        raise DemistoException("analyst_tlp not provided")

    response = client.add_analyst_tlp(object_id, object_type, data)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Add Analyst TLP", data, removeNull=True),
            outputs_prefix="CTIX.AddAnalystTLP",
            outputs=data,
            raw_response=data,
        )

        return results


def add_analyst_score_command(client: Client, args: dict) -> CommandResults:
    """
    Add Analyst Score Command

    :Description Add Analyst Score for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_id = args["object_id"]
    object_type = args.get("object_type")
    data = json.loads(args.get("data", "{}"))

    analyst_tlp = data.get("analyst_score")
    if not analyst_tlp:
        raise DemistoException("analyst_score not provided")

    response = client.add_analyst_score(object_id, object_type, data)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Add Analyst Score", data, removeNull=True),
            outputs_prefix="CTIX.AddAnalystScore",
            outputs=data,
            raw_response=data,
        )
        return results


def saved_result_set_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Saved Result Set data Command

    :Description Get Saved Result Set data
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = int(check_for_empty_variable(args["page"], 1))
    page_size = int(check_for_empty_variable(args["page_size"], 10))
    version = args.get("version")
    label_name = args.get("label_name")
    response = client.saved_result_set(page, page_size, label_name, version)
    data = response.get("data", {})
    data_list = data.get("results", [])
    data_list = no_result_found(data_list)

    if isinstance(data_list, CommandResults):
        return data_list
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Saved Result Set", data_list, removeNull=True),
            outputs_prefix="CTIX.SavedResultSet",
            outputs_key_field="id",
            outputs=data,
            raw_response=data,
        )
        return results


def tag_indicator_updation_command(client: Client, args: dict[str, Any], operation: str) -> CommandResults:
    """
    Tag Indicator Updation Command

    :Description Updating Tag of a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    tag_id = args["tag_id"]
    query = args.get("q", {})

    response = client.tag_indicator_updation(query, page, page_size, object_id, object_type, tag_id, operation)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Tag Indicator Updation", data, removeNull=True),
            outputs_prefix="CTIX.TagUpdation",
            outputs=data,
            raw_response=data,
        )

        return results


def search_for_tag_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Search for Tag Command

    :Description Search for Tag
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    q = args.get("q")
    params = {"page": page, "page_size": page_size, "q": q}

    response = client.search_for_tag(params)
    response_data = response.get("data", {})
    data = response_data.get("results", [])
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Search for Tag", data, removeNull=True),
            outputs_prefix="CTIX.SearchTag",
            outputs=response_data,
            raw_response=response_data,
        )

        return results


def get_indicator_details_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Indicator Details Command

    :Description Get Indicator Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}

    response = client.get_indicator_details(object_type.lower(), object_id, params)
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Get Indicator Details", data, removeNull=True),
            outputs_prefix="CTIX.IndicatorDetails",
            outputs=data,
            raw_response=data,
        )
        return results


def get_indicator_tags_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Indicator Tags  Command

    :Description Get Tags Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}

    response = client.get_indicator_tags(object_type, object_id, params)
    data = response.get("data", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Get Indicator Tags", data, removeNull=True),
            outputs_prefix="CTIX.IndicatorTags",
            outputs=data,
            raw_response=data,
        )

        return results


def get_indicator_relations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Indicator Relations Command

    :Description Get Relations Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}
    response = client.get_indicator_relations(object_type, object_id, params)
    response_data = response.get("data", {})
    data = response_data.get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Get Object Relations", data, removeNull=True),
            outputs_prefix="CTIX.IndicatorRelations",
            outputs=response_data,
            raw_response=response_data,
        )

        return results


def get_indicator_observations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Indicator Observations Command

    :Description Get Indicator Observations
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args.get("object_id")
    object_type = args.get("object_type")
    params = {
        "page": page,
        "page_size": page_size,
        "object_id": object_id,
        "object_type": object_type,
    }

    response = client.get_indicator_observations(params)
    response_data = response.get("data", {})
    data = response_data.get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Get Indicator Observations", data, removeNull=True),
            outputs_prefix="CTIX.IndicatorObservations",
            outputs=response_data,
            raw_response=response_data,
        )

        return results


def get_conversion_feed_source_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get Conversion Feed Source Command

    :Description Get Conversion Feed Source
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args.get("object_id")
    object_type = args.get("object_type")
    params = {
        "page": page,
        "page_size": page_size,
        "object_id": object_id,
        "object_type": object_type,
    }
    q = args.get("q")
    if q is not None:
        params.update({"q": q})

    response = client.get_conversion_feed_source(params)
    response_data = response.get("data", {})
    data = response_data.get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Conversion Feed Source", data, removeNull=True),
            outputs_prefix="CTIX.ConversionFeedSource",
            outputs=response_data,
            raw_response=response_data,
        )

        return results


def get_lookup_threat_data_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get Lookup Threat Data Command
    :Description Get Lookup Threat Data
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_type = args.get("object_type", "indicator")
    ioc_type = argToList(args.get("ioc_type"))
    object_names = argToList(args.get("object_names"))
    page_size = args.get("page_size", 10)
    params = {"page_size": page_size}
    response = client.get_lookup_threat_data(object_type, ioc_type, object_names, params)
    data_set = response.get("data").get("results")
    results = no_result_found(data_set)
    reliability = args.get("reliability")

    if isinstance(results, CommandResults):
        return [results]
    else:
        results = iter_dbot_score(
            results, "confidence_score", "ioc_type", "Lookup Data", "CTIX.ThreatDataLookup", "id", reliability
        )
        return results


def get_create_threat_data_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Get or Create Threat Data Command

    :Description Gets Threat Data or creates it if it does not exist
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    """
    object_names = argToList(args.get("object_names"))
    source = args.get("source", "XSOAR")
    collection = args.get("collection", "Intel")
    page_size = args.get("page_size", 10)
    reliability = args.get("reliability")
    created_after_lookup_results = []
    invalid_values_results = []

    response = client.bulk_lookup_and_create_data(object_names, source, collection, page_size).get("data", {})
    results = response.get("found_iocs", {}).get("results", [])
    created_after_lookup = response["values_not_found"]["valid_iocs"]
    invalid_values = response["values_not_found"]["invalid_values"]

    if created_after_lookup:
        created_after_lookup_results.append(
            CommandResults(
                readable_output=tableToMarkdown("Not Found: Created", created_after_lookup, headers=["Name"], removeNull=True),
                outputs_prefix="CTIX.ThreatDataGetCreate.NotFoundCreated",
                outputs=created_after_lookup,
            )
        )

    if invalid_values:
        invalid_values_results.append(
            [
                CommandResults(
                    readable_output=tableToMarkdown("Not Found: Invalid", invalid_values, headers=["Name"], removeNull=True),
                    outputs_prefix="CTIX.ThreatDataGetCreate.NotFoundInvalid",
                    outputs=invalid_values,
                )
            ]
        )

    if isinstance(results, CommandResults):
        return [results]
    else:
        results = iter_dbot_score(
            results,
            "confidence_score",
            "ioc_type",
            "Lookup Data",
            "CTIX.ThreatDataGetCreate.Found",
            "id",
            reliability,
        )

        return results + created_after_lookup_results + invalid_values_results


def domain(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    args["object_names"] = args["domain"]
    args["ioc_type"] = ["domain-name"]
    return get_lookup_threat_data_command(client, args)


def bulk_ioc_lookup_advanced_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Bulk IOC Lookup Advanced command
    """
    object_type: str = args.get("object_type") or ""
    values = argToList(args.get("values"))
    object_ids = argToList(args.get("object_ids"))
    enrichment_data: bool = argToBoolean(args.get("enrichment_data", "true"))
    relation_data: bool = argToBoolean(args.get("relation_data", "false"))
    enrichment_tools: str | None = args.get("enrichment_tools") or None
    fields: str | None = args.get("fields") or None
    page_size = arg_to_number(args.get("page_size", 10))
    page = arg_to_number(args.get("page", 1))

    response = client.bulk_ioc_lookup_advanced(
        object_type=object_type,
        values=values,
        object_ids=object_ids,
        enrichment_data=enrichment_data,
        relation_data=relation_data,
        enrichment_tools=enrichment_tools,
        fields=fields,
        page_size=page_size,
        page=page,
    )

    response_data = response.get("data")
    result = response_data.get("results", []) if isinstance(response_data, dict) else []
    checked = no_result_found(result)

    if isinstance(checked, CommandResults):
        return checked
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Bulk IOC Lookup (Advanced)", result, removeNull=True),
            outputs_prefix="CTIX.BulkIOCLookupAdvanced",
            outputs=response_data,
            raw_response=response,
        )


def url(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    args["object_names"] = args["url"]
    args["ioc_type"] = ["url"]
    return get_lookup_threat_data_command(client, args)


def ip(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    args["object_names"] = args["ip"]
    args["ioc_type"] = ["ipv4-addr", "ipv6-addr"]
    return get_lookup_threat_data_command(client, args)


def file(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    args["object_names"] = args["file"]
    args["ioc_type"] = [
        "MD5",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SSDEEP",
    ]
    return get_lookup_threat_data_command(client, args)


def get_all_notes(client: Client, args: dict[str, Any]) -> CommandResults:
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    response = {}
    object_id = args.get("object_id", "")
    params = {
        "page": page,
        "page_size": page_size,
    }

    if object_id:
        if not is_valid_uuid(object_id):
            return_error("Error: The object ID that was provided is not valid.")
        else:
            params["object_id"] = object_id

    client_url = client.base_url + "ingestion/notes/"
    response = client.get_http_request(client_url, **params)
    response_data = response.get("data", {})
    notes_list = response_data.get("results", [])
    notes_list = no_result_found(notes_list)

    if isinstance(notes_list, CommandResults):
        return notes_list
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Note Data", notes_list, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="id",
            outputs=response_data,
            raw_response=response_data,
        )


def get_note_details(client: Client, args: dict[str, Any]) -> CommandResults:
    id = args["id"]
    client_url = client.base_url + f"ingestion/notes/{id}/"
    response = client.get_http_request(client_url)

    if response["status"] == HTTPStatus.BAD_REQUEST:
        return_error("Error: Note details could not be retrieved because a note with the provided ID could not be found.")

    note_detail = response.get("data", {})
    note_detail = no_result_found(note_detail)

    if isinstance(note_detail, CommandResults):
        return note_detail
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Note Detail Data", note_detail, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="id",
            outputs=note_detail,
        )


def create_note(client: Client, args: dict[str, Any]) -> CommandResults:
    text = args["text"]
    client_url = client.base_url + "ingestion/notes/"
    object_id = args.get("object_id", None)
    object_id = check_for_empty_variable(object_id, None)
    object_type = args.get("object_type", None)
    object_type = check_for_empty_variable(object_type, None)

    if object_id and not is_valid_uuid(object_id):
        return_error("Error: The `object_id` that was provided is not valid.")
    elif object_id and not object_type:
        return_error("Error: `object_type` must be set as well if `object_id` is provided.")
    elif object_type and not object_id:
        return_error("Error: `object_id` must be set as well if `object_type` is provided.")

    payload = {"text": text, "type": "notes", "meta_data": {"component": "notes"}}

    if object_id:
        payload["meta_data"]["component"] = "threatdata"
        payload["meta_data"]["object_id"] = object_id
        payload["meta_data"]["type"] = object_type
        payload["object_id"] = object_id
        payload["type"] = "threatdata"

    response = client.post_http_request(client_url, payload=payload, params={})
    resp = response.get("data", {})
    resp = no_result_found(resp)

    if isinstance(resp, CommandResults):
        return resp
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Created Note Data", resp, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="id",
            outputs=resp,
        )


def update_note(client: Client, args: dict[str, Any]) -> CommandResults:
    id = args["id"]
    text = args.get("text", None)
    client_url = client.base_url + f"ingestion/notes/{id}/"
    object_id = args.get("object_id", None)
    object_id = check_for_empty_variable(object_id, None)
    object_type = args.get("object_type", None)
    object_type = check_for_empty_variable(object_type, None)

    if object_id and not is_valid_uuid(object_id):
        return_error("Error: The `object_id` that was provided is not valid.")
    elif object_id and not object_type:
        return_error("Error: `object_type` must be set as well if `object_id` is provided.")
    elif object_type and not object_id:
        return_error("Error: `object_id` must be set as well if `object_type` is provided.")

    payload = {}

    if text:
        payload["text"] = text

    if object_id:
        payload["meta_data"] = {}
        payload["meta_data"]["component"] = "threatdata"
        payload["meta_data"]["object_id"] = object_id
        payload["meta_data"]["type"] = object_type
        payload["object_id"] = object_id
        payload["type"] = "threatdata"

    if not payload:
        return CommandResults(readable_output="Finished processing. No values to update.")

    response = client.put_http_request(client_url, payload=payload, params={})

    if response["status"] == HTTPStatus.BAD_REQUEST:
        return_error("Error: The note could not be updated because a note with the provided ID could not be found.")

    resp = response.get("data", {})
    resp = no_result_found(resp)

    if isinstance(resp, CommandResults):
        return resp
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Updated Note Data", resp, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="id",
            outputs=resp,
        )


def delete_note(client: Client, args: dict[str, Any]) -> CommandResults:
    id = args["id"]
    client_url = client.base_url + f"ingestion/notes/{id}/"
    response = client.delete_http_request(client_url)

    if response["status"] == HTTPStatus.BAD_REQUEST:
        return_error("Error: The note could not be deleted because a note with the provided ID could not be found.")

    resp = response.get("data", {})
    resp = no_result_found(resp)

    if isinstance(resp, CommandResults):
        return resp
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Deleted Note Data", resp, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="details",
            outputs=resp,
        )


def make_request(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    type = args["type"]
    body = json.loads(args.get("body", "{}"))
    params = json.loads(args.get("params", "{}"))
    client_url = client.base_url + args["endpoint"].lstrip("/")
    response = {}

    if type == "GET":
        response = client.get_http_request(client_url, body, params=params)
    elif type == "POST":
        response = client.post_http_request(client_url, body, params=params)
    elif type == "PUT":
        response = client.put_http_request(client_url, body, params=params)
    elif type == "DELETE":
        response = client.delete_http_request(client_url, body, params=params)

    resp = response.get("data", {})

    if "results" in resp:
        resp = resp["results"]

    resp = no_result_found(resp)

    if isinstance(resp, CommandResults):
        return [resp]
    else:
        if isinstance(resp, list):
            results = []
            for item in resp:
                results.append(
                    CommandResults(
                        readable_output=tableToMarkdown("HTTP Response Data", item, removeNull=True),
                        outputs_prefix=f"CTIX.Request.{type}.{args['endpoint']}",
                        outputs=item,
                    )
                )
            return results
        else:
            return [
                CommandResults(
                    readable_output=tableToMarkdown("HTTP Response Data", resp, removeNull=True),
                    outputs_prefix=f"CTIX.Request.{type}.{args['endpoint']}",
                    outputs=resp,
                )
            ]


def cve_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    page = 1
    page_size = 15
    params = {"page": page, "page_size": page_size}
    cve = argToList(args["cve"])
    extra_fields = argToList(args.get("extra_fields", []))
    response = client.get_lookup_threat_data("vulnerability", [], cve, params)
    threat_data_list = response.get("data", {}).get("results", [])
    results = list(threat_data_list)
    results = no_result_found(results)

    if isinstance(results, CommandResults):
        return [results]

    final_results = []
    for result in results:
        final_results.append(_lookup_cve_result(client, result, page, page_size, extra_fields))
    return final_results


def _lookup_cve_result(client: Client, cve_detail: dict[str, Any], page: int, page_size: int, extra_fields: List[str]):
    cve_uuid = str(cve_detail.get("id"))
    created = str(datetime.fromtimestamp(cve_detail.get("created", 0)))
    modified = str(datetime.fromtimestamp(cve_detail.get("modified", 0)))
    name = cve_detail.get("name")
    extra_field_values = {k: cve_detail.get(k, None) for k in extra_fields}
    cve_sources = [source.get("id") for source in cve_detail.get("sources", []) if source.get("id")]

    response = client.get_vulnerability_product_details(cve_uuid, page, page_size)
    product_details_list = response.get("data", {}).get("results", [])
    results = list(product_details_list)
    cpe_list = ",\n".join(product.get("product") for product in results)

    response = client.get_vulnerability_cvss_score(cve_uuid, page, page_size)
    cvss_score_list = response.get("data", {}).get("results", [])
    cvss2 = next((result.get("cssv2") for result in cvss_score_list if result.get("cssv2")), None)
    cvss3 = next((result.get("cssv3") for result in cvss_score_list if result.get("cssv3")), None)
    cvss_map_value = 0
    if cvss3:
        cvss_map_value = cvss3
    elif cvss2:
        cvss_map_value = cvss2

    dbot_reputation_score = 0
    if 0 < cvss_map_value < 3:
        dbot_reputation_score = 1
    elif 3 <= cvss_map_value < 7:
        dbot_reputation_score = 2
    elif cvss_map_value >= 7:
        dbot_reputation_score = 3

    description = None
    if cve_sources:
        for source in cve_sources:
            response = client.get_vulnerability_source_description(cve_uuid, source, page, page_size)
            source_description = response.get("data", {}).get("result", {})
            if source_description:
                description = source_description.get("description")
                if description:
                    break

    cve_standard_context = Common.CVE(name, cvss2, created, modified, description)
    data = {
        "cpes": cpe_list or "None",
        "cvss2": cvss2 or "None",
        "cvss3": cvss3 or "None",
        "dbot_reputation": dbot_reputation_score,
        "description": description,
        "last_modified": modified,
        "last_published": created,
        "name": name,
        "uuid": cve_uuid,
        "extra_data": json.dumps(extra_field_values),
    }
    return CommandResults(
        readable_output=tableToMarkdown("Get CVE Information", data, removeNull=True),
        outputs_prefix="CTIX.VulnerabilityLookup",
        outputs=data,
        outputs_key_field="id",
        indicator=cve_standard_context,
        raw_response=data,
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = params.get("base_url")
    access_id = params.get("access_id")
    secret_key = params.get("secret_key")
    verify = not params.get("insecure", False)
    timeout = arg_to_number(params.get("timeout")) or 180
    reliability = params.get("integrationReliability", DBotScoreReliability.C)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability)
    else:
        raise Exception("Please provide a valid value for the Source Reliability parameter.")

    args["reliability"] = reliability
    proxies = handle_proxy(proxy_param_name="proxy")
    demisto.debug(f"Command being called is {demisto.command()}")

    try:
        client = Client(
            base_url=base_url, access_id=access_id, secret_key=secret_key, verify=verify, proxies=proxies, timeout=timeout
        )

        command = demisto.command()

        if command == "test-module":
            test_module(client)

        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, params, last_run)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "fetch-indicators":
            last_run = demisto.getLastRun()
            next_run, indicators = fetch_indicators(client, params, last_run)
            # Submit indicators in manageable batches to reduce command payload size.
            for iter_ in batch(indicators, batch_size=1000):
                demisto.createIndicators(iter_)
            demisto.setLastRun(next_run)

        else:
            CMD_TO_FUNC = {
                "ctix-create-tag": (create_tag_command, (client, args)),
                "ctix-get-tags": (get_tags_command, (client, args)),
                "ctix-disable-or-enable-tags": (disable_or_enable_tags_command, (client, args)),
                "ctix-allowed-iocs": (whitelist_iocs_command, (client, args)),
                "ctix-get-allowed-iocs": (get_whitelist_iocs_command, (client, args)),
                "ctix-remove-allowed-ioc": (remove_whitelisted_ioc_command, (client, args)),
                "ctix-get-threat-data": (get_threat_data_command, (client, args)),
                "ctix-get-saved-searches": (get_saved_searches_command, (client, args)),
                "ctix-get-server-collections": (get_server_collections_command, (client, args)),
                "ctix-get-actions": (get_actions_command, (client, args)),
                "ctix-ioc-manual-review": (add_ioc_manual_review_command, (client, args)),
                "ctix-deprecate-ioc": (deprecate_ioc_command, (client, args)),
                "ctix-add-analyst-tlp": (add_analyst_tlp_command, (client, args)),
                "ctix-add-analyst-score": (add_analyst_score_command, (client, args)),
                "ctix-saved-result-set": (saved_result_set_command, (client, args)),
                "ctix-add-tag-indicator": (tag_indicator_updation_command, (client, args, "add_tag_indicator")),
                "ctix-remove-tag-from-indicator": (tag_indicator_updation_command, (client, args, "remove_tag_from_indicator")),
                "ctix-search-for-tag": (search_for_tag_command, (client, args)),
                "ctix-get-indicator-details": (get_indicator_details_command, (client, args)),
                "ctix-get-indicator-tags": (get_indicator_tags_command, (client, args)),
                "ctix-get-object-relations": (get_indicator_relations_command, (client, args)),
                "ctix-get-indicator-observations": (get_indicator_observations_command, (client, args)),
                "ctix-get-conversion-feed-source": (get_conversion_feed_source_command, (client, args)),
                "ctix-get-lookup-threat-data": (get_lookup_threat_data_command, (client, args)),
                "ctix-bulk-ioc-lookup-advanced": (bulk_ioc_lookup_advanced_command, (client, args)),
                "ctix-get-create-threat-data": (get_create_threat_data_command, (client, args)),
                "ctix-add-indicator-as-false-positive": (add_indicator_as_false_positive_command, (client, args)),
                "domain": (domain, (client, args)),
                "url": (url, (client, args)),
                "ip": (ip, (client, args)),
                "file": (file, (client, args)),
                "cve": (cve_command, (client, args)),
                "ctix-get-all-notes": (get_all_notes, (client, args)),
                "ctix-get-note-details": (get_note_details, (client, args)),
                "ctix-create-note": (create_note, (client, args)),
                "ctix-update-note": (update_note, (client, args)),
                "ctix-delete-note": (delete_note, (client, args)),
                "ctix-make-request": (make_request, (client, args)),
                "ctix-get-vulnerability-data": (cve_command, (client, args)),
            }

            func, cmd_args = CMD_TO_FUNC[command]
            return_results(cast(Callable, func)(*cmd_args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{e!s} \
            {traceback.format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# register_module_line("CTIX v3", "end", __line__())
