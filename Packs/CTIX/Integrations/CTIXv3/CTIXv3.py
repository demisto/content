import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from http import HTTPStatus
import urllib3
import requests
from typing import Any, cast
from collections.abc import Callable
import urllib.parse
import time
import json
import hmac
import hashlib
import base64
import uuid
from datetime import datetime


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
        verify: bool,
        proxies: dict,
    ) -> None:
        self.base_url = base_url
        self.access_id = access_id
        self.secret_key = secret_key
        self.verify = verify
        self.proxies = proxies

    def signature(self, expires: int):
        """
        Signature Generation

        :param int expires: Epoch time in which time when signature will expire
        :return str signature : signature queryset
        """
        to_sign = "%s\n%i" % (self.access_id, expires)
        return base64.b64encode(
            hmac.new(
                self.secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1
            ).digest()
        ).decode("utf-8")

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

    def get_http_request(self, full_url: str, payload: dict = None,
                         fallback_full_url: str = None, **kwargs):
        """
        GET HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :param str fallback_full_url: URL to be called if the first 404s, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        kwargs = self.add_common_params(kwargs)
        full_url = full_url + "?" + urllib.parse.urlencode(kwargs)

        headers = {"content-type": "application/json"}
        resp = requests.get(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            timeout=5,
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
                return_error(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def post_http_request(self, full_url: str, payload: dict, params: dict,
                          fallback_full_url: str = None):
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
        full_url = full_url + "?" + urllib.parse.urlencode(params)
        resp = requests.post(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            json=payload,
            headers=headers,
            timeout=15,
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
                return_error(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

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
        full_url = full_url + "?" + urllib.parse.urlencode(params)
        resp = requests.put(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            json=payload,
            headers=headers,
            timeout=15,
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
                return_error(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

    def delete_http_request(self, full_url: str, payload: dict = None, **kwargs):
        """
        DELETE HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        """
        kwargs = self.add_common_params(kwargs)
        full_url = full_url + "?" + urllib.parse.urlencode(kwargs)
        headers = {"content-type": "application/json"}
        resp = requests.delete(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            timeout=5,
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

            return_error(f"Error: status-> {status_code!r}; Reason-> {resp.reason!r}]")

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

    def delete_tag(self, tag_id: str):
        """Deletes a tag from the ctix instance
        :type tag_id: ``str``
        :param name: id of the tag to be deleted
        """
        url_suffix = "ingestion/tags/bulk-actions/"
        client_url = self.base_url + url_suffix
        return self.post_http_request(
            client_url, {"ids": tag_id, "action": "delete"}, {}
        )

    def whitelist_iocs(self, ioc_type, values, reason):
        url_suffix = "conversion/allowed_indicators/"  # for CTIX >= 3.6
        fallback_url_suffix = "conversion/whitelist/"  # for CTIX < 3.6
        client_url = self.base_url + url_suffix
        fallback_client_url = self.base_url + fallback_url_suffix
        payload = {"type": ioc_type, "values": values, "reason": reason}
        return self.post_http_request(client_url, payload, {},
                                      fallback_full_url=fallback_client_url)

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
        return self.get_http_request(client_url, {}, fallback_full_url=fallback_client_url,
                                     **params)

    def remove_whitelisted_ioc(self, whitelist_id: str):
        """Removes whitelisted ioc with given `whitelist_id`
        :type whitelist_id: str
        :param whitelist_id: id of the whitelisted ioc to be removed
        """
        url_suffix = "conversion/whitelist/bulk-actions/"
        client_url = self.base_url + url_suffix
        return self.post_http_request(
            client_url, {"ids": whitelist_id, "action": "delete"}, {}
        )

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
        return self.get_http_request(client_url, {}, None, **params)

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
        return self.get_http_request(client_url, {}, None, **params)

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
        return self.get_http_request(client_url, **params)

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

    def saved_result_set(self, page: int, page_size: int, label_name: str, query: str):
        """
        Saved Result Set

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str label_name: Label name used to get the data from the rule
        :param str query: CQL query to get specific data
        :return dict: Returns response for query
        """
        url_suffix = "ingestion/threat-data/list/"
        client_url = self.base_url + url_suffix
        params = {}
        params.update({"page": page})
        params.update({"page_size": page_size})
        if query is None:
            query = "type=indicator"
        payload = {"label_name": label_name, "query": query}
        return self.post_http_request(client_url, payload, params)

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
        tags_data = self.get_indicator_tags(
            object_type, object_id, {"page": page, "page_size": page_size}
        )["data"]
        tags = [_["id"] for _ in tags_data["tags"]]
        if operation == "add_tag_indicator":
            url_suffix = "ingestion/threat-data/action/add_tag/"
            tags.extend([_.strip() for _ in tag_id.split(",")])
            data = {'tag_id':list(set(tags))}
        elif operation == "remove_tag_from_indicator":
            url_suffix = "ingestion/threat-data/action/remove_tag/"
            tags = [_.strip() for _ in tag_id.split(",")]
            data = {"tag_ids": list(set(tags))}
       
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size, "q": q}
        payload = {
            "object_id": object_id,
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

    def get_lookup_threat_data(
        self, object_type: str, ioc_type: list, object_names: list, params: dict
    ):
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
            "metadata": {
                "tlp": "AMBER",
                "confidence": 100,
                "tags": []
            },
            "source": {
                "source_name": source
            },
            "collection": {
                "collection_name": collection
            }
        }

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
        return self.get_http_request(client_url, {}, None, **params)

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
        return self.get_http_request(client_url, {}, None, **params)

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
        return self.get_http_request(client_url, {}, None, **params)


""" HELPER FUNCTIONS """


def to_dbot_score(ctix_score: int) -> int:
    """
    Maps CTIX Score to DBotScore
    """
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
                ip_standard_context = Common.IP(
                    ip=value.get("name"), asn=value.get("asn"), dbot_score=dbot_score
                )
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
                file_standard_context = Common.File(
                    name=value.get("name"), dbot_score=dbot_score
                )
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
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
                domain_standard_context = Common.Domain(
                    domain=value.get("name"), dbot_score=dbot_score
                )
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
                email_standard_context = Common.Domain(
                    domain=value.get("name"), dbot_score=dbot_score
                )
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
                url_standard_context = Common.URL(
                    url=value.get("name"), dbot_score=dbot_score
                )
                final_data.append(
                    CommandResults(
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
                        readable_output=tableToMarkdown(
                            table_name, value, removeNull=True
                        ),
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
    tags_list = response.get("data", {}).get("results", [])
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
                    outputs=tag,
                )
            )
        return results


def delete_tag_command(client: Client, args: dict) -> CommandResults:
    """
    delete_tag command: Deletes a tag with given tag_name
    """
    tag_name = argToList(args.get("tag_name"))
    final_result = []
    for tag in tag_name:
        search_result = client.get_tags(1, 10, tag)
        tags = search_result.get("data", {}).get("results", [])
        response = client.delete_tag(tags[0]["id"])
        final_result.append(response.get("data"))
    final_result = no_result_found(final_result)
    if isinstance(final_result, CommandResults):
        return final_result
    else:
        results = CommandResults(
            readable_output=tableToMarkdown(
                "Tag Response", final_result, removeNull=True
            ),
            outputs_prefix="CTIX.DeleteTag",
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

    data = (
        client.whitelist_iocs(ioc_type, values, reason)
        .get("data", {})
        .get("details", {})
    )
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


def get_whitelist_iocs_command(
    client: Client, args=dict[str, Any]
) -> List[CommandResults]:
    """
    get_tags commands: Returns paginated list of tags
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    query = args.get("q")
    response = client.get_whitelist_iocs(page, page_size, query)
    ioc_list = response.get("data", {}).get("results", [])
    ioc_list = no_result_found(ioc_list)
    if isinstance(ioc_list, CommandResults):
        return [ioc_list]
    else:
        results = []
        for ioc in ioc_list:
            results.append(
                CommandResults(
                    readable_output=tableToMarkdown(
                        "Whitelist IOC", ioc, removeNull=True
                    ),
                    outputs_prefix="CTIX.IOC",
                    outputs_key_field="value",
                    outputs=ioc,
                )
            )
        return results


def remove_whitelisted_ioc_command(
    client: Client, args=dict[str, Any]
) -> CommandResults:
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


def get_threat_data_command(
    client: Client, args=dict[str, Any]
) -> List[CommandResults]:
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
    data_list = response.get("data", {}).get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown("Saved Search", results, removeNull=True),
            outputs_prefix="CTIX.SavedSearch",
            outputs_key_field="id",
            outputs=results,
            raw_response=results,
        )
        return result


def get_server_collections_command(
    client: Client, args=dict[str, Any]
) -> CommandResults:
    """
    get_server_collections: List server collections
    """
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    response = client.get_server_collections(page, page_size)
    data_list = response.get("data", {}).get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown(
                "Server Collection", results, removeNull=True
            ),
            outputs_prefix="CTIX.ServerCollection",
            outputs_key_field="id",
            outputs=results,
            raw_response=results,
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
    data_list = response.get("data", {}).get("results", [])
    results = list(data_list)
    results = no_result_found(results)
    if isinstance(results, CommandResults):
        return results
    else:
        result = CommandResults(
            readable_output=tableToMarkdown("Actions", results, removeNull=True),
            outputs_prefix="CTIX.Action",
            outputs_key_field="id",
            outputs=results,
            raw_response=results,
        )
        return result


def add_indicator_as_false_positive_command(
    client: Client, args: dict[str, str]
) -> CommandResults:
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
            readable_output=tableToMarkdown(
                "Indicator False Positive", data, removeNull=True
            ),
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
    page = args["page"]
    page = check_for_empty_variable(page, 1)
    page_size = args["page_size"]
    page_size = check_for_empty_variable(page_size, 10)
    label_name = args.get("label_name", "test")
    query = args.get("query", "type=indicator")
    response = client.saved_result_set(page, page_size, label_name, query)
    data_list = response.get("data", {}).get("results", [])
    results = no_result_found(data_list)
    reliability = args.get("reliability")

    if isinstance(results, CommandResults):
        return results
    else:
        results = iter_dbot_score(
            results,
            "confidence_score",
            "ioc_type",
            "Saved Result Set",
            "CTIX.SavedResultSet",
            "id",
            reliability,
        )
        return results


def tag_indicator_updation_command(
    client: Client, args: dict[str, Any], operation: str
) -> CommandResults:
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

    response = client.tag_indicator_updation(
        query, page, page_size, object_id, object_type, tag_id, operation
    )
    data = response.get("data")
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown(
                "Tag Indicator Updation", data, removeNull=True
            ),
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
    data = response.get("data", {}).get("results", [])
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown("Search for Tag", data, removeNull=True),
            outputs_prefix="CTIX.SearchTag",
            outputs=data,
            raw_response=data,
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
            readable_output=tableToMarkdown(
                "Get Indicator Details", data, removeNull=True
            ),
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
            readable_output=tableToMarkdown(
                "Get Indicator Tags", data, removeNull=True
            ),
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
    data = response.get("data", {}).get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown(
                "Get Indicator Relations", data, removeNull=True
            ),
            outputs_prefix="CTIX.IndicatorRelations",
            outputs=data,
            raw_response=data,
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
    data = response.get("data", {}).get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown(
                "Get Indicator Observations", data, removeNull=True
            ),
            outputs_prefix="CTIX.IndicatorObservations",
            outputs=data,
            raw_response=data,
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
    data = response.get("data", []).get("results", {})
    data = no_result_found(data)
    if isinstance(data, CommandResults):
        return data
    else:
        results = CommandResults(
            readable_output=tableToMarkdown(
                "Conversion Feed Source", data, removeNull=True
            ),
            outputs_prefix="CTIX.ConversionFeedSource",
            outputs=data,
            raw_response=data,
        )

        return results


def get_lookup_threat_data_command(
    client: Client, args: dict[str, Any]
) -> List[CommandResults]:
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
    response = client.get_lookup_threat_data(
        object_type, ioc_type, object_names, params
    )
    data_set = response.get("data").get("results")
    results = no_result_found(data_set)
    reliability = args.get("reliability")

    if isinstance(results, CommandResults):
        return [results]
    else:
        results = iter_dbot_score(
            results,
            "confidence_score",
            "ioc_type",
            "Lookup Data",
            "CTIX.ThreatDataLookup",
            "id",
            reliability
        )
        return results


def get_create_threat_data_command(
    client: Client, args: dict[str, Any]
) -> List[CommandResults]:
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
        created_after_lookup_results.append(CommandResults(
            readable_output=tableToMarkdown("Not Found: Created", created_after_lookup, headers=['Name'], removeNull=True),
            outputs_prefix="CTIX.ThreatDataGetCreate.NotFoundCreated",
            outputs=created_after_lookup,
        ))

    if invalid_values:
        invalid_values_results.append([CommandResults(
            readable_output=tableToMarkdown("Not Found: Invalid", invalid_values, headers=['Name'], removeNull=True),
            outputs_prefix="CTIX.ThreatDataGetCreate.NotFoundInvalid",
            outputs=invalid_values,
        )])

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
            params['object_id'] = object_id

    client_url = client.base_url + "ingestion/notes/"
    response = client.get_http_request(client_url, **params)
    notes_list = response.get("data", {}).get("results", [])
    notes_list = no_result_found(notes_list)

    if isinstance(notes_list, CommandResults):
        return notes_list
    else:
        return CommandResults(
            readable_output=tableToMarkdown("Note Data", notes_list, removeNull=True),
            outputs_prefix="CTIX.Note",
            outputs_key_field="id",
            outputs=notes_list,
        )


def get_note_details(client: Client, args: dict[str, Any]) -> CommandResults:
    id = args["id"]
    client_url = client.base_url + f"ingestion/notes/{id}/"
    response = client.get_http_request(client_url)

    if response['status'] == HTTPStatus.BAD_REQUEST:
        return_error(
            "Error: Note details could not be retrieved because a note with the provided ID could not be found."
        )

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
    text = args['text']
    client_url = client.base_url + "ingestion/notes/"
    object_id = args.get('object_id', None)
    object_id = check_for_empty_variable(object_id, None)
    object_type = args.get('object_type', None)
    object_type = check_for_empty_variable(object_type, None)

    if object_id and not is_valid_uuid(object_id):
        return_error("Error: The `object_id` that was provided is not valid.")
    elif object_id and not object_type:
        return_error("Error: `object_type` must be set as well if `object_id` is provided.")
    elif object_type and not object_id:
        return_error("Error: `object_id` must be set as well if `object_type` is provided.")

    payload = {
        "text": text,
        "type": "notes",
        "meta_data": {
            "component": "notes"
        }
    }

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
    id = args['id']
    text = args.get("text", None)
    client_url = client.base_url + f"ingestion/notes/{id}/"
    object_id = args.get('object_id', None)
    object_id = check_for_empty_variable(object_id, None)
    object_type = args.get('object_type', None)
    object_type = check_for_empty_variable(object_type, None)

    if object_id and not is_valid_uuid(object_id):
        return_error("Error: The `object_id` that was provided is not valid.")
    elif object_id and not object_type:
        return_error("Error: `object_type` must be set as well if `object_id` is provided.")
    elif object_type and not object_id:
        return_error("Error: `object_id` must be set as well if `object_type` is provided.")

    payload = {}

    if text:
        payload['text'] = text

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

    if response['status'] == HTTPStatus.BAD_REQUEST:
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
    id = args['id']
    client_url = client.base_url + f"ingestion/notes/{id}/"
    response = client.delete_http_request(client_url)

    if response['status'] == HTTPStatus.BAD_REQUEST:
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
    type = args['type']
    body = json.loads(args.get('body', "{}"))
    params = json.loads(args.get('params', "{}"))
    client_url = client.base_url + args['endpoint']
    response = {}

    if type == "GET":
        response = client.get_http_request(client_url, body, **params)
    elif type == "POST":
        response = client.post_http_request(client_url, body, params)
    elif type == "PUT":
        response = client.put_http_request(client_url, body, params)
    elif type == "DELETE":
        response = client.delete_http_request(client_url, body, **params)

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
    cve_sources = [
        source.get("id") for source in cve_detail.get("sources", []) if source.get("id")
    ]

    response = client.get_vulnerability_product_details(cve_uuid, page, page_size)
    product_details_list = response.get("data", {}).get("results", [])
    results = list(product_details_list)
    cpe_list = ",\n".join(product.get("product") for product in results)

    response = client.get_vulnerability_cvss_score(cve_uuid, page, page_size)
    cvss_score_list = response.get("data", {}).get("results", [])
    cvss2 = next(
        (result.get("cssv2") for result in cvss_score_list if result.get("cssv2")), None
    )
    cvss3 = next(
        (result.get("cssv3") for result in cvss_score_list if result.get("cssv3")), None
    )
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
            response = client.get_vulnerability_source_description(
                cve_uuid, source, page, page_size
            )
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
    reliability = params.get("integrationReliability", DBotScoreReliability.C)

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            reliability
        )
    else:
        raise Exception(
            "Please provide a valid value for the Source Reliability parameter."
        )

    args["reliability"] = reliability
    proxies = handle_proxy(proxy_param_name="proxy")
    demisto.debug(f"Command being called is {demisto.command()}")

    try:
        client = Client(
            base_url=base_url,
            access_id=access_id,
            secret_key=secret_key,
            verify=verify,
            proxies=proxies,
        )

        CMD_TO_FUNC = {
            "test-module": (test_module, (client,)),
            "ctix-create-tag": (create_tag_command, (client, args)),
            "ctix-get-tags": (get_tags_command, (client, args)),
            "ctix-delete-tag": (delete_tag_command, (client, args)),
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
            "ctix-get-indicator-relations": (get_indicator_relations_command, (client, args)),
            "ctix-get-indicator-observations": (get_indicator_observations_command, (client, args)),
            "ctix-get-conversion-feed-source": (get_conversion_feed_source_command, (client, args)),
            "ctix-get-lookup-threat-data": (get_lookup_threat_data_command, (client, args)),
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

        func, params = CMD_TO_FUNC[demisto.command()]
        return_results(cast(Callable, func)(*params))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)} \
            {traceback.format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

# register_module_line("CTIX v3", "end", __line__())
