import demistomock as demisto
from CommonServerPython import *

"""IMPORTS"""


import base64
import hashlib
import hmac
import time

import requests
import urllib.parse
import urllib3
from typing import Any, Dict
import json

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
        '''
        Signature Generation

        :param int expires: Epoch time in which time when signature will expire
        :return str signature : signature queryset
        '''
        to_sign = "%s\n%i" % (self.access_id, expires)
        return base64.b64encode(
            hmac.new(
                self.secret_key.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha1
            ).digest()
        ).decode("utf-8")

    def add_common_params(self, params: dict):
        '''
        Add Common Params
        :param dict params: Paramters to be added in request
        :return dict: Params dictionary with AccessID, Expires and Signature
        '''
        expires = int(time.time() + 5)
        params["AccessID"] = self.access_id
        params["Expires"] = expires
        params["Signature"] = self.signature(expires)
        return params

    def get_http_request(self, full_url: str, payload: dict = None, **kwargs):
        '''
        GET HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        '''
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
        except requests.exceptions.HTTPError as e:
            err_msg = "Error in API call [{}: {}], payload sent: {}, \
            url tried: {}".format(
                resp.status_code, resp.reason, resp.request.body, full_url
            )
            raise DemistoException(err_msg, e)
        json_data = resp.json()
        response = {"data": json_data, "status": status_code}
        return response

    def post_http_request(self, full_url: str, payload: dict, params):
        '''
        POST HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        '''
        headers = {"content-type": "application/json"}
        params = self.add_common_params(params)
        full_url = full_url + "?" + urllib.parse.urlencode(params)
        response = requests.post(
            full_url,
            verify=self.verify,
            proxies=self.proxies,
            json=payload,
            headers=headers,
            timeout=5,
        )
        status_code = response.status_code
        try:
            response.raise_for_status()  # Raising an exception for non-200 status code
        except requests.exceptions.HTTPError as e:
            err_msg = "Error in API call [{}: {}], payload sent: {}, \
            url tried: {} response body: {}".format(
                response.status_code,
                response.reason,
                response.request.body,
                full_url,
                response.text,
            )
            raise DemistoException(err_msg, e)
        json_data = response.json()
        response = {"data": json_data, "status": status_code}
        return response

    def delete_http_request(self, full_url: str, object_id: str, params):
        '''
        DELETE HTTP Request

        :param str full_url: URL to be called
        :param dict payload: Request body, defaults to None
        :raises DemistoException: If Any error is found will be raised on XSOAR
        :return dict: Response object
        '''
        params = self.add_common_params(params)
        full_url = full_url + object_id + "/?" + urllib.parse.urlencode(params)
        response = requests.delete(full_url, verify=self.verify, proxies=self.proxies)
        status_code = response.status_code
        try:
            response.raise_for_status()  # Raising an exception for non-200 status code
        except requests.exceptions.HTTPError as e:
            err_msg = "Error in API call [{}]".format(status_code)
            raise DemistoException(err_msg, e)
        json_data = response.json()
        response = {"data": json_data, "status": status_code}
        return response

    def test_auth(self):
        '''
        Test authentication

        :return dict: Returns result for ping
        '''
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
            params["q"] = q
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
        url_suffix = "conversion/whitelist/"
        client_url = self.base_url + url_suffix
        payload = {"type": ioc_type, "values": values, "reason": reason}
        return self.post_http_request(client_url, payload, {})

    def get_whitelist_iocs(self, page: int, page_size: int, q: str):
        """Paginated list of tags from ctix platform using page_number and page_size
        :type page: int
        :param page: page number for the pagination for list api

        :type page_size: int
        :param page_size: page size for the pagination for list api

        :type q: str
        :param q: search query string for the list api
        """
        url_suffix = "conversion/whitelist/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        if q:
            params["q"] = q
        return self.get_http_request(client_url, {}, **params)

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
        '''
        Get Threat Data

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str query: CQL query for polling specific result
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/list/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        payload = {"query": query}
        return self.post_http_request(client_url, payload=payload, params=params)

    def get_saved_searches(self, page: int, page_size: int):
        '''
        Get Saved Searches

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/saved-searches/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, **params)

    def get_server_collections(self, page: int, page_size: int):
        '''
        Get Server Collections

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :return dict: Returns response for query
        '''
        url_suffix = "publishing/collection/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size}
        return self.get_http_request(client_url, {}, **params)

    def get_actions(self, page: int, page_size: int, params: Dict[str, Any]):
        '''
        Get Actions

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param Dict[str, Any] params: Params to be send with request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/actions/"
        client_url = self.base_url + url_suffix
        params["page"] = page
        params["page_size"] = page_size
        return self.get_http_request(client_url, **params)

    def add_indicator_as_false_positive(self, object_ids: list[str], object_type: str):
        '''
        Add Indicator as False Positive

        :param list[str] object_ids: Object IDs of the IOCs
        :param str object_type: Object type of the IOCs
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/bulk-action/false_positive/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def add_ioc_to_manual_review(self, object_ids: list[str], object_type: str):
        '''
        Add IOC to Manual Review

        :param list[str] object_ids: Object IDs of the IOCs
        :param str object_type: Object type of the IOCs
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/bulk-action/manual_review/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def deprecate_ioc(self, object_ids: str, object_type: str):
        '''
        Deprecate IOC

        :param str object_ids: Object ID of the IOC
        :param str object_type: Object type of the IOC
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/bulk-action/deprecate/"
        client_url = self.base_url + url_suffix
        payload = {"object_ids": object_ids, "object_type": object_type, "data": {}}

        return self.post_http_request(client_url, payload, {})

    def add_analyst_tlp(self, object_id: str, object_type: str, data):
        '''
        Add Analyst TLP

        :param str object_id: Object ID of the IOCs
        :param str object_type: _Object type of the IOCs
        :param dict data: data to be send over POST request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/action/analyst_tlp/"
        client_url = self.base_url + url_suffix
        payload = {"object_id": object_id, "object_type": object_type, "data": data}

        return self.post_http_request(client_url, payload, {})

    def add_analyst_score(self, object_id: str, object_type, data):
        '''
        Add Analyst Score

        :param str object_id: Object ID of the IOCs
        :param str object_type: Object type of the IOCs
        :param dict data: Request body to be send over POST request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/action/analyst_score/"
        client_url = self.base_url + url_suffix
        payload = {"object_id": object_id, "object_type": object_type, "data": data}

        return self.post_http_request(client_url, payload, {})

    def saved_result_set(self, page: int, page_size: int, label_name: str, query: str):
        '''
        Saved Result Set

        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str label_name: Label name used to get the data from the rule
        :param str query: CQL query to get specific data
        :return dict: Returns response for query
        '''
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
        '''
        Tag Indicator Updation

        :param str q: query to be send
        :param int page: Paginated number from where data will be polled
        :param int page_size: Size of the result
        :param str object_id: Object ID of the IOCs
        :param str object_type: Object type of the IOCs
        :param str tag_id: Tag ID that will be removed or added
        :param str operation: Addition or Removal of tag operation
        :return dict: Returns response for query
        '''
        tags_data = self.get_indicator_tags(
            object_type, object_id, {"page": page, "page_size": page_size}
        )["data"]
        tags = [_["id"] for _ in tags_data["tags"]]
        if operation == "add_tag_indicator":
            tags.extend([_.strip() for _ in tag_id.split(",")])
        elif operation == "remove_tag_from_indicator":
            removable_tags = [_.strip() for _ in tag_id.split(",")]
            for r_tag in removable_tags:
                if r_tag in tags:
                    tags.remove(r_tag)
        final_tags = list(set(tags))
        url_suffix = "ingestion/threat-data/action/add_tag/"
        client_url = self.base_url + url_suffix
        params = {"page": page, "page_size": page_size, "q": q}
        payload = {
            "object_id": object_id,
            "object_type": object_type,
            "data": {"tag_id": final_tags},
        }
        return self.post_http_request(client_url, payload, params)

    def search_for_tag(self, params: dict):
        '''
        Search for tag

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/tags/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_details(self, object_type: str, object_id: str, params: dict):
        '''
        Get Indicator Details

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/basic/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_tags(self, object_type: str, object_id: str, params: dict):
        '''
        Get Indicator Tags

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/quick-actions/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_relations(self, object_type: str, object_id: str, params: dict):
        '''
        Get Indicator Relations

        :param str object_type: Object type of the IOCs
        :param str object_id: Object ID of the IOCs
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = f"ingestion/threat-data/{object_type}/{object_id}/relations/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_indicator_observations(self, params: dict):
        '''
        Get Indicator Observations

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/source-references/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_conversion_feed_source(self, params: dict):
        '''
        Get Conversion Feed Source

        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = "conversion/feed-sources/"
        client_url = self.base_url + url_suffix
        return self.get_http_request(client_url, **params)

    def get_lookup_threat_data(
        self, object_type: str, object_names: list, params: dict
    ):
        '''
        Get Lookup Threat Data

        :param str object_type: Object type of the IOCs
        :param list object_names: Indicator/IOCs names
        :param dict params: Paramters to be added in request
        :return dict: Returns response for query
        '''
        url_suffix = "ingestion/threat-data/list/"
        query = f"type={object_type} AND value IN {tuple(object_names)}"
        payload = {"query": query}
        client_url = self.base_url + url_suffix
        return self.post_http_request(client_url, payload, params)


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


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Performs basic get request to get sample ip details.
    """
    client.test_auth()
    # test was successful
    demisto.results("ok")


def create_tag_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    create_tag command: Creates a new tag in the CTIX platform
    """
    name = args.get("tag_name")
    color_code = args.get("color_code")

    if color_code is not None:
        if not color_code.startswith("#") or len(color_code) != 7:
            return_warning(
                "Color code is invalid, it should be a hex code: {}".format(color_code)
            )

    response = client.create_tag(name, color_code)
    data = response.get("data")
    results = CommandResults(
        readable_output=tableToMarkdown("Tag Data", data, removeNull=True),
        outputs_prefix="CTIX.Tag",
        outputs_key_field="name",
        outputs=data,
        raw_response=data,
    )

    return results


def get_tags_command(client: Client, args=Dict[str, Any]) -> List[CommandResults]:
    """
    get_tags commands: Returns paginated list of tags
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    query = args.get("q")
    response = client.get_tags(page, page_size, query)
    tags_list = response.get("data", {}).get("results", [])
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
    data = final_result
    results = CommandResults(
        readable_output=tableToMarkdown("Tag Response", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs_key_field="result",
        outputs=data,
        raw_response=data,
    )
    return results


def whitelist_iocs_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Whitelist IOCs command

    :Description Whitelist IOCs for a given value
    :param Dict[str, Any] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    ioc_type = args.get("type")
    values = args.get("values")
    values = argToList(values)
    reason = args.get("reason")

    data = (
        client.whitelist_iocs(ioc_type, values, reason)
        .get("data", {})
        .get("details", {})
    )
    results = CommandResults(
        readable_output=tableToMarkdown("Whitelist IOC", data, removeNull=True),
        outputs_prefix="CTIX.Detail",
        outputs=data,
        raw_response=data,
    )
    return results


def get_whitelist_iocs_command(
    client: Client, args=Dict[str, Any]
) -> List[CommandResults]:
    """
    get_tags commands: Returns paginated list of tags
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    query = args.get("q")
    response = client.get_whitelist_iocs(page, page_size, query)
    ioc_list = response.get("data", {}).get("results", [])
    results = []
    for ioc in ioc_list:
        results.append(
            CommandResults(
                readable_output=tableToMarkdown("Whitelist IOC", ioc, removeNull=True),
                outputs_prefix="CTIX.IOC",
                outputs_key_field="value",
                outputs=ioc,
            )
        )
    return results


def remove_whitelisted_ioc_command(
    client: Client, args=Dict[str, Any]
) -> CommandResults:
    """
    remove_whitelist_ioc: Deletes a whitelisted ioc with given id
    """
    whitelist_id = argToList(args.get("ids"))
    response = client.remove_whitelisted_ioc(whitelist_id)
    data = response.get("data")
    results = CommandResults(
        readable_output=tableToMarkdown("Details", data, removeNull=True),
        outputs_prefix="CTIX.Detail",
        outputs_key_field="detail",
        outputs=data,
        raw_response=data,
    )
    return results


def get_threat_data_command(client: Client, args=Dict[str, Any]) -> CommandResults:
    """
    get_threat_data: List thread data and allow query
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 1))
    query = args.get("query", "type=indicator")
    response = client.get_threat_data(page, page_size, query)
    threat_data_list = response.get("data", {}).get("results", [])
    results = [data for data in threat_data_list]
    result = CommandResults(
        readable_output=tableToMarkdown("Threat Data", results, removeNull=True),
        outputs_prefix="CTIX.ThreatData",
        outputs_key_field="id",
        outputs=results,
        raw_response=results,
    )
    return result


def get_saved_searches_command(client: Client, args=Dict[str, Any]) -> CommandResults:
    """
    get_saved_searches: List saved search data
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    response = client.get_saved_searches(page, page_size)
    data_list = response.get("data", {}).get("results", [])
    results = [data for data in data_list]
    result = CommandResults(
        readable_output=tableToMarkdown("Saved Search", results, removeNull=True),
        outputs_prefix="CTIX.SavedSearch",
        outputs_key_field="id",
        outputs=results,
        raw_response=results,
    )
    return result


def get_server_collections_command(
    client: Client, args=Dict[str, Any]
) -> CommandResults:
    """
    get_server_collections: List server collections
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    response = client.get_server_collections(page, page_size)
    data_list = response.get("data", {}).get("results", [])
    results = [data for data in data_list]
    result = CommandResults(
        readable_output=tableToMarkdown("Server Collection", results, removeNull=True),
        outputs_prefix="CTIX.ServerCollection",
        outputs_key_field="id",
        outputs=results,
        raw_response=results,
    )
    return result


def get_actions_command(client: Client, args=Dict[str, Any]) -> CommandResults:
    """
    get_actions: List Actions
    """
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    object_type = args.get("object_type")
    action_type = args.get("actions_type")
    params = {}
    if action_type:
        params["action_type"] = action_type
    if object_type:
        params["object_type"] = object_type
    response = client.get_actions(page, page_size, params)
    data_list = response.get("data", {}).get("results", [])
    results = [data for data in data_list]
    result = CommandResults(
        readable_output=tableToMarkdown("Actions", results, removeNull=True),
        outputs_prefix="CTIX.Action",
        outputs_key_field="id",
        outputs=results,
        raw_response=results,
    )
    return result


def add_indicator_as_false_positive_command(
    client: Client, args: Dict[str, str]
) -> CommandResults:
    '''
    Add Indicator as False Positive Command

    :Description Add Indicator as False Positive for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    object_ids = args.get("object_ids")
    object_type = args.get("object_type", "indicator")
    object_ids = argToList(object_ids)
    response = client.add_indicator_as_false_positive(object_ids, object_type)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def add_ioc_manual_review_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Add IOC for Manual Review Command

    :Description Add IOC for Manual Review for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    object_ids = args.get("object_ids")
    object_type = args.get("object_type", "indicator")
    object_ids = argToList(object_ids)
    response = client.add_ioc_to_manual_review(object_ids, object_type)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def deprecate_ioc_command(client: Client, args: dict) -> CommandResults:
    """
    deprecate_ioc command: Deprecate indicators bulk api
    """
    object_ids = args.get("object_ids")
    object_type = args.get("object_type")
    object_ids = argToList(object_ids)
    response = client.deprecate_ioc(object_ids, object_type)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def add_analyst_tlp_command(client: Client, args: dict) -> CommandResults:
    '''
    Add Analyst TLP Command

    :Description Add Analyst TLP for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    object_id = args.get("object_id")
    object_type = args.get("object_type")
    data = json.loads(args.get("data"))

    analyst_tlp = data.get("analyst_tlp")
    if not analyst_tlp:
        raise DemistoException("analyst_tlp not provided")

    response = client.add_analyst_tlp(object_id, object_type, data)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def add_analyst_score_command(client: Client, args: dict) -> CommandResults:
    '''
    Add Analyst Score Command

    :Description Add Analyst Score for a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    object_id = args.get("object_id")
    object_type = args.get("object_type")
    data = json.loads(args.get("data", "{}"))

    analyst_tlp = data.get("analyst_score")
    if not analyst_tlp:
        raise DemistoException("analyst_score not provided")

    response = client.add_analyst_score(object_id, object_type, data)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def saved_result_set_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get Saved Result Set data Command

    :Description Get Saved Result Set data
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = int(args.get("page", 1))
    page_size = int(args.get("page_size", 10))
    label_name = args.get("label_name", "test")
    query = args.get("query", "type=indicator")
    response = client.saved_result_set(page, page_size, label_name, query)
    data_list = response.get("data", {}).get("results", [])
    results = [data for data in data_list]
    result = CommandResults(
        readable_output=tableToMarkdown("SavedResultSet", results, removeNull=True),
        outputs_prefix="CTIX.SavedResultSet",
        outputs_key_field="id",
        outputs=results,
        raw_response=results,
    )
    return result


def tag_indicator_updation_command(
    client: Client, args: Dict[str, Any], operation: str
) -> CommandResults:
    '''
    Tag Indicator Updation Command

    :Description Updating Tag of a given Indicator
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    tag_id = args["tag_id"]
    query = args["q"]

    response = client.tag_indicator_updation(
        query, page, page_size, object_id, object_type, tag_id, operation
    )
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def search_for_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Search for Tag Command

    :Description Search for Tag
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    q = args.get("q")
    params = {"page": page, "page_size": page_size, "q": q}

    response = client.search_for_tag(params)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_indicator_details_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Get Indicator Details Command
    :Description Get Indicator Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}

    response = client.get_indicator_details(object_type, object_id, params)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_indicator_tags_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    '''
    Get Indicator Tags  Command

    :Description Get Tags Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args.get("object_id")
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}

    response = client.get_indicator_tags(object_type, object_id, params)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_indicator_relations_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Get Indicator Relations Command

    :Description Get Relations Details
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    page = args.get("page", 1)
    page_size = args.get("page_size", 10)
    object_id = args["object_id"]
    object_type = args["object_type"]
    params = {"page": page, "page_size": page_size}

    response = client.get_indicator_relations(object_type, object_id, params)
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_indicator_observations_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Get Indicator Observations Command

    :Description Get Indicator Observations
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
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
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_conversion_feed_source_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Get Conversion Feed Source Command

    :Description Get Conversion Feed Source
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
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
    data = response.get("data")
    data = {"result": data}
    results = CommandResults(
        readable_output=tableToMarkdown("Result", data, removeNull=True),
        outputs_prefix="CTIX.Result",
        outputs=data,
        raw_response=data,
    )

    return results


def get_lookup_threat_data_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    '''
    Get Lookup Threat Data Command

    :Description Get Lookup Threat Data
    :param Dict[str, str] args: Paramters to be send to in request
    :return CommandResults: XSOAR based result
    '''
    object_type = args.get("object_type", "indicator")
    object_names = argToList(args.get("object_names"))
    page_size = args.get("page_size", 10)
    params = {"page_size": page_size}
    response = client.get_lookup_threat_data(object_type, object_names, params)
    data_set = response.get("data").get("results")
    results = [data for data in data_set]
    results = CommandResults(
        readable_output=tableToMarkdown("Result", results, removeNull=True),
        outputs_prefix="CTIX.ThreatDataLookup",
        outputs=results,
        raw_response=results,
    )

    return results


def main() -> None:

    base_url = demisto.params().get("base_url")
    access_id = demisto.params().get("access_id")
    secret_key = demisto.params().get("secret_key")
    verify = not demisto.params().get("insecure", False)
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

        if demisto.command() == "test-module":
            test_module(client)
        elif demisto.command() == "create_tag":
            return_results(create_tag_command(client, demisto.args()))
        elif demisto.command() == "get_tags":
            return_results(get_tags_command(client, demisto.args()))
        elif demisto.command() == "delete_tag":
            return_results(delete_tag_command(client, demisto.args()))
        elif demisto.command() == "whitelist_iocs":
            return_results(whitelist_iocs_command(client, demisto.args()))
        elif demisto.command() == "get_whitelist_iocs":
            return_results(get_whitelist_iocs_command(client, demisto.args()))
        elif demisto.command() == "remove_whitelist_ioc":
            return_results(remove_whitelisted_ioc_command(client, demisto.args()))
        elif demisto.command() == "get_threat_data":
            return_results(get_threat_data_command(client, demisto.args()))
        elif demisto.command() == "get_saved_searches":
            return_results(get_saved_searches_command(client, demisto.args()))
        elif demisto.command() == "get_server_collections":
            return_results(get_server_collections_command(client, demisto.args()))
        elif demisto.command() == "get_actions":
            return_results(get_actions_command(client, demisto.args()))
        elif demisto.command() == "ioc_manual_review":
            return_results(add_ioc_manual_review_command(client, demisto.args()))
        elif demisto.command() == "deprecate_ioc":
            return_results(deprecate_ioc_command(client, demisto.args()))
        elif demisto.command() == "add_analyst_tlp":
            return_results(add_analyst_tlp_command(client, demisto.args()))
        elif demisto.command() == "add_analyst_score":
            return_results(add_analyst_score_command(client, demisto.args()))
        elif demisto.command() == "saved_result_set":
            return_results(saved_result_set_command(client, demisto.args()))
        elif demisto.command() == "add_tag_indicator":
            return_results(
                tag_indicator_updation_command(
                    client, demisto.args(), "add_tag_indicator"
                )
            )
        elif demisto.command() == "remove_tag_from_indicator":
            return_results(
                tag_indicator_updation_command(
                    client, demisto.args(), "remove_tag_from_indicator"
                )
            )
        elif demisto.command() == "search_for_tag":
            return_results(search_for_tag_command(client, demisto.args()))
        elif demisto.command() == "get_indicator_details":
            return_results(get_indicator_details_command(client, demisto.args()))
        elif demisto.command() == "get_indicator_tags":
            return_results(get_indicator_tags_command(client, demisto.args()))
        elif demisto.command() == "get_indicator_relations":
            return_results(get_indicator_relations_command(client, demisto.args()))
        elif demisto.command() == "get_indicator_observations":
            return_results(get_indicator_observations_command(client, demisto.args()))
        elif demisto.command() == "get_conversion_feed_source":
            return_results(get_conversion_feed_source_command(client, demisto.args()))
        elif demisto.command() == "get_lookup_threat_data":
            return_results(get_lookup_threat_data_command(client, demisto.args()))
        elif demisto.command() == "add_indicator_as_false_positive":
            return_results(
                add_indicator_as_false_positive_command(client, demisto.args())
            )

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)} \
            {traceback.format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
