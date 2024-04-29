import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import dateparser
import demistomock as demisto
import urllib3
from CommonServerPython import *
from CommonServerUserPython import *
from requests import Response

API_V1 = "V1"

API_V2 = "V2"


@dataclass
class Constants:
    """
    This class contains constants for the API versions.
    """

    IS_V1 = False
    IS_V2 = False
    INVESTIGATIONS_HEADERS: tuple = ()
    INVESTIGATION_KEY_FIELD = ""
    DEFAULT_KEY_FIELD = ""
    VERSION = ""


@dataclass
class ConstantsV1(Constants):
    """
    This class contains constants for the API version 1.
    """
    VERSION = API_V1
    IS_V1 = True
    IS_V2 = False
    INVESTIGATIONS_HEADERS: tuple = (
        "title",
        "id",
        "status",
        "created_time",
        "source",
        "assignee",
        "alerts",
    )
    INVESTIGATION_KEY_FIELD = "id"
    DEFAULT_KEY_FIELD = "id"


@dataclass
class ConstantsV2(Constants):
    """
    This class contains constants for the API version 2.
    """

    IS_V1 = False
    IS_V2 = True
    INVESTIGATIONS_HEADERS: tuple = (
        "title",
        "rrn",
        "status",
        "created_time",
        "source",
        "assignee",
        "priority",
    )
    DEFAULT_KEY_FIELD = "rrn"
    VERSION = API_V2


# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

THREATS_FIELDS = ["name", "note", "indicator_count", "published"]
LOGS_FIELDS = ["name", "id"]
EVENTS_FIELDS = ["log_id", "message", "timestamp"]
DEFAULT_DISPOSITION = "Undecided"
DEFAULT_PAGE = "0"
INTEGRATION_PREFIX = "Rapid7InsightIDR"
SEARCH_CONTAINS_OPERATOR = "CONTAINS"
SEARCH_EQUALS_OPERATOR = "EQUALS"
INVESTIGATION_SEARCH = [
    ("actor_asset_hostname", SEARCH_CONTAINS_OPERATOR),
    ("actor_user_name", SEARCH_CONTAINS_OPERATOR),
    ("alert_mitre_t_codes", SEARCH_EQUALS_OPERATOR),
    ("alert_rule_rrn", SEARCH_EQUALS_OPERATOR),
    ("assignee_id", SEARCH_EQUALS_OPERATOR),
    ("organization_id", SEARCH_EQUALS_OPERATOR),
    ("priority", SEARCH_EQUALS_OPERATOR),
    ("rrn", SEARCH_EQUALS_OPERATOR),
    ("source", SEARCH_EQUALS_OPERATOR),
    ("status", SEARCH_EQUALS_OPERATOR),
    ("title", SEARCH_CONTAINS_OPERATOR),
]
USER_SEARCH = ["first_name", "last_name", "name"]
ALERTS_HEADERS = ["alert_source", "created_time", "alert_type", "title", "id"]
PRODUCT_ALERTS_HEADERS = ["name", "alert_type", "alert_id"]
USERS_HEADERS = ["rrn", "name", "first_name", "last_name", "domain"]


class Client(BaseClient):
    """Client for Rapid7 InsightIDR REST API."""

    def __init__(
        self,
        base_url: str,
        headers: dict,
        verify: bool,
        proxy: bool,
        is_multi_customer: bool,
    ):
        self.is_multi_customer = is_multi_customer
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def list_investigations(
        self,
        api_version: str = API_V1,
        investigation_id: str = None,
        statuses: str = None,
        start_time: str = None,
        end_time: str = None,
        index: str = None,
        size: str = None,
        sources: str = None,
        priorities: str = None,
        assignee_email: str = None,
        sort_field: str = None,
        sort_direction: str = None,
        tags: str = None,
    ) -> dict:
        """
        List investigations.

        Args:
            api_version (str, optional): The InsightIDR API version to request to. Defaults to API_V1.
            investigation_id (str, optional): _description_. Defaults to None.
            statuses (str, optional): A comma-separated list of investigation statuses to include in the result.
            Defaults to None.
            start_time (str, optional): _description_. Defaults to None.
            end_time (str, optional): _description_. Defaults to None.
            index (str, optional): The optional 0 based index of the page to retrieve. Defaults to None.
            size (str, optional): The optional size of the page to retrieve.
            Must be an integer greater than 0 or less than or equal to 1000. Defaults to None.
            sources (str, optional): A comma-separated list of investigation sources to include in the result.
            Defaults to None.
            priorities (str, optional): A comma-separated list of investigation priorities to include in the result.
            assignee_email (str, optional): A user's email address. Defaults to None.
            sort_field (str, optional): A field for investigations to be sorted by. Defaults to None.
            sort_direction (str, optional): The sorting direction. Defaults to None.
            tags (str, optional): A comma-separated list of tags to include in the result. Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        params = (
            remove_empty_elements(
                {
                    "index": index,
                    "size": size,
                    "statuses": statuses,
                    "start_time": start_time,
                    "end_time": end_time,
                    "sources": sources,
                    "priorities": priorities,
                    "assignee_email": assignee_email,
                    "sort_field": sort_field,
                    "sort_direction": sort_direction,
                    "tags": tags,
                    "multi-customer": self.is_multi_customer if api_version == API_V2 else None,
                }
            )
            if not investigation_id
            else {}
        )
        endpoint = f"idr/{api_version.lower()}/investigations"
        url = (
            urljoin(endpoint, investigation_id)
            if investigation_id and api_version == API_V2
            else endpoint
        )
        return self._http_request(
            method="GET",
            url_suffix=url,
            params=params,
            ok_codes=[200, 404],
        )

    def bulk_close_investigations(
        self,
        source: str,
        start_time: str,
        end_time: str,
        alert_type: str = None,
        disposition: str = None,
        detection_rule_rrn: str = None,
        max_investigations_to_close: int = None,
    ) -> dict:
        """
        Close investigations.

        Args:
            source (str): The name of an investigation source.
            start_time (str): The time investigations are to be closed from (an ISO formatted timestamp).
            end_time (str): The time investigations are to be closed by (an ISO formatted timestamp).
            alert_type (str, optional): The category of types of alerts that should be closed. Defaults to None.
            disposition (str, optional): A disposition to set the investigation to. Defaults to None.
            detection_rule_rrn (str, optional): The RRN of the detection rule. Defaults to None.
            max_investigations_to_close (int, optional): The maximum number of alerts to close. Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        body = remove_empty_elements(
            {
                "source": source,
                "alert_type": alert_type,
                "disposition": disposition.replace(" ", "_") if disposition else None,
                "detection_rule_rrn": detection_rule_rrn,
                "from": start_time,
                "to": end_time,
                "max_investigations_to_close": max_investigations_to_close,
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="idr/v2/investigations/bulk_close",
            headers=self._headers,
            json_data=body,
        )

    def assign_user(
        self, investigation_id: str, api_version: str, user_email_address: str
    ) -> dict[str, Any]:
        """
        Assign a user by email to an investigation.

        Args:
            api_version (str): The InsightIDR API version to request to.
            investigation_id (str): Comma-separated list of the ID or RRN.
            user_email_address (str): The email address of the user to assign to this Investigation.

        Returns:
            dict: API response from Insight IDR API.
        """
        params = remove_empty_elements(
            {"multi-customer": self.is_multi_customer if api_version == "V2" else None}
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"idr/{api_version.lower()}/investigations/{investigation_id}/assignee",
            headers=self._headers,
            json_data={"user_email_address": user_email_address},
            params=params,
        )

    def set_status(
        self,
        api_version: str,
        investigation_id: str,
        status: str,
        disposition: str = None,
        threat_command_close_reason: str = None,
        threat_command_free_text: str = None,
    ) -> dict[str, Any]:
        """
        Set investigation status.

        Args:
            api_version (str): The InsightIDR API version to request to.
            investigation_id (str): Comma-separated list of the ID or RRN.
            status (str): The new status for the investigation.
            disposition (str, optional): A disposition to set the investigation to. Defaults to None.
            threat_command_close_reason (str, optional): The Threat Command reason for closing. Defaults to None.
            threat_command_free_text (str, optional): Additional information. Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        data = remove_empty_elements(
            {
                "disposition": disposition,
                "threat_command_close_reason": threat_command_close_reason,
                "threat_command_free_text": threat_command_free_text,
            }
        )
        params = remove_empty_elements(
            {"multi-customer": self.is_multi_customer if api_version == API_V2 else None}
        )
        return self._http_request(
            method="PUT",
            url_suffix=f"idr/{api_version.lower()}/investigations/{investigation_id}/status/{status}",
            headers=self._headers,
            json_data=data,
            params=params,
        )

    def add_threat_indicators(self, key: str, body: dict) -> dict:
        return self._http_request(
            method="POST",
            url_suffix=f"idr/v1/customthreats/key/{key}/indicators/add",
            headers=self._headers,
            params={"format": "json"},
            json_data=body,
        )

    def replace_threat_indicators(self, key: str, body: dict) -> dict:
        return self._http_request(
            method="POST",
            url_suffix=f"idr/v1/customthreats/key/{key}/indicators/replace",
            headers=self._headers,
            params={"format": "json"},
            json_data=body,
        )

    def list_logs(self) -> dict:
        return self._http_request(
            method="GET", url_suffix="log_search/management/logs", headers=self._headers
        )

    def list_log_sets(self) -> dict:
        return self._http_request(
            method="GET", url_suffix="log_search/management/logsets", headers=self._headers
        )

    def download_logs(self, log_ids: str, params: dict) -> Response:
        headers = self._headers.copy()
        headers["Accept-Encoding"] = ""
        return self._http_request(
            method="GET",
            url_suffix=f"log_search/download/logs/{log_ids}",
            headers=headers,
            params=params,
            resp_type="response",
        )

    def query_log(self, log_id: str, params: dict) -> dict:
        return self._http_request(
            method="GET",
            url_suffix=f"log_search/query/logs/{log_id}",
            headers=self._headers,
            params=params,
        )

    def query_log_set(self, log_set_id: str, params: dict) -> dict:
        return self._http_request(
            method="GET",
            url_suffix=f"log_search/query/logsets/{log_set_id}",
            headers=self._headers,
            params=params,
        )

    def query_log_callback(self, url: str) -> dict:
        return self._http_request(method="GET", url_suffix="", full_url=url, headers=self._headers)

    def create_investigation(
        self,
        title: str,
        status: str,
        priority: str,
        disposition: str,
        user_email_address: str = None,
    ) -> dict:
        """
        Create an investigation.

        Args:
            title (str): The name of the investigation.
            status (str): The status of the investigation.
            priority (str): The priority for the investigation.
            disposition (str): The disposition for the investigation.
            user_email_address (str, optional): The email address of the user to assign to this Investigation.
            Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        data = remove_empty_elements(
            {
                "assignee": {"email": user_email_address},
                "disposition": disposition.replace(" ", "_"),
                "priority": priority,
                "status": status,
                "title": title,
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="idr/v2/investigations",
            headers=self._headers,
            json_data=data,
        )

    def update_investigation(
        self,
        investigation_id: str,
        title: str = None,
        status: str = None,
        priority: str = None,
        disposition: str = None,
        user_email_address: str = None,
        threat_command_free_text: str = None,
        threat_command_close_reason: str = None,
    ) -> dict:
        """
        Update an investigation.

        Args:
            investigation_id (str): The ID or RRN of the investigation to to update.
            title (str, optional): The name of the investigation. Defaults to None.
            status (str, optional): The status of the investigation. Defaults to None.
            priority (str, optional): The priority for the investigation. Defaults to None.
            disposition (str, optional): The disposition for the investigation. Defaults to None.
            user_email_address (str, optional): The email address of the user to assign to this Investigation.
            Defaults to None.
            threat_command_free_text (str, optional): Additional information. Defaults to None.
            threat_command_close_reason (str, optional): The Threat Command reason for closing. Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        data = remove_empty_elements(
            {
                "assignee": {"email": user_email_address},
                "disposition": disposition.replace(" ", "_") if disposition else None,
                "priority": priority,
                "status": status,
                "title": title,
                "threat_command_close_reason": threat_command_close_reason,
                "threat_command_free_text": threat_command_free_text,
            }
        )
        return self._http_request(
            method="PATCH",
            url_suffix=f"idr/v2/investigations/{investigation_id}",
            headers=self._headers,
            json_data=data,
            params={
                "multi-customer": self.is_multi_customer,
            },
        )

    def list_investigation_alerts(
        self,
        investigation_id: str,
    ) -> dict:
        """
        Retrieve and list all alerts associated with an investigation

        Args:
            investigation_id (str): The ID of the investigation.

        Returns:
            dict: API response from Insight IDR API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"idr/v2/investigations/{investigation_id}/alerts",
            params={
                "multi-customer": self.is_multi_customer,
            },
        )

    def list_investigation_product_alerts(
        self,
        investigation_id: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve and list all Rapid7 product alerts associated with an investigation.

        Args:
            investigation_id (str): The ID of the investigation.

        Returns:
            list[dict[str, Any]]: API response from Insight IDR API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"idr/v2/investigations/{investigation_id}/rapid7-product-alerts",
            params={
                "multi-customer": self.is_multi_customer,
            },
        )

    def get_user(
        self,
        rrn: str,
    ) -> dict:
        """
        Get user by user RNN.

        Args:
            rrn (str): The RNN of the user.

        Returns:
            dict: API response from Insight IDR API.
        """
        return self._http_request(method="GET", url_suffix=f"idr/v1/users/{rrn}")

    def search_users(
        self,
        search: list[dict[str, Any]],
        sort: list[dict[str, Any]],
        index: str,
        page_size: str,
    ) -> dict:
        """
        Search for users matching the given search/sort criteria.

        Args:
            search (List[Dict[str, Any]]): Comma-separated list of search filters
            sort (list[dict[str, Any]]): Comma-separated list of sorts.
            index (str): The optional 0 based index of the page to retrieve.
            page_size (str): The optional size of the page to retrieve.

        Returns:
            dict: API response from Insight IDR API.
        """
        return self._http_request(
            method="POST",
            url_suffix="idr/v1/users/_search",
            params={
                "index": index,
                "size": page_size,
            },
            json_data=remove_empty_elements(
                {
                    "search": search,
                    "sort": sort,
                }
            ),
        )

    def search_investigations(
        self,
        search: list,
        sort: list,
        index: str,
        page_size: str,
        start_time: str = None,
        end_time: str = None,
    ) -> dict:
        """
        Search for investigations matching the given search/sort criteria.

        Args:
            search (list): Comma-separated list of search filters
            sort (list): Comma-separated list of sorts.
            index (str): The optional 0 based index of the page to retrieve.
            page_size (str): The optional size of the page to retrieve.
            start_time (str, optional):
            An optional ISO formatted timestamp for the start of the time period to search for matching investigations.
            Defaults to None.
            end_time (str, optional):
            An optional ISO formatted timestamp for the end of the time period to search for matching investigations.
            Defaults to None.

        Returns:
            dict: API response from Insight IDR API.
        """
        data = remove_empty_elements(
            {
                "search": search,
                "sort": sort,
                "start_time": start_time,
                "end_time": end_time,
            }
        )
        return self._http_request(
            method="POST",
            url_suffix="idr/v2/investigations/_search",
            params={
                "index": index,
                "size": page_size,
                "multi-customer": self.is_multi_customer,
            },
            json_data=data,
        )

    def validate(self) -> Response:
        """
        Validate API using list-investigations method.

        Returns:
            response(Response): API response from InsightIDR
        """
        params = {"size": 1}
        return self._http_request(
            method="GET", url_suffix="idr/v1/investigations", params=params, resp_type="response"
        )


@logger
def insight_idr_list_investigations_command(
    client: Client,
    args: dict[str, Any],
    constants: Constants,
) -> CommandResults:
    """
    List investigations.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    start_time = raise_on_invalid_time(args.get("start_time"))
    end_time = raise_on_invalid_time(args.get("end_time"))

    # start_time and end_time can come in "last 1 day" format, so we parse it

    if time_range := args.get("time_range"):
        start_time, end_time = parse_date_range(date_range=time_range, date_format=DATE_FORMAT)

    v2_params: dict[str, Any] = (
        {
            "sources": args.get("sources"),
            "priorities": args.get("priorities"),
            "assignee_email": args.get("assignee_email"),
            "sort_field": to_snake_case(args.get("sort_field")),
            "sort_direction": args.get("sort_direction"),
            "tags": args.get("tags"),
        }
        if constants.IS_V2
        else {}
    )

    results = client.list_investigations(
        api_version=constants.VERSION,
        statuses=args.get("statuses"),
        start_time=start_time,
        end_time=end_time,
        index=str(arg_to_number(args["index"])),
        size=get_pagination_size(
            page_size=args.get("page_size"),
            limit=args["limit"],
        ),
        **v2_params,
    )

    data_for_output = results.get("data", [])
    return generate_command_results(
        title="Investigations",
        outputs_prefix="Investigation",
        outputs_key_field=constants.DEFAULT_KEY_FIELD,
        headers=list(constants.INVESTIGATIONS_HEADERS),
        outputs=data_for_output,
        raw_response=results,
    )


@logger
def insight_idr_get_investigation_command(
    client: Client,
    args: dict[str, Any],
    constants: Constants,
) -> CommandResults:
    """
    Get investigation.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    investigation_data = {}
    investigation_id = args["investigation_id"]
    api_version = constants.VERSION
    results = client.list_investigations(api_version=api_version, investigation_id=investigation_id)
    if constants.IS_V1:
        demisto.debug("Find the investigation ID in list response (V1)")
        data = results.get("data", [])
        for investigation in data:

            if investigation.get("id") == investigation_id:
                investigation_data = investigation
                break

        if not investigation_data:
            return CommandResults(raw_response=None)

    else:
        # Get the investigation ID in get response (V2)
        if not results.get("rrn"):
            return CommandResults(raw_response=None)

        investigation_data = results

    return generate_command_results(
        title=f'Investigation "{investigation_id}" Information',
        outputs_prefix="Investigation",
        outputs_key_field=constants.DEFAULT_KEY_FIELD,
        headers=list(constants.INVESTIGATIONS_HEADERS),
        outputs=investigation_data,
        raw_response=investigation_data,
    )


@logger
def insight_idr_close_investigations_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Close investiagtions.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    arg_to_datetime(args["start_time"])
    arg_to_datetime(args["end_time"])
    results = client.bulk_close_investigations(
        source=args["source"],
        alert_type=args.get("alert_type"),
        disposition=to_snake_case(args["disposition"], False),
        detection_rule_rrn=args.get("detection_rule_rrn"),
        start_time=args["start_time"],
        end_time=args["end_time"],
        max_investigations_to_close=arg_to_number(args.get("max_investigations_to_close")),
    )

    ids = results.get("ids", [])
    data_for_outputs = [{"id": id, "status": "CLOSED"} for id in ids]

    return generate_command_results(
        title=f"Investigation '{ids}' ({len(ids)}) was successfully closed.",
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV1.DEFAULT_KEY_FIELD,
        headers=["id", "status"],
        outputs=data_for_outputs,
        raw_response=results,
    )


@logger
def insight_idr_assign_user_command(
    client: Client,
    args: dict[str, Any],
    constants: Constants,
) -> CommandResults:
    """
    Assigning user, by email, to investigation or investigations.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    outputs: list[dict[str, Any]] = []
    investigation_ids = args["investigation_id"]
    user_email_address = args["user_email_address"]
    for investigation in argToList(investigation_ids):

        result = client.assign_user(
            investigation,
            api_version=constants.VERSION,
            user_email_address=user_email_address,
        )
        outputs.append(result)
        time.sleep(0.01)

    return generate_command_results(
        title=f"Investigation '{investigation_ids}' was successfully assigned to {user_email_address}.",
        outputs_prefix="Investigation",
        outputs_key_field=constants.DEFAULT_KEY_FIELD,
        headers=list(constants.INVESTIGATIONS_HEADERS),
        outputs=outputs,
        raw_response=outputs,
    )


@logger
def insight_idr_set_status_command(
    client: Client,
    args: dict[str, Any],
    constants: Constants,
) -> CommandResults:
    """
    Change the status of investigation or investigations.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    v2_params: dict[str, Any] = (
        {
            "disposition": args.get("disposition"),
            "threat_command_close_reason": to_camel_case(args.get("threat_command_close_reason")),
            "threat_command_free_text": args.get("threat_command_free_text"),
        }
        if constants.IS_V2
        else {}
    )
    results = []
    data_for_readable_output = []
    investigation_ids = args["investigation_id"]
    status = args["status"]
    for investigation_id in argToList(investigation_ids):
        result = client.set_status(
            api_version=constants.VERSION,
            investigation_id=investigation_id,
            status=status,
            **v2_params,
        )
        results.append(result)

        data_for_readable_output.append(result)
        time.sleep(0.01)

    return generate_command_results(
        title=f"Investigation '{investigation_ids}' status was successfully updated to {status}.",
        outputs_prefix="Investigation",
        outputs_key_field=constants.DEFAULT_KEY_FIELD,
        headers=list(constants.INVESTIGATIONS_HEADERS),
        outputs=data_for_readable_output,
        raw_response=results,
    )


@logger
def insight_idr_add_threat_indicators_command(
    client: Client,
    key: str,
    ip_addresses: str = None,
    hashes: str = None,
    domain_names: str = None,
    url: str = None,
) -> CommandResults:
    """
    Adding threat indicators to threat (or threats) by key.

    Args:
        client(Client): Rapid7 client
        key(str): Threat key (Threat IDs), One or XSOAR list (str separated by commas)
        ip_addresses(str): IPs addresses, One or XSOAR list (str separated by commas)
        hashes(str): Hashes, One or XSOAR list (str separated by commas)
        domain_names(str): Domain names, One or XSOAR list (str separated by commas)
        url(str): URLs, One or XSOAR list (str separated by commas)

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    body = {
        "ips": argToList(ip_addresses),
        "hashes": argToList(hashes),
        "domain_names": argToList(domain_names),
        "urls": argToList(url),
    }
    body = remove_empty_elements(body)

    results = []
    data_for_readable_output = []

    for threat in argToList(key):
        result = client.add_threat_indicators(threat, body)
        results.append(result)

        data_for_readable_output.append(result.get("threat"))
        time.sleep(0.01)

    readable_output = tableToMarkdown(
        f"Threat Information (key: {key})",
        data_for_readable_output,
        headers=THREATS_FIELDS,
        removeNull=True,
    )

    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.Threat",
        outputs_key_field="name",
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


@logger
def insight_idr_replace_threat_indicators_command(
    client: Client,
    key: str,
    ip_addresses: str = None,
    hashes: str = None,
    domain_names: str = None,
    url: str = None,
) -> CommandResults:
    """
    Replace threat indicators to threat (or threats) by key.

    Args:
        client(Client): Rapid7 Client
        key(str): Threat key (threat ID), One or XSOAR list (str separated by commas)
        ip_addresses(str/List[str]): IPs addresses, One or XSOAR list (str separated by commas)
        hashes(str/List[str]): hashes, One or XSOAR list (str separated by commas)
        domain_names(str/List[str]): DOMAIN NAMEs, One or XSOAR list (str separated by commas)
        url(str/List[str]): URLs, One or XSOAR list (str separated by commas)

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    body = {
        "ips": argToList(ip_addresses),
        "hashes": argToList(hashes),
        "domain_names": argToList(domain_names),
        "urls": argToList(url),
    }
    body = remove_empty_elements(body)

    results = []
    data_for_readable_output = []

    for threat in argToList(key):
        result = client.replace_threat_indicators(threat, body)
        results.append(result)

        data_for_readable_output.append(result.get("threat"))
        time.sleep(0.01)

    readable_output = tableToMarkdown(
        f"Threat Information (key: {key})",
        data_for_readable_output,
        headers=THREATS_FIELDS,
        removeNull=True,
    )

    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.Threat",
        outputs_key_field="name",
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


@logger
def insight_idr_list_logs_command(client: Client) -> CommandResults:
    """
    List all logs.

    Args:
        client(Client): Rapid7 Client

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    results = client.list_logs()

    logs = results.get("logs", {})
    data_for_readable_output = []

    for log in logs:
        data_for_readable_output.append(log)

    readable_output = tableToMarkdown(
        "List Logs", data_for_readable_output, headers=LOGS_FIELDS, removeNull=True
    )

    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.Log",
        outputs_key_field="id",
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


@logger
def insight_idr_list_log_sets_command(client: Client) -> CommandResults:
    """
    List all log sets.

    Args:
        client(Client): Rapid7 Client

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    results = client.list_log_sets()

    logs = results.get("logsets", {})
    data_for_readable_output = []

    for log in logs:
        data_for_readable_output.append(log)

    readable_output = tableToMarkdown(
        "List Log Sets", data_for_readable_output, headers=LOGS_FIELDS, removeNull=True
    )

    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.LogSet",
        outputs_key_field="id",
        raw_response=results,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


@logger
def insight_idr_download_logs_command(
    client: Client,
    log_ids: str,
    time_range: str = None,
    start_time: str = None,
    end_time: str = None,
    query: str = None,
    limit: str = None,
):
    """
    Download logs to .log file based on time and query (query - optional)

    Args:
        client(Client): Rapid7 Client
        log_ids(str): Log ids to be downloaded
        time_range(str): human time format 'last 4 days' (can be hours, days, months, years
        start_time(str): UNIX timestamp in milliseconds
        end_time(str): UNIX timestamp in milliseconds
        query(str): LEQL query
        limit(int): max number of logs to download

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if not (start_time or end_time or time_range):
        time_range = "Last 3 days"

    params = {
        "from": start_time,
        "to": end_time,
        "time_range": time_range,
        "query": query,
        "limit": limit,
    }
    response = client.download_logs(log_ids.replace(",", ":"), remove_empty_elements(params))
    content_disposition = response.headers.get("Content-Disposition")
    try:
        filename = content_disposition.split(";")[1].split("=")[1].replace(" ", "")  # type: ignore
    except AttributeError:
        filename = datetime.now().strftime(DATE_FORMAT) + ".log"

    file_type = entryTypes["entryInfoFile"]
    return fileResult(filename, response.content, file_type)


@logger
def insight_idr_query_log_command(
    client: Client,
    log_id: str,
    query: str,
    time_range: str = None,
    start_time: str = None,
    end_time: str = None,
    logs_per_page: int = None,
    sequence_number: int = None,
) -> CommandResults:
    """
    Search a log by Query.

    Args:
        client(Client): Rapid7 Client
        log_id(str): Logentries log key
        query(str): A valid LEQL query to run against the log
        time_range(str): An optional relative time range in a readable format
        start_time(str): Lower bound of the time range you want to query against
        end_time(str): Upper bound of the time range you want to query against
        logs_per_page(int): The number of log entries to return per page
        sequence_number(int): The earlier sequence number of a log entry to start searching from

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if time_range:
        start_time, end_time = parse_date_range(time_range, to_timestamp=True)

    params = {
        "query": query,
        "from": start_time,
        "to": end_time,
        "per_page": logs_per_page,
        "sequence_number": sequence_number,
    }

    params = remove_empty_elements(params)

    results = client.query_log(log_id, params)

    data_for_readable_output, raw_response = handle_query_log_results(client, results)

    readable_output = tableToMarkdown(
        "Query Results", data_for_readable_output, headers=EVENTS_FIELDS, removeNull=True
    )
    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.Event",
        outputs_key_field="message",
        raw_response=raw_response,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


@logger
def insight_idr_query_log_set_command(
    client: Client,
    log_set_id: str,
    query: str,
    time_range: str = None,
    start_time: str = None,
    end_time: str = None,
    logs_per_page: int = None,
    sequence_number: int = None,
) -> CommandResults:
    """
    Search a log set by Query.

    Args:
        client(Client): Rapid7 Client
        log_set_id(str): log set id
        query(str): A valid LEQL query to run against the log
        time_range(str): An optional relative time range in a readable format
        start_time(str): Lower bound of the time range you want to query against (ISO  format)
        end_time(str): Upper bound of the time range you want to query against (ISO  format)
        logs_per_page(int): The number of log entries to return per page
        sequence_number(int): The earlier sequence number of a log entry to start searching from

    Returns:
        CommandResults with raw_response, readable_output and outputs.
    """
    if time_range:
        start_time, end_time = parse_date_range(time_range, to_timestamp=True)

    params = {
        "query": query,
        "from": start_time,
        "to": end_time,
        "per_page": logs_per_page,
        "sequence_number": sequence_number,
    }

    params = remove_empty_elements(params)

    results = client.query_log_set(log_set_id, params)

    data_for_readable_output, raw_response = handle_query_log_results(client, results)

    readable_output = tableToMarkdown(
        "Query Results", data_for_readable_output, headers=EVENTS_FIELDS, removeNull=True
    )
    command_results = CommandResults(
        outputs_prefix="Rapid7InsightIDR.Event",
        outputs_key_field="message",
        raw_response=raw_response,
        outputs=data_for_readable_output,
        readable_output=readable_output,
    )
    return command_results


def handle_query_log_results(client: Client, result: dict) -> tuple[list, list]:
    """
    This function get the first result of the query,
    then handles if the query is still in progress, and handle pagination.

    Args:
        client (Client): Rapid7 Client
        result (dict): The first result of the query

    Returns:
        Tuple[list, list]:
            data_for_readable_output: The data for the readable output which contains all the events
            raw_responcse: Raw response from all events returned by the requests
    """
    data_for_readable_output = []
    raw_responcse = []

    results_list = [result]
    while results_list:
        results = results_list.pop(0)

        if events := results.get("events", []):
            data_for_readable_output.extend(events)
            raw_responcse.append(results)

        if links := results.get("links", []):
            for link in links:
                url = link.get("href")
                new_results = client.query_log_callback(url)
                results_list.append(new_results)

                progress = results.get("progress")
                demisto.debug(f"Events length: {len(events)}, progress: {progress}")

    return data_for_readable_output, raw_responcse


@logger
def insight_idr_create_investigation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Create an new investigation manually.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    results = client.create_investigation(
        title=args["title"],
        status=args["status"],
        priority=args["priority"],
        disposition=to_snake_case(args["disposition"], False) or DEFAULT_DISPOSITION,
        user_email_address=args.get("user_email_address"),
    )
    investigation_id = results["rrn"]
    return generate_command_results(
        title=f"Investigation '{investigation_id}' was successfully created.",
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=list(ConstantsV2.INVESTIGATIONS_HEADERS),
        outputs=results,
        raw_response=results,
    )


@logger
def insight_idr_update_investigation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Update an exsiting investigation.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    investigation_id = args["investigation_id"]
    results = client.update_investigation(
        investigation_id=investigation_id,
        title=args.get("title"),
        status=args.get("status"),
        priority=args.get("priority"),
        disposition=to_snake_case(args.get("disposition"), False),
        user_email_address=args.get("user_email_address"),
        threat_command_free_text=args.get("threat_command_free_text"),
        threat_command_close_reason=to_camel_case(args.get("threat_command_close_reason")),
    )

    return generate_command_results(
        title=f"Investigation '{investigation_id}' was successfully updated.",
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=list(ConstantsV2.INVESTIGATIONS_HEADERS),
        outputs=results,
        raw_response=results,
    )


@logger
def insight_idr_list_investigation_alerts_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List all alerts associated with an investigation.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    investigation_id = args["investigation_id"]
    results = client.list_investigation_alerts(
        investigation_id=investigation_id,
    )
    data = results.get("data", [])
    data_for_output = {
        "rrn": investigation_id,
        "alert": (
            data if argToBoolean(args["all_results"]) else data[: arg_to_number(args["limit"])]
        ),
    }
    return generate_command_results(
        title=f'Investigation "{investigation_id}" alerts:',
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=ALERTS_HEADERS,
        outputs=data_for_output,
        raw_response=results,
        readable_outputs=data_for_output.get("alert", []),
    )


@logger
def insight_idr_list_investigation_product_alerts_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List all Rapid7 product alerts associated with an investigation.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    investigation_id = args["investigation_id"]
    results = client.list_investigation_product_alerts(
        investigation_id=investigation_id,
    )
    data = generate_product_alerts_readable(results)
    data_for_output = {
        "rrn": investigation_id,
        "ProductAlert": (
            data if argToBoolean(args["all_results"]) else data[: arg_to_number(args["limit"])]
        ),
    }
    return generate_command_results(
        title=f'Investigation "{investigation_id}" product alerts',
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=PRODUCT_ALERTS_HEADERS,
        outputs=data_for_output,
        raw_response=results,
        readable_outputs=data_for_output.get("ProductAlert", []),
    )


def generate_product_alerts_readable(response: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Generate product alerts readable outputs.

    Args:
        response (dict[str, Any]): The product alerts response.

    Returns:
        list[dict[str, Any]]: Readable outputs.
    """
    data = []
    for result in response:
        for product_name in list(result.keys()):
            if isinstance(result[product_name], list):
                for threat in result[product_name]:
                    data.append(threat | {"name": result["type"]})
            elif isinstance(result[product_name], dict):
                data.append(result[product_name] | {"name": result["type"]})
    return data


@logger
def insight_idr_list_users_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Search for users or retrieve a user with the given RRN.

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    if rrn := args.get("rrn"):
        results = client.get_user(
            rrn=rrn,
        )
    else:
        results = client.search_users(
            search=handle_user_search(args=args, filter=USER_SEARCH),
            sort=handle_sort(args=args),
            index=str(arg_to_number(args["index"])) or DEFAULT_PAGE,
            page_size=get_pagination_size(
                page_size=args.get("page_size"),
                limit=args["limit"],
            ),
        ).get("data", [])

    return generate_command_results(
        title="Users",
        outputs_prefix="User",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=USERS_HEADERS,
        outputs=results,
        raw_response=results,
    )


@logger
def insight_idr_search_investigation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Search for investigations matching the given search/sort criteria..

    Args:
        client (Client): Rapid7 Insight IDR API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    search = handle_investigation_search(args, INVESTIGATION_SEARCH)
    sort = handle_sort(args)
    start_time = raise_on_invalid_time(time_str=args.get("start_time"))
    end_time = raise_on_invalid_time(args.get("end_time"))

    results = client.search_investigations(
        search=search,
        sort=sort,
        start_time=start_time,
        end_time=end_time,
        index=str(arg_to_number(args["index"])),
        page_size=get_pagination_size(
            page_size=args.get("page_size"),
            limit=args["limit"],
        ),
    )

    return generate_command_results(
        title="Investigations",
        outputs_prefix="Investigation",
        outputs_key_field=ConstantsV2.DEFAULT_KEY_FIELD,
        headers=list(ConstantsV2.INVESTIGATIONS_HEADERS),
        outputs=results.get("data", []),
        raw_response=results,
    )


@logger
def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to.

    200 - success
    401 - API key not valid
    500 - not account region
    Args:
        client(Client): Rapid7 Client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    try:
        response = client.validate()
        status_code = response.status_code
        if status_code == 200:
            return "ok"

        if status_code == 401:
            return "API key is not valid."

        if status_code == 500:
            return "This isn't your account region."

        return "Something went wrong..."
    except DemistoException:
        return "Connection error. Check your region or your Credentials."


@logger
def fetch_incidents(
    client: Client, last_run: dict, first_fetch_time: str, max_fetch: str
) -> tuple[dict[str, int], list[dict]]:
    """
    Fetch incidents (investigations) each minute (by default).

    Args:
        client(Client): Rapid7 Client
        last_run(Dict[str, int]): Dict with last_fetch object,
                                  saving the last fetch time(in millisecond timestamp)
        first_fetch_time: Dict with first fetch time in str (ex: 3 days ago) need to be parsed
        max_fetch(str): Max number of alerts per fetch. Default is 50
    Returns:
        Tuple of next_run (millisecond timestamp) and the incidents list
    """
    last_fetch_timestamp = last_run.get("last_fetch", None)

    if last_fetch_timestamp:
        last_fetch = datetime.fromtimestamp(last_fetch_timestamp / 1000)
    else:
        last_fetch, _ = parse_date_range(first_fetch_time)

    incidents = []
    next_run = last_fetch

    size = max_fetch or "50"

    investigations = client.list_investigations(
        start_time=last_fetch.strftime(DATE_FORMAT), size=size
    )
    for investigation in investigations.get("data", []):
        investigation_created_time = investigation.get("created_time")
        created_time = dateparser.parse(
            investigation_created_time, settings={"RETURN_AS_TIMEZONE_AWARE": False}
        )
        assert created_time is not None, f"could not parse {investigation_created_time}"
        incident = {
            "name": investigation.get("title"),
            "occurred": created_time.strftime(DATE_FORMAT)[:-4] + "Z",
            "rawJSON": json.dumps(investigation),
        }
        incidents.append(incident)
        if created_time > next_run:
            next_run = created_time

    # add 1 millisecond to next_run to prevent duplication
    next_run = next_run + timedelta(milliseconds=1)
    next_run_timestamp = int(datetime.timestamp(next_run) * 1000)

    return {"last_fetch": next_run_timestamp}, incidents


def handle_investigation_search(
    args: dict[str, Any], filter: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    """
    Handle search for investigations - from user input to API input.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.
        filter (list[tuple[str, str]]): Search settings.

    Returns:
        list: List of API search inputs.
    """
    search = []

    for filter_field, filter_operator in filter:
        search.extend(
            [
                {"field": filter_field, "operator": filter_operator, "value": value}
                for value in argToList(args.get(filter_field, [])) or []
            ]
        )

    return search


def handle_user_search(args: dict[str, Any], filter: list[str]) -> list[dict[str, Any]]:
    """
    Handle search for users - from user input to API input.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.
        filter (list[tuple]): Search settings.

    Returns:
        list: List of API search inputs.
    """
    search = []
    for filter_field in filter:
        values = argToList(args.get(filter_field, [])) or []
        if len(values) > 0 and not args.get("search_operator"):
            raise ValueError("Please insert search_operator in order to use filters.")
        search.extend(
            [
                {
                    "field": filter_field,
                    "operator": args["search_operator"].upper(),
                    "value": value,
                }
                for value in values
            ]
        )
    return search


def handle_sort(args: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Handle sort criteria - from user input to API input.
    For example, for the input:
        args = {"sort": "Priority,Created time", "sort_direction": "ASC"}
    The output will be
        [{
            "field": "priority",
            "order": "ASC"
        },{
            "field": "created_time",
            "order": "ASC"
        }]

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        list: List of API search inputs.
    """
    mapper = {
        "Alert created time": "created_time",
        "Created time": "created_time",
        "Priority": "priority",
        "RRN Last Created Alert": "alerts_most_recent_created_time",
        "Last Detection Alert": "alerts_most_recent_detection_created_time",
    }
    return [
        {
            "field": mapper.get(field) or field,
            "order": args["sort_direction"].upper(),
        }
        for field in argToList(args.get("sort")) or []
    ]


def generate_command_results(
    title: str,
    outputs_prefix: str,
    outputs_key_field: str,
    headers: list[str],
    outputs: list[dict[str, Any]] | dict[str, Any],
    raw_response: list[dict[str, Any]] | dict[str, Any],
    readable_outputs: dict[str, Any] = None,
) -> CommandResults:
    """
    Generates Command Results object.

    Args:
        title (str): The readable output title.
        outputs_prefix (str): The output prefix.
        outputs_key_field (str): The output key field.
        headers (list): The readable output headers.
        outputs (list[dict[str, Any]] | dict[str, Any]): The outputs.
        raw_response (dict[str, Any]): The raw response.
        readable_outputs (dict[str, Any], optional): Readable outputs data. Defaults to None.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.{outputs_prefix}",
        outputs_key_field=outputs_key_field,
        raw_response=raw_response,
        outputs=outputs,
        readable_output=tableToMarkdown(
            title,
            readable_outputs or outputs,
            headers=headers,
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def to_snake_case(text: str | None, is_lower: bool = True) -> str | None:
    """
    Convert text to snake case.

    Args:
        text (str, optional): The text to be converted.
        is_lower (bool, optional): Wether to return in lower case or upper case. Defaults to True.

    Returns:
        str | None: Converted text.
    """
    return (text.lower() if is_lower else text.upper()).replace(" ", "_") if text else None


def to_camel_case(text: str | None) -> str | None:
    """
    Convert text to camel case.


    Args:
        text (str | None): The text to be converted.

    Returns:
        str | None: Converted text.
    """
    return camelize_string(text, " ") if text else None


def raise_on_invalid_time(time_str: str | None) -> str | None:
    """
    Validate a time string is a correct time.

    Args:
        time_str (str | None): Time string to be checked.

    Raises:
        ValueError: Time string is wrong.

    Returns:
        str | None: The time string.
    """
    if time_str:
        arg_to_datetime(time_str)
    return time_str


def get_pagination_size(page_size: str | None, limit: str) -> str:
    """
    Get pagination API size argument in case of using size and limit.

    Args:
        page_size (str | None): The page size.
        limit (str): The limit.

    Returns:
        int: API size input.
    """
    if (lmt := arg_to_number(limit)) and lmt > 100:
        raise ValueError("The maximum limit is 100.")
    if (pgz := arg_to_number(page_size)) and pgz > 100:
        raise ValueError("The maximum page_size is 100.")

    return str(arg_to_number(page_size) or arg_to_number(limit) or 50)


def main():
    """PARSE AND VALIDATE INTEGRATION PARAMS"""

    params = demisto.params()
    region = params.get("region", {})
    api_key = params.get("apikey_creds", {}).get("password") or params.get("apiKey", {})
    is_multi_customer = argToBoolean(params.get("is_multi_customer", "false"))
    max_fetch = params.get("max_fetch", "50")

    base_url = f"https://{region}.api.insight.rapid7.com/"

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    headers = {"X-Api-Key": api_key, "content-type": "application/json"}

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get("fetch_time", "3 days").strip()

    command = demisto.command()
    demisto.info(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
            is_multi_customer=is_multi_customer,
        )
        if demisto.args().get("api_version") == API_V1:
            api_version = API_V1
        elif demisto.args().get("api_version") == API_V2:
            api_version = API_V2
        else:
            api_version = API_V2 if argToBoolean(demisto.params().get("is_v2", "false")) else API_V1

        api_version_constants: Constants = {
            API_V1: ConstantsV1,
            API_V2: ConstantsV2,
        }.get(api_version, ConstantsV1)()
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                max_fetch=max_fetch,
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "rapid7-insight-idr-list-investigations":
            return_results(
                insight_idr_list_investigations_command(
                    client=client,
                    args=demisto.args(),
                    constants=api_version_constants,
                )
            )

        elif command == "rapid7-insight-idr-get-investigation":
            return_results(
                insight_idr_get_investigation_command(
                    client,
                    demisto.args(),
                    constants=api_version_constants,
                )
            )

        elif command == "rapid7-insight-idr-close-investigations":
            return_results(
                insight_idr_close_investigations_command(
                    client,
                    demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-assign-user":
            return_results(
                insight_idr_assign_user_command(
                    client=client,
                    args=demisto.args(),
                    constants=api_version_constants,
                )
            )

        elif command == "rapid7-insight-idr-set-status":
            return_results(
                insight_idr_set_status_command(
                    client=client,
                    args=demisto.args(),
                    constants=api_version_constants,
                )
            )

        elif command == "rapid7-insight-idr-add-threat-indicators":
            return_results(insight_idr_add_threat_indicators_command(client, **demisto.args()))

        elif command == "rapid7-insight-idr-replace-threat-indicators":
            return_results(insight_idr_replace_threat_indicators_command(client, **demisto.args()))

        elif command == "rapid7-insight-idr-list-logs":
            return_results(insight_idr_list_logs_command(client))

        elif command == "rapid7-insight-idr-list-log-sets":
            return_results(insight_idr_list_log_sets_command(client))

        elif command == "rapid7-insight-idr-download-logs":
            return_results(insight_idr_download_logs_command(client, **demisto.args()))

        elif command == "rapid7-insight-idr-query-log":
            return_results(insight_idr_query_log_command(client, **demisto.args()))

        elif command == "rapid7-insight-idr-query-log-set":
            return_results(insight_idr_query_log_set_command(client, **demisto.args()))

        elif command == "rapid7-insight-idr-create-investigation":
            return_results(
                insight_idr_create_investigation_command(
                    client=client,
                    args=demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-update-investigation":
            return_results(
                insight_idr_update_investigation_command(
                    client=client,
                    args=demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-list-investigation-alerts":
            return_results(
                insight_idr_list_investigation_alerts_command(
                    client=client,
                    args=demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-list-investigation-product-alerts":
            return_results(
                insight_idr_list_investigation_product_alerts_command(
                    client=client,
                    args=demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-list-users":
            return_results(
                insight_idr_list_users_command(
                    client=client,
                    args=demisto.args(),
                )
            )

        elif command == "rapid7-insight-idr-search-investigation":
            return_results(
                insight_idr_search_investigation_command(
                    client=client,
                    args=demisto.args(),
                )
            )

    # Log exceptions
    except Exception as error:
        return_error(f"Failed to execute {command} command. Error: {str(error)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
