from typing import Any, TypeAlias
from collections.abc import Callable
import urllib3
import copy
import dateparser
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
LIMIT = 10
DEFAULT_PAGE_SIZE = 5

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

BACKOFF_FACTOR = 7.5
TOTAL_RETRIES = 4
REQUEST_TIMEOUT = 180
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore

# Asimily Constants
INCIDENT_CRITICALITY_INFORMATIONAL = 0.5
ASIMILY_ANOMALY_CRITICALITY_INCIDENT_CRITICALITY_MAPPING = {"High": 3, "Medium": 2, "Low": 1}
HIGH_RISK_CVE_LIMIT = 7.5
MEDIUM_RISK_CVE_LIMIT = 3.5
LOW_RISK_CVE_LIMIT = 0.0

MAX_FETCH_PAGE_LIMIT = 500
MAX_FETCH_TOTAL_LIMIT = 1000

# CLI command fetch limit
MAX_FETCH_TOTAL_LIMIT_ASSETS = 1200
MAX_FETCH_PAGE_LIMIT_ASSETS = 400
MAX_FETCH_TOTAL_LIMIT_ASSETS_WITH_APP = 100
MAX_FETCH_PAGE_LIMIT_ASSETS_WITH_APP = 100

# CLI command fetch limit
MAX_FETCH_TOTAL_LIMIT_ANOMALIES_CLI = 10000
MAX_FETCH_PAGE_LIMIT_ANOMALIES_CLI = 100

MAX_FETCH_TOTAL_LIMIT_CVES_CLI = 10000
MAX_FETCH_PAGE_LIMIT_CVES_CLI = 50

# Internal limit of Anomalies/CVEs incident fetch limit per fetch
MAX_FETCH_TOTAL_LIMIT_ANOMALIES = 200
MAX_FETCH_PAGE_LIMIT_ANOMALIES = 100

MAX_FETCH_TOTAL_LIMIT_CVES = 200
MAX_FETCH_PAGE_LIMIT_CVES = 25

ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API = "/api/extapi/assets/device-cves"
ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API = "/api/extapi/assets/anomalies"
ASIMILY_INSIGHT_FETCH_ASSETS_API = "/api/extapi/assets"

ANOMALIES_API_SORT_DEVICE_ID = "deviceRangeId"
CVES_API_SORT_DEVICE_ID = "deviceInfoId"

ASIMILY_ASSET_CONTEXT_OUTPUT_KEY_ORDER = [
    "asimilydeviceid",
    "asimilydevicemacaddress",
    "asimilydeviceipv4address",
    "asimilydevicemanufacturer",
    "asimilydevicemodel",
    "asimilydevicehostname",
    "asimilydeviceos",
    "asimilydeviceosversion",
    "asimilydevicetype",
    "asimilydeviceserialnumber",
    "asimilydevicefamilies",
    "asimilydevicetag",
    "asimilydevicedepartment",
    "asimilydevicefacility",
    "asimilydevicehardwarearchitecture",
    "asimilydevicelocation",
    "asimilydeviceregion",
    "asimilydevicesoftwareverison",
    "asimilydeviceifstoreephi",
    "asimilydeviceiftransmitephi",
    "asimilydeviceifusingendpointsecurity",
    "asimilydeviceriskscore",
    "asimilydevicelikelihood",
    "asimilydeviceimpact",
    "asimilydeviceaverageutilizationpercent",
    "asimilydeviceuptime",
    "asimilydeviceisconnected",
    "asimilydeviceiscurrentlyinuse",
    "asimilydeviceisnetworkingdevice",
    "asimilydeviceiswireless",
    "asimilydeviceclass",
    "asimilydevicemanagedby",
    "asimilydeviceanomalypresent",
    "asimilydevicemds2",
    "asimilydevicecmmsid",
    "asimilydevicelastdiscoveredtime",
    "asimilydevicemasterfamily",
    "asimilydevicediscoverysource",
    "asimilydeviceapplications",
    "asimilydeviceurl",
    "asimilydeviceipv6address",
]

ASIMILY_ANOMALY_CONTEXT_OUTPUT_KEY_ORDER = [
    "asimilyanomalyname",
    "asimilyanomalycriticality",
    "asimilyanomalyearliesttriggertime",
    "asimilyanomalylasttriggertime",
    "asimilyanomalyalertid",
    "asimilyanomalyurls",
    "asimilyanomalyisfixed",
    "asimilyanomalyfixby",
    "asimilyanomalycriticalityscore",
    "asimilyanomalymitretactic",
    "asimilyanomalymitretechnique",
    "asimilyanomalycategory",
    "asimilyanomalydescription",
    "asimilyanomalycustomeranomalyid",
    "asimilydeviceid",
    "asimilydevicemacaddress",
    "asimilydeviceipv4address",
    "asimilydevicehostname",
    "asimilydevicetype",
    "asimilydevicemodel",
    "asimilydeviceos",
    "asimilydevicemanufacturer",
    "asimilydevicefamilies",
]

ASIMILY_CVE_CONTEXT_OUTPUT_KEY_ORDER = [
    "asimilycvename",
    "asimilycvecwetype",
    "asimilycveentitytype",
    "asimilycveentityname",
    "asimilycvescore",
    "asimilycvecvss3basescore",
    "asimilycvedescripttion",
    "asimilycveisfixed",
    "asimilycvefixedby",
    "asimilycveoempatched",
    "asimilycveismuted",
    "asimilycveexploitableinwild",
    "asimilycvepublisheddate",
    "asimilycveopendate",
    "asimilycvefixeddate",
    "asimilydeviceid",
    "asimilydevicemacaddress",
    "asimilydeviceipv4address",
    "asimilydevicehostname",
    "asimilydevicetype",
    "asimilydevicemodel",
    "asimilydeviceos",
    "asimilydevicemanufacturer",
    "asimilydevicefamilies",
]

QueryFilterType: TypeAlias = dict[str, Any]


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def get_base_url(self):
        return self._base_url

    def _force_get_all_wrapper(
        self,
        paginated_getter_func: Callable,
        filters: QueryFilterType | None = None,
        page_start: int | None = None,
        page_size_limit: int | None = None,
        page_end: int | None = None,
        total_limit: int | None = None,
        args: dict | None = {},
        api: str | None = ASIMILY_INSIGHT_FETCH_ASSETS_API,
    ) -> tuple[int, list[Any]]:
        """
        Wrapper method to do paginated query of Asimily Insight APIs
        Args:
        paginated_getter_func: Callable method that calls specific APIs
        filters: QueryFilterType dict
        page_start: start page index
        page_size_limit: page size limit
        page_end: page count limit for fetch
        total_limit: total count fetch limit
        args: dict of parameters for API qeury filter
        api: str of Asimily Insight API

        Returns:
        total_elements: total count of elements to be fetched with given args as query parameter (can be > len(records))
        records: array of fetched events
        """

        page = page_start or 0
        size = page_size_limit or MAX_FETCH_PAGE_LIMIT
        limit = total_limit or MAX_FETCH_TOTAL_LIMIT
        initial_data = paginated_getter_func(filters=filters, page=page, size=size, args=args)

        records = []
        total_pages = 0
        total_elements = 0
        total_incident_count = 0

        if initial_data:
            total_pages = initial_data.get("totalPages", 0)
            total_elements = initial_data.get("totalElements", 0)
            print_debug_msg(
                f"Total pages to be fetched: {total_pages} with page size: {size}, total elements to process: {total_elements}"
            )
            records = initial_data.get("content", [])

        if len(records) > 0 and "v4IpAddrs" in records[0]:
            total_incident_count += len(initial_data.get("content", []))
        else:
            records = []
            for item in initial_data.get("content", []):
                count = len(item.get("anomalies", [])) + len(item.get("cves", []))
                total_incident_count += count
                records.append(item)
                if total_incident_count >= limit:
                    break

        if total_incident_count >= limit:
            print_debug_msg(f"Stop fetching events as limit exceeded, fetched {total_incident_count} events.")
            return total_elements, records

        if page_end is not None and total_pages > 1:
            total_pages = min(page_end, total_pages)

        for page_num in range(1, total_pages):
            print_debug_msg(
                f"Fetching events for page {page_num} with page size {size} with {total_incident_count} events fetched."
            )
            page_data = paginated_getter_func(filters=filters, page=page_num, size=size, args=args)
            if len(records) > 0 and "v4IpAddrs" in records[0]:
                records.extend(page_data.get("content", []))
                total_incident_count += len(page_data.get("content", []))
            else:
                for item in page_data.get("content", []):
                    count = len(item.get("anomalies", [])) + len(item.get("cves", []))
                    total_incident_count += count
                    records.append(item)
                    if total_incident_count >= limit:
                        break

            if total_incident_count >= limit:
                print_debug_msg(f"Stop fetching events as limit exceeded, fetched {total_incident_count} events.")
                break

        records = records[:limit]
        return total_elements, records

    def get_asset_applications_by_mac_addr(self, mac_addr) -> list[dict]:
        """
        Helper method to query asset applications API given mac address
        """
        print_debug_msg(f"Fetching applications for device with mac {mac_addr}")
        init_data = self._http_request(
            method="GET",
            url_suffix="/api/extapi/assets/application",
            params={"macAddr": mac_addr},
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            timeout=REQUEST_TIMEOUT,
        )
        if not init_data:
            return []
        raw_data = init_data[0]
        if raw_data and raw_data.get("applications"):
            app_list = [item["application"] for item in raw_data.get("applications")]
            return app_list
        return []

    def force_get_asset_details(
        self,
        args: dict | None = {},
        page_size_limit: int | None = MAX_FETCH_PAGE_LIMIT_ASSETS,
        total_limit: int | None = MAX_FETCH_TOTAL_LIMIT_ASSETS,
        api: str | None = ASIMILY_INSIGHT_FETCH_ASSETS_API,
    ) -> tuple[int, list[Any]]:
        return self._force_get_all_wrapper(
            paginated_getter_func=self.get_asset_details_call,
            args=args,
            page_size_limit=page_size_limit,
            total_limit=total_limit,
            api=api,
        )

    def force_get_asset_anomalies(
        self,
        args: dict | None = {},
        page_size_limit: int | None = MAX_FETCH_PAGE_LIMIT_ANOMALIES,
        total_limit: int | None = MAX_FETCH_TOTAL_LIMIT_ANOMALIES,
        api: str | None = ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API,
    ) -> tuple[int, list[Any]]:
        return self._force_get_all_wrapper(
            paginated_getter_func=self.get_asset_anomalies_call,
            args=args,
            page_size_limit=page_size_limit,
            total_limit=total_limit,
            api=api,
        )

    def force_get_asset_cves(
        self,
        args: dict | None = {},
        page_size_limit: int | None = MAX_FETCH_PAGE_LIMIT_CVES,
        total_limit: int | None = MAX_FETCH_TOTAL_LIMIT_CVES,
        api: str | None = ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API,
    ) -> tuple[int, list[Any]]:
        return self._force_get_all_wrapper(
            paginated_getter_func=self.get_asset_cves_call,
            args=args,
            page_size_limit=page_size_limit,
            total_limit=total_limit,
            api=api,
        )

    def get_asset_details_call(
        self,
        args: dict | None = {},
        page: int | None = 0,
        size: int | None = MAX_FETCH_PAGE_LIMIT,
        filters: QueryFilterType | None = None,
        resp_type: str | None = "json",
        api: str | None = ASIMILY_INSIGHT_FETCH_ASSETS_API,
    ) -> dict:
        result = args.copy() if args is not None else {}
        result["size"] = size if size is not None else MAX_FETCH_PAGE_LIMIT
        result["page"] = page if page is not None else 0
        return self._http_request(
            method="GET",
            url_suffix=api,
            params=result,
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            timeout=REQUEST_TIMEOUT,
            resp_type=resp_type,
        )

    def get_asset_anomalies_call(
        self,
        args: dict | None = {},
        page: int | None = 0,
        size: int | None = MAX_FETCH_PAGE_LIMIT,
        filters: QueryFilterType | None = None,
        resp_type: str | None = "json",
        api: str | None = ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API,
    ) -> dict:
        filter_json = create_filter_json(args, api)
        print_debug_msg(filter_json)
        result: Dict[str, int | str] = {}
        result["size"] = size if size is not None else MAX_FETCH_PAGE_LIMIT
        result["page"] = page if page is not None else 0
        result["sort"] = ANOMALIES_API_SORT_DEVICE_ID
        print_debug_msg(result)
        return self._http_request(
            method="POST",
            url_suffix=api,
            params=result,
            json_data=filter_json,
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            timeout=REQUEST_TIMEOUT,
        )

    def get_asset_cves_call(
        self,
        args: dict | None = {},
        page: int | None = 0,
        size: int | None = MAX_FETCH_PAGE_LIMIT,
        filters: QueryFilterType | None = None,
        resp_type: str | None = "json",
        api: str | None = ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API,
    ) -> dict:
        filter_json = create_filter_json(args, api)
        add_non_fixed_cve_filter(filter_json)
        print_debug_msg(filter_json)
        result: Dict[str, int | str] = {}
        result["size"] = size if size is not None else MAX_FETCH_PAGE_LIMIT
        result["page"] = page if page is not None else 0
        result["sort"] = CVES_API_SORT_DEVICE_ID
        return self._http_request(
            method="POST",
            url_suffix=api,
            params=result,
            json_data=filter_json,
            retries=TOTAL_RETRIES,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            timeout=REQUEST_TIMEOUT,
        )


""" HELPER FUNCTIONS """


def calculate_asimily_cve_incident_criticality(cve_score) -> int:
    """
    Helper method to calculate Asimily CVE incident XSOAR severity using CVE score
    """
    if cve_score:
        if cve_score >= HIGH_RISK_CVE_LIMIT:
            return 3
        if cve_score >= MEDIUM_RISK_CVE_LIMIT:
            return 2
        return 1
    return 0


def populate_asimily_asset_anomaly_incident_system_field(incident, raw_data, device_data):
    if raw_data is None:
        return
    incident["type"] = "Asimily Anomaly"
    incident["severity"] = ASIMILY_ANOMALY_CRITICALITY_INCIDENT_CRITICALITY_MAPPING.get(raw_data.get("criticality"), 0)
    incident["dbotMirrorId"] = str(raw_data.get("alertId")) + (
        ("|" + str(device_data.get("deviceId"))) if device_data.get("deviceId") else ""
    )

    # anomalyname|hostname|ip|mac
    incident["name"] = raw_data.get("anomaly") if raw_data.get("anomaly") else ""
    if device_data.get("hostName"):
        incident["name"] = incident["name"] + "|" + device_data.get("hostName")
    if device_data.get("ipAddr"):
        incident["name"] = incident["name"] + "|" + device_data.get("ipAddr")
    if device_data.get("macAddr"):
        incident["name"] = incident["name"] + "|" + device_data.get("macAddr")
    incident["name"] = incident["name"].lstrip("|")


def populate_asimily_asset_cve_incident_system_field(incident, raw_data, device_data):
    if raw_data is None:
        return
    incident["type"] = "Asimily CVE"
    incident["severity"] = calculate_asimily_cve_incident_criticality(raw_data.get("score"))

    # cvename|hostname|ip|mac
    incident["name"] = raw_data.get("cveName") if raw_data.get("cveName") else ""
    incident["dbotMirrorId"] = incident["name"] + (
        ("|" + str(device_data.get("deviceId"))) if device_data.get("deviceId") else ""
    )

    if device_data.get("hostName"):
        incident["name"] = incident["name"] + "|" + device_data.get("hostName")
    if device_data.get("ipAddr"):
        incident["name"] = incident["name"] + "|" + device_data.get("ipAddr")
    if device_data.get("macAddr"):
        incident["name"] = incident["name"] + "|" + device_data.get("macAddr")
    incident["name"] = incident["name"].lstrip("|")


def create_filter_json(
    input_dict: dict[str, Any] | None = {}, api: str | None = ASIMILY_INSIGHT_FETCH_ASSETS_API
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """
    Convert an input dictionary to a JSON filter structure based on specified rules.
    Args:
        input_dict: Dictionary with keys like "cveScore", "criticality", etc.

    Returns:
        Dictionary formatted as the requested JSON structure.
    """
    result: dict[str, list[dict[str, Any]]] = {}

    # Define mappings for criticality
    criticality_map = {"High Only": ["HIGH"], "Medium and High": ["MEDIUM", "HIGH"]}

    # Define mappings for cveScore with operator
    cve_score_map = {"High Only": (7.5, "Gte"), "Medium and High": (3.5, "Gte")}

    input_filters = (input_dict or {}).copy()
    if input_filters.get("deviceFamily") and (not isinstance(input_filters["deviceFamily"], list)):
        input_filters["deviceFamily"] = argToList(input_filters["deviceFamily"])
    if input_filters.get("deviceTag") and (not isinstance(input_filters["deviceTag"], list)):
        input_filters["deviceTag"] = argToList(input_filters["deviceTag"])

    for key, value in input_filters.items():
        # Skip if value is "All" or a list containing "All"
        if value == "All" or (isinstance(value, list) and "All" in value):
            continue

        # Skip adding limit as filter
        if key == "limit":
            continue

        # Handle criticality
        if key == "criticality":
            if api != ASIMILY_INSIGHT_FETCH_DEVICE_ANOMALIES_API:
                continue
            if isinstance(value, list):
                print_debug_msg("criticality must be a string, not a list")
                continue
            if value in criticality_map:
                result["anomaliesCriticality"] = [{"operator": ":", "value": crit} for crit in criticality_map[value]]
            elif value != "All":
                print_debug_msg(f"Unsupported criticality value {value}")
                continue
            continue

        # Handle cveScore
        if key == "cveScore":
            if api != ASIMILY_INSIGHT_FETCH_DEVICE_CVES_API:
                continue
            if isinstance(value, list):
                print_debug_msg("cveScore must be a string, not a list")
                continue
            if value in cve_score_map:
                val, op = cve_score_map[value]
                result["cveScore"] = [{"operator": op, "value": val}]
            elif value != "All":
                print_debug_msg(f"Unsupported cveScore value {value}")
                continue
            continue

        if key == "deviceRangeId":
            if value > 0:
                result[key] = [{"operator": "Grt", "value": value}]
            continue

        if key == "cvesLastUpdatedSince" or key == "anomaliesLastUpdatedSince":
            result[key] = [{"operator": ">", "value": value}]
            continue

        # Handle other fields (deviceFamily, deviceTag, ipAddr, macAddr)
        if isinstance(value, list):
            # Create an object for each list item
            result[key] = [{"operator": ":", "value": item} for item in value]
        else:
            # Create a single object for non-list values
            result[key] = [{"operator": ":", "value": value}]

    filter_json: dict[str, dict[str, list[dict[str, Any]]]] = {}
    filter_json["filters"] = result
    print_debug_msg(filter_json)

    return filter_json


def process_params_and_args(params: dict[str, Any], args: dict[str, Any], command: str) -> dict[str, Any]:
    """
    Process and update args based on command and params.

    Logic:
    0. Rename "asimilyDeviceId" to "deviceInfoId" in args.
    1. If command != "fetch-incidents", return updated args.
    2. If command == "fetch-incidents", further process params:
       - If "fetchonlydevicefamilies" in params, add to args["deviceFamily"]
       - If "fetchonlydevicetags" in params, add to args["deviceTag"]
       - If "iffetchanomalies" is True and "fetchanomalycriticality" in params, set args["criticality"]
       - If "iffetchcves" is True and "fetchcvescore" in params, set args["cveScore"]

    Args:
        params (dict): Additional parameters.
        args (dict): Arguments dictionary to process.
        command (str): Command name.

    Returns:
        dict: A new dictionary with the updated keys.
    """
    updated_args = args.copy()

    if "asimily_device_id" in updated_args:
        if command == "asimily-get-asset-details":
            updated_args["deviceId"] = updated_args.pop("asimily_device_id")  # asset API expects different key
        else:
            updated_args["deviceInfoId"] = updated_args.pop("asimily_device_id")

    if command != "fetch-incidents":
        # transform XSOAR parameters into Asimily filter names
        if "mac_addr" in updated_args:
            updated_args["macAddr"] = updated_args.pop("mac_addr")
        if "ip_addr" in updated_args:
            updated_args["ipAddr"] = updated_args.pop("ip_addr")
        if "device_family" in updated_args:
            updated_args["deviceFamily"] = updated_args.pop("device_family")
        if "device_tag" in updated_args:
            updated_args["deviceTag"] = updated_args.pop("device_tag")
        if "cve_score" in updated_args:
            updated_args["cveScore"] = updated_args.pop("cve_score")
        return updated_args

    if "fetchonlydevicefamilies" in params:
        updated_args["deviceFamily"] = params["fetchonlydevicefamilies"]

    if "fetchonlydevicetags" in params:
        updated_args["deviceTag"] = params["fetchonlydevicetags"]

    if params.get("iffetchanomalies") and "fetchanomalycriticality" in params:
        updated_args["criticality"] = params["fetchanomalycriticality"]

    if params.get("iffetchcves") and "fetchcvescore" in params:
        updated_args["cveScore"] = params["fetchcvescore"]

    return updated_args


def add_non_fixed_cve_filter(filter_json: dict[str, Any]):
    if filter_json.get("filters"):
        filter_json["filters"]["isFixed"] = [{"operator": ":", "value": 56}]


""" COMMAND FUNCTIONS """


def test_module(client: Client, params: dict[str, Any]) -> str:
    try:
        response = client.get_asset_details_call(size=1, page=0, resp_type="text")
        if "loginStyle" in response:  # Current Asimily API will direct to login page when creds are incorrect
            return "Authentication Error: The specified API username and password are not correct."
        if params.get("isFetch", False) and params.get("iffetchanomalies", False):
            response = client.get_asset_anomalies_call(size=1, page=0)
            if "content" not in response:
                return "Exception occured when validating fetch anomalies, no content in response."
        if params.get("isFetch", False) and params.get("iffetchcves", False):
            response = client.get_asset_cves_call(size=1, page=0)
            if "content" not in response:
                return "Exception occured when validating fetch cves, no content in response."

    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authentication Error: The specified API username and password are not correct."
        else:
            return f"Exception occured: {str(e)}"
    return "ok"


def print_debug_msg(msg: Any):
    """
    Prints a message to debug with Asimily-Insight-Msg prefix.
    Args:
        msg (str): Message to be logged.
    """
    demisto.debug(f"Asimily-Insight-Msg - {msg}")


def format_date(date: Union[str, datetime] | None, format: str = DATE_FORMAT) -> str:
    if not date:
        return ""
    dt = date if isinstance(date, datetime) else dateparser.parse(date)
    assert dt is not None
    return dt.strftime(format)


def construct_url(base, *paths, **query_params):
    url = base.rstrip("/")
    for path in paths:
        url += "/" + path.strip("/")
    if query_params:
        url += "?" + urllib.parse.urlencode(query_params, doseq=True)
    return url


def construct_asimily_asset_portal_url(portal_base_url, asimilydeviceid):
    if asimilydeviceid:
        return f"{portal_base_url}/index.html#/asset/1/{asimilydeviceid}"
    return None


def map_asimily_asset_entity_from_asimily_assets_json(client: Client, incident, raw_data, base_url):
    incident["customFields"] = {}
    if raw_data is None:
        return
    incident["customFields"]["asimilydeviceid"] = raw_data.get("deviceID")
    incident["customFields"]["asimilydevicemacaddress"] = raw_data.get("macAddr")
    incident["customFields"]["asimilydeviceipv4address"] = raw_data.get("v4IpAddrs")
    incident["customFields"]["asimilydeviceipv6address"] = raw_data.get("v6IpAddrs")
    incident["customFields"]["asimilydevicemanufacturer"] = raw_data.get("manufacturer")
    incident["customFields"]["asimilydevicemodel"] = raw_data.get("deviceModel")
    incident["customFields"]["asimilydeviceos"] = raw_data.get("os")
    incident["customFields"]["asimilydeviceosversion"] = raw_data.get("osVersion")
    incident["customFields"]["asimilydevicetype"] = raw_data.get("deviceType")
    incident["customFields"]["asimilydevicefamilies"] = raw_data.get("deviceFamilies")
    incident["customFields"]["asimilydeviceserialnumber"] = raw_data.get("serialNumber")
    incident["customFields"]["asimilydevicedepartment"] = raw_data.get("department")
    incident["customFields"]["asimilydevicefacility"] = raw_data.get("facility")
    incident["customFields"]["asimilydevicehardwarearchitecture"] = raw_data.get("hardwareArchitecture")
    incident["customFields"]["asimilydevicehostname"] = raw_data.get("hostName")
    incident["customFields"]["asimilydevicelocation"] = raw_data.get("location")
    incident["customFields"]["asimilydeviceregion"] = raw_data.get("region")
    incident["customFields"]["asimilydevicesoftwareverison"] = raw_data.get("softwareVersion")
    incident["customFields"]["asimilydeviceifstoreephi"] = raw_data.get("storesEphi")
    incident["customFields"]["asimilydeviceiftransmitephi"] = raw_data.get("transmitEphi")
    incident["customFields"]["asimilydeviceriskscore"] = raw_data.get("riskScore")
    incident["customFields"]["asimilydevicelikelihood"] = raw_data.get("likelihood")
    incident["customFields"]["asimilydeviceimpact"] = raw_data.get("impact")
    incident["customFields"]["asimilydeviceaverageutilizationpercent"] = raw_data.get("avgUtilizationPercent")
    incident["customFields"]["asimilydeviceuptime"] = raw_data.get("uptime")
    incident["customFields"]["asimilydeviceisconnected"] = raw_data.get("isConnected")
    incident["customFields"]["asimilydeviceiscurrentlyinuse"] = raw_data.get("isCurrentlyInUse")
    incident["customFields"]["asimilydeviceisnetworkingdevice"] = raw_data.get("isNetworkingDevice")
    incident["customFields"]["asimilydeviceiswireless"] = raw_data.get("isWireless")
    incident["customFields"]["asimilydeviceclass"] = raw_data.get("deviceClass")
    incident["customFields"]["asimilydevicemangedby"] = raw_data.get("managedBy")
    incident["customFields"]["asimilydeviceanomalypresent"] = raw_data.get("anomalyPresent")
    incident["customFields"]["asimilydevicemds2"] = raw_data.get("mds2")
    incident["customFields"]["asimilydevicecmmsid"] = raw_data.get("cmmsId")
    incident["customFields"]["asimilydevicelastdiscoveredtime"] = (
        format_date(dateparser.parse(raw_data.get("lastDiscoveredAt"))) if raw_data.get("lastDiscoveredAt") else None
    )
    incident["customFields"]["asimilydevicetag"] = raw_data.get("deviceTag")
    incident["customFields"]["asimilydevicemasterfamily"] = raw_data.get("deviceMasterFamily")
    incident["customFields"]["asimilydevicediscoverysource"] = raw_data.get("discoverySourceValue")
    incident["customFields"]["asimilydeviceifusingendpointsecurity"] = (
        False if raw_data.get("isUsingEndpointSecurity") is None else raw_data.get("isUsingEndpointSecurity")
    )
    incident["customFields"]["asimilydeviceurl"] = construct_asimily_asset_portal_url(base_url, raw_data.get("deviceID"))

    if raw_data.get("macAddr"):
        incident["customFields"]["asimilydeviceapplications"] = client.get_asset_applications_by_mac_addr(raw_data.get("macAddr"))


def get_asset_anomalies_cves_asimily_device_fields(device_obj):
    device_fields = {}
    device_fields["asimilydeviceid"] = device_obj.get("deviceId")
    device_fields["asimilydevicemacaddress"] = device_obj.get("macAddr")
    device_fields["asimilydeviceipv4address"] = [device_obj.get("ipAddr")]
    device_fields["asimilydevicetype"] = device_obj.get("deviceType")
    device_fields["asimilydevicemodel"] = device_obj.get("deviceModel")
    device_fields["asimilydeviceos"] = device_obj.get("os")
    device_fields["asimilydevicemanufacturer"] = device_obj.get("manufacturer")
    device_fields["asimilydevicehostname"] = device_obj.get("hostName")
    if device_obj.get("deviceFamily"):
        device_family_str = device_obj.get("deviceFamily")
        device_fields["asimilydevicefamilies"] = [s.strip() for s in device_family_str.split(",")]

    # populate built-in incident fields for search
    device_fields["devicelocalip"] = device_obj.get("ipAddr")  # searchable
    device_fields["macaddress"] = device_obj.get("macAddr")  # searchable
    device_fields["devicemodel"] = device_obj.get("deviceModel")  # searchable
    device_fields["hostnames"] = device_obj.get("hostName")  # searchable
    device_fields["deviceid"] = str(device_obj.get("deviceId") or "")  # searchable

    return device_fields


def populate_asset_anomalies_asimily_anomaly_fields(incident, anomaly_obj):
    anomaly_fields = {}
    anomaly_fields["asimilyanomalyname"] = anomaly_obj.get("anomaly")
    anomaly_fields["asimilyanomalydescription"] = anomaly_obj.get("description")
    anomaly_fields["asimilyanomalycriticality"] = anomaly_obj.get("criticality")
    anomaly_fields["asimilyanomalyearliesttriggertime"] = (
        format_date(dateparser.parse(anomaly_obj.get("earliestTriggerTime"))) if anomaly_obj.get("earliestTriggerTime") else None
    )
    anomaly_fields["asimilyanomalylasttriggertime"] = (
        format_date(dateparser.parse(anomaly_obj.get("latestTriggerTime"))) if anomaly_obj.get("latestTriggerTime") else None
    )
    anomaly_fields["asimilyanomalyalertid"] = anomaly_obj.get("alertId")

    value = anomaly_obj.get("domainDeviceOrIpDevice")
    anomaly_fields["asimilyanomalyurls"] = [x.strip() for x in value.split(",")] if value else []
    anomaly_fields["asimilyanomalyisfixed"] = anomaly_obj.get("isFixed") == 55
    anomaly_fields["asimilyanomalyfixby"] = anomaly_obj.get("fixBy")
    anomaly_fields["asimilyanomalycriticalityscore"] = anomaly_obj.get("anomalyScore")
    anomaly_fields["asimilyanomalymitretactic"] = anomaly_obj.get("mitreTactic")
    anomaly_fields["asimilyanomalymitretechnique"] = anomaly_obj.get("mitreTechnique")
    anomaly_fields["asimilyanomalycategory"] = anomaly_obj.get("anomalyCategory")
    anomaly_fields["asimilyanomalycustomeranomalyid"] = anomaly_obj.get("customerAnomalyId")
    if incident.get("customFields") is None:
        incident["customFields"] = anomaly_fields
    else:
        incident.get("customFields").update(anomaly_fields)


def populate_asset_cves_asimily_cve_fields(incident, cve_obj):
    cve_fields = {}
    cve_fields["asimilycvename"] = cve_obj.get("cveName")
    cve_fields["asimilycvecwetype"] = cve_obj.get("cveTitle")
    cve_fields["asimilycveentitytype"] = cve_obj.get("productType")
    cve_fields["asimilycveentityname"] = cve_obj.get("productName")
    cve_fields["asimilycvescore"] = cve_obj.get("score")
    cve_fields["asimilycvecvss3basescore"] = cve_obj.get("cvssBaseScore")
    cve_fields["asimilycvedescription"] = cve_obj.get("description")
    cve_fields["asimilycveisfixed"] = cve_obj.get("isFixed") and cve_obj.get("isFixed") == 55
    cve_fields["asimilycvefixedby"] = cve_obj.get("fixedBy")
    cve_fields["asimilycveoempatched"] = cve_obj.get("oemPatched")
    cve_fields["asimilycveismuted"] = cve_obj.get("isCveMuted")
    cve_fields["asimilycveexploitableinwild"] = cve_obj.get("exploitableInWild")
    cve_fields["asimilycvepublisheddate"] = (
        format_date(dateparser.parse(cve_obj.get("nvdPublishDate"))) if cve_obj.get("nvdPublishDate") else None
    )
    cve_fields["asimilycveopendate"] = format_date(dateparser.parse(cve_obj.get("openDate"))) if cve_obj.get("openDate") else None
    cve_fields["asimilycvefixeddate"] = (
        format_date(dateparser.parse(cve_obj.get("fixedDate"))) if cve_obj.get("fixedDate") else None
    )

    if incident.get("customFields") is None:
        incident["customFields"] = cve_fields
    else:
        incident.get("customFields").update(cve_fields)


def get_asset_anomalies_command(client: Client, args, if_from_fetch_incident):
    """
    Returns:
        CommandResults: when triggered from CLI command
        incidents, last_device_id, total_elements: when triggered from fetch-incident

    """
    try:
        limit = int(args.get("limit", 0))
    except (ValueError, TypeError):
        limit = 0

    page_size_limit = MAX_FETCH_PAGE_LIMIT_ANOMALIES if if_from_fetch_incident else MAX_FETCH_PAGE_LIMIT_ANOMALIES_CLI
    total_limit = MAX_FETCH_TOTAL_LIMIT_ANOMALIES if if_from_fetch_incident else MAX_FETCH_TOTAL_LIMIT_ANOMALIES_CLI
    if limit > 0:
        page_size_limit = min(page_size_limit, limit)
        total_limit = min(limit, total_limit)

    total_elements, init_data = client.force_get_asset_anomalies(
        args=args, page_size_limit=page_size_limit, total_limit=total_limit
    )
    anomaly_incidents = []
    last_device_id = None
    for device_obj in init_data:
        device_anomaly_list = device_obj.get("anomalies", [])
        device_fields_dict = get_asset_anomalies_cves_asimily_device_fields(device_obj)
        last_device_id = device_obj.get("deviceId")
        for anomaly_obj in device_anomaly_list:
            incident = {}
            incident["customFields"] = device_fields_dict.copy()
            populate_asimily_asset_anomaly_incident_system_field(incident, anomaly_obj, device_obj)
            populate_asset_anomalies_asimily_anomaly_fields(incident, anomaly_obj)
            anomaly_incidents.append(incident)
    msg = (
        f"Fetched {len(anomaly_incidents)} anomalies for {len(init_data)} devices "
        f"matching search, total matching device count is {total_elements}"
    )
    print_debug_msg(msg)

    # return CommandResults when calling from CLI command
    if not if_from_fetch_incident:
        msg = f"Fetched {len(anomaly_incidents)} anomalies for {len(init_data)} devices matching search."
        if total_elements and total_elements > len(init_data):
            msg = (
                msg + f"\n{total_elements - len(init_data)} devices matching search is not fetched. "
                f"Fetch count is limited to avoid server overload."
            )

        asimily_anomaly_list = [item["customFields"] for item in anomaly_incidents if "customFields" in item]

        human_readable_output = tableToMarkdown(
            "Asimily Insight Anomalies List", asimily_anomaly_list, headers=ASIMILY_ANOMALY_CONTEXT_OUTPUT_KEY_ORDER
        )
        results = CommandResults(
            readable_output=f"{msg}\n\n{human_readable_output}",
            outputs_prefix="AsimilyInsight.Anomaly",
            outputs_key_field=["asimilydeviceid", "asimilyanomalyname"],
            outputs=asimily_anomaly_list,
            raw_response=init_data,
            ignore_auto_extract=True,
        )
        return results

    # return incident list for incident creation
    return anomaly_incidents, last_device_id, total_elements


def get_asset_cves_command(client: Client, args, if_from_fetch_incident):
    """
    Returns:
        CommandResults: when triggered from CLI command
        incidents, last_device_id, total_elements: when triggered from fetch-incident

    """
    try:
        limit = int(args.get("limit", 0))
    except (ValueError, TypeError):
        limit = 0

    page_size_limit = MAX_FETCH_PAGE_LIMIT_CVES if if_from_fetch_incident else MAX_FETCH_PAGE_LIMIT_CVES_CLI
    total_limit = MAX_FETCH_TOTAL_LIMIT_CVES if if_from_fetch_incident else MAX_FETCH_TOTAL_LIMIT_CVES_CLI
    if limit > 0:
        page_size_limit = min(page_size_limit, limit)
        total_limit = min(limit, total_limit)

    total_elements, init_data = client.force_get_asset_cves(args=args, page_size_limit=page_size_limit, total_limit=total_limit)
    cves_incidents = []
    last_device_id = None
    for device_obj in init_data:
        device_cve_list = device_obj.get("cves", [])
        device_fields_dict = get_asset_anomalies_cves_asimily_device_fields(device_obj)
        last_device_id = device_obj.get("deviceId")
        for cve_obj in device_cve_list:
            incident = {}
            incident["customFields"] = device_fields_dict.copy()
            populate_asimily_asset_cve_incident_system_field(incident, cve_obj, device_obj)
            populate_asset_cves_asimily_cve_fields(incident, cve_obj)
            cves_incidents.append(incident)

    msg = (
        f"Fetched {len(cves_incidents)} CVEs for {len(init_data)} devices "
        f"matching search, total matching device count is {total_elements}"
    )
    print_debug_msg(msg)

    # return CommandResults when calling from CLI command
    if not if_from_fetch_incident:
        msg = f"Fetched {len(cves_incidents)} CVEs for {len(init_data)} devices matching search."
        if total_elements and total_elements > len(init_data):
            msg = (
                msg + f"\n{total_elements - len(init_data)} devices matching search is not fetched. "
                f"Fetch count is limited to avoid server overload."
            )

        asimily_cve_list = [item["customFields"] for item in cves_incidents if "customFields" in item]

        human_readable_output = tableToMarkdown(
            "Asimily Insight CVEs List", asimily_cve_list, headers=ASIMILY_CVE_CONTEXT_OUTPUT_KEY_ORDER
        )
        results = CommandResults(
            readable_output=f"{msg}\n\n{human_readable_output}",
            outputs_prefix="AsimilyInsight.CVE",
            outputs_key_field=["asimilydeviceid", "asimilycvename"],
            outputs=asimily_cve_list,
            raw_response=init_data,
            ignore_auto_extract=True,
        )
        return results

    # return incident list for incident creation
    return cves_incidents, last_device_id, total_elements


def get_asset_details_command(client: Client, args) -> CommandResults:
    if_fetch_applications = True  # For now we need to fetch assets with applications and query apps in separate call always
    init_data: List[Any] = []

    try:
        limit = int(args.get("limit", 0))
    except (ValueError, TypeError):
        limit = 0

    page_size_limit = MAX_FETCH_PAGE_LIMIT_ASSETS_WITH_APP if if_fetch_applications else MAX_FETCH_PAGE_LIMIT_ASSETS
    total_limit = MAX_FETCH_TOTAL_LIMIT_ASSETS_WITH_APP if if_fetch_applications else MAX_FETCH_TOTAL_LIMIT_ASSETS
    if limit > 0:
        page_size_limit = min(page_size_limit, limit)
        total_limit = min(limit, total_limit)

    total_elements, init_data = client.force_get_asset_details(
        args=args, page_size_limit=page_size_limit, total_limit=total_limit
    )

    incidents = []
    if init_data:
        counter = 0
        for raw_data in init_data:
            try:
                counter += 1
                print_debug_msg(f"Processing {counter} device details for incident creation.")
                entity: Dict[str, Any] = {}
                map_asimily_asset_entity_from_asimily_assets_json(client, entity, raw_data, client.get_base_url())
                incidents.append(entity["customFields"])
            except Exception as e:
                print_debug_msg(f"Failure during converting asset incident: {str(e)}")

    msg = (
        f"Fetched {len(incidents)} out of {total_elements} assets matching search. "
        f"Asset fetch count is limited to avoid server overload."
    )

    print_debug_msg(msg)

    asimily_asset_list = incidents
    human_readable_output = tableToMarkdown(
        "Asimily Insight Asset Details List", asimily_asset_list, headers=ASIMILY_ASSET_CONTEXT_OUTPUT_KEY_ORDER
    )
    results = CommandResults(
        readable_output=f"{msg}\n\n{human_readable_output}",
        outputs_prefix="AsimilyInsight.Asset",
        outputs_key_field="asimilydeviceid",
        outputs=asimily_asset_list,
        raw_response=init_data,
        ignore_auto_extract=True,
    )
    return results


def update_next_run(last_run: dict, updated: dict, flags: dict) -> dict:
    """
    LastRun Object key:
        last_type: "anomaly" or "cve". The last fetch-incident run's fetch entity type. Anomalies/CVEs are fetched in turns
        last_anomaly_deviceid: last asimily device id that we fetched the anomalies for.
        last_cve_deviceid: last asimily device id that we fetched the cves for.
        last_anom_syncstart: the last full sync of anomaly start time. Used as anomaliesLastUpdatedSince filter for fetch.
        last_cve_syncstart: the last full sync of cve start time. Used as the cvesLastUpdatedSince filter for fetch.
        cur_anom_syncstart: the current full sync of anomaly start time.
        cur_cve_syncstart: the current full sync of cve start time.
    """
    next_run = {"last_type": "anomaly" if flags.get("trigger_anomalies_fetch") else "cve"}
    if flags.get("last_anomaly_deviceid") is not None:
        next_run["last_anomaly_deviceid"] = str(flags["last_anomaly_deviceid"])
    if flags.get("last_cve_deviceid") is not None:
        next_run["last_cve_deviceid"] = str(flags["last_cve_deviceid"])
    if flags.get("last_anom_syncstart"):
        next_run["last_anom_syncstart"] = format_date(flags["last_anom_syncstart"])
    if flags.get("cur_anom_syncstart"):
        next_run["cur_anom_syncstart"] = format_date(flags["cur_anom_syncstart"])
    if flags.get("last_cve_syncstart"):
        next_run["last_cve_syncstart"] = format_date(flags["last_cve_syncstart"])
    if flags.get("cur_cve_syncstart"):
        next_run["cur_cve_syncstart"] = format_date(flags["cur_cve_syncstart"])

    return {**last_run, **next_run, **updated}


def should_trigger_anomaly(params: dict, last_type: str) -> bool:
    return bool(params.get("iffetchanomalies") and (not params.get("iffetchcves") or last_type != "anomaly"))


def should_trigger_cve(params: dict, last_type: str) -> bool:
    return bool(params.get("iffetchcves") and (not params.get("iffetchanomalies") or last_type == "anomaly"))


def fetch_asimily_incidents(client: Client, args, params):
    last_run = demisto.getLastRun() or {}
    last_type = last_run.get("last_type", "anomaly")
    print_debug_msg(f"Last run type: {last_type}")

    flags = {
        "last_anomaly_deviceid": int(last_run.get("last_anomaly_deviceid", 0)),
        "last_cve_deviceid": int(last_run.get("last_cve_deviceid", 0)),
        "last_anom_syncstart": last_run.get("last_anom_syncstart"),
        "last_cve_syncstart": last_run.get("last_cve_syncstart"),
        "cur_anom_syncstart": last_run.get("cur_anom_syncstart"),
        "cur_cve_syncstart": last_run.get("cur_cve_syncstart"),
    }
    print_debug_msg(f"Initial flags: {flags}")

    flags["trigger_anomalies_fetch"] = should_trigger_anomaly(params, last_type)
    flags["trigger_cves_fetch"] = should_trigger_cve(params, last_type)
    print_debug_msg(f"Trigger flags: Anomaly: {flags['trigger_anomalies_fetch']}, CVE: {flags['trigger_cves_fetch']}")

    updated_args = args.copy()
    updated_args.pop("lastRun", None)

    total_elements = 0
    incidents = []

    if flags["trigger_anomalies_fetch"]:
        updated_args["deviceRangeId"] = flags["last_anomaly_deviceid"]
        if flags["last_anom_syncstart"]:
            updated_args["anomaliesLastUpdatedSince"] = flags["last_anom_syncstart"]

        if flags["cur_anom_syncstart"] is None:  # first full sync
            flags["cur_anom_syncstart"] = datetime.utcnow()

        print_debug_msg(f"Fetching anomalies with args: {updated_args}")
        incidents, flags["last_anomaly_deviceid"], total_elements = get_asset_anomalies_command(client, updated_args, True)
        print_debug_msg(f"Fetched {len(incidents)} anomaly incidents for {total_elements} devices")
        if total_elements == 0:
            flags["last_anomaly_deviceid"] = 0
            flags["last_anom_syncstart"] = flags["cur_anom_syncstart"]
            flags["cur_anom_syncstart"] = datetime.utcnow()
    elif flags["trigger_cves_fetch"]:
        updated_args["deviceRangeId"] = flags["last_cve_deviceid"]
        if flags["last_cve_syncstart"]:
            updated_args["cvesLastUpdatedSince"] = flags["last_cve_syncstart"]

        if flags["cur_cve_syncstart"] is None:  # first full sync
            flags["cur_cve_syncstart"] = datetime.utcnow()

        print_debug_msg(f"Fetching CVEs with args: {updated_args}")
        incidents, flags["last_cve_deviceid"], total_elements = get_asset_cves_command(client, updated_args, True)
        print_debug_msg(f"Fetched {len(incidents)} CVE incidents for {total_elements} devices")
        if total_elements == 0:
            flags["last_cve_deviceid"] = 0
            flags["last_cve_syncstart"] = flags["cur_cve_syncstart"]
            flags["cur_cve_syncstart"] = datetime.utcnow()

    print_debug_msg(f"Pushing {len(incidents)} incidents to XSOAR")
    demisto.incidents(incidents)
    new_last_run = update_next_run(last_run, {}, flags)
    print_debug_msg(f"Setting new lastRun: {new_last_run}")
    demisto.setLastRun(new_last_run)


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    print_params = copy.deepcopy(params)
    print_params.get("asimilycred", {}).pop("password", None)
    print_debug_msg(print_params)

    base_url = params.get("url")
    api_key = params["asimilycred"]["password"]
    user_name = params["asimilycred"]["identifier"]

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    processed_args = process_params_and_args(params, args, command)

    print_debug_msg(f"Command being called is {command}")
    try:
        client = Client(base_url=base_url, verify=verify_certificate, auth=(user_name, api_key), proxy=proxy)

        if command == "test-module":
            result = test_module(client, params)
            return_results(result)

        elif command == "fetch-incidents":
            fetch_asimily_incidents(client, processed_args, params)

        elif command == "asimily-get-asset-details":
            return_results(get_asset_details_command(client, processed_args))

        elif command == "asimily-get-asset-anomalies":
            return_results(get_asset_anomalies_command(client, processed_args, False))

        elif command == "asimily-get-asset-vulnerabilities":
            return_results(get_asset_cves_command(client, processed_args, False))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
