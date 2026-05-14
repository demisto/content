"""Ignite Main File."""

import ipaddress
import re
from copy import deepcopy
from typing import Any

import demistomock as demisto
import requests
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

urllib3.disable_warnings()

""" CONSTANTS """
INTEGRATION_VERSION = get_pack_version()
INTEGRATION_PLATFORM = "Cortex XSOAR"
DEFAULT_API_PATH = "api.flashpoint.io"
DEFAULT_PLATFORM_PATH = "https://app.flashpoint.io"
DEFAULT_OLD_PLATFORM_PATH = "https://fp.tools"
FIRST_FETCH = "3 days"
DEFAULT_FETCH = 15
DEFAULT_PAGE_SIZE = 50
DEFAULT_FROM_VALUE = 0
DEFAULT_LIMIT = 10
DEFAULT_REPORT_LIMIT = 5
DEFAULT_REPUTATION_LIMIT = 5
DEFAULT_REPUTATION_CONTEXT_LIMIT = 50  # Default max entries for both relationships and enrichments per reputation result
MAX_PAGE_SIZE = 1000
MAX_FETCH_LIMIT = 200
MAX_PRODUCT = 10000
MAX_ALERTS_LIMIT = 500
MIN_CVSS_AND_EPSS_SCORE = 0
MAX_EPSS_SCORE = 1
MAX_CVSS_SCORE = 10
DEFAULT_SORT_ORDER = "asc"
DEFAULT_SORT_VALUE = "id"
DEFAULT_VULNERABILITIES_SORT_ORDER = "desc"
DEFAULT_VULNERABILITIES_SORT = "published at"
DEFAULT_FETCH_TYPE = "Compromised Credentials"
DEFAULT_FROM_VALUE = 0
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
READABLE_DATE_FORMAT = "%b %d, %Y  %H:%M"
TOTAL_RETRIES = 4
TOTAL_RETRIES_ON_ENRICHMENT = 0
DEFAULT_TIMEOUT = 60
TIMEOUT_ON_ENRICHMENT = 15
STATUS_CODE_TO_RETRY = (429, *(status_code for status_code in requests.status_codes._codes if status_code >= 500))  # type: ignore
OK_CODES = (
    400,
    401,
    403,
    404,
    521,
    *(
        status_code
        for status_code in requests.status_codes._codes  # type: ignore
        if status_code  # type: ignore[attr-defined]
        >= 200
        and status_code < 300
    ),  # type: ignore[attr-defined]
)  # type: ignore
BACKOFF_FACTOR = 7.5  # Sleep for [0s, 15s, 30s, 60s] between retries.
DEFAULT_END_TIME = "now"
DEFAULT_SEVERITY = "Unknown"

IS_FRESH_VALUES = ["true", "false"]
SORT_ORDER_VALUES = ["asc", "desc"]
SORT_DATE_VALUES = ["created_at", "first_observed_at"]
FILTER_DATE_VALUES = ["created_at", "first_observed_at"]
ALERT_STATUS_VALUES = ["archived", "starred", "sent", "none"]
ALERT_ORIGIN_VALUES = ["searches", "assets"]
LIBRARY_AND_PACKAGE_SORT_VALUES = ["id", "name"]

DATE_OBSERVED = "Date Observed (UTC)"
STRING_FORMAT = "[{}]({})"
TIME_OBSERVED = "Observed time (UTC)"
QUERY = r'+type:("ip-src","ip-dst","ip-dst|port") +value.\*:"'
HR_TITLE = "### Ignite {} reputation for "
REPUTATION_MALICIOUS = "Reputation: Malicious\n\n"
TABLE_TITLE = "Events in which this IOC observed"
ALL_DETAILS_LINK = "\nAll events and details (ignite): [{}]({})\n"
PLATFORM_LINK = "\nPlatform Link(ignite): [{}]({})\n"
MALICIOUS_DESCRIPTION = "Found in malicious indicators dataset"
SUSPICIOUS_DESCRIPTION = "Found in suspicious indicators dataset"
UNKONWN_DESCRIPTION = "Reputation of this Indicator is Unknown"
STIX_ATTACK_PATTERN = "STIX Attack Pattern"
REPUTATION_UNKNOWN = "Reputation: Unknown\n\n"
REPUTATION_SUSPICIOUS = "Reputation: Suspicious\n\n"
MALICIOUS_REPUTATION_SCORE = 3
UNKNOWN_REPUTATION_SCORE = 0
SUSPICIOUS_REPUTATION_SCORE = 2
FORUM_NAME = "Forum Name"
ROOM_TITLE = "Room Title"
AUTHOR_NAME = "Author Name"
THREAD_TITLE = "Thread Title"
EMPTY_DATA = "N/A"
VENDOR_NAME = "Ignite"
PAGINATION_HR = "#### To retrieve the next set of result use,"
MARKDOWN_CHARS = r"\*_{}[]()#+-!"
X_FP_HIGHLIGHT_TEXT = r"</?x-fp-highlight>"
DEFAULT_REPUTATION_VALUE = "unknown"
CUSTOM_INDICATOR_DBOTSCORE = DBotScoreType.CUSTOM
CUSTOM_OUTPUT_PREFIX = "Ignite.{}"

REPUTATION_SCORE_MAPPING = {"unknown": 0, "no_score": 0, "informational": 1, "suspicious": 2, "malicious": 3}

IOC_TYPE_MAPPING = {
    "ip": FeedIndicatorType.IP,
    "ipv4": FeedIndicatorType.IP,
    "ipv6": FeedIndicatorType.IPv6,
    "domain": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "file": FeedIndicatorType.File,
}

DBOTSCORE_IOC_TYPE_MAPPING = {
    "ipv4": DBotScoreType.IP,
    "ipv6": DBotScoreType.IP,
    "domain": DBotScoreType.DOMAIN,
    "url": DBotScoreType.URL,
    "file": DBotScoreType.FILE,
}

URL_SUFFIX = {
    "LIST_INDICATORS": "/technical-intelligence/v2/indicators",
    "INDICATOR_SEARCH": "/technical-intelligence/v1/simple",
    "REPORT_SEARCH": "/finished-intelligence/v1/reports",
    "COMPROMISED_CREDENTIALS": "/sources/v1/noncommunities/search",
    "GET_REPORT_BY_ID": "/finished-intelligence/v1/reports/{}",
    "RELATED_REPORT_LIST": "/finished-intelligence/v1/reports/{}/related",
    "EVENT_LIST": "/technical-intelligence/v1/event",
    "EVENT_GET": "/technical-intelligence/v1/event/{}",
    "COMMUNITY_SEARCH": "/sources/v2/communities",
    "ALERTS": "/alert-management/v1/notifications",
    "VENDORS": "/vulnerability-intelligence/v1/vendors",
    "PRODUCTS": "/vulnerability-intelligence/v1/products",
    "VULNERABILITY_LIBRARIES": "/vulnerability-intelligence/v1/vulnerabilities/{}/libraries",
    "VULNERABILITY_PACKAGES": "/vulnerability-intelligence/v1/vulnerabilities/{}/packages",
    "VULNERABILITY_LIST": "/vulnerability-intelligence/v1/vulnerabilities",
    "VULNERABILITY_GET": "/vulnerability-intelligence/v1/vulnerabilities",
}

IGNITE_PATHS = {
    "Filename": "Ignite.Filename.Event(val.Fpid && val.Fpid == obj.Fpid)",
}

HR_SUFFIX = {
    "IOC_EMAIL": "/cti/malware/iocs?sort_date=All%20Time&types=email-dst,email-src,"
    "email-src-display-name,email-subject,email&query=%22{}%22",
    "IOC_FILENAME": "/cti/malware/iocs?sort_date=All%20Time&types=filename&query=%22{}%22",
    "IOC_URL": "/cti/malware/iocs?sort_date=All%20Time&types=url&query=%22{}%22",
    "IOC_FILE": "/cti/malware/iocs?sort_date=All%20time&types=md5,sha1,sha256,sha512,ssdeep&query=%22{}%22",
    "IOC_IP": "/cti/malware/iocs?query=%22{}%22&sort_date=All%20Time&types=ip-dst,ip-src,ip-dst|port",
    "IOC_SEARCH": "/cti/malware/iocs?query=%22{}%22&sort_date=All%20Time",
    "IOC_DOMAIN": "/cti/malware/iocs?sort_date=All%20Time&types=domain&query=%22{}%22",
    "IOC_ITEM": "/cti/malware/iocs/{}",
    "IOC_LIST": "/cti/malware/iocs",
    "IOC_UUID_LIST": "/cti/malware/iocs?query={}&sort_date=All+Time",
    "REPORT": "/cti/intelligence/report/{}#detail",
    "COMMUNITY_SEARCH": "/search/results/communities?query={}&include.date=all%20time",
    "VULNERABILITY": "/vuln/vulnerabilities/{}",
    "PRODUCT": "/vuln/products/{}",
    "VENDOR": "/vuln/vendors/{}",
}

OUTPUT_PREFIX = {
    "COMPROMISED_CREDENTIALS": "Ignite.CompromisedCredential",
    "REPORT": "Ignite.Report",
    "EMAIL": "Ignite.Email.Event",
    "FILENAME": "Ignite.Filename.Event",
    "DOMAIN": "Ignite.Domain",
    "IP": "Ignite.IP",
    "IP_COMMUNITY_SEARCH": "Ignite.IP",
    "IPV4": "Ignite.IP",
    "IPV6": "Ignite.IP",
    "URL": "Ignite.URL",
    "FILE": "Ignite.File",
    "EVENT": "Ignite.Event",
    "ALERT": "Ignite.Alert",
    "TOKEN": "Ignite.PageToken.Alert",
    "VULNERABILITY_LIBRARY": "Ignite.Library",
    "VULNERABILITY_PACKAGE": "Ignite.Package",
    "VULNERABILITY": "Ignite.Vulnerability",
    "VENDOR": "Ignite.Vendor",
    "PRODUCT": "Ignite.Product",
}

OUTPUT_KEY_FIELD = {
    "FPID": "Fpid",
    "REPORT_ID": "ReportId",
    "EVENT_ID": "EventId",
    "COMPROMISED_CREDENTIAL_ID": "_id",
    "VULNERABILITY_ID": "id",
}

ALERT_SOURCES_MAPPING = {
    "Github": "data_exposure__github",
    "Gitlab": "data_exposure__gitlab",
    "Bitbucket": "data_exposure__bitbucket",
    "Communities": "communities",
    "Images": "media",
    "Marketplaces": "marketplaces",
}

ALERT_RESOURCE_URL = {
    "communities": "/search/context/communities/{}",
    "marketplaces": "/search/context/marketplaces/{}",
    "media": "/search/results/media?include.date=all+time&include.media_id={}",
}

ALERT_STATUS_MAPPING = {
    "starred": "flagged",
}

VALID_SEVERITIES = ("critical", "high", "medium", "low", "informational")
VALID_RANSOMWARE_SCORE = ("critical", "high", "medium", "low")
DEFAULT_FROM = 0

VULNERABILITY_SORT_MAPPING = {
    "id": "id",
    "severity": "severity",
    "title": "title",
    "cvssv3 score": "cvssv3_score",
    "published at": "published_at",
}
REFERENCE_TYPES_MAPPING = {
    "bugtraq id": "bid",
    "bug tracker": "bugtracker",
    "immunity canvas": "canvas",
    "immunity canvas (d2exploitpack)": "canvasd2",
    "immunity canvas (white phosphorus)": "canvaswp",
    "cert": "cert",
    "cert vu": "certvu",
    "ciac advisory": "ciac",
    "cve id": "cveid",
    "d2 elliot": "elliot",
    "exploit activity": "exploitactivity",
    "exploit database": "exploitdb",
    "flashpoint": "flashpoint",
    "generic exploit url": "gexploiturl",
    "generic informational url": "ginformurl",
    "disa iava": "iava",
    "iss x-force id": "iss",
    "japan vulnerability notes": "jpcert",
    "keyword": "keyword",
    "mail list post": "mailpost",
    "metasploit url": "metasploit",
    "microsoft knowledge base article": "mskb",
    "microsoft security bulletin": "mssb",
    "nessus script id": "nessus",
    "news article": "news",
    "nikto item id": "nikto",
    "other advisory url": "oadvisoryurl",
    "other solution url": "osolutionurl",
    "oval id": "oval",
    "packet storm": "packetstorm",
    "redhat rhsa": "redhat",
    "related vulndb id": "relvulndbid",
    "scip vuldb id": "scipid",
    "secunia advisory id": "secunia",
    "security tracker": "securitytracker",
    "snort signature id": "snort",
    "tenable pvs": "tenpvs",
    "us-cert cyber security alert": "uscert",
    "vendor specific advisory url": "vendadvisoryurl",
    "vendor specific solution url": "vendsolutionurl",
    "vendor url": "vendurl",
    "vendor specific news/changelog entry": "vsnewschangelog",
    "vupen advisory": "vupen",
}

LOCATION_MAPPING = {
    "context dependent": "context",
    "dial-up access required": "dialup",
    "local access required": "local",
    "legacy: local / remote": "local_remote",
    "mobile phone / hand-held device": "mobile",
    "physical access required": "physical",
    "remote / network access": "remote",
    "location unknown": "unknown",
    "wireless vector": "wireless",
}

ATTACK_TYPE_MAPPING = {
    "authentication management": "auth_manage",
    "cryptographic": "crypt",
    "infrastructure": "infrastruct",
    "input manipulation": "input_manip",
    "misconfiguration": "miss_config",
    "man-in-the-middle (mitm)": "mitm",
    "other": "other",
    "race condition": "race",
    "attack type unknown": "unknown",
}

VULNERABILITY_REPUTATION_SCORE_MAPPING = {
    "critical": Common.DBotScore.BAD,
    "high": Common.DBotScore.BAD,
    "medium": Common.DBotScore.SUSPICIOUS,
    "low": Common.DBotScore.SUSPICIOUS,
    "informational": Common.DBotScore.GOOD,
    "unknown": Common.DBotScore.NONE,
}
MESSAGES = {
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 to 200.",
    "INVALID_JSON_OBJECT": "Failed to parse json object from response: {}.",
    "STATUS_CODE": "Error in API call [{}] - {}",
    "INVALID_FETCH_TIME": "{} is invalid value for First Fetch Time. First fetch time should not be in the future.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time' should be a valid date or relative timestamp such as "
    "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "SIZE_ERROR": "{} is an invalid value for size. Size must be between 1 to {}.",
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "PAGE_SIZE_ERROR": "{} is an invalid value for the page size. The page size must be between 1 to {}.",
    "LIMIT_ERROR": "{} is an invalid value for the limit. The limit must be between 1 to {}.",
    "PAGE_NUMBER_ERROR": "{} is an invalid value for the page number. The page number must be greater than 0.",
    "PRODUCT_ERROR": "The multiplication of the page_size and the page_number parameters cannot exceed {}. "
    "Current multiplication is {}.",
    "START_DATE_ERROR": "Requires the start_date argument along with the end_date argument.",
    "FILTER_DATE_ERROR": "{} is an invalid value for filter date. Filter date value must be of {}.",
    "SORT_DATE_ERROR": "{} is an invalid value for the sort date. The sort date value must be of {}.",
    "SORT_ORDER_ERROR": "{} is an invalid value for the sort order. The sort order value must be of {}.",
    "MISSING_DATE_ERROR": "Requires the argument value for at least the 'start_date' argument.",
    "MISSING_FILTER_DATE_ERROR": "Requires the filter_date argument's value when the start_date or the "
    "end_date argument is provided.",
    "MISSING_SORT_DATE_ERROR": "Requires sort_date value when sort_order is provided.",
    "IS_FRESH_ERROR": "{} is an invalid value for is fresh. Is fresh value must be of {}.",
    "MISSING_DATA": "{} response contains incorrect or missing data.",
    "TIME_RANGE_ERROR": f"The maximum records to fetch for the given first fetch can not exceed {MAX_PRODUCT}."
    " Current records are {}. Try decreasing the time interval.",
    "NO_PARAM_PROVIDED": "Please provide the {}.",
    "INVALID_ARGUMENT_RESPONSE": "Invalid argument value while trying to get information from Ignite: ",
    "INVALID_API_KEY": "Encountered error while trying to get information from Ignite: Invalid API Key configured.",
    "NO_RECORD_FOUND": "No record found for given argument(s): Not Found.",
    "TEST_CONNECTIVITY_FAILED": "Test connectivity failed. Please provide valid input parameters.",
    "MISSING_REQUIRED_ARGS": "{} is a required field. Please provide correct input.",
    "INVALID_IP_ADDRESS": "Invalid IP - {}",
    "INVALID_SINGLE_SELECT_PARAM": "{} is an invalid value for {}. Possible values are: {}.",
    "INVALID_TIME_INTERVAL": "{} parameter must be before {} parameter.({} - {})",
    "INVALID_PASSWORD_LENGTH": "Minimum length of password must be greater than zero.",
    "INVALID_FROM_PROVIDED": "{} is an invalid value for from. From must be greater than or equal to 0.",
    "INVALID_INTEGER_IDS": "The following {} IDs are not valid integers and will be ignored: {}",
    "INVALID_MULTI_PARAMS_PROVIDED": "{} is an invalid value for {}. Possible values are: {}.",
    "INVALID_INT_PARAMS_PROVIDED": "{} is an invalid value for {}. Please provide valid integer value(s).",
    "INVALID_CVSS_SCORE": "{} must be a float between 0 and 10.",
    "INVALID_EPSS_SCORE": "{} must be a float between 0 and 1.",
    "INVALID_SCORE_RANGE": "{} must be less than or equal to {}.",
    "INVALID_LIMIT_PROVIDED": "{} is an invalid value for limit. Limit must be between 1 to {}.",
}


class Client(BaseClient):
    """
    Client to use in integration with powerful http_request.
    """

    def __init__(
        self,
        url,
        headers,
        verify,
        proxy,
        create_relationships,
        reputation_enrichments_limit: int = DEFAULT_REPUTATION_CONTEXT_LIMIT,
    ):
        """Initialize class object.

        :type url: ``str``
        :param url: Base server address with suffix, for example: https://example.com.

        :type headers: ``Dict``
        :param headers: Additional headers to be included in the requests.

        :type verify: ``bool``
        :param verify: Use to indicate secure/insecure http request.

        :type proxy: ``bool``
        :param proxy: The proxy settings to be used.

        :type create_relationships: ``bool``
        :param create_relationships: True if integration will create relationships.

        :type reputation_enrichments_limit: ``int``
        :param reputation_enrichments_limit: Maximum number of enrichment entries stored per reputation
            command result. Lower values improve performance; higher values preserve more details.
        """
        self.url = url

        if DEFAULT_API_PATH in url:
            self.platform_url = DEFAULT_PLATFORM_PATH
        else:
            self.platform_url = url

        self.headers = headers
        self.verify = verify
        self.proxy = proxy
        self.create_relationships = create_relationships
        self.reputation_enrichments_limit = reputation_enrichments_limit

        super().__init__(base_url=self.url, headers=self.headers, verify=self.verify, proxy=self.proxy)

    def http_request(self, method, url_suffix, params=None, json_data=None):
        """
        Get http response based on url and given parameters.

        :param method: Specify http methods
        :param url_suffix: url encoded url suffix
        :param params: None
        :param json_data: None
        :return: http response on json
        """
        demisto.debug(f"Requesting Ignite with method: {method}, url_suffix: {url_suffix} and params: {params}")
        # For reputation commands which run during an enrichment we limit the timeout and the retries
        retries = TOTAL_RETRIES_ON_ENRICHMENT if is_time_sensitive() else TOTAL_RETRIES
        timeout = TIMEOUT_ON_ENRICHMENT if is_time_sensitive() else DEFAULT_TIMEOUT

        resp = self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            json_data=json_data,
            retries=retries,
            status_list_to_retry=STATUS_CODE_TO_RETRY,
            backoff_factor=BACKOFF_FACTOR,
            raise_on_redirect=False,
            raise_on_status=False,
            resp_type="response",
            ok_codes=OK_CODES,
            timeout=timeout,
        )  # type: ignore

        status_code = resp.status_code

        try:
            resp_json = resp.json()
        except ValueError as exception:
            raise DemistoException(
                MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["INVALID_JSON_OBJECT"].format(resp.text)), exception
            ) from exception

        if status_code != 200:
            if status_code == 400:
                raise DemistoException(
                    MESSAGES["STATUS_CODE"].format(
                        status_code,
                        MESSAGES["INVALID_ARGUMENT_RESPONSE"]
                        + str(resp_json.get("detail", resp_json.get("message", json.dumps(resp_json)))),
                    )
                )
            if status_code == 401:
                raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["INVALID_API_KEY"]))
            if status_code == 404:
                raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, MESSAGES["NO_RECORD_FOUND"]))
            if status_code in (521, 403):
                error_message = MESSAGES["TEST_CONNECTIVITY_FAILED"]
                if resp_json:
                    error_message += json.dumps(resp_json)
                raise DemistoException(MESSAGES["STATUS_CODE"].format(status_code, error_message))
            self.client_error_handler(resp)

        return resp_json

    def get_indicator(self, indicator_value: str, indicator_type: str, exact_match: bool = False):
        """
        Get an indicator by its type and value.

        :param indicator_type: The indicator type.
        :param indicator_value: The indicator value.
        :param exact_match: Whether to perform an exact match. If true, the indicator value is enclosed in quotes.

        :return: The indicator response.
        """
        indicator_value = f'"{indicator_value}"' if exact_match else indicator_value
        params = {"ioc_types": indicator_type, "ioc_value": indicator_value, "embed": "all"}

        return self.http_request("GET", URL_SUFFIX["LIST_INDICATORS"], params=params)

    def get_indicator_by_id(self, indicator_id: str):
        """
        Get an indicator by its id.

        :param indicator_id: ID of the indicator.

        :return: The indicator response.
        """

        url = f'{URL_SUFFIX["LIST_INDICATORS"]}/{indicator_id}'

        return self.http_request("GET", url)

    def get_vendors(self, params: dict):
        """
        Get vendors.

        :param params: Params to get vendors.

        :return: The vendors response.
        """
        return self.http_request("GET", URL_SUFFIX["VENDORS"], params=params)

    def get_products(self, params: dict):
        """
        Get products.

        :param params: Params to get products.

        :return: The products response.
        """
        return self.http_request("GET", URL_SUFFIX["PRODUCTS"], params=params)

    def get_vulnerability_libraries(self, vulnerability_id: str, params: dict):
        """
        Get libraries affected by a particular vulnerability.

        :param vulnerability_id: The vulnerability ID assigned by Flashpoint.
        :param params: Query parameters for the request.

        :return: The vulnerability libraries response.
        """
        url_suffix = URL_SUFFIX["VULNERABILITY_LIBRARIES"].format(vulnerability_id)

        return self.http_request("GET", url_suffix, params=params)

    def get_vulnerability_packages(self, vulnerability_id: str, params: dict):
        """
        Get packages affected by a particular vulnerability.

        :param vulnerability_id: The vulnerability ID assigned by Flashpoint.
        :param params: Query parameters for the request.

        :return: The vulnerability packages response.
        """
        url_suffix = URL_SUFFIX["VULNERABILITY_PACKAGES"].format(vulnerability_id)

        return self.http_request("GET", url_suffix, params=params)

    def vulnerability_list(self, query_params: dict, payload: dict):
        """
        List vulnerabilities

        :param query_params: Query parameters.
        :param payload: Body parameters.

        :return: The vulnerability response.
        """
        return self.http_request("POST", URL_SUFFIX["VULNERABILITY_LIST"], params=query_params, json_data=payload)


""" HELPER FUNCTIONS """


def string_escape_markdown(data: Any):
    """
    Escape any chars that might break a markdown string.

    :param data: The data to be modified (required).

    :return: A modified data.
    """
    if isinstance(data, str):
        data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in data])
    elif isinstance(data, list):
        new_data = []
        for sub_data in data:
            if isinstance(sub_data, str):
                sub_data = "".join(["\\" + str(c) if c in MARKDOWN_CHARS else str(c) for c in sub_data])
            new_data.append(sub_data)
        data = new_data

    return data


def get_url_suffix(query):
    """
    Create url-suffix using the query value with url encoding.

    :param query: value of query param
    :return: url-encoded url-suffix
    """
    return URL_SUFFIX["INDICATOR_SEARCH"] + "?query=" + urllib.parse.quote(query.encode("utf8"))


def remove_space_from_args(args):
    """Remove space from args."""
    for key in args:
        if isinstance(args[key], str):
            args[key] = args[key].strip()
    return args


def validate_params(command: str, params: dict):
    """
    Validate the parameters.

    :param command: Command name.
    :type command: str

    :param params: Params to validate.
    :type params: Dict
    :return:
    """
    if not params.get("url"):
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format("Server URL"))
    if not str(params.get("credentials", {}).get("password", "")).strip():
        raise DemistoException(MESSAGES["NO_PARAM_PROVIDED"].format("API Key"))
    if params.get("isFetch"):
        first_fetch = arg_to_datetime(params.get("first_fetch", FIRST_FETCH)).astimezone(timezone.utc)  # type: ignore
        current_time = arg_to_datetime(DEFAULT_END_TIME).astimezone(timezone.utc)  # type: ignore
        if first_fetch > current_time and command == "test-module":
            raise DemistoException(MESSAGES["INVALID_FETCH_TIME"].format(first_fetch.strftime(DATE_FORMAT)))


def replace_key(dictionary, new_key, old_key):
    """
    Replace key in dictionary.

    :param dictionary: dictionary object on which we wan to replace key.
    :param new_key: key which will replace in dictionary
    :param old_key: existing key in dictionary
    :return: dict object
    """
    if dictionary.get(old_key):
        dictionary[new_key] = dictionary.pop(old_key)
    return dictionary


def parse_event_response(client, event, fpid, href):
    """
    Prepare required event json object from event response.

    :param href: reference link of event
    :param fpid: unique id of event. i.e EventId
    :param client: object of client class
    :param event: event indicator from response
    :return: required event json object
    """
    observed_time = time.strftime(READABLE_DATE_FORMAT, time.gmtime(float(event["timestamp"])))
    name = event.get("info", "")
    uuid = event.get("uuid", "")
    if uuid:
        fp_link = urljoin(client.platform_url, HR_SUFFIX["IOC_UUID_LIST"].format(uuid))
        name_str = STRING_FORMAT.format(name, fp_link)
    else:
        name_str = name

    tags_list = [tag["name"] for tag in event.get("Tag", [])]
    tags_value = ", ".join(tags_list)

    event_creator_email = event.get("event_creator_email", "")

    event = {
        TIME_OBSERVED: observed_time,
        "Name": name_str,
        "EventName": name,
        "Tags": tags_value,
        "EventCreatorEmail": event_creator_email,
        "EventId": fpid,
        "UUID": uuid,
        "Href": href,
    }

    return event


def validate_fetch_incidents_params(params: dict, last_run: dict) -> dict:
    """
    Validate the parameter list for fetch incidents.

    :param params: Dictionary containing demisto configuration parameters
    :param last_run: last run returned by function demisto.getLastRun

    :return: Dictionary containing validated configuration parameters in proper format.
    """
    fetch_params = {}

    fetch_type = params.get("fetch_type", DEFAULT_FETCH_TYPE)
    if not fetch_type:
        fetch_type = DEFAULT_FETCH_TYPE

    first_fetch = arg_to_datetime(params.get("first_fetch", FIRST_FETCH))
    start_time = first_fetch.strftime(DATE_FORMAT)  # type: ignore

    if last_run and "start_time" in last_run:
        start_time = last_run.get("start_time")  # type: ignore

    is_fresh = argToBoolean(params.get("is_fresh_compromised_credentials", "true"))

    password_has_lowercase = params.get("password_has_lowercase", "")
    if password_has_lowercase:
        password_has_lowercase = argToBoolean(password_has_lowercase)

    password_has_uppercase = params.get("password_has_uppercase", "")
    if password_has_uppercase:
        password_has_uppercase = argToBoolean(password_has_uppercase)

    password_has_number = params.get("password_has_number", "")
    if password_has_number:
        password_has_number = argToBoolean(password_has_number)

    password_has_symbol = params.get("password_has_symbol", "")
    if password_has_symbol:
        password_has_symbol = argToBoolean(password_has_symbol)

    password_min_length = params.get("password_min_length", "")
    if password_min_length:
        password_min_length = arg_to_number(password_min_length)
        if password_min_length <= 0:
            raise ValueError(MESSAGES["INVALID_PASSWORD_LENGTH"])

    alert_status = params.get("status", "").lower()
    alert_origin = params.get("origin", "").lower()
    alert_sources = argToList(params.get("sources", ""))

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_FETCH))

    if fetch_type == DEFAULT_FETCH_TYPE:
        fetch_params = prepare_args_for_fetch_compromised_credentials(
            max_fetch,  # type: ignore
            start_time,
            is_fresh,  # type: ignore
            password_has_lowercase,
            password_has_uppercase,
            password_has_number,
            password_has_symbol,
            password_min_length,
            last_run,
        )  # type: ignore

    elif fetch_type == "Alerts":
        fetch_params = prepare_args_for_fetch_alerts(
            max_fetch,  # type: ignore
            first_fetch,  # type: ignore
            alert_origin,
            alert_status,
            alert_sources,
            last_run,
        )
        start_time = fetch_params["created_after"]

    remove_nulls_from_dictionary(fetch_params)

    return {"fetch_type": fetch_type, "start_time": start_time, "fetch_params": fetch_params}


def prepare_args_for_fetch_compromised_credentials(
    max_fetch: int,
    start_time: str,
    is_fresh: bool,
    password_has_lowercase: bool,
    password_has_uppercase: bool,
    password_has_number: bool,
    password_has_symbol: bool,
    password_min_length: int,
    last_run: dict,
) -> dict:
    """
    Prepare arguments for fetching compromised credentials.

    :param max_fetch: Maximum number of incidents per fetch
    :param start_time: Date time to start fetching incidents from
    :param is_fresh: Boolean value showing whether to fetch the fresh compromised credentials or not
    :param password_has_lowercase: Value showing whether to fetch the compromised credentials with password containing lowercase
    :param password_has_uppercase: Value showing whether to fetch the compromised credentials with password containing uppercase
    :param password_has_number: Boolean value showing whether to fetch the compromised credentials with password containing number
    :param password_has_symbol: Boolean value showing whether to fetch the compromised credentials with password containing symbol
    :param password_min_length: Integer showing the minimum length of the password
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: dict[str, Any] = {}

    if max_fetch > MAX_FETCH_LIMIT and demisto.command() == "fetch-incidents":
        demisto.debug(
            f"The value for the Max Fetch parameter is {max_fetch} which is greater than "
            f"{MAX_FETCH_LIMIT}, so reducing it to {MAX_FETCH_LIMIT}."
        )
        max_fetch = 200

    if max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))
    fetch_params["limit"] = max_fetch

    if not last_run.get("fetch_count"):
        last_run["fetch_count"] = 0

    if not last_run.get("fetch_sum"):
        last_run["fetch_sum"] = 0

    fetch_params["skip"] = last_run["fetch_sum"]

    total = last_run.get("total")
    if total:
        # if total is present in record fetch_sum will be max_fetch and previous fetch_sum addition.
        fetch_sum = fetch_params["limit"] + fetch_params["skip"]
        if fetch_sum > total:
            # if calculated fetch sum is more than total records than calculate rest records from total value.
            fetch_params["limit"] = total - fetch_params["skip"]

    # update fetch_sum in last run is calculated fetch limit and fetched records addition.
    last_run["fetch_sum"] = fetch_params["limit"] + fetch_params["skip"]

    start_time = arg_to_datetime(start_time)
    start_time = datetime.timestamp(start_time)  # type: ignore

    if last_run["fetch_count"] == 0:
        # for first time fetch we have to update end_time as current time otherwise update end time as last run end_time.
        end_time = arg_to_datetime("now")
        last_run["end_time"] = end_time.strftime(DATE_FORMAT)  # type: ignore
    else:
        end_time = last_run["end_time"]
        end_time = arg_to_datetime(end_time)
    end_time = datetime.timestamp(end_time)  # type: ignore

    query = "+basetypes:(credential-sighting)"
    query += f" +header_.indexed_at: [{int(start_time)} TO {int(end_time)}]"  # type: ignore

    if is_fresh:
        query += " +is_fresh:true"

    if password_has_lowercase is not None:
        if password_has_lowercase is True:
            query += " +password_complexity.has_lowercase:(true)"
        if password_has_lowercase is False:
            query += " +password_complexity.has_lowercase:(false)"

    if password_has_uppercase is not None:
        if password_has_uppercase is True:
            query += " +password_complexity.has_uppercase:(true)"
        if password_has_uppercase is False:
            query += " +password_complexity.has_uppercase:(false)"

    if password_has_number is not None:
        if password_has_number is True:
            query += " +password_complexity.has_number:(true)"
        if password_has_number is False:
            query += " +password_complexity.has_number:(false)"

    if password_has_symbol is not None:
        if password_has_symbol is True:
            query += " +password_complexity.has_symbol:(true)"
        if password_has_symbol is False:
            query += " +password_complexity.has_symbol:(false)"

    if password_min_length is not None and password_min_length != "":
        query += f" +password_complexity.length:(>={password_min_length})"  # noqa: E231

    fetch_params["query"] = query
    fetch_params["sort"] = "header_.indexed_at:asc"

    return fetch_params


def prepare_args_for_fetch_alerts(
    max_fetch: int, first_fetch: str, alert_origin: str, alert_status: str, alert_sources: list, last_run: dict
) -> dict:
    """
    Prepare arguments for fetching alerts.

    :param max_fetch: Maximum number of incidents per fetch
    :param first_fetch: Date time to start fetching incidents from
    :param alert_origin: Alert origin
    :param alert_status: Alert status
    :param alert_sources: Alert sources
    :param last_run: Dictionary containing last run objects

    :return: Dictionary of fetch arguments
    """
    fetch_params: dict[str, Any] = {}
    end_time = arg_to_datetime("now").strftime(DATE_FORMAT)  # type: ignore
    start_time = first_fetch.strftime(DATE_FORMAT)  # type: ignore

    if max_fetch > MAX_FETCH_LIMIT and demisto.command() == "fetch-incidents":
        demisto.debug(
            f"The value for the Max Fetch parameter is {max_fetch} which is greater than "
            f"{MAX_FETCH_LIMIT}, so reducing it to {MAX_FETCH_LIMIT}."
        )
        max_fetch = 200

    if max_fetch < 1 or max_fetch > MAX_FETCH_LIMIT:
        raise DemistoException(MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))

    fetch_params["size"] = max_fetch
    fetch_params["created_after"] = last_run.get("after_time", start_time)
    fetch_params["created_before"] = last_run.get("before_time", end_time)
    fetch_params["cursor"] = last_run.get("cursor")

    if alert_status and alert_status not in ALERT_STATUS_VALUES:
        raise ValueError(MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(alert_status, "alert_status", ALERT_STATUS_VALUES))

    if alert_origin and alert_origin not in ALERT_ORIGIN_VALUES:
        raise ValueError(MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(alert_origin, "alert_origin", ALERT_ORIGIN_VALUES))

    alert_sources = [ALERT_SOURCES_MAPPING.get(key, key) for key in alert_sources]

    fetch_params["status"] = ALERT_STATUS_MAPPING.get(alert_status, alert_status)  # type: ignore
    fetch_params["origin"] = alert_origin  # type: ignore
    fetch_params["sources"] = ",".join(alert_sources)  # type: ignore

    return fetch_params


def remove_duplicate_records(records: List, fetch_type: str, next_run: dict) -> List:
    """
    Check for duplicate records and remove them from the list.

    :param records: List of records
    :param fetch_type: Type of the records
    :param next_run: Dictionary to set in last run

    :return: Updated list of alerts
    """
    last_run_key = ""
    id_key = ""
    if fetch_type == DEFAULT_FETCH_TYPE:
        last_run_key = "hit_ids"
        id_key = "_id"

    if next_run.get(last_run_key):
        prev_alert_ids = next_run[last_run_key]
        records = [i for i in records if i[id_key] not in prev_alert_ids]

    return records


def prepare_incidents_from_alerts_data(
    response: dict, last_run: dict, fetch_params: dict, platform_url: str
) -> tuple[dict, list]:
    """
    Prepare incidents from the alerts data.

    :param response: Response from the alerts API
    :param last_run: Dictionary to set in last run
    :param fetch_params: Dictionary of fetch parameters
    :param platform_url: Platform URL

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    alerts = response.get("items", [])
    alerts = remove_empty_elements(alerts)

    severity = demisto.params().get("severity", DEFAULT_SEVERITY)
    last_found_alert_ids = last_run.get("alert_ids", [])

    for alert in alerts:
        alert_id = alert.get("id")
        if alert_id in last_found_alert_ids:
            demisto.debug(f"Found existing alert with alert id: {alert_id}")
            continue

        tags = alert.get("tags", {})
        alert["tag_as_list"] = list(tags.keys())

        origin = alert.get("reason", {}).get("origin")
        source = alert.get("source")
        resource_url = alert.get("resource", {}).get("url")
        if not resource_url and origin == "searches":
            resource_url = get_resource_url(source, alert.get("resource", {}).get("id"), platform_url)

        alert["resource"].update({"url": resource_url})

        incidents.append(
            {
                "name": alert.get("reason", {}).get("name", "") + " : " + str(alert.get("id", "")),
                "severity": IncidentSeverity.__dict__.get(severity.upper()),
                "occurred": alert.get("generated_at"),
                "rawJSON": json.dumps(alert),
            }
        )
        last_found_alert_ids.append(alert_id)

    next_run = {}
    _next = response.get("pagination", {}).get("next")

    if _next:
        parsed_url = urllib.parse.urlparse(_next)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        cursor = query_params.get("cursor")[0]  # type: ignore
        next_run["cursor"] = cursor
        next_run["after_time"] = fetch_params["created_after"]
        next_run["before_time"] = fetch_params["created_before"]
    else:
        next_run["after_time"] = fetch_params["created_before"]

    demisto.debug(f"Set the last Run for notification alerts: {next_run}")
    next_run["alert_ids"] = last_found_alert_ids
    return next_run, incidents


def get_incident_name(hit_source: dict) -> str:
    """
    Determines the incident name based on available fields in the hit source.
    :param hit_source: The source data from the hit.
    :return: The incident name.
    """
    for field in ["username", "email", "fpid"]:
        value = hit_source.get(field)
        if value:
            demisto.debug(f"Setting incident name with {field}: {value}")
            return value
    demisto.debug("Setting incident name with default: Compromised Credential Alert")
    return "Compromised Credential Alert"


def prepare_incidents_from_compromised_credentials_data(
    response: dict, next_run: dict, start_time: str, is_test: bool
) -> tuple[dict, list]:
    """
    Prepare incidents from the compromised credentials data.

    :param response: Response from the compromised credentials API
    :param next_run: Dictionary to set in last run
    :param start_time: Date time saved of the last fetch

    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    incidents = []
    total = arg_to_number(response.get("hits", {}).get("total"))
    check_value_of_total_records(total, next_run)

    if is_test:
        return {}, []

    hits = response.get("hits", {}).get("hits", [])

    hit_ids = [hit["_id"] for hit in hits]
    hits = remove_duplicate_records(hits, DEFAULT_FETCH_TYPE, next_run)
    severity = demisto.params().get("severity", DEFAULT_SEVERITY)

    for hit in hits:
        hit_source = hit.get("_source", {})
        incidents.append(
            {
                "name": get_incident_name(hit_source),
                "severity": getattr(IncidentSeverity, severity.upper(), None),  # safer access to enum
                "occurred": hit_source.get("breach", {}).get("created_at", {}).get("date-time"),
                "rawJSON": json.dumps(hit),
            }
        )

    if hits:
        prepare_checkpoint_and_related_objects(hits, hit_ids, next_run)

    if total > next_run["fetch_sum"]:
        # If more records are available, then increase the fetch count
        prepare_next_run_when_data_is_present(next_run, start_time)
    else:
        prepare_next_run_when_data_is_empty(next_run, hits)

    next_run_without_ids = {k: v for k, v in next_run.items() if k != "hit_ids"}
    demisto.debug(f"Set the last Run for compromised credentials: {next_run_without_ids}")
    return next_run, incidents


def check_value_of_total_records(total: Any, next_run: dict) -> None:
    """
    Check if total number of records are more than the limit or not.

    :param total: Total number of records
    :param next_run: Dictionary to set in last run

    :return: None
    """
    if total:
        if total > MAX_PRODUCT:  # type: ignore
            raise ValueError(MESSAGES["TIME_RANGE_ERROR"].format(total))
        next_run["total"] = total


def prepare_checkpoint_and_related_objects(hits: List, hit_ids: List, next_run: dict) -> None:
    """
    Prepare checkpoint and related objects for incidents of type compromised credentials.

    :param hits: List of compromised credentials
    :param hit_ids: List of ids of compromised credentials
    :param next_run: Dictionary to set in last run

    :return: None
    """
    indexed_at = hits[-1].get("_source", {}).get("header_", {}).get("indexed_at")
    indexed_at_date = datetime.utcfromtimestamp(float(indexed_at))
    indexed_at_date = indexed_at_date.strftime(DATE_FORMAT)
    next_run["last_time"] = indexed_at_date

    if next_run.get("last_timestamp"):
        if next_run["last_timestamp"] == indexed_at:
            # last_timestamp is similar as last_record indexed_at time than hit_ids will be appended to list.
            next_run["hit_ids"] += hit_ids
        else:
            # last_timestamp is not similar as last_record indexed_at so for that response hits_ids will be replaced.
            next_run["hit_ids"] = hit_ids
    else:
        next_run["hit_ids"] = hit_ids

    next_run["last_timestamp"] = indexed_at


def prepare_next_run_when_data_is_present(next_run: dict, start_time: str) -> None:
    """
    Prepare next run when data is present.

    :param next_run: Dictionary to set in last run
    :param start_time:  Date time saved of the last fetch

    :return: None
    """
    next_run["start_time"] = start_time
    next_run["fetch_count"] = next_run["fetch_count"] + 1


def prepare_next_run_when_data_is_empty(next_run: dict, hits: List) -> None:
    """
    Prepare next run when data is present.

    :param next_run: Dictionary to set in last run
    :param hits: List of compromised credentials

    :return: None
    """
    if hits:
        next_run["start_time"] = next_run["last_time"]
    next_run["fetch_count"] = 0
    next_run["fetch_sum"] = 0
    next_run["total"] = None


def validate_compromised_credentials_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    :raises: ValueError on invalid arguments
    """
    params = {"query": "+basetypes:(credential-sighting)"}

    validate_page_parameters_for_compromised_credentials(args, params)

    validate_date_parameters_for_compromised_credentials(args, params)

    validate_sort_parameters_for_compromised_credentials(args, params)

    is_fresh = args.get("is_fresh", "").lower()
    if is_fresh:
        if is_fresh not in IS_FRESH_VALUES:
            raise ValueError(MESSAGES["IS_FRESH_ERROR"].format(is_fresh, IS_FRESH_VALUES))
        params["query"] += f" +is_fresh:{is_fresh}"  # noqa: E231

    remove_nulls_from_dictionary(params)

    return params


def validate_date_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate date params for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    start_date = arg_to_datetime(args.get("start_date"))
    end_date = arg_to_datetime(args.get("end_date"))

    if end_date and not start_date:
        raise ValueError(MESSAGES["START_DATE_ERROR"])

    if start_date and not end_date:
        end_date = arg_to_datetime("now")

    filter_date = args.get("filter_date")
    if filter_date:
        if filter_date not in FILTER_DATE_VALUES:
            raise ValueError(MESSAGES["FILTER_DATE_ERROR"].format(filter_date, FILTER_DATE_VALUES))
        if not (start_date or end_date):
            raise ValueError(MESSAGES["MISSING_DATE_ERROR"])
        # type: ignore
        date_query = (
            f" +breach.{filter_date}.date-time: [{start_date.strftime(DATE_FORMAT)} TO"  # type: ignore[union-attr]
            f" {end_date.strftime(DATE_FORMAT)}]"  # type: ignore
        )  # type: ignore[union-attr]
        params["query"] += date_query
    elif start_date or end_date:
        raise ValueError(MESSAGES["MISSING_FILTER_DATE_ERROR"])


def validate_page_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate page_size and page_number for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    page_size = arg_to_number(args.get("page_size", DEFAULT_PAGE_SIZE))
    if page_size is None or page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ValueError(MESSAGES["PAGE_SIZE_ERROR"].format(page_size, MAX_PAGE_SIZE))

    page_number = arg_to_number(args.get("page_number", 1))
    if page_number is None or page_number < 1:
        raise ValueError(MESSAGES["PAGE_NUMBER_ERROR"].format(page_number))

    product = page_size * page_number
    if product > MAX_PRODUCT:
        raise ValueError(MESSAGES["PRODUCT_ERROR"].format(MAX_PRODUCT, product))

    params["skip"] = page_size * (page_number - 1)  # type: ignore
    params["limit"] = page_size  # type: ignore


def validate_sort_parameters_for_compromised_credentials(args: dict, params: dict) -> None:
    """
    Validate sort_order and sort_date for flashpoint-ignite-compromised-credentials-list command.

    :param args: The command arguments
    :param params: Dictionary of parameters

    :return: None
    """
    sort_order = args.get("sort_order", "").lower()
    if sort_order and sort_order not in SORT_ORDER_VALUES:
        raise ValueError(MESSAGES["SORT_ORDER_ERROR"].format(sort_order, SORT_ORDER_VALUES))

    sort_date = args.get("sort_date")
    if sort_date:
        if sort_date not in SORT_DATE_VALUES:
            raise ValueError(MESSAGES["SORT_DATE_ERROR"].format(sort_date, SORT_DATE_VALUES))
        if not sort_order:
            sort_order = DEFAULT_SORT_ORDER

        params["sort"] = f"breach.{sort_date}.timestamp:{sort_order}"  # noqa: E231
    elif sort_order:
        raise ValueError(MESSAGES["MISSING_SORT_DATE_ERROR"])


def validate_alert_list_args(args: dict) -> dict:
    """
    Validate arguments for flashpoint-ignite-alert-list command.

    :param args: The command arguments

    :return: Validated dictionary of arguments
    :raises: ValueError for invalid arguments
    """
    params = {}
    size = arg_to_number(args.get("size", DEFAULT_LIMIT))
    if size is None or size < 1 or size > MAX_ALERTS_LIMIT:  # type: ignore
        raise ValueError(MESSAGES["SIZE_ERROR"].format(size, MAX_ALERTS_LIMIT))
    params["size"] = size

    created_after = arg_to_datetime(args.get("created_after"))
    if created_after:
        params["created_after"] = created_after.strftime(DATE_FORMAT)  # type: ignore

    created_before = arg_to_datetime(args.get("created_before"))
    if created_before:
        params["created_before"] = created_before.strftime(DATE_FORMAT)  # type: ignore

    if created_after and created_before and created_after >= created_before:
        raise ValueError(
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "created_after", "created_before", params["created_after"], params["created_before"]
            )
        )

    params["cursor"] = args.get("cursor")  # type: ignore

    status = args.get("status", "").lower()
    if status and status not in ALERT_STATUS_VALUES:
        raise ValueError(MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(status, "status", ALERT_STATUS_VALUES))
    params["status"] = ALERT_STATUS_MAPPING.get(status, status)  # type: ignore

    origin = args.get("origin", "").lower()
    if origin and origin not in ALERT_ORIGIN_VALUES:
        raise ValueError(MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(origin, "origin", ALERT_ORIGIN_VALUES))
    params["origin"] = origin  # type: ignore

    params["cursor"] = args.get("cursor")  # type: ignore

    tags = argToList(args.get("tags"))
    if tags:
        params["tags"] = ",".join(tags)  # type: ignore

    sources = argToList(args.get("sources", ""))
    if sources:
        sources = [ALERT_SOURCES_MAPPING.get(key, key) for key in sources]
        params["sources"] = ",".join(sources)  # type: ignore

    asset_ids = argToList(args.get("asset_ids"))
    if asset_ids:
        params["asset_ids"] = ",".join(asset_ids)  # type: ignore

    query_ids = argToList(args.get("query_ids"))
    if query_ids:
        params["query_ids"] = ",".join(query_ids)  # type: ignore

    params["asset_type"] = args.get("asset_type")  # type: ignore

    asset_ip = args.get("asset_ip")
    if asset_ip and not is_ip_valid(asset_ip, True):
        raise ValueError(MESSAGES["INVALID_IP_ADDRESS"].format(asset_ip))
    params["asset_ip"] = asset_ip  # type: ignore

    remove_nulls_from_dictionary(params)

    return params


def validate_cvss_score(min_cvss: Optional[str], min_cvss_label: str, max_cvss: Optional[str], max_cvss_label: str) -> None:
    """
    Validate the CVSS score parameters.

    :type min_cvss: ``Optional[str]``
    :param min_cvss: Minimum CVSS score.

    :type min_cvss_label: ``str``
    :param min_cvss_label: Label for minimum CVSS score.

    :type max_cvss: ``Optional[str]``
    :param max_cvss: Maximum CVSS score.

    :type max_cvss_label: ``str``
    :param max_cvss_label: Label for maximum CVSS score.

    :raises DemistoException: If min_cvss or max_cvss is not a valid float between 0 and 10.
    :raises DemistoException: If min_cvss is greater than max_cvss.
    """
    min_cvss_float = None
    max_cvss_float = None
    if min_cvss:
        try:
            min_cvss_float = float(min_cvss)
        except ValueError:
            raise DemistoException(MESSAGES["INVALID_CVSS_SCORE"].format(min_cvss_label))
    if max_cvss:
        try:
            max_cvss_float = float(max_cvss)
        except ValueError:
            raise DemistoException(MESSAGES["INVALID_CVSS_SCORE"].format(max_cvss_label))

    if min_cvss_float is not None and (min_cvss_float < MIN_CVSS_AND_EPSS_SCORE or min_cvss_float > MAX_CVSS_SCORE):
        raise DemistoException(MESSAGES["INVALID_CVSS_SCORE"].format(min_cvss_label))
    if max_cvss_float is not None and (max_cvss_float < MIN_CVSS_AND_EPSS_SCORE or max_cvss_float > MAX_CVSS_SCORE):
        raise DemistoException(MESSAGES["INVALID_CVSS_SCORE"].format(max_cvss_label))

    if min_cvss_float is not None and max_cvss_float is not None and min_cvss_float > max_cvss_float:
        raise DemistoException(MESSAGES["INVALID_SCORE_RANGE"].format(min_cvss_label, max_cvss_label))


def validate_epss_score(min_epss: Optional[str], min_epss_label: str, max_epss: Optional[str], max_epss_label: str) -> None:
    """
    Validate the EPSS score parameters.

    :type min_epss: ``Optional[str]``
    :param min_epss: Minimum EPSS score.

    :type min_epss_label: ``str``
    :param min_epss_label: Label for minimum EPSS score.

    :type max_epss: ``Optional[str]``
    :param max_epss: Maximum EPSS score.

    :type max_epss_label: ``str``
    :param max_epss_label: Label for maximum EPSS score.

    :raises DemistoException: If min_epss or max_epss is not a valid float between 0 and 1.
    :raises DemistoException: If min_epss is greater than max_epss.
    """
    min_epss_float = None
    max_epss_float = None
    if min_epss:
        try:
            min_epss_float = float(min_epss)
        except ValueError:
            raise DemistoException(MESSAGES["INVALID_EPSS_SCORE"].format(min_epss_label))
    if max_epss:
        try:
            max_epss_float = float(max_epss)
        except ValueError:
            raise DemistoException(MESSAGES["INVALID_EPSS_SCORE"].format(max_epss_label))

    if min_epss_float is not None and (min_epss_float < MIN_CVSS_AND_EPSS_SCORE or min_epss_float > MAX_EPSS_SCORE):
        raise DemistoException(MESSAGES["INVALID_EPSS_SCORE"].format(min_epss_label))
    if max_epss_float is not None and (max_epss_float < MIN_CVSS_AND_EPSS_SCORE or max_epss_float > MAX_EPSS_SCORE):
        raise DemistoException(MESSAGES["INVALID_EPSS_SCORE"].format(max_epss_label))

    if min_epss_float is not None and max_epss_float is not None and min_epss_float > max_epss_float:
        raise DemistoException(MESSAGES["INVALID_SCORE_RANGE"].format(min_epss_label, max_epss_label))


def validate_time_range(
    after_time: Optional[datetime], before_time: Optional[datetime], after_arg_name: str, before_arg_name: str
) -> None:
    """
    Validate that the 'after' timestamp is earlier than the 'before' timestamp.

    Args:
        after_time (Optional[datetime]): The 'after' timestamp.
        before_time (Optional[datetime]): The 'before' timestamp.
        after_arg_name (str): The name of the 'after' argument for error messages.
        before_arg_name (str): The name of the 'before' argument for error messages.

    Raises:
        DemistoException: If after_time is not earlier than before_time.
    """
    if after_time and before_time and after_time >= before_time:
        raise DemistoException(MESSAGES["INVALID_TIME_INTERVAL"].format(after_arg_name, before_arg_name, after_time, before_time))


def validate_vulnerabilities_args(args: dict) -> tuple[dict, dict]:
    """
    Validate the parameter list for vulnerability list command.

    :type args: ``dict``
    :param args: Dictionary of arguments.

    :return: Tuple of (query_params, body_params) dicts.
    :rtype: ``tuple[dict, dict]``
    """
    tags = argToList(args.get("tags"))
    products = argToList(args.get("products"))
    vendors = argToList(args.get("vendors"))
    cwe_ids = argToList(args.get("cwe_ids"))
    ref_types = argToList(args.get("ref_types"), transform=lambda s: s.lower())
    ref_values = argToList(args.get("ref_values"))
    locations = argToList(args.get("locations"), transform=lambda s: s.lower())
    severities = argToList(args.get("severities"), transform=lambda s: s.lower())
    ransomware_scores = argToList(args.get("ransomware_scores"), transform=lambda s: s.lower())
    attack_types = argToList(args.get("attack_types"), transform=lambda s: s.lower())
    sort_by = args.get("sort_by", DEFAULT_VULNERABILITIES_SORT)
    sort_order = args.get("sort_order", DEFAULT_VULNERABILITIES_SORT_ORDER)
    updated_after = arg_to_datetime(args.get("updated_after"))
    updated_before = arg_to_datetime(args.get("updated_before"))
    disclosed_after = arg_to_datetime(args.get("disclosed_after"))
    disclosed_before = arg_to_datetime(args.get("disclosed_before"))
    published_after = arg_to_datetime(args.get("published_after"))
    published_before = arg_to_datetime(args.get("published_before"))
    last_touched_after = arg_to_datetime(args.get("last_touched_after"))
    last_touched_before = arg_to_datetime(args.get("last_touched_before"))
    min_epss_score = args.get("min_epss_score")
    max_epss_score = args.get("max_epss_score")
    min_cvssv2_score = args.get("min_cvssv2_score")
    max_cvssv2_score = args.get("max_cvssv2_score")
    min_cvssv3_score = args.get("min_cvssv3_score")
    max_cvssv3_score = args.get("max_cvssv3_score")
    min_cvssv4_score = args.get("min_cvssv4_score")
    max_cvssv4_score = args.get("max_cvssv4_score")

    validate_cvss_score(min_cvssv2_score, "Minimum CVSS v2 Score", max_cvssv2_score, "Maximum CVSS v2 Score")
    validate_cvss_score(min_cvssv3_score, "Minimum CVSS v3 Score", max_cvssv3_score, "Maximum CVSS v3 Score")
    validate_cvss_score(min_cvssv4_score, "Minimum CVSS v4 Score", max_cvssv4_score, "Maximum CVSS v4 Score")
    validate_epss_score(min_epss_score, "Minimum EPSS Score", max_epss_score, "Maximum EPSS Score")

    valid_severity = [severity for severity in severities if severity in VALID_SEVERITIES]
    invalid_severity = [severity for severity in severities if severity not in VALID_SEVERITIES]

    valid_ref_types = [REFERENCE_TYPES_MAPPING[ref_type] for ref_type in ref_types if ref_type in REFERENCE_TYPES_MAPPING]
    invalid_ref_types = [ref_type for ref_type in ref_types if ref_type not in REFERENCE_TYPES_MAPPING]

    valid_cwe_ids = [cwe_id for cwe_id in cwe_ids if cwe_id.isdigit()]
    invalid_cwe_ids = [cwe_id for cwe_id in cwe_ids if not cwe_id.isdigit()]

    valid_location = [LOCATION_MAPPING[loc] for loc in locations if loc in LOCATION_MAPPING]
    invalid_location = [loc for loc in locations if loc not in LOCATION_MAPPING]

    valid_ransomware_scores = [score for score in ransomware_scores if score in VALID_RANSOMWARE_SCORE]
    invalid_ransomware_scores = [score for score in ransomware_scores if score not in VALID_RANSOMWARE_SCORE]

    valid_attack_types = [ATTACK_TYPE_MAPPING[attack_type] for attack_type in attack_types if attack_type in ATTACK_TYPE_MAPPING]
    invalid_attack_types = [attack_type for attack_type in attack_types if attack_type not in ATTACK_TYPE_MAPPING]

    # Build query_params first (pagination and sorting)
    size = arg_to_number(args.get("size", DEFAULT_LIMIT))
    if size is not None and (size < 1 or size > MAX_PAGE_SIZE):
        raise DemistoException(MESSAGES["INVALID_LIMIT_PROVIDED"].format(size, MAX_PAGE_SIZE))

    from_ = arg_to_number(args.get("from", DEFAULT_FROM))
    if from_ is not None and from_ < 0:
        raise DemistoException(MESSAGES["INVALID_FROM_PROVIDED"].format(from_))

    sort_value = None
    if sort_by and sort_by.lower() not in VULNERABILITY_SORT_MAPPING:
        raise DemistoException(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(sort_by, "sort_by", VULNERABILITY_SORT_MAPPING.keys())
        )
    if sort_order and sort_order.lower() not in SORT_ORDER_VALUES:
        raise DemistoException(MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(sort_order, "sort_order", SORT_ORDER_VALUES))
    if sort_by:
        sort_value = (
            f"{VULNERABILITY_SORT_MAPPING[sort_by.lower()]}:desc"
            if sort_order and sort_order.lower() == "desc"
            else VULNERABILITY_SORT_MAPPING[sort_by.lower()]
        )

    query_params = assign_params(
        size=size,
        sort=sort_value,
    )

    if from_ is not None:
        query_params["from"] = from_

    errors = []
    if invalid_severity:
        errors.append(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                invalid_severity, "Severity", [severity.title() for severity in VALID_SEVERITIES]
            )
        )
    if invalid_ref_types:
        errors.append(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                invalid_ref_types, "Reference Types", [ref_type.title() for ref_type in REFERENCE_TYPES_MAPPING]
            )
        )
    if invalid_cwe_ids:
        errors.append(MESSAGES["INVALID_INT_PARAMS_PROVIDED"].format(invalid_cwe_ids, "CWE IDs"))

    if invalid_location:
        errors.append(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                invalid_location, "Locations", [loc.title() for loc in LOCATION_MAPPING]
            )
        )
    if invalid_ransomware_scores:
        errors.append(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                invalid_ransomware_scores, "Ransomware Scores", [score.title() for score in VALID_RANSOMWARE_SCORE]
            )
        )
    if invalid_attack_types:
        errors.append(
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                invalid_attack_types, "Attack Types", [attack_type.title() for attack_type in ATTACK_TYPE_MAPPING]
            )
        )

    if errors:
        raise DemistoException("\n\n".join(errors))

    # Build payload (filters and search criteria)

    payload = assign_params(
        tags=",".join(tags),
        min_epss_score=min_epss_score,
        max_epss_score=max_epss_score,
        min_cvssv2_score=min_cvssv2_score,
        max_cvssv2_score=max_cvssv2_score,
        min_cvssv3_score=min_cvssv3_score,
        max_cvssv3_score=max_cvssv3_score,
        min_cvssv4_score=min_cvssv4_score,
        max_cvssv4_score=max_cvssv4_score,
        products=",".join(products),
        vendors=",".join(vendors),
        cwe_ids=",".join(valid_cwe_ids),
        ref_types=",".join(valid_ref_types),
        ref_values=",".join(ref_values),
        location=",".join(valid_location),
        severity=",".join(valid_severity),
        ransomware_score=",".join(valid_ransomware_scores),
        attack_type=",".join(valid_attack_types),
        updated_after=updated_after.strftime(DATE_FORMAT) if updated_after else None,  # type: ignore
        updated_before=updated_before.strftime(DATE_FORMAT) if updated_before else None,  # type: ignore
        disclosed_after=disclosed_after.strftime(DATE_FORMAT) if disclosed_after else None,  # type: ignore
        disclosed_before=disclosed_before.strftime(DATE_FORMAT) if disclosed_before else None,  # type: ignore
        published_after=published_after.strftime(DATE_FORMAT) if published_after else None,  # type: ignore
        published_before=published_before.strftime(DATE_FORMAT) if published_before else None,  # type: ignore
        last_touched_after=last_touched_after.strftime(DATE_FORMAT) if last_touched_after else None,  # type: ignore
        last_touched_before=last_touched_before.strftime(DATE_FORMAT) if last_touched_before else None,  # type: ignore
    )

    validate_time_range(payload.get("updated_after"), payload.get("updated_before"), "updated_after", "updated_before")
    validate_time_range(payload.get("disclosed_after"), payload.get("disclosed_before"), "disclosed_after", "disclosed_before")
    validate_time_range(payload.get("published_after"), payload.get("published_before"), "published_after", "published_before")
    validate_time_range(
        payload.get("last_touched_after"),
        payload.get("last_touched_before"),
        "last_touched_after",
        "last_touched_before",
    )

    remove_nulls_from_dictionary(query_params)
    remove_nulls_from_dictionary(payload)

    return query_params, payload


def prepare_hr_for_list_vulnerabilities(vulnerabilities: list, platform_url: str) -> str:
    """
    Prepare human-readable output for a list of vulnerabilities.

    :param vulnerabilities: List of vulnerability data dictionaries.
    :param platform_url: Platform URL for generating clickable links.

    :return: Human-readable markdown string.
    """
    hr = []

    for vulnerability in vulnerabilities:
        cve_ids = vulnerability.get("cve_ids", [])
        vuln_id = vulnerability.get("id", "")

        data = {
            "ID": f"FP-VULN-{vuln_id}, [link]({urljoin(platform_url, HR_SUFFIX['VULNERABILITY'].format(vuln_id))})",
            "CVE IDs": cve_ids,
            "Title": vulnerability.get("title", ""),
            "Description": vulnerability.get("description", ""),
            "Solution": vulnerability.get("solution", ""),
            "Vulnerability Status": vulnerability.get("vuln_status", ""),
            "Severity": vulnerability.get("scores", {}).get("severity", ""),
            "CVSS v3 Score": vulnerability.get("cvssv3_score", ""),
            "EPSS Score": vulnerability.get("scores", {}).get("epss_score", ""),
            "Ransomware Score": vulnerability.get("scores", {}).get("ransomware_score", ""),
            "Published At": vulnerability.get("timelines", {}).get("published_at", ""),
            "Last Modified At": vulnerability.get("timelines", {}).get("last_modified_at", ""),
            "Tags": vulnerability.get("tags", ""),
            "CVSS v2": vulnerability.get("cvss_v2s", ""),
            "CVSS v3": vulnerability.get("cvss_v3s", ""),
            "CVSS v4": vulnerability.get("cvss_v4s", ""),
            "Products": vulnerability.get("products", ""),
            "CWEs": vulnerability.get("cwes", ""),
            "Exploits": vulnerability.get("exploits", ""),
            "Exploits Count": vulnerability.get("exploits_count", ""),
        }
        hr.append(data)

    headers = [
        "ID",
        "CVE IDs",
        "Title",
        "Description",
        "Solution",
        "Vulnerability Status",
        "Severity",
        "CVSS v3 Score",
        "EPSS Score",
        "Ransomware Score",
        "Published At",
        "Last Modified At",
        "Tags",
        "CVSS v2",
        "CVSS v3",
        "CVSS v4",
        "Products",
        "CWEs",
        "Exploits",
        "Exploits Count",
    ]

    return tableToMarkdown(
        name="Vulnerability List",
        t=hr,
        headers=headers,
        removeNull=True,
        json_transform_mapping={
            header: JsonTransformer(is_nested=True)
            for header in ["CVSS v2", "CVSS v3", "CVSS v4", "Products", "CWEs", "Exploits"]
        },
    )


def prepare_hr_for_compromised_credentials(hits: list) -> str:
    """
    Prepare human readable format for compromised credentials.

    :param hits: List of compromised credentials

    :return: Human readable format of compromised credentials
    """
    hr = []
    for hit in hits:
        source = hit.get("_source", {})
        created_date = source.get("breach", {}).get("created_at", {}).get("date-time")
        created_date = arg_to_datetime(created_date)
        if created_date:
            created_date = created_date.strftime(READABLE_DATE_FORMAT)  # type: ignore

        first_observed_date = source.get("breach", {}).get("first_observed_at", {}).get("date-time")
        first_observed_date = arg_to_datetime(first_observed_date)
        if first_observed_date:
            first_observed_date = first_observed_date.strftime(READABLE_DATE_FORMAT)  # type: ignore

        data = {
            "FPID": source.get("fpid", ""),
            "Email": source.get("email", ""),
            "Username": source.get("username", ""),
            "Breach Source": source.get("breach", {}).get("source"),
            "Breach Source Type": source.get("breach", {}).get("source_type"),
            "Password": source.get("password"),
            "Created Date (UTC)": created_date,
            "First Observed Date (UTC)": first_observed_date,
        }
        hr.append(data)

    return tableToMarkdown(
        "Compromised Credential(s)",
        hr,
        [
            "FPID",
            "Email",
            "Username",
            "Breach Source",
            "Breach Source Type",
            "Password",
            "Created Date (UTC)",
            "First Observed Date (UTC)",
        ],
        removeNull=True,
    )


def parse_indicator_response(indicators):
    """
    Extract Ignite event details and href values from each of the indicator in an indicator list.

    :param indicators: list of indicators
    :return: dict containing event details and href
    """
    events = []
    hrefs = []
    attack_ids = []
    for indicator in indicators:
        hrefs.append(indicator.get("Attribute", {}).get("href", ""))

        event = indicator.get("Attribute", {}).get("Event", {})
        attack_ids = event.get("attack_ids", [])
        tags_list = list(event["Tags"])
        tags_value = ", ".join(tags_list)

        observed_time = time.strftime(READABLE_DATE_FORMAT, time.gmtime(float(event["timestamp"])))

        events.append(
            {
                DATE_OBSERVED: observed_time,
                "Name": event.get("info", ""),
                "Tags": tags_value,
            }
        )

    return {"events": events, "href": hrefs, "attack_ids": attack_ids}


def create_relationships_list_v2(client, related_iocs, indicator_value, indicator_type):
    """
    Create relationships list from given data.

    :param client: object of client class
    :param related_iocs: list of related iocs
    :param indicator_value: value of indicator
    :param indicator_type: type of indicator

    :return: list of relationships
    """

    relationships = []
    if client.create_relationships and related_iocs:
        for ioc in related_iocs:
            if ioc.get("type", "") != "extracted_config":
                relationships.append(
                    EntityRelationship(
                        name="related-to",
                        entity_a=indicator_value,
                        entity_a_type=IOC_TYPE_MAPPING.get(indicator_type, indicator_type),
                        entity_b=ioc.get("value"),
                        entity_b_type=IOC_TYPE_MAPPING.get(ioc.get("type"), ioc.get("type")),
                        brand=VENDOR_NAME,
                    )
                )
    return relationships


def create_relationships_list_for_community_search(client, indicators, ip):
    relationships: list = []
    limit = client.reputation_enrichments_limit
    if client.create_relationships:
        ip_address_data = indicators.get("enrichments", {}).get("ip_address", [])
        for ip_address in ip_address_data:
            if is_ip_valid(ip_address, True):
                if len(relationships) >= limit:
                    demisto.debug(
                        f"Reached the maximum limit of relationships: {limit} "
                        "for community search. truncating the rest of the relationships."
                    )
                    break
                relationships.append(
                    EntityRelationship(
                        name="indicator-of",
                        entity_a=ip,
                        entity_a_type=FeedIndicatorType.IP,
                        entity_b=ip_address,
                        entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                        brand=VENDOR_NAME,
                    )
                )

        indicator_data = indicators.get("enrichments", {}).get("url_domains", [])
        indicator_data += indicators.get("enrichments", {}).get("email_addresses", [])
        indicator_data += indicators.get("enrichments", {}).get("cve_ids", [])

        for indicator in indicator_data:
            if len(relationships) >= limit:
                demisto.debug(
                    f"Reached the maximum limit of relationships: {limit} "
                    "for community search. truncating the rest of the relationships."
                )
                break
            relationships.append(
                EntityRelationship(
                    name="indicator-of",
                    entity_a=ip,
                    entity_a_type=FeedIndicatorType.IP,
                    entity_b=indicator,
                    entity_b_type=FeedIndicatorType.indicator_type_by_server_version(STIX_ATTACK_PATTERN),
                    brand=VENDOR_NAME,
                )
            )

    return relationships


def create_indicator_object(item: dict, relationships: dict):
    """
    Create indicator object from given data.

    :param item: item dictionary from  response
    :param relationships: relationships dictionary

    :return: Indicator object
    """

    indicator_value = item.get("value", "")
    indicator_type = item.get("type", "")

    dbot_score = Common.DBotScore(
        indicator=indicator_value,
        indicator_type=DBOTSCORE_IOC_TYPE_MAPPING.get(indicator_type, CUSTOM_INDICATOR_DBOTSCORE),
        integration_name=VENDOR_NAME,
        score=REPUTATION_SCORE_MAPPING.get(item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)),
        malicious_description=MALICIOUS_DESCRIPTION,
        reliability=demisto.params().get("integrationReliability"),
    )
    dbot_score.integration_name = VENDOR_NAME

    if indicator_type == "domain":
        return Common.Domain(domain=indicator_value, dbot_score=dbot_score, relationships=relationships)
    elif indicator_type == "url":
        return Common.URL(url=indicator_value, dbot_score=dbot_score, relationships=relationships)
    elif indicator_type == "file":
        hashes = {
            "md5": item.get("hashes", {}).get("md5"),
            "sha1": item.get("hashes", {}).get("sha1"),
            "sha256": item.get("hashes", {}).get("sha256"),
        }
        return Common.File(dbot_score=dbot_score, relationships=relationships, **hashes)
    elif indicator_type == "ipv4" or indicator_type == "ipv6":
        return Common.IP(ip=indicator_value, dbot_score=dbot_score, relationships=relationships)
    else:
        return Common.CustomIndicator(
            value=indicator_value,
            indicator_type=indicator_type,
            data=remove_empty_elements(item),
            context_prefix=indicator_type,
            dbot_score=dbot_score,
            relationships=relationships,
        )


def get_resource_url(source: str, resource_id: str, platform_url: str):
    """
    Generates the resource URL based on the given source and resource ID.

    :param source: The source of the resource.
    :param resource_id: The ID of the resource.
    :param platform_url: The platform URL

    :return: The generated resource URL.
    """
    if not resource_id:
        raise ValueError(MESSAGES["MISSING_DATA"].format("alerts"))

    resource_url = platform_url + ALERT_RESOURCE_URL[source].format(resource_id)

    return resource_url


def prepare_hr_for_alerts(alerts: List, platform_url: str) -> str:
    """
    Prepare human readable format for alerts.

    :param alerts: List of alerts
    :param platform_url: The platform URL

    :return: Human readable format of alerts
    """
    table_data = []
    for alert in alerts:
        _id = alert.get("id")
        keyword_text = alert.get("reason", {}).get("text")
        created_at = arg_to_datetime(alert.get("created_at"))
        if created_at:
            created_at = created_at.strftime(READABLE_DATE_FORMAT)  # type: ignore

        source = alert.get("source")
        repo = alert.get("resource", {}).get("repo")
        owner = alert.get("resource", {}).get("owner")
        origin = alert.get("reason", {}).get("origin")
        resource_url = alert.get("resource", {}).get("url")
        if not resource_url and origin == "searches":
            resource_url = get_resource_url(source, alert.get("resource", {}).get("id"), platform_url)
        highlight_text = alert.get("highlight_text")
        ports = ", ".join([re.sub(X_FP_HIGHLIGHT_TEXT, "", port) for port in alert.get("highlights", {}).get("ports", [])])
        services = ", ".join(
            [re.sub(X_FP_HIGHLIGHT_TEXT, "", service) for service in alert.get("highlights", {}).get("services", [])]
        )
        site_title = alert.get("resource", {}).get("site", {}).get("title")
        shodan_info = alert.get("resource", {}).get("shodan_host", {})
        if created_at:
            table_data.append(
                {
                    "ID": _id,
                    "Created at (UTC)": created_at,
                    "Query": keyword_text,
                    "Highlight Text": string_escape_markdown(highlight_text),
                    "Source": source,
                    "Repository": repo,
                    "Owner": owner,
                    "Resource URL": resource_url,
                    "Origin": origin,
                    "Site Title": site_title,
                    "Shodan Host": shodan_info,
                    "Ports": ports,
                    "Services": services,
                }
            )

    headers = [
        "ID",
        "Created at (UTC)",
        "Query",
        "Source",
        "Resource URL",
        "Site Title",
        "Shodan Host",
        "Repository",
        "Owner",
        "Origin",
        "Ports",
        "Services",
        "Highlight Text",
    ]

    return tableToMarkdown(
        "Alerts",
        remove_empty_elements(table_data),
        headers,
        removeNull=True,
        url_keys=["Resource URL", "shodan_url"],
        json_transform_mapping={"Shodan Host": JsonTransformer()},
    )


def get_related_iocs_and_tags(item: dict) -> tuple[list, list]:
    """
    Get related IOCs and tags from the given item.

    :param item: The item to get related IOCs and tags from.

    :return: A tuple containing a list of related IOCs and a list of tags.
    """

    tags = deepcopy(item.get("latest_sighting", {}).get("tags", []))
    related_iocs = []
    related_iocs_data = []
    latest_sighting_related_iocs = item.get("latest_sighting", {}).get("related_iocs", [])
    related_iocs_data.append(latest_sighting_related_iocs)
    sightings_data = item.get("sightings", [])

    for sighting in sightings_data:
        related_iocs_data.append(sighting.get("related_iocs", []))
        for tag in sighting.get("tags", []):
            if tag not in tags:
                tags.append(tag)

    for related_ioc in related_iocs_data:
        for ioc in related_ioc:
            if ioc.get("value") != item.get("value"):
                if ioc.get("type", "") == "extracted_config":
                    ioc_data = {
                        "type": ioc.get("type"),
                        "value": json.loads(ioc.get("value")),
                    }
                else:
                    ioc_data = {
                        "type": ioc.get("type"),
                        "value": ioc.get("value"),
                    }
                if ioc_data not in related_iocs:
                    related_iocs.append(ioc_data)

    return related_iocs, tags


def html_to_text(html) -> str:
    """
    Convert HTML to text.

    param html: The HTML to convert.

    return: The converted text.
    """

    # Remove HTML tags
    text = re.sub(r"<.*?>", "", html)

    # Replace HTML entities with their corresponding characters
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), text)

    return text.strip()


def prepare_hr_for_vulnerability(vulnerability: dict, platform_url: str, is_reputation: bool = False) -> str:
    """
    Prepare human-readable output for vulnerability details.

    :param vulnerability: Vulnerability data dictionary
    :param platform_url: Platform URL
    :param is_reputation: Whether the vulnerability is a reputation
    :return: Human-readable markdown string
    """
    if not is_reputation:
        hr = f"### Ignite FP-VULN-{vulnerability.get('id')} Vulnerability Details" + (
            " for: " + ", ".join(vulnerability.get("cve_ids", [])) if vulnerability.get("cve_ids") else ""
        )
    else:
        hr = "### Ignite CVE Details for: " + ", ".join(vulnerability.get("cve_ids", []))

    vulnerability_details = {
        "ID": f"[{vulnerability.get('id', '')}]"
        + f"({urljoin(platform_url, HR_SUFFIX['VULNERABILITY'].format(vulnerability.get('id', '')))})",
        "Title": vulnerability.get("title", EMPTY_DATA),
        "Status": vulnerability.get("vuln_status", EMPTY_DATA),
        "Keywords": vulnerability.get("keywords", EMPTY_DATA),
        "Description": vulnerability.get("description", EMPTY_DATA),
        "Solution": vulnerability.get("solution", EMPTY_DATA),
        "Technical Description": vulnerability.get("technical_description", EMPTY_DATA),
        "Exploits Count": vulnerability.get("exploits_count", EMPTY_DATA),
        "Alternate VulnDB ID": vulnerability.get("alternate_vulndb_id", EMPTY_DATA),
        "Tags": ", ".join(vulnerability.get("tags", [])) if vulnerability.get("tags") else EMPTY_DATA,
        "Creditees": vulnerability.get("creditees", EMPTY_DATA),
    }

    hr += "\n" + tableToMarkdown(
        "Vulnerability Information",
        vulnerability_details,
        headers=[
            "ID",
            "Title",
            "Status",
            "Keywords",
            "Description",
            "Solution",
            "Technical Description",
            "Exploits Count",
            "Alternate VulnDB ID",
            "Tags",
            "Creditees",
        ],
        json_transform_mapping={
            "Creditees": JsonTransformer(is_nested=True),
        },
        removeNull=True,
    )

    scores = vulnerability.get("scores", {})
    if scores:
        score_details = {
            "EPSS Score": scores.get("epss_score", EMPTY_DATA),
            "EPSS v1 Score": scores.get("epss_v1_score", EMPTY_DATA),
            "Ransomware Score": scores.get("ransomware_score", EMPTY_DATA),
            "Severity": scores.get("severity", EMPTY_DATA),
            "Social Risk Scores": scores.get("social_risk_scores", EMPTY_DATA),
        }
        hr += "\n" + tableToMarkdown(
            "Score Information",
            score_details,
            headers=[
                "EPSS Score",
                "EPSS v1 Score",
                "Ransomware Score",
                "Severity",
                "Social Risk Scores",
            ],
            json_transform_mapping={
                "Social Risk Scores": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

    timelines = vulnerability.get("timelines", {})
    if timelines:
        timeline_details = {
            "Published At": timelines.get("published_at", EMPTY_DATA),
            "Last Modified At": timelines.get("last_modified_at", EMPTY_DATA),
            "Exploit Published At": timelines.get("exploit_published_at", EMPTY_DATA),
            "Discovered At": timelines.get("discovered_at", EMPTY_DATA),
            "Disclosed At": timelines.get("disclosed_at", EMPTY_DATA),
            "Vendor Informed At": timelines.get("vendor_informed_at", EMPTY_DATA),
            "Vendor Acknowledged At": timelines.get("vendor_acknowledged_at", EMPTY_DATA),
            "Third Party Solution Provided At": timelines.get("third_party_solution_provided_at", EMPTY_DATA),
            "Solution Provided At": timelines.get("solution_provided_at", EMPTY_DATA),
            "Exploited In The Wild At": timelines.get("exploited_in_the_wild_at", EMPTY_DATA),
            "Vendor Response Time": timelines.get("vendor_response_time", EMPTY_DATA),
            "Time To Patch": timelines.get("time_to_patch", EMPTY_DATA),
            "Total Time To Patch": timelines.get("total_time_to_patch", EMPTY_DATA),
            "Time Unpatched": timelines.get("time_unpatched", EMPTY_DATA),
            "Time To Exploit": timelines.get("time_to_exploit", EMPTY_DATA),
            "Total Time To Exploit": timelines.get("total_time_to_exploit", EMPTY_DATA),
        }
        hr += "\n" + tableToMarkdown(
            "Timeline Information",
            timeline_details,
            headers=[
                "Published At",
                "Last Modified At",
                "Discovered At",
                "Disclosed At",
                "Vendor Informed At",
                "Vendor Acknowledged At",
                "Third Party Solution Provided At",
                "Solution Provided At",
                "Exploited In The Wild At",
                "Vendor Response Time",
                "Time To Patch",
                "Total Time To Patch",
                "Time Unpatched",
                "Time To Exploit",
                "Total Time To Exploit",
            ],
            removeNull=True,
        )

    cvss_v2s = vulnerability.get("cvss_v2s", [])
    if cvss_v2s:
        cvss_data = []
        for cvss in cvss_v2s:
            cvss_data.append(
                {
                    "Score": cvss.get("score", EMPTY_DATA),
                    "Source": cvss.get("source", EMPTY_DATA),
                    "Generated At": cvss.get("generated_at", EMPTY_DATA),
                    "CVE ID": cvss.get("cve_id", EMPTY_DATA),
                    "Calculated CVSS Base Score": cvss.get("calculated_cvss_base_score", EMPTY_DATA),
                    "Access Vector": cvss.get("access_vector", EMPTY_DATA),
                    "Access Complexity": cvss.get("access_complexity", EMPTY_DATA),
                    "Authentication": cvss.get("authentication", EMPTY_DATA),
                    "Confidentiality Impact": cvss.get("confidentiality_impact", EMPTY_DATA),
                    "Integrity Impact": cvss.get("integrity_impact", EMPTY_DATA),
                    "Availability Impact": cvss.get("availability_impact", EMPTY_DATA),
                }
            )
        if cvss_data:
            hr += "\n" + tableToMarkdown(
                "CVSS v2 Scores",
                cvss_data,
                headers=[
                    "Score",
                    "Source",
                    "Generated At",
                    "CVE ID",
                    "Calculated CVSS Base Score",
                    "Access Vector",
                    "Access Complexity",
                    "Authentication",
                    "Confidentiality Impact",
                    "Integrity Impact",
                    "Availability Impact",
                ],
                removeNull=True,
            )

    cvss_v3s = vulnerability.get("cvss_v3s", [])
    if cvss_v3s:
        cvss_data = []
        for cvss in cvss_v3s:
            cvss_data.append(
                {
                    "Score": cvss.get("score", EMPTY_DATA),
                    "Vector String": cvss.get("vector_string", EMPTY_DATA),
                    "Source": cvss.get("source", EMPTY_DATA),
                    "Version": cvss.get("version", EMPTY_DATA),
                    "Updated At": cvss.get("updated_at", EMPTY_DATA),
                    "Generated At": cvss.get("generated_at", EMPTY_DATA),
                    "CVE ID": cvss.get("cve_id", EMPTY_DATA),
                    "Temporal Score": cvss.get("temporal_score", EMPTY_DATA),
                    "Calculated CVSS Base Score": cvss.get("calculated_cvss_base_score", EMPTY_DATA),
                    "Attack Vector": cvss.get("attack_vector", EMPTY_DATA),
                    "Attack Complexity": cvss.get("attack_complexity", EMPTY_DATA),
                    "Privileges Required": cvss.get("privileges_required", EMPTY_DATA),
                    "User Interaction": cvss.get("user_interaction", EMPTY_DATA),
                    "Scope": cvss.get("scope", EMPTY_DATA),
                    "Confidentiality Impact": cvss.get("confidentiality_impact", EMPTY_DATA),
                    "Integrity Impact": cvss.get("integrity_impact", EMPTY_DATA),
                    "Availability Impact": cvss.get("availability_impact", EMPTY_DATA),
                    "Remediation Level": cvss.get("remediation_level", EMPTY_DATA),
                    "Report Confidence": cvss.get("report_confidence", EMPTY_DATA),
                    "Exploit Code Maturity": cvss.get("exploit_code_maturity", EMPTY_DATA),
                }
            )
        if cvss_data:
            hr += "\n" + tableToMarkdown(
                "CVSS v3 Scores",
                cvss_data,
                headers=[
                    "Score",
                    "Vector String",
                    "Source",
                    "Version",
                    "Updated At",
                    "Generated At",
                    "CVE ID",
                    "Temporal Score",
                    "Calculated CVSS Base Score",
                    "Attack Vector",
                    "Attack Complexity",
                    "Privileges Required",
                    "User Interaction",
                    "Scope",
                    "Confidentiality Impact",
                    "Integrity Impact",
                    "Availability Impact",
                    "Remediation Level",
                    "Report Confidence",
                    "Exploit Code Maturity",
                ],
                removeNull=True,
            )

    cvss_v4s = vulnerability.get("cvss_v4s", [])
    if cvss_v4s:
        cvss_v4s_data = []
        for cvss_v4 in cvss_v4s:
            cvss_v4s_data.append(
                {
                    "Score": cvss_v4.get("score", EMPTY_DATA),
                    "Vector String": cvss_v4.get("vector_string", EMPTY_DATA),
                    "Threat Score": cvss_v4.get("threat_score", EMPTY_DATA),
                    "Source": cvss_v4.get("source", EMPTY_DATA),
                    "Version": cvss_v4.get("version", EMPTY_DATA),
                    "Generated At": cvss_v4.get("generated_at", EMPTY_DATA),
                    "Updated At": cvss_v4.get("updated_at", EMPTY_DATA),
                    "CVE ID": cvss_v4.get("cve_id", EMPTY_DATA),
                    "Attack Vector": cvss_v4.get("attack_vector", EMPTY_DATA),
                    "Attack Complexity": cvss_v4.get("attack_complexity", EMPTY_DATA),
                    "Attack Requirements": cvss_v4.get("attack_requirements", EMPTY_DATA),
                    "Privileges Required": cvss_v4.get("privileges_required", EMPTY_DATA),
                    "User Interaction": cvss_v4.get("user_interaction", EMPTY_DATA),
                    "Exploit Maturity": cvss_v4.get("exploit_maturity", EMPTY_DATA),
                    "Vulnerable System Confidentiality Impact": cvss_v4.get(
                        "vulnerable_system_confidentiality_impact", EMPTY_DATA
                    ),
                    "Vulnerable System Integrity Impact": cvss_v4.get("vulnerable_system_integrity_impact", EMPTY_DATA),
                    "Vulnerable System Availability Impact": cvss_v4.get("vulnerable_system_availability_impact", EMPTY_DATA),
                    "Subsequent System Confidentiality Impact": cvss_v4.get(
                        "subsequent_system_confidentiality_impact", EMPTY_DATA
                    ),
                    "Subsequent System Integrity Impact": cvss_v4.get("subsequent_system_integrity_impact", EMPTY_DATA),
                    "Subsequent System Availability Impact": cvss_v4.get("subsequent_system_availability_impact", EMPTY_DATA),
                }
            )
        if cvss_v4s_data:
            hr += "\n" + tableToMarkdown(
                "CVSS v4 Score",
                cvss_v4s_data,
                headers=[
                    "Score",
                    "Vector String",
                    "Threat Score",
                    "Source",
                    "Version",
                    "Generated At",
                    "Updated At",
                    "CVE ID",
                    "Attack Vector",
                    "Attack Complexity",
                    "Attack Requirements",
                    "Privileges Required",
                    "User Interaction",
                    "Exploit Maturity",
                    "Vulnerable System Confidentiality Impact",
                    "Vulnerable System Integrity Impact",
                    "Vulnerable System Availability Impact",
                    "Subsequent System Confidentiality Impact",
                    "Subsequent System Integrity Impact",
                    "Subsequent System Availability Impact",
                ],
                removeNull=True,
            )

    products = vulnerability.get("products", [])
    if products:
        product_data = []
        for product in products:
            product_data.append(
                {
                    "Product ID": product.get("id", EMPTY_DATA),
                    "Product": product.get("name", EMPTY_DATA),
                    "Vendor ID": product.get("vendor_id", EMPTY_DATA),
                    "Vendor": product.get("vendor", EMPTY_DATA),
                    "Versions": product.get("versions", EMPTY_DATA),
                }
            )
        if product_data:
            hr += "\n" + tableToMarkdown(
                "Affected Products",
                product_data,
                headers=["Product ID", "Product", "Vendor ID", "Vendor", "Versions"],
                json_transform_mapping={
                    "Versions": JsonTransformer(is_nested=True),
                },
                removeNull=True,
            )

    external_references = vulnerability.get("ext_references", [])
    if external_references:
        external_reference_data = []
        for external_reference in external_references:
            external_reference_data.append(
                {
                    "Value": external_reference.get("value", EMPTY_DATA),
                    "Type": external_reference.get("type", EMPTY_DATA),
                    "URL": external_reference.get("url", EMPTY_DATA),
                    "Description": external_reference.get("description", EMPTY_DATA),
                    "Created At": external_reference.get("created_at", EMPTY_DATA),
                }
            )
        if external_reference_data:
            hr += "\n" + tableToMarkdown(
                "External References",
                external_reference_data,
                headers=["Value", "Type", "URL", "Description", "Created At"],
                url_keys=["URL"],
                removeNull=True,
            )

    cwes = vulnerability.get("cwes", [])
    if cwes:
        cwe_data = []
        for cwe in cwes:
            cwe_data.append(
                {
                    "CWE ID": cwe.get("cwe_id", EMPTY_DATA),
                    "Name": cwe.get("name", EMPTY_DATA),
                    "Source": cwe.get("source", EMPTY_DATA),
                    "CVE IDs": cwe.get("cve_ids", EMPTY_DATA),
                }
            )
        if cwe_data:
            hr += "\n" + tableToMarkdown(
                "CWES",
                cwe_data,
                headers=["CWE ID", "Name", "Source", "CVE IDs"],
                removeNull=True,
            )

    exploits = vulnerability.get("exploits", [])
    if exploits:
        exploit_data = []
        for exploit in exploits:
            exploit_data.append(
                {
                    "Value": exploit.get("value", EMPTY_DATA),
                    "Type": exploit.get("type", EMPTY_DATA),
                }
            )
        if exploit_data:
            hr += "\n" + tableToMarkdown(
                "Exploits",
                exploit_data,
                headers=["Value", "Type"],
                removeNull=True,
            )

    changelog = vulnerability.get("changelog", [])
    if changelog:
        changelog_data = []
        for change in changelog:
            changelog_data.append(
                {
                    "Created At": change.get("created_at", EMPTY_DATA),
                    "Description": change.get("description", EMPTY_DATA),
                }
            )
        if changelog_data:
            hr += "\n" + tableToMarkdown(
                "Changelog",
                changelog_data,
                headers=["Created At", "Description"],
                removeNull=True,
            )

    return hr


def create_cvss_table(cvss_data: dict) -> list:
    """
    Creates a CVSS table for the indicator.

    :type cvss_data: ``dict``
    :param cvss_data: CVSS data.

    :return: CVSS table.
    :rtype: ``list``
    """
    cvss_table_rows = []
    for item in cvss_data:
        cvss_table_rows.append({"metrics": item, "value": cvss_data[item]})

    return cvss_table_rows


def create_vulnerability_indicator(
    vulnerability: dict,
    platform_url: str,
    is_reputation: bool = False,
    create_relationships: bool = False,
) -> list[Common.CVE | Common.CustomIndicator]:
    """
    Creates a Common.CVE or Common.CustomIndicator object from the given vulnerability.

    :param vulnerability: The vulnerability to create the indicator from.
    :type vulnerability: dict

    :param platform_url: The platform URL to use for the indicator.
    :type platform_url: str

    :param is_reputation: Whether the indicator is a reputation.
    :type is_reputation: bool

    :param create_relationships: Whether to create relationships for the indicator.
    :type create_relationships: bool

    :return: The Common.CVE or Common.CustomIndicator object.
    :rtype: list[Common.CVE | Common.CustomIndicator]
    """
    vulnerability_ioc: list[Common.CVE | Common.CustomIndicator] = []
    severity = vulnerability.get("scores", {}).get("severity", DEFAULT_SEVERITY).lower()
    relationships = []

    cvss_score = ""
    cvss_version = ""
    cvss_vector = ""
    cvss_table_rows = []
    cvss_v2s = vulnerability.get("cvss_v2s", [])
    cvss_v3s = vulnerability.get("cvss_v3s", [])
    cvss_v4s = vulnerability.get("cvss_v4s", [])
    if cvss_v4s:
        item = [item for item in cvss_v4s if item.get("source") == "Flashpoint"]
        cvss_v4 = item[0] if item else cvss_v4s[0]
        cvss_score = cvss_v4.get("score", "")
        cvss_version = cvss_v4.get("version", "")
        cvss_vector = cvss_v4.get("vector_string", "")
        cvss_table_rows = create_cvss_table(cvss_v4)
    elif cvss_v3s:
        item = [item for item in cvss_v3s if item.get("source") == "Flashpoint"]
        cvss_v3 = item[0] if item else cvss_v3s[0]
        cvss_score = cvss_v3.get("score", "")
        cvss_version = cvss_v3.get("version", "")
        cvss_vector = cvss_v3.get("vector_string", "")
        cvss_table_rows = create_cvss_table(cvss_v3)
    elif cvss_v2s:
        item = [item for item in cvss_v2s if item.get("source") == "Flashpoint"]
        cvss_v2 = item[0] if item else cvss_v2s[0]
        cvss_score = cvss_v2.get("score", "")
        cvss_version = cvss_v2.get("version", "")
        cvss_vector = cvss_v2.get("vector_string", "")
        cvss_table_rows = create_cvss_table(cvss_v2)

    cpe: list = []
    cve_cpe: list = []
    products = vulnerability.get("products", [])
    for product in products:
        versions = product.get("versions", [])
        for _version in versions:
            cve_cpe.extend(Common.CPE(cpe=cpe.get("name", "")) for cpe in _version.get("cpes", []))
            cpe.extend({"CPE": cpe.get("name", "")} for cpe in _version.get("cpes", []))

    if not is_reputation:
        custom_dbot_score = Common.DBotScore(
            indicator=f"FP-VULN-{vulnerability.get('id')}",
            indicator_type=DBotScoreType.CUSTOM,
            integration_name=VENDOR_NAME,
            score=VULNERABILITY_REPUTATION_SCORE_MAPPING.get(severity, Common.DBotScore.NONE),
            reliability=demisto.params().get("integrationReliability"),
        )

        custom_vulnerability_context = deepcopy(vulnerability)
        custom_vulnerability_context["cvss_details"] = {
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "cvss_vector": cvss_vector,
            "cvss_table": cvss_table_rows,
        }
        custom_vulnerability_context["vulnerable_products"] = cpe
        custom_vulnerability_context["platform_url"] = urljoin(
            platform_url, HR_SUFFIX["VULNERABILITY"].format(vulnerability.get("id", ""))
        )

        if create_relationships:
            relationships = create_relationship_for_cve(f"FP-VULN-{vulnerability.get('id')}", vulnerability.get("cve_ids", []))

        custom_indicator = Common.CustomIndicator(
            value=f"FP-VULN-{vulnerability.get('id')}",
            indicator_type="Flashpoint Vulnerability",
            dbot_score=custom_dbot_score,
            context_prefix="FlashpointVulnerability",
            data=custom_vulnerability_context,
            relationships=relationships,
        )
        vulnerability_ioc.append(custom_indicator)

    if vulnerability.get("cve_ids"):
        for item in vulnerability.get("cve_ids", []):
            dbot_score = Common.DBotScore(
                indicator=item,
                indicator_type=DBotScoreType.CVE,
                integration_name=VENDOR_NAME,
                score=VULNERABILITY_REPUTATION_SCORE_MAPPING.get(severity, Common.DBotScore.NONE),
                reliability=demisto.params().get("integrationReliability"),
            )

            if create_relationships:
                relationships = create_relationship_for_cve(item, vulnerability.get("cve_ids", []))  # type: ignore

            cve_ioc = Common.CVE(
                id=item,
                cvss=cvss_score,
                cvss_version=cvss_version,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_table=cvss_table_rows,
                description=vulnerability.get("description", ""),
                modified=vulnerability.get("timelines", {}).get("last_modified_at", ""),
                published=vulnerability.get("timelines", {}).get("published_at", ""),
                tags=vulnerability.get("tags", []),
                vulnerable_products=cve_cpe,
                dbot_score=dbot_score,
                relationships=relationships,
            )
            vulnerability_ioc.append(cve_ioc)

    return vulnerability_ioc


def validate_vulnerability_library_and_package_list_args(args: dict, _type: str) -> tuple[dict, str]:
    """
    Validate arguments and build query_params for flashpoint-ignite-vulnerability-library-list
    and flashpoint-ignite-vulnerability-package-list command.

    :param args: Dictionary of command arguments.
    :param _type: Type of the command (library or package).

    :return: Tuple of (query_params, vulnerability_id)
    :rtype: ``tuple[dict, str]``

    :raises: ValueError on invalid arguments
    """
    vulnerability_id = args.get("vulnerability_id")
    from_index = arg_to_number(args.get("from", DEFAULT_FROM_VALUE), arg_name="from")
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    sort_by = args.get("sort_by", DEFAULT_SORT_VALUE)
    ids = argToList(args.get(f"{_type}_ids"))
    name = args.get(f"{_type}_name")
    query = args.get("query")
    size = arg_to_number(args.get("size", DEFAULT_LIMIT), arg_name="size")

    if not vulnerability_id:
        raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("vulnerability_id"))

    if size is not None and (size < 1 or size > MAX_PAGE_SIZE):
        raise ValueError(MESSAGES["SIZE_ERROR"].format(size, MAX_PAGE_SIZE))

    if sort_by:
        sort_value = sort_by.lower()
        if sort_value not in LIBRARY_AND_PACKAGE_SORT_VALUES:
            raise ValueError(
                MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(sort_value, "sort_by", LIBRARY_AND_PACKAGE_SORT_VALUES)
            )

    if sort_order and sort_order.lower() not in SORT_ORDER_VALUES:
        raise ValueError(MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format(sort_order, "sort_order", SORT_ORDER_VALUES))

    if from_index is not None and (from_index < 0):
        raise ValueError(MESSAGES["INVALID_FROM_PROVIDED"].format(from_index))

    valid_ids = []
    invalid_ids = []

    if ids:
        valid_ids = [id_str for id_str in ids if id_str.isdigit()]
        invalid_ids = [id_str for id_str in ids if not id_str.isdigit()]

        if invalid_ids:
            return_warning(MESSAGES["INVALID_INTEGER_IDS"].format(_type, ", ".join(invalid_ids)))

    sort_value = None
    if sort_by:
        sort_value = f"{sort_by.lower()}:desc" if sort_order and sort_order.lower() == "desc" else sort_by.lower()

    # Build query_params
    query_params = assign_params(
        **{"from": from_index},
        size=size,
        sort=sort_value,
        ids=",".join(valid_ids) if valid_ids else None,
        name=name,
        query=query,
    )

    return query_params, vulnerability_id


def validate_vendor_and_product_list_args(args: dict, _type: str) -> dict:
    """
    Validate and parse arguments for the vendor list and product list commands.

    :param args: Demisto args
    :param _type: Entity type - "vendor" or "product"
    :return: Validated and processed parameters dict
    """

    from_index = arg_to_number(args.get("from", DEFAULT_FROM_VALUE), arg_name="from")
    ids = argToList(args.get(f"{_type}_ids"))
    name = args.get(f"{_type}_name")
    size = arg_to_number(args.get("size", DEFAULT_LIMIT), arg_name="size")
    updated_after = arg_to_datetime(args.get("updated_after"))
    updated_before = arg_to_datetime(args.get("updated_before"))

    if from_index is not None and (from_index < 0):
        raise ValueError(MESSAGES["INVALID_FROM_PROVIDED"].format(from_index))

    if size is not None and (size < 1 or size > MAX_PAGE_SIZE):
        raise ValueError(MESSAGES["SIZE_ERROR"].format(size, MAX_PAGE_SIZE))

    valid_ids = []
    invalid_ids = []

    if ids:
        valid_ids = [id_str for id_str in ids if id_str.isdigit()]
        invalid_ids = [id_str for id_str in ids if not id_str.isdigit()]

        if invalid_ids:
            return_warning(MESSAGES["INVALID_INTEGER_IDS"].format(_type, ", ".join(invalid_ids)))

    vendor_ids_raw = argToList(args.get("vendor_ids")) if _type == "product" else []
    valid_vendor_ids = []
    invalid_vendor_ids = []
    if vendor_ids_raw:
        valid_vendor_ids = [v for v in vendor_ids_raw if v.isdigit()]
        invalid_vendor_ids = [v for v in vendor_ids_raw if not v.isdigit()]
        if invalid_vendor_ids:
            return_warning(MESSAGES["INVALID_INTEGER_IDS"].format("vendor", ", ".join(invalid_vendor_ids)))

    # Build query_params
    query_params = assign_params(
        **{"from": from_index},
        size=size,
        ids=",".join(valid_ids),
        name=name,
        vendor_ids=",".join(valid_vendor_ids),
        updated_after=updated_after.strftime(DATE_FORMAT) if updated_after else None,  # type: ignore
        updated_before=updated_before.strftime(DATE_FORMAT) if updated_before else None,  # type: ignore
    )

    if updated_after and updated_before and updated_after >= updated_before:
        raise ValueError(
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "updated_after", "updated_before", query_params["updated_after"], query_params["updated_before"]
            )
        )

    remove_nulls_from_dictionary(query_params)

    return query_params


def prepare_hr_for_vendors(vendors: list[dict], platform_url: str) -> str:
    """
    Prepare human readable format for vendors.

    :param vendors: List of vendors
    :param platform_url: Platform URL for generating clickable links.

    :return: Human readable format of vendors
    """
    vendor_data = []
    for vendor in vendors:
        vendor_id = vendor.get("id", "")
        data = {
            "ID": f"[{vendor_id}]({urljoin(platform_url, HR_SUFFIX['VENDOR'].format(vendor_id))})",
            "Name": vendor.get("name", ""),
        }
        vendor_data.append(data)

    headers = ["ID", "Name"]

    return tableToMarkdown(
        name="Vendor List",
        t=vendor_data,
        headers=headers,
        removeNull=True,
    )


def prepare_hr_for_products(products: List, platform_url: str) -> str:
    """
    Prepare human readable format for products.

    :param products: List of products
    :param platform_url: Platform URL for generating clickable links.

    :return: Human readable format of products
    """
    product_data = []
    for product in products:
        vendor = product.get("vendor") or {}
        product_id = product.get("id", "")
        data = {
            "Product ID": f"[{product_id}]({urljoin(platform_url, HR_SUFFIX['PRODUCT'].format(product_id))})",
            "Product Name": product.get("name", ""),
            "Vendor ID": vendor.get("id", ""),
            "Vendor Name": vendor.get("name", ""),
        }
        product_data.append(data)

    headers = [
        "Product ID",
        "Product Name",
        "Vendor ID",
        "Vendor Name",
    ]

    return tableToMarkdown(
        name="Product List",
        t=product_data,
        headers=headers,
        removeNull=True,
    )


def prepare_hr_for_vulnerability_libraries(libraries: list[dict]) -> str:
    """
    Prepare human readable format for vulnerability libraries.

    :param libraries: List of vulnerability libraries

    :return: Human readable format of vulnerability libraries
    """
    hr = []
    for library in libraries:
        data = {
            "ID": library.get("id", ""),
            "Name": library.get("name", ""),
            "Version": library.get("version", ""),
            "Type": library.get("type", ""),
            "Namespace": library.get("namespace", ""),
            "Package URL": library.get("constructed_purl", ""),
            "Affected": library.get("affected", ""),
        }
        hr.append(data)

    return tableToMarkdown(
        "Vulnerability Libraries",
        hr,
        [
            "ID",
            "Name",
            "Version",
            "Type",
            "Namespace",
            "Package URL",
            "Affected",
        ],
        removeNull=True,
    )


def prepare_hr_for_vulnerability_packages(packages: list[dict]) -> str:
    """
    Prepare human readable format for vulnerability packages.

    :param packages: List of package records.

    :return: Markdown string.
    """
    hr_data = []
    for pkg in packages:
        hr_data.append(
            {
                "ID": pkg.get("id"),
                "Package": pkg.get("name"),
                "Version": pkg.get("version"),
                "Filename": pkg.get("filename"),
                "OS": pkg.get("os"),
                "OS Version": pkg.get("os_version"),
                "OS Architecture": pkg.get("os_arch"),
                "Package URL": pkg.get("purl"),
                "Affected": pkg.get("affected"),
            }
        )

    return tableToMarkdown(
        "Vulnerability Packages",
        hr_data,
        headers=["ID", "Package", "Version", "Filename", "OS", "OS Version", "OS Architecture", "Package URL", "Affected"],
        removeNull=True,
    )


def validate_cve_values(cve_ids: list[str]) -> tuple[list[str], list[str]]:
    """
    Validate CVE format and return valid/invalid CVE lists.

    Args:
        cve_ids: List of CVE identifiers to validate

    Returns:
        Tuple of (valid_cves, invalid_cves)
    """

    valid_cves = []
    invalid_cves = []

    cve_pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

    for cve_id in cve_ids:
        normalized_cve = cve_id.upper().strip()
        if cve_pattern.match(normalized_cve):
            valid_cves.append(normalized_cve)
        else:
            invalid_cves.append(cve_id)

    return valid_cves, invalid_cves


def create_relationship_for_cve(entity_a: str, entity_b_data: list) -> list:
    """
    Create a list of relationships objects from the tags.

    :param entity_a: the entity a of the relation which is the current indicator.
    :param entity_b_data: list of entity_b_data returned from the API.

    :return: list of EntityRelationship objects containing all the relationships.
    """
    relationships = []
    for entity_b in entity_b_data:
        if "FP-VULN-" in entity_a:
            entity_a_type = "Flashpoint Vulnerability"
        else:
            entity_a_type = FeedIndicatorType.CVE

        if entity_b:
            obj = EntityRelationship(
                name=EntityRelationship.Relationships.RELATED_TO,
                entity_a=entity_a,
                entity_a_type=entity_a_type,
                entity_b=entity_b,
                entity_b_type=FeedIndicatorType.CVE,
            )
            relationships.append(obj)

    return relationships


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Test the Ignite instance configuration.

    :param: client: Object of Client class.
    :return: str
    """
    params = demisto.params()
    is_fetch = params.get("isFetch")
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        client.http_request(method="GET", url_suffix=URL_SUFFIX["LIST_INDICATORS"], params={"size": 1})

    return "ok"


def fetch_incidents(client: Client, last_run: dict, params: dict, is_test: bool = False) -> tuple[dict, list]:
    """
    Fetch incidents from Flashpoint.

    :param client: Client object
    :param last_run: Last run returned by function demisto.getLastRun
    :param params: Dictionary of parameters
    :param is_test:to test test-module using is_test value.
    :return: Tuple of dictionary of next run and list of fetched incidents
    """
    fetch_params = validate_fetch_incidents_params(params, last_run)
    fetch_type = fetch_params["fetch_type"]

    url_suffix = ""
    if fetch_type == DEFAULT_FETCH_TYPE:
        url_suffix = URL_SUFFIX["COMPROMISED_CREDENTIALS"]
    elif fetch_type == "Alerts":
        url_suffix = URL_SUFFIX["ALERTS"]

    response = client.http_request("GET", url_suffix=url_suffix, params=fetch_params["fetch_params"])

    incidents: List[dict[str, Any]] = []
    next_run = last_run
    start_time = fetch_params["start_time"]

    if fetch_type == DEFAULT_FETCH_TYPE:
        next_run, incidents = prepare_incidents_from_compromised_credentials_data(response, next_run, start_time, is_test)

    elif fetch_type == "Alerts":
        if is_test:
            return {}, []
        next_run, incidents = prepare_incidents_from_alerts_data(
            response, last_run, fetch_params["fetch_params"], client.platform_url
        )

    demisto.info(f"Fetched {len(incidents)} incidents for {fetch_type}")
    return next_run, incidents


def email_lookup_command(client: Client, email: str) -> CommandResults:
    """
    Lookup a particular email address or subject.

    :param client: object of client class
    :param email: email address or subject
    :return: command output
    """
    query = (
        r'+type:("email-dst", "email-src", "email-src-display-name", "email-subject", "email") +value.\*.keyword:"' + email + '"'
    )
    demisto.debug(get_url_suffix(query))
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = deepcopy(resp)
    else:
        indicators = []

    if len(indicators) > 0:
        hr = HR_TITLE.format("Email") + email + "\n"
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details["events"], [DATE_OBSERVED, "Name", "Tags"])

        fp_link = urljoin(client.platform_url, HR_SUFFIX["IOC_EMAIL"].format(urllib.parse.quote(email.encode("utf-8"))))
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        dbot_score = Common.DBotScore(
            indicator=email,
            indicator_type=DBotScoreType.EMAIL,
            integration_name=VENDOR_NAME,
            score=MALICIOUS_REPUTATION_SCORE,
            reliability=demisto.params().get("integrationReliability"),
        )
        dbot_score.integration_name = VENDOR_NAME

        email_ioc = Common.EMAIL(address=email, dbot_score=dbot_score, description=MALICIOUS_DESCRIPTION.strip())

        ignite_email_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                "Email": email,
                "EventDetails": indicator.get("Event", ""),
                "Category": indicator.get("category", ""),
                "Fpid": indicator.get("fpid", ""),
                "Href": indicator.get("href", ""),
                "Timestamp": indicator.get("timestamp", ""),
                "Type": indicator.get("type", ""),
                "Uuid": indicator.get("uuid", ""),
                "Comment": indicator["value"].get("comment", ""),
            }
            ignite_email_context.append(event)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["EMAIL"],
            outputs_key_field=OUTPUT_KEY_FIELD["FPID"],
            outputs=remove_empty_elements(ignite_email_context),
            readable_output=hr,
            indicator=email_ioc,
            raw_response=resp,
        )

    hr = HR_TITLE.format("Email") + email + "\n"
    hr += REPUTATION_UNKNOWN
    dbot_score = Common.DBotScore(
        indicator=email,
        indicator_type=DBotScoreType.EMAIL,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get("integrationReliability"),
    )
    dbot_score.integration_name = VENDOR_NAME

    email_ioc = Common.EMAIL(address=email, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())
    return CommandResults(
        indicator=email_ioc,
        readable_output=hr,
        raw_response=resp,
    )


def filename_lookup_command(client: Client, filename: str) -> CommandResults:
    """
    Lookup a particular filename.

    :param client: object of client class
    :param filename: filename
    :return: command output
    """
    query = r'+type:("filename") +value.\*.keyword:"' + filename.replace("\\", "\\\\") + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    if isinstance(resp, list):
        indicators = deepcopy(resp)
    else:
        indicators = []

    if len(indicators) > 0:
        hr = HR_TITLE.format("Filename") + filename + "\n"
        hr += REPUTATION_MALICIOUS

        events_details = parse_indicator_response(indicators)

        hr += tableToMarkdown(TABLE_TITLE, events_details["events"], [DATE_OBSERVED, "Name", "Tags"])

        fp_link = urljoin(
            client.platform_url,
            HR_SUFFIX["IOC_FILENAME"].format(urllib.parse.quote(filename.replace("\\", "\\\\").encode("utf-8"))),
        )
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        filename_context = {"Name": filename, "Malicious": {"Vendor": VENDOR_NAME, "Description": MALICIOUS_DESCRIPTION}}

        dbot_context = {
            "Indicator": filename,
            "Type": "filename",
            "Vendor": VENDOR_NAME,
            "Score": MALICIOUS_REPUTATION_SCORE,
            "Reliability": demisto.params().get("integrationReliability"),
        }

        ignite_filename_context = []
        for indicator in resp:
            indicator = indicator.get("Attribute", {})
            event = {
                "Filename": filename,
                "Category": indicator.get("category", ""),
                "Fpid": indicator.get("fpid", ""),
                "Href": indicator.get("href", ""),
                "Timestamp": indicator.get("timestamp", ""),
                "Type": indicator.get("type"),
                "Uuid": indicator.get("uuid", ""),
                "EventDetails": indicator.get("Event", []),
                "Comment": indicator["value"].get("comment", ""),
            }
            ignite_filename_context.append(event)

        ec = {
            "DBotScore": dbot_context,
            "Filename(val.Name == obj.Name)": filename_context,
            IGNITE_PATHS["Filename"]: ignite_filename_context,
        }

        return CommandResults(
            outputs=remove_empty_elements(ec),
            readable_output=hr,
            raw_response=resp,
        )

    hr = HR_TITLE.format("Filename") + filename + "\n"
    hr += REPUTATION_UNKNOWN
    ec = {
        "DBotScore": {
            "Indicator": filename,
            "Type": "filename",
            "Vendor": VENDOR_NAME,
            "Score": UNKNOWN_REPUTATION_SCORE,
            "Reliability": demisto.params().get("integrationReliability"),
        },
        "Filename(val.Name == obj.Name)": {"Name": filename, "Description": UNKONWN_DESCRIPTION},
    }

    return CommandResults(
        outputs=remove_empty_elements(ec),
        readable_output=hr,
        raw_response=resp,
    )


def ip_lookup_command(client: Client, ip: str, exact_match: bool = False) -> CommandResults:
    """
    Lookup a particular ip-address.

    This command searches for the ip in Ignite's IOC Dataset. If found, mark it as Malicious.
    If not found, lookup in Community search for matching peer ip. If found, mark it as Suspicious.

    : param client: object of client class
    : param ip: ip-address
    : param exact_match: Whether to perform an exact match. If true, the indicator value is enclosed in quotes.
    : return: command output
    """
    if not is_ip_valid(ip, True):
        raise ValueError(MESSAGES["INVALID_IP_ADDRESS"].format(ip))

    if is_ip_address_internal(ip):
        return CommandResults(readable_output=f"Skipping internal IP: {ip}")

    if is_ipv6_valid(ip):
        response = client.get_indicator(ip, "ipv6", exact_match)
    else:
        response = client.get_indicator(ip, "ipv4", exact_match)
    items = response.get("items", [])

    if items:
        item = items[0]
        reputation = item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f'{HR_TITLE.format("IP Address")}{ip}\nReputation: {reputation.capitalize()}\n\n'
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(item)
        malware_description = item.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        ip_hr_data = {
            "ID": item.get("id", ""),
            "IP": item.get("value", ""),
            "Type": item.get("type", ""),
            "Malware Description": malware_description,
            "Tags": tags,
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": item.get("mitre_attack_ids", []),
            "Created At": arg_to_datetime(item.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("created_at")
            else "",
            "Modified At": arg_to_datetime(item.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(item.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "IP",
            "Type",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            ip_hr_data,
            headers=headers,
            json_transform_mapping={
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = item.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=REPUTATION_SCORE_MAPPING.get(reputation, DEFAULT_REPUTATION_VALUE),
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get("integrationReliability"),
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = create_relationships_list_v2(client, related_iocs, ip, "ip")
        ip_ioc = Common.IP(ip=ip, dbot_score=dbot_score, relationships=relationships)

        command_results = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["IP"],
            outputs_key_field="id",
            outputs=remove_empty_elements(item),
            readable_output=human_readable,
            indicator=ip_ioc,
            raw_response=response,
            relationships=relationships,
        )

    else:
        # Search for IP in Communities
        json_data = {"query": ip, "size": DEFAULT_REPUTATION_LIMIT}

        community_response = client.http_request("POST", url_suffix=URL_SUFFIX["COMMUNITY_SEARCH"], json_data=json_data)
        indicators = community_response.get("items", [])

        if indicators:
            community_search_link = urljoin(client.platform_url, HR_SUFFIX["COMMUNITY_SEARCH"].format(ip))

            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=SUSPICIOUS_REPUTATION_SCORE,
                reliability=demisto.params().get("integrationReliability"),
            )
            dbot_score.integration_name = VENDOR_NAME

            relationships = []

            hr_data = []
            for indicator in indicators:
                relationship = create_relationships_list_for_community_search(client, indicator, ip)
                filter_enrichments = deepcopy(indicator.get("enrichments", {}))
                filter_enrichments.pop("translation", None)
                filter_enrichments.pop("bins", None)
                hr_indicator = {
                    "Author": indicator.get("author", EMPTY_DATA),
                    # type: ignore[union-attr]
                    "Date (UTC)": arg_to_datetime(indicator.get("date")).strftime(  # type: ignore
                        READABLE_DATE_FORMAT
                    )
                    if indicator.get("date")
                    else "",
                    "First Observed Date (UTC)": arg_to_datetime(indicator.get("first_observed_at")).strftime(  # type: ignore
                        READABLE_DATE_FORMAT
                    )
                    if indicator.get("first_observed_at")
                    else "",
                    "Last Observed Date (UTC)": arg_to_datetime(indicator.get("last_observed_at")).strftime(  # type: ignore
                        READABLE_DATE_FORMAT
                    )
                    if indicator.get("last_observed_at")
                    else "",
                    "Title": indicator.get("title", EMPTY_DATA),
                    "Site": indicator.get("site", EMPTY_DATA),
                    "Enrichments": filter_enrichments,
                }
                relationships += relationship
                hr_data.append(hr_indicator)

            ip_ioc = Common.IP(
                dbot_score=dbot_score, ip=ip, relationships=relationships, description=SUSPICIOUS_DESCRIPTION.strip()
            )

            title = HR_TITLE.format("IP Address") + ip + "\n" + REPUTATION_SUSPICIOUS
            title = title[4:]
            human_readable = tableToMarkdown(
                title, hr_data, json_transform_mapping={"Enrichments": JsonTransformer()}, removeNull=True
            )
            human_readable += f"\nIgnite link to community search: [{community_search_link}]({community_search_link})\n"

            limited_indicators = []
            for indicator in indicators:
                for enr_key, enr_val in indicator.get("enrichments", {}).items():
                    if isinstance(enr_val, list) and len(enr_val) > client.reputation_enrichments_limit:
                        demisto.debug(
                            f"Community search for IP {ip}: enrichments[{enr_key}] truncated to "
                            f"{client.reputation_enrichments_limit} entries for indicator "
                            f"{indicator.get('id', 'unknown')}. Full data available in raw_response."
                        )
                        indicator["enrichments"][enr_key] = enr_val[: client.reputation_enrichments_limit]
                limited_indicators.append(indicator)
            command_results = CommandResults(
                outputs_prefix=OUTPUT_PREFIX["IP_COMMUNITY_SEARCH"],
                outputs_key_field="id",
                outputs=remove_empty_elements(limited_indicators),
                readable_output=human_readable,
                indicator=ip_ioc,
                raw_response=community_response,
                relationships=relationships,
            )

        else:
            human_readable = HR_TITLE.format("IP Address") + ip + "\n"
            human_readable += REPUTATION_UNKNOWN
            dbot_score = Common.DBotScore(
                indicator=ip,
                indicator_type=DBotScoreType.IP,
                integration_name=VENDOR_NAME,
                score=UNKNOWN_REPUTATION_SCORE,
                reliability=demisto.params().get("integrationReliability"),
            )
            dbot_score.integration_name = VENDOR_NAME

            ip_ioc = Common.IP(dbot_score=dbot_score, ip=ip, description=UNKONWN_DESCRIPTION.strip())
            command_results = CommandResults(readable_output=human_readable, indicator=ip_ioc, raw_response=response)

    return command_results


def common_lookup_command(client: Client, indicator_value: str) -> CommandResults:
    """
    Lookup all types of the indicators.

    :param client: object of client class
    :param indicator_value: value of the indicator to lookup
    :return: command output
    """

    try:
        ipaddress.ip_address(indicator_value)
        if is_ipv6_valid(indicator_value):
            response = client.get_indicator(indicator_value, "ipv6")
        else:
            response = client.get_indicator(indicator_value, "ipv4")
    except ValueError:
        params = {"ioc_value": indicator_value, "embed": "all"}
        response = client.http_request("GET", URL_SUFFIX["LIST_INDICATORS"], params=params)

    items = response.get("items", [])

    if items:
        item = items[0]
        indicator_type = item.get("type", "")
        reputation = item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f"{HR_TITLE.format(indicator_type.capitalize())} {indicator_value}\nReputation: {reputation.capitalize()}\n\n"
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(item)
        malware_description = item.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        indicator_hr_data = {
            "ID": item.get("id", ""),
            "Type": indicator_type,
            "Hashes": remove_empty_elements(item.get("hashes", {})),
            "Malware Description": malware_description,
            "Tags": tags,
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": item.get("mitre_attack_ids", []),
            "Created At": arg_to_datetime(item.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("created_at")
            else "",
            "Modified At": arg_to_datetime(item.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(item.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "Type",
            "Hashes",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            indicator_hr_data,
            headers=headers,
            json_transform_mapping={
                "Hashes": JsonTransformer(is_nested=True),
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = item.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        relationships = create_relationships_list_v2(client, related_iocs, indicator_value, indicator_type)

        common_ioc = create_indicator_object(item=item, relationships=relationships)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX.get(indicator_type.upper(), CUSTOM_OUTPUT_PREFIX.format(indicator_type)),
            outputs_key_field="id",
            outputs=remove_empty_elements(item),
            readable_output=human_readable,
            indicator=common_ioc,
            raw_response=response,
            relationships=relationships,
        )

    human_readable = "### Ignite reputation for " + indicator_value + "\n"
    human_readable += REPUTATION_UNKNOWN

    return CommandResults(
        readable_output=human_readable,
        raw_response=response,
    )


def indicator_get_command(client: Client, args: dict) -> CommandResults:
    """
    Lookup all types of the indicators.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """

    indicator_id = args.get("indicator_id")
    if not indicator_id:
        raise DemistoException(MESSAGES["MISSING_REQUIRED_ARGS"].format("indicator_id"))

    indicator = client.get_indicator_by_id(indicator_id)

    if indicator:
        indicator_value = indicator.get("value", "")
        indicator_type = indicator.get("type", "")
        reputation = indicator.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f"{HR_TITLE.format(indicator_type.capitalize())} {indicator_value}\nReputation: {reputation.capitalize()}\n\n"
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(indicator)
        malware_description = indicator.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        indicator_hr_data = {
            "ID": indicator.get("id", ""),
            "Type": indicator_type,
            "Hashes": remove_empty_elements(indicator.get("hashes", {})),
            "Malware Description": malware_description,
            "Tags": indicator.get("historical_tags", []),
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": indicator.get("mitre_attack_ids", []),
            "Reports": indicator.get("reports", []),
            "Created At": arg_to_datetime(indicator.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if indicator.get("created_at")
            else "",
            "Modified At": arg_to_datetime(indicator.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if indicator.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(indicator.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if indicator.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "Type",
            "Hashes",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Reports",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            indicator_hr_data,
            headers=headers,
            json_transform_mapping={
                "Hashes": JsonTransformer(is_nested=True),
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
                "Reports": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = indicator.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        relationships = create_relationships_list_v2(client, related_iocs, indicator_value, indicator_type)

        common_ioc = create_indicator_object(item=indicator, relationships=relationships)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX.get(indicator_type.upper(), CUSTOM_OUTPUT_PREFIX.format(indicator_type)),
            outputs_key_field="id",
            outputs=remove_empty_elements(indicator),
            readable_output=human_readable,
            indicator=common_ioc,
            raw_response=indicator,
            relationships=relationships,
        )

    human_readable = "No indicator found for the given ID."

    return CommandResults(
        readable_output=human_readable,
        raw_response=indicator,
    )


def url_lookup_command(client: Client, url: str, exact_match: bool = False) -> CommandResults:
    """
    Lookup a particular url.

    :param client: object of client class
    :param url: url as indicator
    :param exact_match: Whether to perform an exact match. If true, the indicator value is enclosed in quotes.
    :return: command output
    """
    response = client.get_indicator(url, "url", exact_match)
    items = response.get("items", [])

    if items:
        item = items[0]
        reputation = item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f'{HR_TITLE.format("URL")}{url}\nReputation: {reputation.capitalize()}\n\n'
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(item)
        malware_description = item.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        ip_hr_data = {
            "ID": item.get("id", ""),
            "URL": item.get("value", ""),
            "Malware Description": malware_description,
            "Tags": tags,
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": item.get("mitre_attack_ids", []),
            "Created At": arg_to_datetime(item.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("created_at")
            else "",
            "Modified At": arg_to_datetime(item.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(item.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "URL",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            ip_hr_data,
            headers=headers,
            json_transform_mapping={
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = item.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        dbot_score = Common.DBotScore(
            indicator=url,
            indicator_type=DBotScoreType.URL,
            integration_name=VENDOR_NAME,
            score=REPUTATION_SCORE_MAPPING.get(reputation, DEFAULT_REPUTATION_VALUE),
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get("integrationReliability"),
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = create_relationships_list_v2(client, related_iocs, url, "url")
        url_ioc = Common.URL(url=url, dbot_score=dbot_score, relationships=relationships)

        command_results = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["URL"],
            outputs_key_field="id",
            outputs=remove_empty_elements(item),
            readable_output=human_readable,
            indicator=url_ioc,
            raw_response=response,
            relationships=relationships,
        )
        return command_results

    hr = HR_TITLE.format("URL") + url + "\n"
    hr += REPUTATION_UNKNOWN
    dbot_score = Common.DBotScore(
        indicator=url,
        indicator_type=DBotScoreType.URL,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get("integrationReliability"),
    )
    dbot_score.integration_name = VENDOR_NAME

    url_ioc = Common.URL(url=url, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())
    command_results = CommandResults(
        indicator=url_ioc,
        readable_output=hr,
        raw_response=response,
    )

    return command_results


def domain_lookup_command(client: Client, domain: str, exact_match: bool = False) -> CommandResults:
    """
    Lookup a particular domain.

    :param client: object of client class
    :param domain: domain
    :param exact_match: Whether to perform an exact match. If true, the indicator value is enclosed in quotes.
    :return: command output
    """

    response = client.get_indicator(domain, "domain", exact_match)
    items = response.get("items", [])

    if items:
        item = items[0]
        reputation = item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f'{HR_TITLE.format("Domain")}{domain}\nReputation: {reputation.capitalize()}\n\n'
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(item)
        malware_description = item.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        domain_hr_data = {
            "ID": item.get("id", ""),
            "Domain": item.get("value", ""),
            "Malware Description": malware_description,
            "Tags": tags,
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": item.get("mitre_attack_ids", []),
            "Created At": arg_to_datetime(item.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("created_at")
            else "",
            "Modified At": arg_to_datetime(item.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(item.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "Domain",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            domain_hr_data,
            headers=headers,
            json_transform_mapping={
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = item.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=REPUTATION_SCORE_MAPPING.get(reputation, DEFAULT_REPUTATION_VALUE),
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get("integrationReliability"),
        )
        dbot_score.integration_name = VENDOR_NAME

        relationships = create_relationships_list_v2(client, related_iocs, domain, "domain")
        domain_ioc = Common.Domain(domain=domain, dbot_score=dbot_score, relationships=relationships)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["DOMAIN"],
            outputs_key_field="id",
            outputs=remove_empty_elements(item),
            readable_output=human_readable,
            indicator=domain_ioc,
            raw_response=response,
            relationships=relationships,
        )

    human_readable = HR_TITLE.format("Domain") + domain + "\n"
    human_readable += REPUTATION_UNKNOWN
    dbot_score = Common.DBotScore(
        indicator=domain,
        indicator_type=DBotScoreType.DOMAIN,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get("integrationReliability"),
    )
    dbot_score.integration_name = VENDOR_NAME

    domain_ioc = Common.Domain(domain=domain, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())

    return CommandResults(indicator=domain_ioc, readable_output=human_readable, raw_response=response)


def file_lookup_command(client: Client, file: str, exact_match: bool = False) -> CommandResults:
    """
    Lookup a particular file hash.

    :param client: object of client class
    :param file: file as indicator
    :param exact_match: Whether to perform an exact match. If true, the indicator value is enclosed in quotes.
    :return: command output
    """

    response = client.get_indicator(file, "file", exact_match)
    items = response.get("items", [])

    if items:
        item = items[0]
        reputation = item.get("score", {}).get("value", DEFAULT_REPUTATION_VALUE)
        reputation = DEFAULT_REPUTATION_VALUE if reputation == "no_score" else reputation
        title = f'{HR_TITLE.format("File")}{file}\nReputation: {reputation.capitalize()}\n\n'
        title = title[4:]

        related_iocs, tags = get_related_iocs_and_tags(item)
        hash_type = get_hash_type(file)
        malware_description = item.get("malware_description", "")
        if not malware_description or malware_description == "N/A":
            malware_description = ""
        else:
            malware_description = html_to_text(malware_description)

        file_hr_data = {
            "ID": item.get("id", ""),
            "Hash Type": hash_type,
            "Hashes": remove_empty_elements(item.get("hashes", {})),
            "Malware Description": malware_description,
            "Tags": tags,
            "Related IOCs": related_iocs,
            "Mitre Attack IDs": item.get("mitre_attack_ids", []),
            "Created At": arg_to_datetime(item.get("created_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("created_at")
            else "",
            "Modified At": arg_to_datetime(item.get("modified_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("modified_at")
            else "",
            "Last Seen At": arg_to_datetime(item.get("last_seen_at")).strftime(  # type: ignore
                READABLE_DATE_FORMAT
            )
            if item.get("last_seen_at")
            else "",
        }
        headers = [
            "ID",
            "Hash Type",
            "Hashes",
            "Malware Description",
            "Tags",
            "Related IOCs",
            "Mitre Attack IDs",
            "Created At",
            "Modified At",
            "Last Seen At",
        ]

        human_readable = tableToMarkdown(
            title,
            file_hr_data,
            headers=headers,
            json_transform_mapping={
                "Hashes": JsonTransformer(is_nested=True),
                "Related IOCs": JsonTransformer(is_nested=True),
                "Mitre Attack IDs": JsonTransformer(is_nested=True),
            },
            removeNull=True,
        )

        platform_link = item.get("platform_urls", {}).get("ignite", "")
        human_readable += PLATFORM_LINK.format(platform_link, platform_link)

        dbot_score = Common.DBotScore(
            indicator=file,
            indicator_type=DBotScoreType.FILE,
            integration_name=VENDOR_NAME,
            score=REPUTATION_SCORE_MAPPING.get(reputation, DEFAULT_REPUTATION_VALUE),
            malicious_description=MALICIOUS_DESCRIPTION,
            reliability=demisto.params().get("integrationReliability"),
        )
        dbot_score.integration_name = VENDOR_NAME

        hashes = {
            "md5": item.get("hashes", {}).get("md5"),
            "sha1": item.get("hashes", {}).get("sha1"),
            "sha256": item.get("hashes", {}).get("sha256"),
        }
        relationships = create_relationships_list_v2(client, related_iocs, file, "file")
        file_ioc = Common.File(dbot_score=dbot_score, relationships=relationships, **hashes)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["FILE"],
            outputs_key_field="id",
            outputs=remove_empty_elements(item),
            readable_output=human_readable,
            indicator=file_ioc,
            raw_response=response,
            relationships=relationships,
        )

    hr = HR_TITLE.format("File") + file + "\n"
    hr += REPUTATION_UNKNOWN

    dbot_score = Common.DBotScore(
        indicator=file,
        indicator_type=DBotScoreType.FILE,
        integration_name=VENDOR_NAME,
        score=UNKNOWN_REPUTATION_SCORE,
        reliability=demisto.params().get("integrationReliability"),
    )
    dbot_score.integration_name = VENDOR_NAME

    file_ioc = Common.File(name=file, dbot_score=dbot_score, description=UNKONWN_DESCRIPTION.strip())

    return CommandResults(indicator=file_ioc, readable_output=hr, raw_response=response)


def get_reports_command(client, args) -> CommandResults:
    """
    Get reports matching the given search term or query.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    report_search = args.get("report_search")
    if not report_search:
        raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("report_search"))
    params = {"query": urllib.parse.quote(report_search), "limit": DEFAULT_REPORT_LIMIT}

    response = client.http_request(method="GET", url_suffix=URL_SUFFIX["REPORT_SEARCH"], params=params)
    reports = deepcopy(response.get("data", []))
    human_readable = "### Ignite Intelligence reports related to search: " + report_search + "\n"
    report_details: List[Any] = []

    if reports:
        human_readable += "Top 5 reports:\n\n"

        index = 0
        for report in reports:
            title = report.get("title", EMPTY_DATA)
            platform_url = report.get("platform_url", "")
            if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
                platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
            summary = string_escape_markdown(report.get("summary", EMPTY_DATA))
            index += 1
            human_readable += "" + str(index) + f") [{title}]({platform_url})" + "\n"
            if report.get("summary"):
                human_readable += "   Summary: " + str(summary) + "\n\n\n"
            else:
                human_readable += "   Summary: N/A\n\n\n"

            report_detail = {
                "ReportId": report.get("id", EMPTY_DATA),
                "UpdatedAt": report.get("updated_at", ""),
                "PostedAt": report.get("posted_at", ""),
                "NotifiedAt": report.get("notified_at", ""),
                "PlatformUrl": platform_url,
                "Title": title,
                "Summary": summary,
            }
            report_details.append(report_detail)
        report_details = remove_empty_elements(report_details)

        fp_url = urljoin(client.platform_url, "/cti/intelligence/search?sort_date=All Time&query=" + report_search)
        fp_url = urllib.parse.quote(fp_url, safe=":/?&=")
        human_readable += f"Link to Report-search on Ignite platform: [{fp_url}]({fp_url})\n"

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["REPORT"],
            outputs_key_field=OUTPUT_KEY_FIELD["REPORT_ID"],
            outputs=report_details,
            readable_output=human_readable,
            raw_response=response,
        )

    human_readable += "No reports found for the search."
    return CommandResults(readable_output=human_readable, raw_response=response)


def flashpoint_ignite_compromised_credentials_list_command(client: Client, args: dict) -> CommandResults:
    """
    List compromised credentials from Flashpoint Ignite platform.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    args = validate_compromised_credentials_list_args(args)
    response = client.http_request("GET", url_suffix=URL_SUFFIX["COMPROMISED_CREDENTIALS"], params=args)

    hits = deepcopy(response.get("hits", {}).get("hits", []))
    if not hits:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("compromised credentials"), raw_response=response
        )

    readable_output = ""

    total_records = response.get("hits", {}).get("total")
    if total_records:
        readable_output += f"#### Total number of records found: {total_records}\n\n"

    readable_output += prepare_hr_for_compromised_credentials(hits)

    outputs = remove_empty_elements(hits)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["COMPROMISED_CREDENTIALS"],
        outputs_key_field=OUTPUT_KEY_FIELD["COMPROMISED_CREDENTIAL_ID"],
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def get_report_by_id_command(client: Client, args: dict) -> CommandResults:
    """
    Get specific report using its fpid.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    report_id = args.get("report_id")
    if not report_id:
        raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("report_id"))

    response = client.http_request(
        method="GET", url_suffix=URL_SUFFIX["GET_REPORT_BY_ID"].format(urllib.parse.quote(str(report_id)))
    )
    report = deepcopy(response)

    human_readable = "### Ignite Intelligence Report details\n"

    if report:
        if report.get("tags") is None:
            raise ValueError(MESSAGES["NO_RECORD_FOUND"])

        timestamp = None
        try:
            time_str = report.get("posted_at", "")[:-10] + "UTC"
            timestamp = time.strptime(time_str, "%Y-%m-%dT%H:%M:%S%Z")
        except (TypeError, ValueError):
            pass

        tags = report.get("tags", [])
        tag_string = ", ".join(tags)

        if timestamp:
            timestamp_str = time.strftime(READABLE_DATE_FORMAT, timestamp)
        else:
            timestamp_str = EMPTY_DATA

        platform_url = report.get("platform_url", "")
        if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
            platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
        report_details = [
            {
                "Title": STRING_FORMAT.format(report.get("title", EMPTY_DATA), platform_url),
                "Date Published (UTC)": timestamp_str,
                "Summary": string_escape_markdown(report.get("summary", EMPTY_DATA)),
                "Tags": tag_string,
            }
        ]

        human_readable += tableToMarkdown(
            "Below are the details found:", report_details, ["Title", "Date Published (UTC)", "Summary", "Tags"]
        )
        human_readable += "\n"
        entry_context = {
            "ReportId": report.get("id", ""),
            "UpdatedAt": report.get("updated_at", ""),
            "PostedAt": report.get("posted_at", ""),
            "NotifiedAt": report.get("notified_at", ""),
            "PlatformUrl": platform_url,
            "Title": report.get("title", ""),
            "Summary": report.get("summary", ""),
            "Tags": tag_string,
        }
        entry_context = remove_empty_elements(entry_context)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["REPORT"],
            outputs_key_field=OUTPUT_KEY_FIELD["REPORT_ID"],
            outputs=entry_context,
            readable_output=human_readable,
            raw_response=response,
        )

    human_readable += "No report found for the given ID."
    return CommandResults(readable_output=human_readable, raw_response=response)


def related_report_list_command(client: Client, args: dict) -> CommandResults:
    """
    Get reports related to given report.

    :param args: demisto args
    :param client: object of client class
    :return: command output
    """
    report_id = args.get("report_id")
    if not report_id:
        raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("report_id"))
    params = {"limit": DEFAULT_REPORT_LIMIT}

    response = client.http_request(
        method="GET", url_suffix=URL_SUFFIX["RELATED_REPORT_LIST"].format(urllib.parse.quote(str(report_id))), params=params
    )
    reports = deepcopy(response.get("data", []))
    human_readable = "### Ignite Intelligence related reports:\n"
    report_details: List[Any] = []

    if reports:
        human_readable += "Top 5 related reports:\n\n"
        index = 0
        for report in reports:
            title = report.get("title", EMPTY_DATA)
            platform_url = report.get("platform_url", "")
            if isinstance(platform_url, str) and DEFAULT_OLD_PLATFORM_PATH in platform_url:
                platform_url = platform_url.replace(DEFAULT_OLD_PLATFORM_PATH, DEFAULT_PLATFORM_PATH)
            summary = string_escape_markdown(report.get("summary", EMPTY_DATA))
            index += 1
            human_readable += "" + str(index) + f") [{title}]({platform_url})" + "\n"
            human_readable += "   Summary: " + str(summary) + "\n\n\n"

            report_detail = {
                "ReportId": report.get("id", EMPTY_DATA),
                "UpdatedAt": report.get("updated_at", ""),
                "PostedAt": report.get("posted_at", ""),
                "NotifiedAt": report.get("notified_at", ""),
                "PlatformUrl": platform_url,
                "Title": title,
                "Summary": summary,
            }
            report_details.append(report_detail)
        report_details = remove_empty_elements(report_details)

        fp_url = urljoin(client.platform_url, HR_SUFFIX["REPORT"].format(urllib.parse.quote(str(report_id))))
        human_readable += f"Link to the given Report on Ignite platform: [{fp_url}]({fp_url})\n"

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["REPORT"],
            outputs_key_field=OUTPUT_KEY_FIELD["REPORT_ID"],
            outputs=report_details,
            readable_output=human_readable,
            raw_response=response,
        )

    human_readable += "No reports found for the search."
    return CommandResults(readable_output=human_readable, raw_response=response)


def event_list_command(client, args) -> CommandResults:
    """
    Get events matching the given parameters.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT), "limit")
    report_fpid = args.get("report_fpid")
    attack_ids = args.get("attack_ids")
    time_period = args.get("time_period")
    url_suffix = f'{URL_SUFFIX["EVENT_LIST"]}?sort_timestamp=desc&'
    getvars = {}
    if limit or limit == 0:
        if limit < 1 or limit > MAX_PRODUCT:
            raise DemistoException(MESSAGES["LIMIT_ERROR"].format(limit, MAX_PRODUCT))
        getvars["limit"] = limit

    if report_fpid:
        getvars["report"] = report_fpid

    if attack_ids:
        getvars["attack_ids"] = attack_ids

    if time_period:
        getvars["time_period"] = time_period

    url_suffix = url_suffix + urllib.parse.urlencode(getvars)

    resp = client.http_request("GET", url_suffix=url_suffix)
    indicators = deepcopy(resp)
    hr = ""
    events = []

    if len(indicators) > 0:
        hr += "### Ignite Events\n\n"

        for indicator in indicators:
            href = indicator.get("href", "")
            event = indicator.get("Event", {})
            fpid = indicator.get("fpid", "")
            event = parse_event_response(client, event, fpid, href)
            if indicator.get("malware_description"):
                event["Malware Description"] = indicator.get("malware_description")
            events.append(event)

        hr += tableToMarkdown("Below are the detail found:", events, [TIME_OBSERVED, "Name", "Tags", "Malware Description"])

        fp_link = urljoin(client.platform_url, HR_SUFFIX["IOC_LIST"])
        hr += ALL_DETAILS_LINK.format(fp_link, fp_link)

        # Replacing the dict keys for ec  to strip any white spaces and special characters
        for event in events:
            replace_key(event, "ObservedTime", TIME_OBSERVED)
            replace_key(event, "MalwareDescription", "Malware Description")
            replace_key(event, "Name", "EventName")

        events = remove_empty_elements(events)

        return CommandResults(
            outputs_prefix=OUTPUT_PREFIX["EVENT"],
            outputs_key_field=OUTPUT_KEY_FIELD["EVENT_ID"],
            outputs=events,
            readable_output=hr,
            raw_response=resp,
        )

    hr += MESSAGES["NO_RECORDS_FOUND"].format("events")
    return CommandResults(readable_output=hr, raw_response=resp)


def event_get_command(client, args) -> CommandResults:
    """
    Get specific event using its event id.

    :param client: object of client class
    :param args: demisto args
    :return: command output
    """
    event_id = args.get("event_id")
    if not event_id:
        raise DemistoException(MESSAGES["MISSING_REQUIRED_ARGS"].format("event_id"))
    url_suffix = URL_SUFFIX["EVENT_GET"].format(urllib.parse.quote(event_id.encode("utf-8")))
    resp = client.http_request("GET", url_suffix=url_suffix)

    ec: dict[Any, Any] = {}

    if len(resp) <= 0:
        hr = MESSAGES["NO_RECORDS_FOUND"].format("event")
        return CommandResults(readable_output=hr, raw_response=resp)

    hr = "### Ignite Event details\n"
    indicator = deepcopy(resp[0])
    event = indicator.get("Event", "")
    fpid = indicator.get("fpid", "")
    href = indicator.get("href", "")

    if event:
        event = parse_event_response(client, event, fpid, href)
        if indicator.get("malware_description"):
            event["Malware Description"] = indicator.get("malware_description", "")

        hr += tableToMarkdown("Below are the detail found:", event, [TIME_OBSERVED, "Name", "Tags", "Malware Description"])

        ec = {
            "EventId": event["EventId"],
            "UUID": event["UUID"],
            "Name": event["EventName"],
            "Tags": event["Tags"],
            "ObservedTime": event[TIME_OBSERVED],
            "EventCreatorEmail": event["EventCreatorEmail"],
            "Href": href,
        }
        # if no key `malware_description` is present, it should not be included in context data
        if event.get("Malware Description"):
            ec["MalwareDescription"] = event["Malware Description"]

    ec = remove_empty_elements(ec)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["EVENT"],
        outputs_key_field=OUTPUT_KEY_FIELD["EVENT_ID"],
        outputs=ec,
        readable_output=hr,
        raw_response=resp,
    )


def vulnerability_library_list_command(client: Client, args: dict) -> CommandResults:
    """
    List libraries affected by a particular vulnerability.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    query_params, vulnerability_id = validate_vulnerability_library_and_package_list_args(args, "library")

    response = client.get_vulnerability_libraries(vulnerability_id, query_params)

    libraries = deepcopy(response.get("results", []))
    if not libraries:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vulnerability libraries"),
            raw_response=response,
        )

    readable_output = ""

    total_records = response.get("total")
    if total_records is not None:
        readable_output += f"#### Total number of libraries found: {total_records}\n\n"

    readable_output += prepare_hr_for_vulnerability_libraries(libraries)

    from_index = response.get("from", DEFAULT_FROM_VALUE)
    size = response.get("size", DEFAULT_LIMIT)
    next_index = from_index + size
    if total_records and next_index < total_records:
        readable_output += f"\n{PAGINATION_HR} from = {next_index}, size = {size}\n"

    outputs = remove_empty_elements(libraries)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["VULNERABILITY_LIBRARY"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def vulnerability_package_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve a list of packages affected by a particular vulnerability.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    query_params, vulnerability_id = validate_vulnerability_library_and_package_list_args(args, "package")

    response = client.get_vulnerability_packages(vulnerability_id, query_params)

    packages = deepcopy(response.get("results", []))
    if not packages:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vulnerability packages"),
            raw_response=response,
        )

    readable_output = ""
    total_records = response.get("total")
    if total_records is not None:
        readable_output += f"#### Total number of packages found: {total_records}\n\n"

    readable_output += prepare_hr_for_vulnerability_packages(packages)

    from_index = response.get("from", DEFAULT_FROM_VALUE)
    size = response.get("size", DEFAULT_LIMIT)
    next_index = from_index + size
    if total_records and next_index < total_records:
        readable_output += f"\n{PAGINATION_HR} from = {next_index}, size = {size}\n"

    outputs = remove_empty_elements(packages)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["VULNERABILITY_PACKAGE"],
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def alert_list_command(client: Client, args: dict):
    """
    List alerts notification from Flashpoint Ignite.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    params = validate_alert_list_args(args)

    response = client.http_request("GET", url_suffix=URL_SUFFIX["ALERTS"], params=params)

    alerts = deepcopy(response.get("items", []))
    command_results = []

    if alerts:
        human_readable = prepare_hr_for_alerts(alerts, client.platform_url)

        alert_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["ALERT"],
            outputs_key_field="id",
            outputs=remove_empty_elements(alerts),
            raw_response=response,
            readable_output=human_readable,
        )
        command_results.append(alert_result)

        _next = response.get("pagination", {}).get("next")
        if _next:
            token_hr = PAGINATION_HR
            parsed_url = urllib.parse.urlparse(_next)
            query_params = urllib.parse.parse_qs(parsed_url.query)

            token_context_keys = ["created_after", "created_before", "size", "cursor"]
            token_context = {key: EMPTY_DATA for key in token_context_keys}

            for query in token_context_keys:
                query_value = query_params.get(query)
                if query_value:
                    token_context[query] = query_value[0]
                    token_hr += "\n" + query + " = " + token_context[query]

            token_context["name"] = "flashpoint-ignite-alert-list"
            token_context = remove_empty_elements(token_context)

            token_result = CommandResults(
                outputs_prefix=OUTPUT_PREFIX["TOKEN"], outputs_key_field="name", outputs=token_context, readable_output=token_hr
            )
            command_results.append(token_result)
    else:
        command_results.append(
            CommandResults(raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("alerts"))
        )

    return command_results


def vulnerability_get_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Get specific vulnerability using its ID.

    :param client: Client object
    :param args: Demisto args
    :return: Command output
    """
    platform_url = client.platform_url
    create_relationships = client.create_relationships
    vulnerability_id = args.get("id")
    if not vulnerability_id:
        raise DemistoException(MESSAGES["MISSING_REQUIRED_ARGS"].format("id"))

    if "FP-VULN-" in vulnerability_id:
        vulnerability_id = vulnerability_id.replace("FP-VULN-", "")

    url_suffix = f"{URL_SUFFIX['VULNERABILITY_GET']}/{vulnerability_id}"
    resp = client.http_request("GET", url_suffix=url_suffix)

    if not resp:
        hr = MESSAGES["NO_RECORDS_FOUND"].format("vulnerability")
        return [CommandResults(readable_output=hr, raw_response=resp)]

    vulnerability = deepcopy(resp)
    hr = prepare_hr_for_vulnerability(vulnerability, platform_url)

    vulnerability = remove_empty_elements(vulnerability)

    vulnerability_ioc = create_vulnerability_indicator(vulnerability, platform_url, create_relationships=create_relationships)

    results = []
    if vulnerability_ioc:
        for ioc in vulnerability_ioc:
            if ioc == vulnerability_ioc[0]:
                results.append(
                    CommandResults(
                        outputs_prefix=OUTPUT_PREFIX["VULNERABILITY"],
                        outputs_key_field=OUTPUT_KEY_FIELD["VULNERABILITY_ID"],
                        outputs=vulnerability,
                        indicator=ioc,
                        readable_output=hr,
                        raw_response=resp,
                    )
                )
            else:
                results.append(
                    CommandResults(
                        readable_output="Created Indicator for " + ioc.id,  # type: ignore
                        indicator=ioc,
                    )
                )

    return results


def vendor_list_command(client: Client, args: dict) -> list:
    """
    Retrieve a list of vendors.

    :param client: Client object
    :param args: Demisto args
    :return: Command output
    """
    query_params = validate_vendor_and_product_list_args(args, "vendor")

    response = client.get_vendors(query_params)

    vendors = deepcopy(response.get("results", []))
    command_results = []

    if vendors:
        human_readable = ""

        total_vendors = response.get("total")
        if total_vendors is not None:
            human_readable += f"#### Total number of vendors found: {total_vendors}\n\n"

        human_readable += prepare_hr_for_vendors(vendors, client.platform_url)

        next_index = query_params.get("size", DEFAULT_LIMIT) + query_params.get("from", DEFAULT_FROM_VALUE)
        if total_vendors and next_index < total_vendors:
            human_readable += f"\n\n{PAGINATION_HR} from = {next_index}, size = {query_params.get('size', DEFAULT_LIMIT)}"

        vendor_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["VENDOR"],
            outputs_key_field="id",
            outputs=remove_empty_elements(vendors),
            raw_response=response,
            readable_output=human_readable,
        )
        command_results.append(vendor_result)
    else:
        command_results.append(
            CommandResults(raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vendors"))
        )

    return command_results


def product_list_command(client: Client, args: dict) -> list:
    """
    Retrieve a list of products.

    :param client: Client object
    :param args: Demisto args
    :return: Command output
    """
    query_params = validate_vendor_and_product_list_args(args, "product")

    response = client.get_products(query_params)

    products = deepcopy(response.get("results", []))
    command_results = []

    if products:
        human_readable = ""

        total_products = response.get("total")
        if total_products is not None:
            human_readable += f"#### Total number of products found: {total_products}\n\n"

        human_readable += prepare_hr_for_products(products, client.platform_url)

        next_index = query_params.get("size", DEFAULT_LIMIT) + query_params.get("from", DEFAULT_FROM_VALUE)
        if total_products and next_index < total_products:
            human_readable += f"\n\n{PAGINATION_HR} from = {next_index}, size = {query_params.get('size', DEFAULT_LIMIT)}"

        product_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["PRODUCT"],
            outputs_key_field="id",
            outputs=remove_empty_elements(products),
            raw_response=response,
            readable_output=human_readable,
        )
        command_results.append(product_result)
    else:
        command_results.append(
            CommandResults(raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("products"))
        )

    return command_results


def vulnerability_list_command(client: Client, args: dict) -> list[CommandResults]:
    """
    List vulnerabilities from Flashpoint Ignite.

    :param client: Client object
    :param args: The command arguments
    :return: Standard command result or no records found message.
    """
    query_params, payload = validate_vulnerabilities_args(args)

    response = client.vulnerability_list(query_params, payload)

    vulnerabilities = deepcopy(response.get("results", []))
    command_results = []

    if vulnerabilities:
        human_readable = ""

        total_vulnerabilities = response.get("total")
        if total_vulnerabilities is not None:
            human_readable += f"#### Total number of vulnerabilities found: {total_vulnerabilities}\n\n"

        human_readable += prepare_hr_for_list_vulnerabilities(vulnerabilities, client.platform_url)

        next_index = query_params["size"] + query_params["from"]
        if total_vulnerabilities and next_index < total_vulnerabilities:
            human_readable += f"\n\n{PAGINATION_HR} from = {next_index}, size = {query_params['size']}"

        vulnerability_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["VULNERABILITY"],
            outputs_key_field=OUTPUT_KEY_FIELD["VULNERABILITY_ID"],
            outputs=remove_empty_elements(vulnerabilities),
            raw_response=response,
            readable_output=human_readable,
        )
        command_results.append(vulnerability_result)
    else:
        command_results.append(
            CommandResults(raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vulnerabilities"))
        )

    return command_results


def cve_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Get specific vulnerability using its CVE.

    :param client: Client object
    :param args: Demisto args

    :return: Command output
    """
    cves = argToList(args.get("cve"))
    platform_url = client.platform_url
    create_relationships = client.create_relationships

    if not cves:
        raise DemistoException(MESSAGES["MISSING_REQUIRED_ARGS"].format("cve"))

    valid_cves, invalid_cves = validate_cve_values(cves)

    if invalid_cves:
        return_warning(
            "The following CVEs were found invalid: {}".format(", ".join(invalid_cves)), exit=len(invalid_cves) == len(cves)
        )

    url_suffix = URL_SUFFIX["VULNERABILITY_GET"]
    params = {"cves": ",".join(valid_cves)}
    resp = client.http_request("GET", url_suffix=url_suffix, params=params)
    vulnerabilities = resp.get("results", [])

    if not vulnerabilities:
        hr = MESSAGES["NO_RECORDS_FOUND"].format("cve")
        return [CommandResults(readable_output=hr, raw_response=resp)]

    results = []
    for vulnerability in vulnerabilities:
        hr = prepare_hr_for_vulnerability(vulnerability, platform_url=platform_url, is_reputation=True)
        vulnerability = remove_empty_elements(vulnerability)
        vulnerability_ioc = create_vulnerability_indicator(
            vulnerability,
            platform_url=platform_url,
            is_reputation=True,
            create_relationships=create_relationships,
        )

        if vulnerability_ioc:
            for ioc in vulnerability_ioc:
                if ioc == vulnerability_ioc[0]:
                    results.append(
                        CommandResults(
                            outputs_prefix=OUTPUT_PREFIX["VULNERABILITY"],
                            outputs_key_field=OUTPUT_KEY_FIELD["VULNERABILITY_ID"],
                            outputs=vulnerability,
                            indicator=ioc,
                            readable_output=hr,
                            raw_response=resp,
                        )
                    )
                else:
                    results.append(
                        CommandResults(
                            readable_output="Created Indicator for " + ioc.id,  # type: ignore
                            indicator=ioc,
                        )
                    )

    return results


def main():
    """main function, parses params and runs command functions"""
    params = remove_space_from_args(demisto.params())
    remove_nulls_from_dictionary(params)

    api_key = str(params.get("credentials", {}).get("password", "")).strip()
    url = params.get("url")

    verify = not argToBoolean(params.get("insecure", False))

    create_relationships = argToBoolean(params.get("create_relationships", True))

    reputation_enrichments_limit = (
        arg_to_number(params.get("reputation_enrichments_limit", DEFAULT_REPUTATION_CONTEXT_LIMIT))
        or DEFAULT_REPUTATION_CONTEXT_LIMIT
    )

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = argToBoolean(params.get("proxy", False))

    args = remove_space_from_args(demisto.args())
    remove_nulls_from_dictionary(args)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}.")

    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "X-FP-IntegrationPlatform": INTEGRATION_PLATFORM,
            "X-FP-IntegrationPlatformVersion": get_demisto_version_as_str(),
            "X-FP-IntegrationVersion": INTEGRATION_VERSION,
        }
        validate_params(command, params)
        client = Client(url, headers, verify, proxy, create_relationships, reputation_enrichments_limit)

        COMMAND_TO_FUNCTION: dict = {
            "flashpoint-ignite-intelligence-report-search": get_reports_command,
            "flashpoint-ignite-compromised-credentials-list": flashpoint_ignite_compromised_credentials_list_command,
            "flashpoint-ignite-intelligence-report-get": get_report_by_id_command,
            "flashpoint-ignite-intelligence-related-report-list": related_report_list_command,
            "flashpoint-ignite-event-list": event_list_command,
            "flashpoint-ignite-event-get": event_get_command,
            "flashpoint-ignite-alert-list": alert_list_command,
            "flashpoint-ignite-indicator-get": indicator_get_command,
            "flashpoint-ignite-vulnerability-library-list": vulnerability_library_list_command,
            "flashpoint-ignite-vulnerability-package-list": vulnerability_package_list_command,
            "flashpoint-ignite-vulnerability-get": vulnerability_get_command,
            "flashpoint-ignite-vendor-list": vendor_list_command,
            "flashpoint-ignite-product-list": product_list_command,
            "flashpoint-ignite-vulnerability-list": vulnerability_list_command,
            "cve": cve_command,
        }

        REPUTATION_COMMAND_TO_FUNCTION: dict = {
            "email": email_lookup_command,
            "filename": filename_lookup_command,
            "url": url_lookup_command,
            "domain": domain_lookup_command,
            "file": file_lookup_command,
            "ip": ip_lookup_command,
        }

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))  # NOSONAR

        elif command == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params, False)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "flashpoint-ignite-common-lookup":
            indicator_value = args.get("indicator")
            if not indicator_value:
                raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("indicator"))
            indicator_list = argToList(indicator_value)
            indicator_list = [indicator.strip() for indicator in indicator_list if indicator.strip()]
            results = []
            if not indicator_list:
                raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format("indicator"))
            for indicator in indicator_list:
                results.append(common_lookup_command(client, indicator))
            return_results(results)

        elif REPUTATION_COMMAND_TO_FUNCTION.get(command):
            if not args.get(command):
                raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format(command))
            indicator_list = argToList(args.get(command))
            indicator_list = [indicator.strip() for indicator in indicator_list if indicator.strip()]
            exact_match = argToBoolean(args.get("exact_match", False))
            results = []
            if not indicator_list:
                raise ValueError(MESSAGES["MISSING_REQUIRED_ARGS"].format(command))
            for indicator in indicator_list:
                arguments = (client, indicator)
                if exact_match:
                    arguments += (exact_match,)  # type: ignore
                results.append(REPUTATION_COMMAND_TO_FUNCTION[command](*arguments))
            return_results(results)

        elif COMMAND_TO_FUNCTION.get(command):
            return_results(COMMAND_TO_FUNCTION[command](client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except requests.exceptions.ConnectionError as c:
        """ Caused mostly when URL is altered."""
        return_error(f"Failed to execute {command} command. Error: {str(c)}")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError: \n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
