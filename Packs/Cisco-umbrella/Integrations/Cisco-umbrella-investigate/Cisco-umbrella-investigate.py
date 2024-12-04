# pylint: disable=E9010
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

from typing import Any
from collections.abc import Callable
import http
from functools import wraps
import time
import json


INTEGRATION_COMMAND_PREFIX = "umbrella"
INTEGRATION_PREFIX = "Umbrella"
DEFAULT_PAGE = 0
DEFAULT_OFFSET = 0
DEFAULT_LIMIT = 50
DEFAULT_TIME = "now"
HOUR_IN_MS = 3600000
INDICATOR_VENDOR = "Cisco Umbrella Investigate"
SORT_BY_MAPPER = {
    "Min Ttl": "minTtl",
    "Max Ttl": "maxTtl",
    "First Seen": "firstSeen",
    "Last Seen": "lastSeen",
}
PARAMS = demisto.params()
DEFAULT_SUSPICIOUS_THRESHOLD = 0
DEFAULT_MALICIOUS_THRESHOLD = -90
SUSPICIOUS_THRESHOLD = DEFAULT_SUSPICIOUS_THRESHOLD
MALICIOUS_THRESHOLD = DEFAULT_MALICIOUS_THRESHOLD
MAX_THRESHOLD_VALUE = 100
MIN_THRESHOLD_VALUE = -100


def validate_authentication(func: Callable) -> Callable:
    """
    Decorator to manage authentication for API requests.

    This decorator first attempts to execute the provided function using an existing authentication
    access token stored in the 'integration_context'. If the current token is not available or invalid
    (indicated by an HTTP FORBIDDEN status), it will attempt to re-authenticate with the API and then
    retry the function execution.

    The 'integration_context' is used to store and retrieve the authentication token, ensuring that
    the latest valid authentication details are used across different executions.

    Args:
        func (Callable): The API request function to be decorated and executed.

    Raises:
        DemistoException:
            - If the API returns an HTTP FORBIDDEN status during the initial request attempt and
              re-authentication also fails.
            - If the API returns any other error during the request.

    Returns:
        Callable: The result from executing 'func' with the provided arguments and keyword arguments.
    """

    @wraps(wrapped=func)
    def wrapper(client: "Client", *args, **kwargs):
        def try_request():
            """
            Attempts to execute the API request function. If the request fails due to authorization,
            it triggers a re-authentication and retries the request.
            """
            try:
                res = func(client, *args, **kwargs)
                return res
            except DemistoException as err:
                if err.res.status_code == http.HTTPStatus.FORBIDDEN:
                    update_headers()
                return func(client, *args, **kwargs)

        def try_authentication():
            """
            Attempts to authenticate with the API and extract the access token from the response.
            In case of error or exceptions, it handles them appropriately,
            updating the integration context or raising a tailored exception.
            """
            try:
                res = client.authenticate()
                return res.get("access_token")

            except DemistoException as err:
                set_integration_context({})
                raise DemistoException("AUTHORIZATION_ERROR", res=err.res)

        def update_headers():
            """Updates the session and integration context with a new access token."""
            access_token = try_authentication()
            client._headers = {"Authorization": f"Bearer {access_token}"}
            set_integration_context({"access_token": access_token})

        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        client._headers = {"Authorization": f"Bearer {access_token}"}
        return try_request()

    return wrapper


class Client(BaseClient):
    """Client class to interact with Cisco Umbrella Investigate API."""

    def __init__(
        self,
        base_url: str,
        verify: bool,
        proxy: bool,
        api_key: str,
        api_secret: str,
        reliability: str,
    ):
        self.api_key = api_key
        self.api_secret = api_secret
        self.reliability = reliability
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
        )

    def authenticate(
        self,
    ) -> dict[str, Any]:
        """Get API token with username and password.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix="auth/v2/token",
            auth=(
                self.api_key,
                self.api_secret,
            ),
        )

    @validate_authentication
    def get_domain_categorization(
        self,
        domain: str,
        show_labels: bool,
    ) -> dict[str, Any]:
        """
        Get domain categorization.

        Args:
            domain (str): The domain.
            show_labels (bool): Whether to retrieve the category labels or ids.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        url_suffix = f"investigate/v2/domains/categorization/{domain}"
        if show_labels:
            url_suffix = f"{url_suffix}?showLabels"
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
        )

    @validate_authentication
    def search_domain(
        self,
        expression: str,
        start: str,
        stop: str | None,
        include_category: bool,
        type_: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """
        Search for domain.

        Args:
            expression (str): A standard regular expression pattern search.
            start (str): Filter for data that appears after this time.
            stop (str | None): Filter for data that appears before this time.
            include_category (bool): Whether to retrieve security categories in the response.
            type (str | None): Filter with the search database node type.
            limit (int): The maximum number of records to retrieve.
            offset (int): The optional index of the first data to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/search/{expression}",
            params=remove_empty_elements(
                {
                    "start": start,
                    "stop": stop,
                    "includeCategory": include_category,
                    "type": type_,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    @validate_authentication
    def list_domain_co_occurrences(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        List domain co-occurrences.

        Args:
            domain (str): A domain name.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/recommendations/name/{domain}.json",
        )

    @validate_authentication
    def list_related_domains(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        List domain names that are frequently requested around the same time as the given domain name.

        Args:
            domain (str): A domain name.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/links/name/{domain}",
        )

    @validate_authentication
    def get_domain_security_score(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        Get multiple scores or security features for a domain.

        Args:
            domain (str): The domain name.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/security/name/{domain}",
        )

    @validate_authentication
    def get_domain_risk_score(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        Get the domain risk score.

        Args:
            domain (str): The domain name.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/domains/risk-score/{domain}",
        )

    @validate_authentication
    def list_resource_record(
        self,
        type_: str,
        value: str,
        sort_order: str | None,
        sort_by: str | None,
        record_type: str | None,
        include_features: bool,
        min_first_seen: str | None,
        max_first_seen: str | None,
        min_last_seen: str | None,
        max_last_seen: str | None,
        sort_categories: str | None,
        required_categories: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """
        List the Resource Record (RR) data for DNS responses.

        Args:
            type_ (str): The type of the inserted value.
            value (str): The text representation of the data.
            sort_order (str): Sort records by ascending (asc) or descending (desc) order.
            sort_by (str | None): Sort records by one of the following fields.
            record_type (str | None): Comma-separated list of types of records.
            include_features (bool): Whether to add the feature sections to the response.
            min_first_seen (str | None): Select records that are first seen after the inserted value.
            max_first_seen (str | None): Select records that are first seen before the inserted value.
            min_last_seen (str | None): Select records that were last seen after the inserted value.
            max_last_seen (str | None): Select records that were last seen before the inserted value.
            sort_categories (str | None): Comma-separated list of security categories to sort the results.
            required_categories (str | None): Comma-separated list of security categories to filter
            for records that are assigned the specified categories.
            limit (int): The maximum number of records to retrieve.
            offset (int): The optional index of the first data to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/pdns/{type_}/{value}",
            params=remove_empty_elements(
                {
                    "sortorder": sort_order,
                    "sortby": sort_by,
                    "recordType": record_type,
                    "includefeatures": include_features,
                    "minFirstSeen": min_first_seen,
                    "maxFirstSeen": max_first_seen,
                    "minLastSeen": min_last_seen,
                    "maxLastSeen": max_last_seen,
                    "sortCategories": sort_categories,
                    "requiredCategories": required_categories,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    @validate_authentication
    def list_subdomain(
        self,
        domain: str,
        offset_name: str | None,
        limit: int | None,
    ) -> dict[str, Any]:
        """
        List sub-domains of a given domain.

        Args:
            domain (str): A domain name.
            offset_name (str | None): Specify the subdomain to filter the collection.
            limit (int | None): The maximum number of records to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/subdomains/{domain}",
            params=remove_empty_elements(
                {
                    "offsetName": offset_name,
                    "limit": limit,
                }
            ),
        )

    @validate_authentication
    def get_ip_bgp(
        self,
        ip: str,
    ) -> dict[str, Any]:
        """
        Get data about ASN and IP relationships, showing how IP addresses are related
        to each other and to the regional registries.

        Args:
            ip (str): The IPv4 IP address where to obtain the AS information.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/bgp_routes/ip/{ip}/as_for_ip.json",
        )

    @validate_authentication
    def get_asn_bgp(
        self,
        asn: str,
    ) -> dict[str, Any]:
        """
        Get BGP Route Information for ASN

        Args:
            asn (str): Autonomous System Number (ASN) for the AS.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/bgp_routes/asn/{asn}/prefixes_for_asn.json",
        )

    @validate_authentication
    def get_domain_who_is(
        self,
        domain: str,
    ) -> dict[str, Any]:
        """
        Get the WHOIS information for the specified domains.

        Args:
            domain (str): The domain name.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/whois/{domain}",
        )

    @validate_authentication
    def get_domain_who_is_history(
        self,
        domain: str,
        limit: int,
    ) -> dict[str, Any]:
        """
        Get a WHOIS response record for a single domain with available historical WHOIS data returned in an object

        Args:
            domain (str): The domain name.
            limit (int): The maximum number of records to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/whois/{domain}/history",
            params={
                "limit": limit,
            },
        )

    @validate_authentication
    def get_nameserver_who_is(
        self,
        is_list: bool,
        nameserver: str,
        sort: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """
        Get WHOIS information for the nameserver.

        Args:
            is_list (bool): Whether nameserver contains a list of comma-separated nameservers.
            nameserver (str): The nameserver's domain name or comma-separated list of nameservers.
            sort (str | None): Sort the results by.
            limit (int): The maximum number of records to retrieve.
            offset (int): The optional index of the first data to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        url_suffix = (
            "investigate/v2/whois/nameservers"
            if is_list
            else f"investigate/v2/whois/nameservers/{nameserver}"
        )
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=remove_empty_elements(
                {
                    "sortField": sort,
                    "limit": limit,
                    "offset": offset,
                    "nameServerList": nameserver if is_list else None,
                }
            ),
        )

    @validate_authentication
    def get_email_who_is(
        self,
        email: str,
        sort: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """
        Get WHOIS information for the email address.

        Args:
            email (str): An email address that follows the RFC5322 conventions.
            sort (str | None): Sort the results by.
            limit (int): The maximum number of records to retrieve.
            offset (int): The optional index of the first data to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/whois/emails/{email}",
            params=remove_empty_elements(
                {
                    "sortField": sort,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    @validate_authentication
    def get_regex_who_is(
        self,
        regex: str,
        search_field: str,
        sort: str | None,
        start: str,
        stop: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        """
        Performs a regular expression (RegEx) search on the WHOIS data
        (domain, nameserver, and email fields) that was updated or created in the specified time range.

        Args:
            regex (str): A standard regular expression pattern search.
            search_field (str): Specifies the field name to use in the RegEx search.
            sort (str | None): Sort the results by.
            start (str): Filter for data that appears after this time.
            stop (str | None): Filter for data that appears before this time.
            limit (int): The maximum number of records to retrieve.
            offset (int): The optional index of the first data to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/whois/search/{search_field}/{regex}",
            params=remove_empty_elements(
                {
                    "sortField": sort,
                    "start": start,
                    "stop": stop,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    @validate_authentication
    def get_top_seen_domain(
        self,
        limit: int | None,
    ) -> dict[str, Any]:
        """
        List the most seen domains in Umbrella.

        Args:
            limit (int | None): The maximum number of records to retrieve.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix="investigate/v2/topmillion",
            params=remove_empty_elements(
                {
                    "limit": limit,
                }
            ),
        )

    @validate_authentication
    def get_domain_volume(
        self,
        domain: str,
        start: str,
        stop: str | None,
        match: str | None,
    ) -> dict[str, Any]:
        """
        List the query volume for a domain over the last 30 days.

        Args:
            domain (str): A domain name.
            start (str): Filter for data that appears after this time (within the last 30 days).
            stop (str | None): Filter for data that appears before this time (within the last 30 days).
            match (str | None): The type of the query volume for the domain.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/domains/volume/{domain}",
            params=remove_empty_elements(
                {
                    "start": start,
                    "stop": stop,
                    "match": match,
                }
            ),
        )

    @validate_authentication
    def list_timeline(
        self,
        name: str,
    ) -> dict[str, Any]:
        """
        List the historical tagging timeline for a given IP, domain, or URL.

        Args:
            name (str): An IP, a domain, or a URL.

        Returns:
            dict[str, Any]: API response from Cisco Umbrella Investigate API.
        """
        return self._http_request(
            method="GET",
            url_suffix=f"investigate/v2/timeline/{name}",
        )


def get_pagination_args(
    page: str | int,
    limit: str | int,
    page_size: str | None,
) -> tuple[int, int]:
    """
    Get XSOAR pagination in Cisco Umbrella Investigate API format.

    Args:
        page (str | int): Page.
        limit (str | int): Limit.
        page_size (str | None): Page Size.

    Returns:
        tuple[int, int]: Cisco Umbrella Investigate API limit and offset.
    """
    lmt = arg_to_number(page_size or limit) or DEFAULT_LIMIT

    if (pg := arg_to_number(page)) and (pg_sz := arg_to_number(page_size)):
        ofst = pg * pg_sz
    else:
        ofst = DEFAULT_OFFSET

    return lmt, ofst


def get_domain_categorization_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get the status, security and content category IDs for domain.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.get_domain_categorization(
        domain=domain,
        show_labels=argToBoolean(args.get("show_label", True)),
    )
    data = res
    outputs = {
        "Name": domain,
        "SecurityCategories": dict_safe_get(data, [domain, "security_categories"]),
        "ContentCategories": dict_safe_get(data, [domain, "content_categories"]),
        "status": dict_safe_get(data, [domain, "status"]),
    }
    indicator = Common.Domain(
        domain=domain,
        dbot_score=Common.DBotScore(
            integration_name=INDICATOR_VENDOR,
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            score=calculate_domain_dbot_score(status=arg_to_number(outputs.get("status", "0"))),
            reliability=client.reliability,
        ),
    )
    return CommandResults(
        outputs=outputs,
        outputs_key_field="Name",
        outputs_prefix="Domain",
        indicator=indicator,
        readable_output=tableToMarkdown(
            name=f"{domain} categories:",
            t=outputs,
            headers=[
                "name",
                "SecurityCategories",
                "ContentCategories",
                "status",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_unix_time(str_time: str) -> int:
    dtm = arg_to_datetime(str_time)
    if not dtm:
        raise ValueError("Please provide a valid time")

    return int(time.mktime(dtm.timetuple()) * 1000)


def search_domain_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Search for newly seen domains that match a regular expression pattern.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )
    regex = args["regex"]
    res = client.search_domain(
        expression=regex,
        start=get_unix_time(args["start"]),
        stop=get_unix_time(args["stop"]),
        include_category=argToBoolean(args.get("include_category")),
        type_=args.get("type"),
        limit=limit,
        offset=offset,
    )
    data = res
    outputs = [
        {
            "Name": match["name"],
            "FirstSeen": match["firstSeen"],
            "FirstSeenISO": match["firstSeenISO"],
            "SecurityCategories": match["securityCategories"],
        }
        for match in data.get("matches", [])
    ]

    return CommandResults(
        outputs=outputs,
        outputs_key_field="Name",
        outputs_prefix="Domain",
        readable_output=tableToMarkdown(
            name=f"{regex} matched domains:",
            t=outputs,
            headers=[
                "Name",
                "FirstSeen",
                "FirstSeenISO",
                "SecurityCategories",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def list_domain_co_occurences_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List the co-occurences for the specified domain.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.list_domain_co_occurrences(
        domain,
    )
    outputs = {
        "Name": domain,
        "CoOccurrences": [
            {
                "Name": co[0],
                "Score": co[1],
            }
            for co in res.get("pfs2", [])
        ],
    }

    return CommandResults(
        outputs=outputs,
        outputs_key_field="Name",
        outputs_prefix="Domain",
        readable_output=tableToMarkdown(
            f"{domain} co-occurences:",
            outputs.get("CoOccurrences"),
            headers=[],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def list_related_domain_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List domain names that are frequently requested around the same time.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.list_related_domains(
        domain,
    )
    outputs = {
        "Name": domain,
        "Related": [
            {
                "Name": co[0],
                "Score": co[1],
            }
            for co in res.get("tb1") or []
        ],
    }
    return CommandResults(
        outputs=outputs,
        outputs_key_field="Name",
        outputs_prefix="Domain",
        readable_output=tableToMarkdown(
            f"{domain} related domains:",
            outputs.get("Related"),
            headers=["Name", "Score"],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_domain_security_score_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get multiple scores or security features for a domain.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.get_domain_security_score(
        domain,
    )
    data = res
    outputs = {
        "Name": domain,
        "Security": {
            "ThreatType": data.get("threat_type"),
            "AttackName": data.get("attack"),
            "KolmoorovSmirnov": data.get("ks_test"),
            "GeoScore": data.get("geoscore"),
            "Popularity": data.get("popularity"),
            "RipScore": data.get("rip_score"),
            "PrefixScore": data.get("prefix_score"),
            "ASNScore": data.get("asn_score"),
            "PageRank": data.get("pagerank"),
            "SecureRank": data.get("securerank2"),
            "Entropy": data.get("entropy"),
            "Perplexity": data.get("perplexity"),
            "DGA": data.get("dga_score"),
        },
        "tld_geodiversity": data.get("tld_geodiversity", ""),
        "GeodiversityNormalized": [
            {"score": geo[1], "country_code": geo[0]} for geo in data.get("geodiversity", [])
        ],
        "Geodiversity": [
            {"score": geo[1], "country_code": geo[0]}
            for geo in data.get("geodiversity_normalized", [])
        ],
    }
    return CommandResults(
        outputs=outputs,
        outputs_key_field="Name",
        outputs_prefix="Domain",
        readable_output=tableToMarkdown(
            f"{domain} security score:",
            outputs,
            headers=["Security", "GeodiversityNormalized", "Geodiversity"],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_domain_risk_score_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get the domain risk score.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.get_domain_risk_score(
        domain,
    )
    data = res
    outputs = {
        "name": domain,
        "risk_score": data.get("risk_score"),
        "Indicator": [
            {
                "indicator": indicator.get("indicator"),
                "indicator_id": indicator.get("indicator_id"),
                "normalized_score": indicator.get("normalized_score"),
                "score": indicator.get("score"),
            }
            for indicator in data.get("indicators", [])
        ],
    }
    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.Domain",
        indicator=Common.Domain(
            domain=domain,
            dbot_score=Common.DBotScore(
                integration_name=INDICATOR_VENDOR,
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                score=calculate_domain_dbot_score(
                    risk_score=arg_to_number(data.get("risk_score")) or 0
                ),
                reliability=client.reliability,
            ),
        ),
        readable_output=tableToMarkdown(
            name=f"{domain} risk score:",
            t=outputs["Indicator"],
            headers=[
                "indicator",
                "normalized_score",
                "score",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def list_resource_record_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List the Resource Record (RR) data for DNS responses.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )

    value = args["value"]
    types = {
        "IP": "ip",
        "Domain": "domain",
        "Raw": "raw",
        "Name": "name",
    }
    res = client.list_resource_record(
        type_=types[args["type"]],
        value=value,
        sort_order=args.get("sort_order"),
        sort_by=SORT_BY_MAPPER.get(args.get("sort_by") or ""),
        record_type=args["record_type"].upper() if args.get("record_type") else None,
        include_features=argToBoolean(args.get("include_features", False)),
        min_first_seen=args.get("min_first_seen"),
        max_first_seen=args.get("max_first_seen"),
        min_last_seen=args.get("min_last_seen"),
        max_last_seen=args.get("max_last_seen"),
        sort_categories=args.get("sort_categories"),
        required_categories=args.get("required_categories"),
        limit=limit,
        offset=offset,
    )
    data = res
    outputs = [
        {
            "value": value,
            "last_seen_iso": val.get("lastSeenISO"),
            "first_seen_iso": val.get("firstSeenISO"),
            "content_categories": val.get("contentCategories"),
            "security_categories": val.get("securityCategories"),
            "type": val.get("type"),
            "name": val.get("name"),
            "rr": val.get("rr"),
            "last_seen": val.get("lastSeen"),
            "first_seen": val.get("firstSeen"),
            "max_ttl": val.get("maxTtl"),
            "min_ttl": val.get("minTtl"),
        }
        for val in data["records"]
    ]
    return CommandResults(
        outputs=outputs,
        outputs_key_field="rr",
        outputs_prefix=f"{INTEGRATION_PREFIX}.ResourceRecord",
        readable_output=tableToMarkdown(
            name=f"{value} resource records:",
            t=outputs,
            headers=[
                "value",
                "last_seen_iso",
                "first_seen_iso",
                "content_categories",
                "security_categories",
                "type",
                "name",
                "rr",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def list_sub_domain_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List sub-domains of a given domain.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.list_subdomain(
        domain=args["domain"],
        offset_name=args.get("offset_name"),
        limit=(
            None
            if argToBoolean(args.get("all_results"))
            else arg_to_number(args.get("limit") or DEFAULT_LIMIT)
        ),
    )
    data = res
    outputs = {
        "name": domain,
        "SubDomain": [
            {
                "name": sub_domain["name"],
                "first_seen": sub_domain["firstSeen"],
                "security_categories": sub_domain["securityCategories"],
            }
            for sub_domain in data
        ],
    }

    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.Domain",
        readable_output=tableToMarkdown(
            name=f"{domain} sub-domains:",
            t=outputs["SubDomain"],
            headers=[
                "name",
                "first_seen",
                "security_categories",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_ip_bgp_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get data about ASN and IP relationships, showing how IP addresses are related
    to each other and to the regional registries.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ip = args["ip"]
    res = client.get_ip_bgp(
        ip,
    )
    data = res
    outputs = [val | {"ip": ip} for val in data]
    return CommandResults(
        outputs=outputs,
        outputs_key_field="cidr",
        outputs_prefix=f"{INTEGRATION_PREFIX}.BGPInformation",
        readable_output=tableToMarkdown(
            name=f"{ip} BGP route information:",
            t=data,
            headers=[
                "creation_date",
                "ir",
                "description",
                "asn",
                "cidr",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def string_to_header(string: str) -> str:
    """
    Convert srting to header. Change underscores to spaces, capitalize every word.

    Args:
        string (str): The string to be converted.

    Returns:
        str: The converted string.
    """
    if string in ["FirstSeen", "FirstSeenISO"]:
        return pascalToSpace(string)
    if string in ["asn", "ir", "rr"]:
        return string.upper()
    return string_to_table_header(string)


def get_asn_bgp_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get BGP Route Information for ASN.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    asn = args["asn"]
    res = client.get_asn_bgp(
        asn,
    )
    outputs = [
        {
            "asn": asn,
            "cidr": val.get("cidr"),
            "Geo": val.get("geo"),
        }
        for val in res
    ]
    hr = [
        {
            **val,
            "country_name": dict_safe_get(val, ["Geo", "country_name"]),
            "country_code": dict_safe_get(val, ["Geo", "country_code"]),
        }
        for val in outputs
    ]

    return CommandResults(
        outputs=outputs,
        outputs_key_field="cidr",
        outputs_prefix=f"{INTEGRATION_PREFIX}.BGPInformation",
        readable_output=tableToMarkdown(
            name=f"{asn} BGP route information:",
            t=hr,
            headers=[
                "cidr",
                "asn",
                "country_name",
                "country_code",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_domain_who_is_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get the WHOIS information for the specified domains.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    whois_res = client.get_domain_who_is(
        domain,
    )
    whois_data = whois_res
    security_res = client.get_domain_security_score(
        domain,
    )
    security_data = security_res

    outputs = {
        "name": domain,
        "Domain": domain,
        "Data": {
            "RegistrarName": whois_data.get("registrantName"),
            "LastRetrieved": whois_data.get("timeOfLatestRealtimeCheck"),
            "Created": whois_data.get("created"),
            "Updated": whois_data.get("updated"),
            "Expires": whois_data.get("expires"),
            "IANAID": whois_data.get("registrarIANAID"),
            "LastObserved": whois_data.get("auditUpdatedDate"),
            "Nameservers": [
                {
                    "Name": nameserver,
                }
                for nameserver in whois_data.get("nameServers", [])
            ],
            "Emails": [
                {
                    "Name": emails,
                }
                for emails in whois_data.get("emails", [])
            ],
        },
    }
    secure_rank = security_data.get("securerank2")
    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.WHOIS",
        readable_output=tableToMarkdown(
            name=f"{domain} WHOIS information:",
            t=outputs.get("Data"),
            headers=[],
            removeNull=True,
            headerTransform=string_to_header,
        ),
        indicator=Common.Domain(
            domain=domain,
            admin_country=whois_data.get("administrativeContactCountry"),
            admin_email=whois_data.get("administrativeContactEmail"),
            admin_name=whois_data.get("administrativeContactName"),
            admin_phone=whois_data.get("administrativeContactTelephone"),
            registrant_country=whois_data.get("registrantCountry"),
            registrant_email=whois_data.get("registrantEmail"),
            registrant_name=whois_data.get("registrantName"),
            registrant_phone=whois_data.get("registrantTelephone"),
            creation_date=whois_data.get("created"),
            domain_status=whois_data.get("status"),
            updated_date=whois_data.get("updated"),
            expiration_date=whois_data.get("expires"),
            registrar_name=whois_data.get("registrarName"),
            dbot_score=Common.DBotScore(
                integration_name=INDICATOR_VENDOR,
                indicator=domain,
                indicator_type=DBotScoreType.DOMAIN,
                score=calculate_domain_dbot_score(
                    secure_rank=arg_to_number(int(secure_rank) if secure_rank else None)
                ),
                reliability=client.reliability,
            ),
        ),
    )


def get_domain_who_is_history_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get a WHOIS response record for a single domain with available historical WHOIS data.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    res = client.get_domain_who_is_history(
        domain=domain,
        limit=arg_to_number(args.get("limit")) or DEFAULT_LIMIT,
    )
    data = res

    outputs = {"DomainHistory": parse_domain_history(data), "name": domain}

    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.WHOIS",
        readable_output=tableToMarkdown(
            name=f"{domain} WHOIS History Information:",
            t=outputs.get("DomainHistory"),
            headers=["created", "updated", "emails", "name_servers"],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_nameserver_who_is_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get WHOIS information for the nameserver.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    nameserver = args["nameserver"]
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )
    is_list = len(argToList(nameserver)) > 1
    res = client.get_nameserver_who_is(
        nameserver=nameserver,
        limit=limit,
        offset=offset,
        sort=args["sort"].upper().replace(" ", "") if args.get("sort") else None,
        is_list=is_list,
    )
    data = res
    outputs = [{"name": name, "Domain": data.get("domains", [])} for name, data in data.items()]

    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.WHOIS.Nameserver",
        readable_output=tableToMarkdown(
            name=f"{nameserver} WHOIS information:",
            t=outputs if is_list else data.get(nameserver, {}).get("domains"),
            headers=(
                [
                    "name",
                    "Domain",
                ]
                if is_list
                else ["domain", "current"]
            ),
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_email_who_is_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Get WHOIS information for the email address.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    email = args["email"]
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )
    res = client.get_email_who_is(
        email=email,
        limit=limit,
        offset=offset,
        sort=args.get("sort"),
    )
    data = res
    outputs = {"name": email, "Domain": dict_safe_get(data, [email, "domains"])}
    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.WHOIS.Email",
        readable_output=tableToMarkdown(
            name=f"{email} WHOIS information:",
            t=outputs.get("Domain"),
            headers=[
                "current",
                "domain",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_regex_who_is_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Performs a regular expression (RegEx) search on the WHOIS data
    (domain, nameserver, and email fields) that was updated or created in the specified time range.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    regex = args["regex"]
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )

    res = client.get_regex_who_is(
        regex=regex,
        search_field=args["search_field"],
        start=get_unix_time(args["start"]),
        stop=get_unix_time(args.get("stop") or DEFAULT_TIME),
        sort=args.get("sort"),
        limit=limit,
        offset=offset,
    )
    data = res

    outputs = parse_domain_history(data["records"])

    return CommandResults(
        outputs=outputs,
        outputs_key_field="domain_name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.WHOIS.Regex",
        readable_output=tableToMarkdown(
            name=f"{regex} WHOIS Information:",
            t=outputs,
            headers=["created", "updated", "emails", "name_servers"],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_top_seen_domain_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List the most seen domains in Umbrella.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = (
        (arg_to_number(args.get("limit")) or DEFAULT_LIMIT)
        if argToBoolean(args.get("all_results")) is False
        else None
    )
    res = client.get_top_seen_domain(limit)
    data = res
    outputs = [{"domain": domain} for domain in data]
    return CommandResults(
        outputs=outputs,
        outputs_key_field="domain",
        outputs_prefix=f"{INTEGRATION_PREFIX}.MostSeenDomain",
        readable_output=tableToMarkdown(
            name="Top Most Seen Domains:",
            t=data,
            headers=[
                "domain",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def get_domain_volume_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    List the query volume for a domain over the last 30 days.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domain = args["domain"]
    limit = (
        None
        if argToBoolean(args["all_results"])
        else arg_to_number(args.get("limit") or DEFAULT_LIMIT)
    )
    res = client.get_domain_volume(
        domain=domain,
        start=get_unix_time(args["start"]),
        stop=get_unix_time(args["stop"]),
        match=args.get("match"),
    )
    data = res
    dates = data.get("dates", [])
    start_time = dates[0] if isinstance(dates, list) and len(dates) > 0 else None

    queries = data.get("queries", [])[:limit] if limit else data.get("queries", [])

    outputs = {
        "name": domain,
        "Domain": domain,
        "Data": {
            "StartDate": args["start"],
            "StopDate": args.get("stop"),
        },
        "QueriesInfo": (
            [
                {
                    "QueryHour": (start_time + HOUR_IN_MS * index if start_time else None),
                    "Queries": query_number,
                }
                for (index, query_number) in enumerate(queries)
            ]
            if start_time
            else None
        ),
    }
    return CommandResults(
        outputs=outputs,
        outputs_key_field="name",
        outputs_prefix=f"{INTEGRATION_PREFIX}.QueryVolume",
        readable_output=tableToMarkdown(
            name=f"{domain} volume:",
            t=outputs["QueriesInfo"],
            headers=[
                "QueryHour",
                "Queries",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def list_timeline_command(
    client: Client,
    args: dict[str, Any],
    input_type: str,
) -> CommandResults:
    """
    List the historical tagging timeline for a given IP, domain, or URL.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    name = args[input_type.lower()]
    data = client.list_timeline(
        name,
    )

    limit = (
        None
        if argToBoolean(args["all_results"])
        else arg_to_number(args.get("limit") or DEFAULT_LIMIT)
    )
    outputs = {
        input_type: name,
        "Data": [
            {
                "MalwareCategories": obj.get("categories"),
                "Attacks": obj.get("attacks"),
                "ThreatTypes": obj.get("threatTypes"),
                "Timestamp": obj.get("timestamp"),
            }
            for obj in (data[:limit] if limit else data)
        ],
    }

    return CommandResults(
        outputs=outputs,
        outputs_key_field=input_type,
        outputs_prefix=f"{INTEGRATION_PREFIX}.Timeline",
        readable_output=tableToMarkdown(
            name=f"{name} tagging timeline:",
            t=outputs["Data"],
            headers=[
                "MalwareCategories",
                "Attacks",
                "ThreatTypes",
                "Timestamp",
            ],
            removeNull=True,
            headerTransform=string_to_header,
        ),
    )


def domain_command(
    client: Client,
    args: dict[str, Any],
) -> list[CommandResults]:
    """
    Get the WHOIS information for the specified domains.
    You can search by multiple email addresses or multiple nameservers.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    domains = argToList(args["domain"]) or []
    command_results = []
    for domain in domains:
        whois_res = client.get_domain_who_is(
            domain,
        )
        whois_data = whois_res
        risk_score_res = client.get_domain_risk_score(
            domain,
        )
        risk_score_data = risk_score_res
        categorization_res = client.get_domain_categorization(
            domain=domain,
            show_labels=False,
        )
        categorization_data = categorization_res[domain]

        security_res = client.get_domain_security_score(
            domain,
        )
        security_data = security_res
        secure_rank = security_data.get("securerank2")
        dbot_score = Common.DBotScore(
            integration_name=INDICATOR_VENDOR,
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            score=calculate_domain_dbot_score(
                secure_rank=arg_to_number(int(secure_rank) if secure_rank else None)
            ),
            reliability=client.reliability,
            malicious_description="Malicious domain found with risk score -1",
        )
        outputs = {
            "Name": domain,
            "Umbrella": {
                "RiskScore": risk_score_data.get("risk_score"),
                "SecureRank": security_data.get("securerank2"),
                "FirstQueriedTime": whois_data.get("created"),
                "ContentCategories": categorization_data.get("content_categories"),
                "MalwareCategories": categorization_data.get("security_categories"),
            },
            "Admin": {
                "Country": whois_data.get("administrativeContactCountry"),
                "Email": whois_data.get("administrativeContactEmail"),
                "Name": whois_data.get("administrativeContactName"),
                "Phone": whois_data.get("administrativeContactTelephone"),
            },
            "Registrant": {
                "Country": whois_data.get("registrantCountry"),
                "Email": whois_data.get("registrantEmail"),
                "Name": whois_data.get("registrantName"),
                "Phone": whois_data.get("registrantTelephone"),
            },
            "CreationDate": whois_data.get("created"),
            "DomainStatus": whois_data.get("status"),
            "UpdatedDate": whois_data.get("updated"),
            "ExpirationDate": whois_data.get("expires"),
            "Registrar": {
                "Name": whois_data.get("registrarName"),
            },
        }
        readable_domain_reputation = tableToMarkdown(
            name=f'"Umbrella Investigate" Domain Reputation for: {domain}',
            t={
                "Risk Score": risk_score_data.get("risk_score"),
                "Secure Rank": security_data.get("securerank2"),
                "Populairty": security_res.get("popularity"),
                "Demisto Reputation": scoreToReputation(dbot_score),
                "First Queried time": whois_data.get("created"),
            },
            headers=[],
        )
        readable_whois = tableToMarkdown(
            name=f'"Umbrella Investigate" WHOIS Record Data for: {domain}',
            t={
                "Name": domain,
                "Registrar Name": whois_data.get("registrarName"),
                "Last Retrieved": whois_data.get("timeOfLatestRealtimeCheck"),
                "Created": whois_data.get("created"),
                "Updated": whois_data.get("updated"),
                "Expires": whois_data.get("expires"),
                "IANAID": whois_data.get("registrarIANAID"),
                "Last Observed": whois_data.get("auditUpdatedDate"),
            },
            headers=[],
            date_fields=["Last Retrieved"],
        )
        readable_name_servers = tableToMarkdown(
            name="Name Servers:",
            t={"Name Servers": whois_data.get("nameServers", [])},
            headers=[],
        )
        readable_emails = tableToMarkdown(
            name="Emails:", t=whois_data.get("emails", []), headers=["Emails"]
        )
        readable_domain = tableToMarkdown(
            name="Domain Categorization:",
            t={
                "Content Categories": categorization_data.get("content_categories"),
                "Malware Categories": categorization_data.get("security_categories"),
            },
            headers=[],
        )
        readable = (
            readable_domain_reputation
            + readable_whois
            + readable_name_servers
            + readable_emails
            + readable_domain
        )

        command_results.append(
            CommandResults(
                outputs=outputs,
                outputs_key_field="Name",
                outputs_prefix="Domain",
                indicator=Common.Domain(
                    domain=domain,
                    dbot_score=dbot_score,
                ),
                readable_output=readable,
            )
        )

    return command_results


def test_module(client: Client, api_key: str, api_secret: str) -> str:
    """
    Test module.

    Args:
        client (Client): Cisco Umbrella Investigate API client.
        params (Dict): Integration parameters.

    Raises:
        ValueError: In case of wrong request.

    Returns:
        str: Output message.
    """

    try:
        client.authenticate()
        return "ok"
    except DemistoException as err:
        demisto.debug(str(err))
        return f"Error: {get_request_error_message(err.res.json())}"


# HELPER COMMANDS


def get_request_error_message(error_data: dict[str, Any]) -> str:
    return (
        error_data.get("errorMessage") or error_data.get("message") or str(json.dumps(error_data))
    )


def parse_domain_history(data: list[dict[str, Any]]):
    return [snakify(history) for history in data]


def calculate_domain_dbot_score(
    status: int | None = None,
    secure_rank: int | None = None,
    risk_score: int | None = None,
) -> int:
    """
    Calculates the domain dbot score.

    Args:
        status (int | None): The status of the domain.
        risk_score (int | None, optional): The secure rankof the domain. Defaults to None.
        risk_score (int | None, optional): The risk score of the domain. Defaults to None.

    Raises:
        RuntimeError: Cannot convert the number.
        ValueError: Unexpected status, expected 0,1 or -1

    Returns:
        int: The DbotScore.
    """
    match status:
        case -1:
            return Common.DBotScore.BAD
        case 1:
            return Common.DBotScore.GOOD
        case 0 | None:
            # in these cases, security_rank2 is used
            if secure_rank is None:
                if risk_score is None:
                    return Common.DBotScore.NONE

                secure_rank = (risk_score - 50) * -2

            threshold = demisto.args().get("threshold", MALICIOUS_THRESHOLD)
            malicious_threshold = arg_to_number(threshold)

            if threshold is None or malicious_threshold is None:
                raise RuntimeError(f"Cannot convert {threshold=} to number")

            if secure_rank < malicious_threshold:
                return Common.DBotScore.BAD

            if secure_rank < SUSPICIOUS_THRESHOLD:
                return Common.DBotScore.SUSPICIOUS

            return Common.DBotScore.GOOD

        case _:
            raise ValueError(f"unexpected {status=}, expected 0,1 or -1")


def verify_threshold(suspicious_threshold: int, malicious_threshold: int):
    """
    Validate the suspicious and malicious thresholds.

    Args:
        suspicious_threshold (int): Suspicious threshold.
        malicious_threshold (int): Malicious threshold.
    """
    if not (
        MAX_THRESHOLD_VALUE >= suspicious_threshold > malicious_threshold >= MIN_THRESHOLD_VALUE
    ):
        return_error(
            "Invalid threshold values: 'Suspicious' must be less than 'Malicious', "
            f"and both must be between {MIN_THRESHOLD_VALUE} and {MAX_THRESHOLD_VALUE}."
        )


def main() -> None:
    set_integration_context({})

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    global SUSPICIOUS_THRESHOLD
    global MALICIOUS_THRESHOLD
    SUSPICIOUS_THRESHOLD = (
        arg_to_number(params.get("suspicious_threshold", 0)) or DEFAULT_SUSPICIOUS_THRESHOLD
    )
    MALICIOUS_THRESHOLD = (
        arg_to_number(params.get("dboscore_threshold", -90)) or -DEFAULT_MALICIOUS_THRESHOLD
    )

    base_url = params["baseURL"]
    api_key = dict_safe_get(params, ["apitoken_creds", "identifier"])
    api_secret = dict_safe_get(params, ["apitoken_creds", "password"])
    insecure: bool = not params.get("insecure", False)
    proxy = argToBoolean(params.get("proxy", ""))
    reliability = params.get("integrationReliability", "")
    execution_metrics = ExecutionMetrics()

    command = demisto.command()
    demisto.debug(f"The command being called is {command}.")

    commands: dict[str, Callable] = {
        f"{INTEGRATION_COMMAND_PREFIX}-domain-co-occurrences": list_domain_co_occurences_command,
        f"{INTEGRATION_COMMAND_PREFIX}-domain-related": list_related_domain_command,
        f"{INTEGRATION_COMMAND_PREFIX}-domain-search": search_domain_command,
        f"{INTEGRATION_COMMAND_PREFIX}-domain-security": get_domain_security_score_command,
        f"{INTEGRATION_COMMAND_PREFIX}-list-domain-subdomain": list_sub_domain_command,
        f"{INTEGRATION_COMMAND_PREFIX}-list-resource-record": list_resource_record_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-ip-bgp": get_ip_bgp_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-asn-bgp": get_asn_bgp_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-domain-whois-history": get_domain_who_is_history_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-nameserver-whois": get_nameserver_who_is_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-email-whois": get_email_who_is_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-regex-whois": get_regex_who_is_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-top-most-seen-domain": get_top_seen_domain_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-domain-queryvolume": get_domain_volume_command,
        f"{INTEGRATION_COMMAND_PREFIX}-domain-categorization": get_domain_categorization_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-domain-risk-score": get_domain_risk_score_command,
        f"{INTEGRATION_COMMAND_PREFIX}-get-whois-for-domain": get_domain_who_is_command,
        "domain": domain_command,
    }
    timeline_commands: list[str] = [
        f"{INTEGRATION_COMMAND_PREFIX}-get-domain-timeline",
        f"{INTEGRATION_COMMAND_PREFIX}-get-ip-timeline",
        f"{INTEGRATION_COMMAND_PREFIX}-get-url-timeline",
    ]
    timeline_commands_types: dict[str, str] = {
        f"{INTEGRATION_COMMAND_PREFIX}-get-domain-timeline": "Domain",
        f"{INTEGRATION_COMMAND_PREFIX}-get-ip-timeline": "IP",
        f"{INTEGRATION_COMMAND_PREFIX}-get-url-timeline": "URL",
    }

    try:
        verify_threshold(SUSPICIOUS_THRESHOLD, MALICIOUS_THRESHOLD)
        client: Client = Client(
            base_url=base_url,
            api_key=api_key,
            api_secret=api_secret,
            verify=insecure,
            proxy=proxy,
            reliability=reliability,
        )
        if command == "test-module":
            return_results(test_module(client, api_key, api_secret))
        elif command in commands:
            cr = commands[command](client, args)
            execution_metrics.success += 1
            return_results(append_metrics(execution_metrics, [cr]))
        elif command in timeline_commands:
            cr = list_timeline_command(client, args, timeline_commands_types[command])
            execution_metrics.success += 1
            return_results(append_metrics(execution_metrics, [cr]))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except DemistoException as err:
        if err.res is not None:
            if err.res.status_code not in [http.HTTPStatus.OK, http.HTTPStatus.TOO_MANY_REQUESTS]:
                execution_metrics.general_error += 1
            elif err.res.status_code == http.HTTPStatus.TOO_MANY_REQUESTS:
                execution_metrics.quota_error += 1
            cr = CommandResults(readable_output=get_request_error_message(err.res.json()))
            return_results(append_metrics(execution_metrics, [cr]))
        else:
            return_results(CommandResults(readable_output=str(err)))

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
