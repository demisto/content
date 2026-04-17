import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

""" CONSTANTS """

INTEGRATION_NAME = "ZscalerZIA"
BASE_API_URL = "https://api.zsapi.net/zia/api/v1"
TOKEN_URL_TEMPLATE = "https://{server_url}/oauth2/v1/token"
AUDIENCE = "https://api.zscaler.com"
SUSPICIOUS_CATEGORIES = ["SUSPICIOUS_DESTINATION", "SPYWARE_OR_ADWARE"]
TOKEN_EXPIRY_BUFFER_SECONDS = 120  # Refresh the cached token this many seconds before it actually expires

ERROR_CODES_DICT = {
    400: "Invalid or bad request",
    404: "Resource does not exist",
    406: "Not Acceptable",
    409: (
        "Request could not be processed because of possible edit conflict occurred. "
        "Another admin might be saving a configuration change at the same time. "
        "In this scenario, the client is expected to retry after a short time period."
    ),
    415: "Unsupported media type.",
    429: "Exceeded the rate limit or quota.",
    500: "Unexpected error",
    503: "Service is temporarily unavailable",
}

AUTO_ACTIVATE_CHANGES_COMMANDS = (
    "zia-denylist-update",
    "zia-allowlist-update",
    "zia-category-update",
    "zia-ip-destination-group-update",
    "zia-ip-destination-group-add",
    "zia-ip-destination-group-delete",
    "zia-user-update",
)

""" HANDLE PROXY """
handle_proxy()


""" CLIENT CLASS """


class Client(BaseClient):
    """Client for Zscaler ZIA via ZIdentity OAuth 2.0.

    Authenticates using the OAuth 2.0 client credentials grant type against
    the ZIdentity token endpoint and forwards Bearer tokens to the ZIA REST API.

    Attributes:
        server_url: The ZIdentity server URL (e.g. "www.vanity.zslogin.net").
        client_id: The OAuth 2.0 client ID.
        client_secret: The OAuth 2.0 client secret.
        reliability: Source reliability string for DBotScore.
        auto_activate: Whether to auto-activate changes after write commands.
        suspicious_categories: URL categories treated as suspicious for scoring.
    """

    def __init__(
        self,
        server_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
        reliability: str,
        auto_activate: bool,
        suspicious_categories: list[str],
    ):
        """Initializes the Client.

        Args:
            server_url: The ZIdentity server URL (e.g. "www.vanity.zslogin.net").
            client_id: The OAuth 2.0 client ID registered in ZIdentity.
            client_secret: The OAuth 2.0 client secret.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy settings.
            reliability: Source reliability for DBotScore (e.g. "C - Fairly reliable").
            auto_activate: If True, activate ZIA changes after each write command.
            suspicious_categories: List of URL categories considered suspicious.
        """
        super().__init__(base_url=BASE_API_URL, verify=verify, proxy=proxy)
        self.server_url = server_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.reliability = reliability
        self.auto_activate = auto_activate
        self.suspicious_categories = suspicious_categories
        self._access_token: str | None = None

    def _get_access_token(self) -> str:
        """Obtains an OAuth 2.0 access token from ZIdentity using client credentials flow.

        Checks the integration context for a cached, non-expired token first.
        If the cached token is missing or within 30 seconds of expiry, fetches
        a new token from the ZIdentity token endpoint and caches it.

        Returns:
            A valid Bearer access token string.

        Raises:
            DemistoException: If ZIdentity does not return an access_token in the response.
        """
        ctx = get_integration_context() or {}
        token = ctx.get("access_token")
        expires_at = ctx.get("token_expires_at", 0)

        if token and time.time() < expires_at - TOKEN_EXPIRY_BUFFER_SECONDS:
            demisto.debug("Using cached ZIdentity access token.")
            return token

        demisto.debug("Fetching new ZIdentity access token.")
        token_url = TOKEN_URL_TEMPLATE.format(server_url=self.server_url)
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": AUDIENCE,
        }
        response = self._http_request(
            method="POST",
            full_url=token_url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            resp_type="json",
            ok_codes=(200,),
        )
        token = response.get("access_token")
        if not token:
            raise DemistoException("Failed to obtain access token from ZIdentity. Response: " + str(response))

        expires_in = int(response.get("expires_in", 3600))
        ctx["access_token"] = token
        ctx["token_expires_at"] = time.time() + expires_in
        set_integration_context(ctx)
        add_sensitive_log_strs(token)
        return token

    def _get_auth_headers(self) -> dict:
        """Builds the Authorization headers for ZIA API requests.

        Returns:
            A dict containing the Bearer Authorization header and Content-Type.
        """
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _error_handler(self, res) -> None:
        """Handles HTTP error responses from the ZIA API.

        Raises a DemistoException with a descriptive message based on the
        HTTP status code and response body.

        Args:
            res: The requests.Response object from the failed HTTP call.

        Raises:
            DemistoException: Always raised with an appropriate error message.
        """
        if res.status_code in (401, 403):
            raise DemistoException(
                f"Authentication/Authorization error ({res.status_code}): {res.text}. "
                "Verify your Client ID, Client Secret, and Domain are correct."
            )
        elif res.status_code == 400 and res.request.method == "PUT" and "/urlCategories/" in res.request.url:
            raise DemistoException(
                f"The request failed with error {res.status_code}.\nMessage: {res.text}\n"
                "This error might be due to an invalid URL or exceeding your organization's quota.\n"
                "For more information about URL formatting, refer to the Zscaler URL Format Guidelines: "
                "https://help.zscaler.com/zia/url-format-guidelines\n"
                "To check your quota usage, run the command `zia-url-quota-get`."
            )
        elif res.status_code in ERROR_CODES_DICT:
            raise DemistoException(f"The request failed with error: {ERROR_CODES_DICT[res.status_code]}.\nMessage: {res.text}")
        else:
            raise DemistoException(f"The request failed with status code {res.status_code}.\nMessage: {res.text}")

    def _do_http_request(
        self,
        method: str,
        url_suffix: str,
        data: dict | list | None,
        params: dict | None,
        resp_type: str,
    ):
        """Executes a single authenticated HTTP request to the ZIA API.

        Injects the current Bearer token Authorization header and retries
        automatically on HTTP 429 (rate limit) responses up to 3 times.

        Args:
            method: HTTP method string (e.g. "GET", "POST", "PUT", "DELETE").
            url_suffix: The API path suffix appended to BASE_API_URL.
            data: Optional JSON-serializable body payload (dict or list).
            params: Optional URL query parameters dict.
            resp_type: Response parsing mode passed to _http_request.

        Returns:
            The parsed API response (type depends on resp_type).
        """
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=data,
            params=params,
            headers=self._get_auth_headers(),
            error_handler=self._error_handler,
            ok_codes=(200, 204),
            resp_type=resp_type,
            retries=3,
            status_list_to_retry=[429],
        )

    def api_request(
        self,
        method: str,
        url_suffix: str,
        data: dict | list | None = None,
        params: dict | None = None,
        resp_type: str = "json",
    ):
        """Makes an authenticated API request to the ZIA API.

        Automatically injects the Bearer token Authorization header and retries
        on HTTP 429 (rate limit) responses up to 3 times.

        If a 401 response is received (e.g. due to a stale cached token caused
        by clock drift), the cached token is cleared and the request is retried
        once with a freshly obtained token.

        Args:
            method: HTTP method string (e.g. "GET", "POST", "PUT", "DELETE").
            url_suffix: The API path suffix appended to BASE_API_URL.
            data: Optional JSON-serializable body payload (dict or list).
            params: Optional URL query parameters dict.
            resp_type: Response parsing mode passed to _http_request
                (e.g. "json", "response", "content").

        Returns:
            The parsed API response (type depends on resp_type).
        """
        try:
            return self._do_http_request(method, url_suffix, data, params, resp_type)
        except DemistoException as e:
            if getattr(getattr(e, "res", None), "status_code", None) == 401:
                demisto.debug("401 detected - forcing token refresh and retrying request.")
                ctx = get_integration_context() or {}
                ctx.pop("access_token", None)
                ctx.pop("token_expires_at", None)
                set_integration_context(ctx)
                return self._do_http_request(method, url_suffix, data, params, resp_type)
            raise

    def activate_changes(self) -> dict:
        """Activates saved ZIA configuration changes.

        Returns:
            The API response dict containing the activation status.
        """
        return self.api_request("POST", "/status/activate")

    # ---- Denylist ----

    def get_denylist(self) -> dict:
        """Retrieves the current ZIA advanced security policy including the denylist.

        Returns:
            A dict with the full security/advanced policy, including 'blacklistUrls'.
        """
        return self.api_request("GET", "/security/advanced")

    def update_denylist(self, urls: list[str], ips: list[str], action: str) -> None:
        """Updates the ZIA denylist with the given URLs and IPs.

        For OVERWRITE, fetches the current policy and replaces blacklistUrls entirely
        via PUT. For ADD_TO_LIST and REMOVE_FROM_LIST, uses the POST action endpoint.

        Args:
            urls: List of URL strings to add/remove/overwrite.
            ips: List of IP address strings to add/remove/overwrite.
            action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", or "OVERWRITE".
        """
        items = urls + ips
        if action == "OVERWRITE":
            # OVERWRITE uses PUT on /security/advanced with blacklistUrls field
            current = self.get_denylist()
            current["blacklistUrls"] = items
            self.api_request("PUT", "/security/advanced", data=current, resp_type="response")
        else:
            payload = {"blacklistUrls": items}
            self.api_request(
                "POST",
                f"/security/advanced/blacklistUrls?action={action}",
                data=payload,
                resp_type="response",
            )

    # ---- Allowlist ----

    def get_allowlist(self) -> dict:
        """Retrieves the current ZIA security policy including the allowlist.

        Returns:
            A dict with the full security policy, including 'whitelistUrls'.
        """
        return self.api_request("GET", "/security")

    def update_allowlist(self, items: list[str], action: str) -> None:
        """Updates the ZIA allowlist with the given URLs and IPs.

        Since the ZIA API only supports PUT (full replacement), this method
        fetches the current allowlist and merges the changes before sending.
        Deduplicates entries when adding.

        Args:
            items: List of URL/IP strings to add/remove/overwrite.
            action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", or "OVERWRITE".
        """
        current = self.get_allowlist()
        existing = current.get("whitelistUrls", [])
        if action == "ADD_TO_LIST":
            # Only add items not already present
            new_items = [u for u in items if u not in existing]
            current["whitelistUrls"] = existing + new_items
        elif action == "REMOVE_FROM_LIST":
            current["whitelistUrls"] = [u for u in existing if u not in items]
        else:  # OVERWRITE
            current["whitelistUrls"] = items
        self.api_request("PUT", "/security", data=current, resp_type="response")

    # ---- URL Categories ----

    def get_url_categories(
        self,
        category_id: str | None = None,
        custom_only: bool = False,
        include_only_url_keyword_counts: bool = False,
        lite: bool = False,
    ) -> list | dict:
        """Retrieves URL categories from ZIA.

        Args:
            category_id: If provided, fetches only the category with this ID.
            custom_only: If True, returns only custom URL categories.
            include_only_url_keyword_counts: If True, returns only URL and keyword
                counts instead of full URL lists.
            lite: If True, returns a lightweight list of category IDs and names only.
                Cannot be combined with other parameters.

        Returns:
            A list of category dicts, or a single category dict if category_id is given.
        """
        if category_id:
            return self.api_request("GET", f"/urlCategories/{category_id}")
        if lite:
            return self.api_request("GET", "/urlCategories/lite")
        params: dict = {}
        if custom_only:
            params["customOnly"] = "true"
        if include_only_url_keyword_counts:
            params["includeOnlyUrlKeywordCounts"] = "true"
        return self.api_request("GET", "/urlCategories", params=params)

    def update_url_category(
        self,
        category_id: str,
        urls: list[str],
        ips: list[str],
        action: str,
        keywords: list[str] | None = None,
        description: str | None = None,
        db_categorized_urls: list[str] | None = None,
        keywords_retaining_parent_category: list[str] | None = None,
        ip_ranges_retaining_parent_category: list[str] | None = None,
    ) -> None:
        """Updates a URL category by merging the given URLs and IPs with existing ones.

        Fetches the current category state first, then applies the action
        (ADD_TO_LIST, REMOVE_FROM_LIST, or OVERWRITE) to URLs and IP ranges,
        and sends the merged payload via PUT.

        Args:
            category_id: The unique identifier of the URL category to update.
            urls: List of URL strings to add/remove/overwrite.
            ips: List of IP range strings to add/remove/overwrite.
            action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", or "OVERWRITE".
            keywords: Optional list of custom keywords to associate with the category.
            description: Optional description string for the category.
            db_categorized_urls: Optional URLs to retain under the parent category.
            keywords_retaining_parent_category: Optional keywords retained from parent.
            ip_ranges_retaining_parent_category: Optional IP ranges retained from parent.
        """
        # Fetch current category to merge
        current = self.api_request("GET", f"/urlCategories/{category_id}")
        existing_urls = current.get("urls", [])
        existing_ips = current.get("ipRanges", [])

        if action == "ADD_TO_LIST":
            new_urls = existing_urls + [u for u in urls if u not in existing_urls]
            new_ips = existing_ips + [ip for ip in ips if ip not in existing_ips]
        elif action == "REMOVE_FROM_LIST":
            new_urls = [u for u in existing_urls if u not in urls]
            new_ips = [ip for ip in existing_ips if ip not in ips]
        else:  # OVERWRITE
            new_urls = urls
            new_ips = ips

        payload: dict = {
            "id": category_id,
            "customCategory": current.get("customCategory"),
            "urls": new_urls,
            "ipRanges": new_ips,
        }
        if current.get("configuredName"):
            payload["configuredName"] = current["configuredName"]
        if current.get("superCategory"):
            payload["superCategory"] = current["superCategory"]
        if description is not None:
            payload["description"] = description
        if keywords is not None:
            payload["keywords"] = keywords
        if db_categorized_urls is not None:
            payload["dbCategorizedUrls"] = db_categorized_urls
        if keywords_retaining_parent_category is not None:
            payload["keywordsRetainingParentCategory"] = keywords_retaining_parent_category
        if ip_ranges_retaining_parent_category is not None:
            payload["ipRangesRetainingParentCategory"] = ip_ranges_retaining_parent_category

        self.api_request("PUT", f"/urlCategories/{category_id}", data=payload, resp_type="response")

    # ---- URL Quota ----

    def get_url_quota(self) -> dict:
        """Retrieves the URL quota information for the organization.

        Returns:
            A dict containing 'uniqueUrlsProvisioned' and 'remainingUrlsQuota'.
        """
        return self.api_request("GET", "/urlCategories/urlQuota")

    # ---- IP Destination Groups ----

    def list_ip_destination_groups(
        self,
        group_id: int | None = None,
        include_ipv6: bool = False,
        exclude_type: str | None = None,
        category_type: list[str] | None = None,
        lite: bool = False,
    ) -> list | dict:
        """Lists IP destination groups from ZIA.

        If group_id is provided, returns only that specific group. Otherwise,
        returns all IPv4 groups (and optionally IPv6 groups).

        Args:
            group_id: If provided, fetches only the group with this ID.
            include_ipv6: If True, also fetches IPv6 destination groups.
            exclude_type: Filter to exclude groups of this type
                (e.g. "DSTN_IP", "DSTN_FQDN", "DSTN_DOMAIN", "DSTN_OTHER").
            category_type: Filter by group type (only valid with lite=True).
            lite: If True, returns lightweight name/ID-only results.

        Returns:
            A list of group dicts, or a single group dict if group_id is given.
        """
        if group_id is not None:
            return self.api_request("GET", f"/ipDestinationGroups/{group_id}")

        lite_suffix = "/lite" if lite else ""
        params: dict = {}
        if exclude_type:
            params["excludeType"] = exclude_type
        if category_type and lite:
            params["type"] = category_type

        results = []
        ipv4_resp = self.api_request("GET", f"/ipDestinationGroups{lite_suffix}", params=params)
        results.extend(ipv4_resp if isinstance(ipv4_resp, list) else [ipv4_resp])

        if include_ipv6:
            ipv6_resp = self.api_request("GET", f"/ipDestinationGroups/ipv6DestinationGroups{lite_suffix}", params=params)
            results.extend(ipv6_resp if isinstance(ipv6_resp, list) else [ipv6_resp])

        return results

    def update_ip_destination_group(self, group_id: int, payload: dict) -> dict:
        """Updates an existing IP destination group.

        Args:
            group_id: The unique identifier of the group to update.
            payload: A dict containing the full updated group definition.

        Returns:
            The updated group dict as returned by the API.
        """
        return self.api_request("PUT", f"/ipDestinationGroups/{group_id}", data=payload)

    def add_ip_destination_group(self, payload: dict) -> dict:
        """Creates a new IP destination group.

        Args:
            payload: A dict containing the new group definition (name, type,
                addresses, description, ipCategories, countries, isNonEditable).

        Returns:
            The created group dict as returned by the API.
        """
        return self.api_request("POST", "/ipDestinationGroups", data=payload)

    def delete_ip_destination_group(self, group_id: int) -> None:
        """Deletes an IP destination group by ID.

        Args:
            group_id: The unique identifier of the group to delete.
        """
        self.api_request("DELETE", f"/ipDestinationGroups/{group_id}", resp_type="response")

    # ---- Users ----

    def get_users(
        self,
        user_id: str | None = None,
        dept: str | None = None,
        group: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list | dict:
        """Retrieves ZIA users.

        If user_id is provided, returns only that specific user. Otherwise,
        returns a paginated list of users with optional department/group filters.

        Args:
            user_id: If provided, fetches only the user with this ID.
            dept: Filter users by department name.
            group: Filter users by group name.
            page: Page offset for pagination (1-based).
            page_size: Number of results per page (max 10,000).

        Returns:
            A list of user dicts, or a single user dict if user_id is given.
        """
        if user_id:
            return self.api_request("GET", f"/users/{user_id}")
        params: dict = {"page": page, "pageSize": page_size}
        if dept:
            params["dept"] = dept
        if group:
            params["group"] = group
        return self.api_request("GET", "/users", params=params)

    def update_user(self, user_id: str, payload: dict) -> dict:
        """Updates a ZIA user by ID.

        Args:
            user_id: The unique identifier of the user to update.
            payload: A dict containing the full updated user definition.

        Returns:
            The updated user dict as returned by the API.
        """
        return self.api_request("PUT", f"/users/{user_id}", data=payload)

    # ---- Groups ----

    def get_groups(
        self,
        search: str | None = None,
        defined_by: str | None = None,
        sort_by: str = "id",
        sort_order: str = "asc",
        page: int = 1,
        page_size: int = 100,
    ) -> list:
        """Retrieves a paginated list of ZIA user groups.

        Args:
            search: Search string matched against group name or comments.
            defined_by: Filter by the attribute that defines the group.
            sort_by: Field to sort results by (e.g. "id", "name", "modTime").
            sort_order: Sort direction, one of "asc", "desc", or "ruleExecution".
            page: Page offset for pagination (1-based).
            page_size: Number of results per page (max 10,000).

        Returns:
            A list of group dicts.
        """
        params: dict = {"page": page, "pageSize": page_size, "sortBy": sort_by, "sortOrder": sort_order}
        if search:
            params["search"] = search
        if defined_by:
            params["definedBy"] = defined_by
        return self.api_request("GET", "/groups", params=params)

    # ---- Departments ----

    def get_departments(
        self,
        department_id: str | None = None,
        search: str | None = None,
        limit_search: bool = False,
        sort_by: str = "id",
        sort_order: str = "asc",
        page: int = 1,
        page_size: int = 100,
    ) -> list | dict:
        """Retrieves ZIA departments.

        If department_id is provided, returns only that specific department.
        Otherwise, returns a paginated list with optional search filters.

        Args:
            department_id: If provided, fetches only the department with this ID.
            search: Search string matched against department name or comments.
            limit_search: If True, restricts search to match only the department name.
            sort_by: Field to sort results by (e.g. "id", "name", "rank").
            sort_order: Sort direction, one of "asc", "desc", or "ruleExecution".
            page: Page offset for pagination (1-based).
            page_size: Number of results per page (max 10,000).

        Returns:
            A list of department dicts, or a single department dict if
            department_id is given.
        """
        if department_id:
            return self.api_request("GET", f"/departments/{department_id}")
        params: dict = {"page": page, "pageSize": page_size, "sortBy": sort_by, "sortOrder": sort_order}
        if search:
            params["search"] = search
            if limit_search:
                params["limitSearch"] = "true"
        return self.api_request("GET", "/departments", params=params)

    # ---- Sandbox ----

    def get_sandbox_report(self, md5: str, report_type: str = "summary") -> dict:
        """Retrieves a Sandbox analysis report for a file identified by MD5 hash.

        Args:
            md5: The MD5 hash of the file analyzed by Sandbox.
            report_type: Type of report to retrieve, either "full" or "summary".
                Defaults to "summary".

        Returns:
            A dict containing the sandbox report data.
        """
        details = "full" if report_type.lower() == "full" else "summary"
        return self.api_request("GET", f"/sandbox/report/{md5}?details={details}")

    # ---- URL Lookup ----

    def url_lookup(self, ioc_list: list[str]) -> list:
        """Looks up the classification for a list of URLs, IPs, or domains.

        Strips http:// and https:// prefixes before sending to the ZIA API,
        as Zscaler expects bare hostnames/URLs without protocol schemes.

        Args:
            ioc_list: A list of URL, IP, or domain strings to classify.
                Maximum 100 items per request.

        Returns:
            A list of classification result dicts, each containing 'url',
            'urlClassifications', and 'urlClassificationsWithSecurityAlert'.
        """
        # Strip protocol prefixes as Zscaler expects bare URLs
        cleaned = [u.replace("https://", "").replace("http://", "") for u in ioc_list]
        return self.api_request("POST", "/urlLookup", data=cleaned)


""" HELPER FUNCTIONS """


def _filter_and_limit(items: list, filter_: str, query: str, limit: int, all_results: bool) -> list:
    """Applies filter, query, and limit to a list of URL/IP strings.

    Filters items by type (url or ip) and/or by a regex query pattern,
    then applies a count limit unless all_results is True.

    Args:
        items: The list of URL or IP strings to filter.
        filter_: Type filter string, either "url" or "ip". Empty string means no filter.
        query: Python regex pattern to match against each item. Empty string means no filter.
        limit: Maximum number of items to return when all_results is False.
        all_results: If True, returns all matching items ignoring limit.

    Returns:
        A filtered and optionally limited list of strings.
    """
    if filter_ or query:
        filtered = []
        for entity in items:
            is_filter_match = not filter_
            is_query_match = not query
            if filter_:
                if re.match(ipv4Regex, entity):
                    is_filter_match = filter_ == "ip"
                else:
                    is_filter_match = filter_ == "url"
            if query:
                is_query_match = bool(re.search(query, entity))
            if is_filter_match and is_query_match:
                filtered.append(entity)
        items = filtered
    return items if all_results else items[:limit]


def _dbot_score_for_url(
    url_classifications: str, url_classifications_with_security_alert: str, suspicious_list: list[str]
) -> int:
    """Calculates the DBotScore for a URL, IP, or domain based on Zscaler classifications.

    Scoring logic:
        - MISCELLANEOUS_OR_UNKNOWN classification → DBotScore.NONE
        - Security alert category in suspicious_list → DBotScore.SUSPICIOUS
        - Any other security alert category → DBotScore.BAD
        - No security alert → DBotScore.GOOD

    Args:
        url_classifications: The primary URL classification string from Zscaler.
        url_classifications_with_security_alert: The security alert classification
            string from Zscaler (empty string if none).
        suspicious_list: List of category strings considered suspicious
            (e.g. ["SUSPICIOUS_DESTINATION", "SPYWARE_OR_ADWARE"]).

    Returns:
        An integer DBotScore value (Common.DBotScore.NONE/GOOD/SUSPICIOUS/BAD).
    """
    if url_classifications == "MISCELLANEOUS_OR_UNKNOWN":
        return Common.DBotScore.NONE
    if url_classifications_with_security_alert:
        if url_classifications_with_security_alert in suspicious_list:
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.BAD
    return Common.DBotScore.GOOD


""" COMMAND FUNCTIONS """


def test_module_command(client: Client) -> str:
    """Tests connectivity to the ZIA API by fetching the status endpoint.

    Args:
        client: The authenticated ZIA Client instance.

    Returns:
        The string "ok" if the connection is successful.

    Raises:
        DemistoException: If the API request fails.
    """
    client.api_request("GET", "/status")
    return "ok"


def zia_denylist_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves the ZIA denylist with optional filtering and limiting.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - filter: "url" or "ip" to filter by type.
            - query: Python regex to match against entries.
            - limit: Maximum number of results (default 50).
            - all_results: If "True", returns all results ignoring limit.

    Returns:
        A CommandResults object with the denylist entries.
    """
    filter_ = args.get("filter", "")
    query = args.get("query", "")
    limit = arg_to_number(args.get("limit", 50)) or 50
    all_results = argToBoolean(args.get("all_results", False))

    response = client.get_denylist()
    denylist = response.get("blacklistUrls", [])
    denylist = _filter_and_limit(denylist, filter_, query, limit, all_results)

    hr_lines = "\n".join(f"- {item}" for item in denylist) if denylist else "No items found."
    readable_output = f"### ZIA Denylist\n{hr_lines}"

    return CommandResults(
        outputs_prefix="ZIA.DenyList",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_denylist_update_command(client: Client, args: dict) -> CommandResults:
    """Updates the ZIA denylist by adding, removing, or overwriting entries.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - url: Comma-separated list of URLs to update.
            - ip: Comma-separated list of IPs to update.
            - action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", "OVERWRITE" (required).

    Returns:
        A CommandResults object with a success message.

    Raises:
        DemistoException: If neither url nor ip is provided, or action is missing.
    """
    urls = argToList(args.get("url", ""))
    ips = argToList(args.get("ip", ""))
    action = args.get("action", "")

    if not urls and not ips:
        raise DemistoException("At least one of 'url' or 'ip' arguments must be provided.")
    if not action:
        raise DemistoException("The 'action' argument is required.")

    client.update_denylist(urls, ips, action)
    return CommandResults(readable_output="The deny list has been successfully updated.")


def zia_allowlist_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves the ZIA allowlist with optional filtering and limiting.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - filter: "url" or "ip" to filter by type.
            - query: Python regex to match against entries.
            - limit: Maximum number of results (default 50).
            - all_results: If "True", returns all results ignoring limit.

    Returns:
        A CommandResults object with the allowlist entries.
    """
    filter_ = args.get("filter", "")
    query = args.get("query", "")
    limit = arg_to_number(args.get("limit", 50)) or 50
    all_results = argToBoolean(args.get("all_results", False))

    response = client.get_allowlist()
    allowlist = response.get("whitelistUrls", [])
    allowlist = _filter_and_limit(allowlist, filter_, query, limit, all_results)

    hr_lines = "\n".join(f"- {item}" for item in allowlist) if allowlist else "No items found."
    readable_output = f"### ZIA Allowlist\n{hr_lines}"

    return CommandResults(
        outputs_prefix="ZIA.AllowList",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_allowlist_update_command(client: Client, args: dict) -> CommandResults:
    """Updates the ZIA allowlist by adding, removing, or overwriting entries.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - url: Comma-separated list of URLs to update.
            - ip: Comma-separated list of IPs to update.
            - action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", "OVERWRITE" (required).

    Returns:
        A CommandResults object with a success message.

    Raises:
        DemistoException: If neither url nor ip is provided, or action is missing.
    """
    urls = argToList(args.get("url", ""))
    ips = argToList(args.get("ip", ""))
    action = args.get("action", "")

    if not urls and not ips:
        raise DemistoException("At least one of 'url' or 'ip' arguments must be provided.")
    if not action:
        raise DemistoException("The 'action' argument is required.")

    client.update_allowlist(urls + ips, action)
    return CommandResults(readable_output="The allowlist has been successfully updated.")


def zia_category_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves ZIA URL categories with optional filtering and display options.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - category_id: Fetch a specific category by ID.
            - custom_only: If "true", returns only custom categories.
            - include_only_url_keyword_counts: If "true", returns counts only.
            - lite: If "true", returns lightweight name/ID list only.
                Cannot be combined with other parameters.
            - limit: Maximum number of results (default 50).
            - all_results: If "True", returns all results ignoring limit.
            - display_url: If "true", includes URLs in the human-readable output.

    Returns:
        A CommandResults object with the URL category data.

    Raises:
        DemistoException: If lite is combined with incompatible parameters.
    """
    category_id = args.get("category_id")
    custom_only = argToBoolean(args.get("custom_only", False))
    include_only_url_keyword_counts = argToBoolean(args.get("include_only_url_keyword_counts", False))
    lite = argToBoolean(args.get("lite", False))
    limit = arg_to_number(args.get("limit", 50)) or 50
    all_results = argToBoolean(args.get("all_results", False))
    display_url = argToBoolean(args.get("display_url", False))

    if lite and (category_id or custom_only or include_only_url_keyword_counts):
        raise DemistoException("The 'lite' option cannot be used in combination with other parameters.")

    response = client.get_url_categories(
        category_id=category_id,
        custom_only=custom_only,
        include_only_url_keyword_counts=include_only_url_keyword_counts,
        lite=lite,
    )

    if isinstance(response, dict):
        categories = [response]
    else:
        categories = response if all_results else response[:limit]

    hr_rows = []
    for cat in categories:
        row: dict = {
            "Category ID": cat.get("id"),
            "Configured Name": cat.get("configuredName"),
            "Super Category": cat.get("superCategory"),
            "Keywords": cat.get("keywords"),
        }
        if display_url:
            row["Urls"] = cat.get("urls")
        hr_rows.append(row)

    readable_output = tableToMarkdown("ZIA URL Categories", hr_rows, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.Category",
        outputs_key_field="id",
        outputs=categories,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_category_update_command(client: Client, args: dict) -> CommandResults:
    """Updates a ZIA URL category with new URLs, IPs, keywords, or description.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - category_id: The category ID to update (required).
            - url: Comma-separated list of URLs to update.
            - ip: Comma-separated list of IP ranges to update.
            - action: One of "ADD_TO_LIST", "REMOVE_FROM_LIST", "OVERWRITE" (required).
            - keywords: Comma-separated custom keywords.
            - description: Category description string.
            - db_categorized_urls: URLs to retain under the parent category.
            - keywords_retaining_parent_category: Keywords retained from parent.
            - ip_ranges_retaining_parent_category: IP ranges retained from parent.

    Returns:
        A CommandResults object with a success message.

    Raises:
        DemistoException: If category_id is missing, neither url nor ip is provided,
            or action is missing.
    """
    category_id = args.get("category_id", "")
    if not category_id:
        raise DemistoException("The 'category_id' argument is required.")

    urls = argToList(args.get("url", ""))
    ips = argToList(args.get("ip", ""))
    action = args.get("action", "")

    if not urls and not ips:
        raise DemistoException("At least one of 'url' or 'ip' arguments must be provided.")
    if not action:
        raise DemistoException("The 'action' argument is required.")

    keywords = argToList(args.get("keywords")) if args.get("keywords") else None
    description = args.get("description")
    db_categorized_urls = argToList(args.get("db_categorized_urls")) if args.get("db_categorized_urls") else None
    keywords_retaining = (
        argToList(args.get("keywords_retaining_parent_category")) if args.get("keywords_retaining_parent_category") else None
    )
    ip_ranges_retaining = (
        argToList(args.get("ip_ranges_retaining_parent_category")) if args.get("ip_ranges_retaining_parent_category") else None
    )

    client.update_url_category(
        category_id=category_id,
        urls=urls,
        ips=ips,
        action=action,
        keywords=keywords,
        description=description,
        db_categorized_urls=db_categorized_urls,
        keywords_retaining_parent_category=keywords_retaining,
        ip_ranges_retaining_parent_category=ip_ranges_retaining,
    )
    return CommandResults(readable_output="The category has been successfully updated.")


def zia_url_quota_get_command(client: Client, args: dict) -> CommandResults:
    """Retrieves the URL quota information for the organization.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict (no arguments required for this command).

    Returns:
        A CommandResults object with quota information including
        uniqueUrlsProvisioned and remainingUrlsQuota.
    """
    response = client.get_url_quota()
    hr = tableToMarkdown(
        "ZIA URL Quota",
        {
            "Unique Urls Provisioned": response.get("uniqueUrlsProvisioned"),
            "Remaining Urls Quota": response.get("remainingUrlsQuota"),
        },
    )
    return CommandResults(
        outputs_prefix="ZIA.UrlQuota",
        outputs=response,
        readable_output=hr,
        raw_response=response,
    )


def zia_ip_destination_group_list_command(client: Client, args: dict) -> CommandResults:
    """Lists ZIA IP destination groups with optional filtering and limiting.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - group_id: Fetch a specific group by ID.
            - include_ipv6: If "True", also fetches IPv6 destination groups.
            - exclude_type: Exclude groups of this type from results.
            - category_type: Filter by group type (only valid with lite=True).
            - lite: If "True", returns lightweight name/ID results only.
            - limit: Maximum number of results (default 50).
            - all_results: If "True", returns all results ignoring limit.

    Returns:
        A CommandResults object with the IP destination group data.

    Raises:
        DemistoException: If category_type is used without lite=True.
    """
    group_id = arg_to_number(args.get("group_id"))
    include_ipv6 = argToBoolean(args.get("include_ipv6", False))
    exclude_type = args.get("exclude_type")
    category_type = argToList(args.get("category_type", "")) or None
    lite = argToBoolean(args.get("lite", False))
    limit = arg_to_number(args.get("limit", 50)) or 50
    all_results = argToBoolean(args.get("all_results", False))

    if category_type and not lite:
        raise DemistoException("The 'category_type' argument only works with the 'lite' argument set to True.")

    response = client.list_ip_destination_groups(
        group_id=group_id,
        include_ipv6=include_ipv6,
        exclude_type=exclude_type,
        category_type=category_type,
        lite=lite,
    )

    if isinstance(response, dict):
        groups = [response]
    else:
        groups = response if all_results else response[:limit]

    hr_rows = [
        {
            "IP Destination Group ID": g.get("id"),
            "Name": g.get("name"),
            "Type": g.get("type"),
            "Addresses": g.get("addresses"),
            "Description": g.get("description"),
            "Countries": g.get("countries"),
            "Ip Categories": g.get("ipCategories"),
        }
        for g in groups
    ]
    readable_output = tableToMarkdown("ZIA IP Destination Groups", hr_rows, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.IPDestinationGroup",
        outputs_key_field="id",
        outputs=groups,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_ip_destination_group_update_command(client: Client, args: dict) -> CommandResults:
    """Updates an existing ZIA IP destination group.

    Fetches the current group state and merges provided arguments on top,
    so only specified fields are changed. The 'action' argument controls how
    the 'address' list is applied: ADD_TO_LIST adds new addresses, REMOVE_FROM_LIST
    removes specified addresses, and OVERWRITE replaces the entire list.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - group_id: The unique identifier of the group to update (required).
            - group_name: New name for the group.
            - group_type: New type (DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER).
            - address: Comma-separated list of addresses.
            - action: How to apply the address list: ADD_TO_LIST, REMOVE_FROM_LIST,
                or OVERWRITE (required).
            - description: Group description.
            - ip_category: Comma-separated list of IP categories.
            - country: Comma-separated list of country codes.

    Returns:
        A CommandResults object with the updated group data.

    Raises:
        DemistoException: If group_id is not provided.
    """
    group_id = arg_to_number(args.get("group_id"))
    if group_id is None:
        raise DemistoException("The 'group_id' argument is required.")

    action = args.get("action", "OVERWRITE")
    new_addresses = argToList(args.get("address", []))

    # Fetch existing group to merge
    existing = client.list_ip_destination_groups(group_id=group_id)
    if isinstance(existing, list):
        existing = existing[0] if existing else {}

    existing_addresses: list[str] = existing.get("addresses", [])
    if action == "ADD_TO_LIST":
        merged_addresses = existing_addresses + [a for a in new_addresses if a not in existing_addresses]
    elif action == "REMOVE_FROM_LIST":
        merged_addresses = [a for a in existing_addresses if a not in new_addresses]
    else:  # OVERWRITE
        merged_addresses = new_addresses if new_addresses else existing_addresses

    payload: dict = {
        "id": group_id,
        "name": args.get("group_name", existing.get("name", "")),
        "type": args.get("group_type", existing.get("type", "")),
        "addresses": merged_addresses,
        "description": args.get("description", existing.get("description", "")),
        "ipCategories": argToList(args.get("ip_category", existing.get("ipCategories", []))),
        "countries": argToList(args.get("country", existing.get("countries", []))),
    }

    response = client.update_ip_destination_group(group_id, payload)
    hr_row = {
        "IP Destination Group ID": response.get("id"),
        "Name": response.get("name"),
        "Type": response.get("type"),
        "Addresses": response.get("addresses"),
        "Description": response.get("description"),
        "Countries": response.get("countries"),
        "Ip Categories": response.get("ipCategories"),
    }
    readable_output = tableToMarkdown("The Ip Destination Group Resource has been successfully edited", hr_row, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.IPDestinationGroup",
        outputs_key_field="id",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_ip_destination_group_add_command(client: Client, args: dict) -> CommandResults:
    """Creates a new ZIA IP destination group.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - group_name: Name for the new group.
            - group_type: Type (DSTN_IP, DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER).
            - address: Comma-separated list of addresses.
            - description: Group description.
            - ip_category: Comma-separated list of IP categories.
            - country: Comma-separated list of country codes.
            - is_non_editable: If "true", marks the group as non-editable.

    Returns:
        A CommandResults object with the newly created group data.
    """
    payload: dict = {
        "name": args.get("group_name", ""),
        "type": args.get("group_type", ""),
        "addresses": argToList(args.get("address", [])),
        "description": args.get("description", ""),
        "ipCategories": argToList(args.get("ip_category", [])),
        "countries": argToList(args.get("country", [])),
        "isNonEditable": argToBoolean(args.get("is_non_editable", False)),
    }

    response = client.add_ip_destination_group(payload)
    hr_row = {
        "IP Destination Group ID": response.get("id"),
        "Name": response.get("name"),
        "Type": response.get("type"),
        "Addresses": response.get("addresses"),
        "Description": response.get("description"),
        "Countries": response.get("countries"),
        "Ip Categories": response.get("ipCategories"),
    }
    readable_output = tableToMarkdown("The Ip Destination Group Resource has been successfully added", hr_row, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.IPDestinationGroup",
        outputs_key_field="id",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_ip_destination_group_delete_command(client: Client, args: dict) -> CommandResults:
    """Deletes a ZIA IP destination group by ID.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - group_id: The unique identifier of the group to delete (required).

    Returns:
        A CommandResults object with a success message.

    Raises:
        DemistoException: If group_id is not provided.
    """
    group_id = arg_to_number(args.get("group_id"))
    if group_id is None:
        raise DemistoException("The 'group_id' argument is required.")

    client.delete_ip_destination_group(group_id)
    return CommandResults(readable_output="The Ip Destination Group Resource has been successfully deleted.")


def zia_user_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves ZIA users with optional filtering by department or group.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - user_id: Fetch a specific user by ID.
            - dept: Filter by department name.
            - group: Filter by group name.
            - page: Page offset for pagination (default 1).
            - page_size: Number of results per page (default 100, max 10,000).

    Returns:
        A CommandResults object with the user data.
    """
    user_id = args.get("user_id")
    dept = args.get("dept")
    group = args.get("group")
    page = arg_to_number(args.get("page", 1)) or 1
    page_size = arg_to_number(args.get("page_size", 100)) or 100

    response = client.get_users(user_id=user_id, dept=dept, group=group, page=page, page_size=page_size)

    if isinstance(response, dict):
        users = [response]
    else:
        users = response

    hr_rows = [
        {
            "User ID": u.get("id"),
            "Name": u.get("name"),
            "Email": u.get("email"),
            "Comment": u.get("comments"),
        }
        for u in users
    ]
    readable_output = tableToMarkdown(f"ZIA Users ({len(users)})", hr_rows, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.User",
        outputs_key_field="id",
        outputs=users,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_user_update_command(client: Client, args: dict) -> CommandResults:
    """Updates a ZIA user's information.

    Fetches the current user state and merges provided arguments on top.
    If a full JSON user object is provided via the 'user' argument, it is used
    as the base payload, with individual field arguments applied on top.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - user_id: The unique identifier of the user to update (required).
            - user: Full user object as a JSON string (optional base payload).
            - user_name: New display name for the user.
            - email: New email address.
            - comments: Additional information about the user.
            - temp_auth_email: Temporary authentication email.
            - password: New password (Hosted DB auth only).

    Returns:
        A CommandResults object with the updated user data.

    Raises:
        DemistoException: If user_id is missing or the 'user' JSON is invalid.
    """
    user_id = args.get("user_id", "")
    if not user_id:
        raise DemistoException("The 'user_id' argument is required.")

    # Fetch existing user to merge
    existing = client.get_users(user_id=user_id)
    if isinstance(existing, list):
        existing = existing[0] if existing else {}

    # If a full JSON user object is provided, use it as base
    user_json = args.get("user")
    if user_json:
        try:
            payload = json.loads(user_json)
        except json.JSONDecodeError as e:
            raise DemistoException(f"Invalid JSON in 'user' argument: {e}")
    else:
        payload = dict(existing)

    # Override individual fields if provided
    if args.get("user_name"):
        payload["name"] = args["user_name"]
    if args.get("email"):
        payload["email"] = args["email"]
    if args.get("comments"):
        payload["comments"] = args["comments"]
    if args.get("temp_auth_email"):
        payload["tempAuthEmail"] = args["temp_auth_email"]
    if args.get("password"):
        payload["password"] = args["password"]

    response = client.update_user(user_id, payload)
    hr_row = {
        "User ID": response.get("id"),
        "Name": response.get("name"),
        "Email": response.get("email"),
        "Comment": response.get("comments"),
    }
    readable_output = tableToMarkdown("ZIA User Updated", hr_row, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.User",
        outputs_key_field="id",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_groups_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves a paginated list of ZIA user groups.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - search: Search string matched against group name or comments.
            - defined_by: Filter by the attribute that defines the group.
            - sort_by: Field to sort by (default "id").
            - sort_order: Sort direction "asc", "desc", or "ruleExecution" (default "asc").
            - page: Page offset for pagination (default 1).
            - page_size: Number of results per page (default 100, max 10,000).
            - all_results: Accepted but not used; pagination is server-side.

    Returns:
        A CommandResults object with the group data.
    """
    search = args.get("search")
    defined_by = args.get("defined_by")
    sort_by = args.get("sort_by", "id")
    sort_order = args.get("sort_order", "asc")
    page = arg_to_number(args.get("page", 1)) or 1
    page_size = arg_to_number(args.get("page_size", 100)) or 100

    response = client.get_groups(
        search=search,
        defined_by=defined_by,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )

    hr_rows = [
        {
            "Group ID": g.get("id"),
            "Name": g.get("name"),
            "IdpId": g.get("idpId"),
            "Comment": g.get("comments"),
            "Is System Defined": g.get("isSystemDefined"),
        }
        for g in response
    ]
    readable_output = tableToMarkdown(f"ZIA Groups ({len(response)})", hr_rows, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.Groups",
        outputs_key_field="id",
        outputs=response,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_departments_list_command(client: Client, args: dict) -> CommandResults:
    """Retrieves ZIA departments with optional filtering.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with optional keys:
            - department_id: Fetch a specific department by ID.
            - search: Search string matched against department name or comments.
            - limit_search: If "true", restricts search to department name only.
            - sort_by: Field to sort by (default "id").
            - sort_order: Sort direction "asc", "desc", or "ruleExecution" (default "asc").
            - page: Page offset for pagination (default 1).
            - page_size: Number of results per page (default 100, max 10,000).
            - all_results: Accepted but not used; pagination is server-side.

    Returns:
        A CommandResults object with the department data.
    """
    department_id = args.get("department_id")
    search = args.get("search")
    limit_search = argToBoolean(args.get("limit_search", False))
    sort_by = args.get("sort_by", "id")
    sort_order = args.get("sort_order", "asc")
    page = arg_to_number(args.get("page", 1)) or 1
    page_size = arg_to_number(args.get("page_size", 100)) or 100

    response = client.get_departments(
        department_id=department_id,
        search=search,
        limit_search=limit_search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )

    if isinstance(response, dict):
        departments = [response]
    else:
        departments = response

    hr_rows = [
        {
            "Department ID": d.get("id"),
            "Name": d.get("name"),
            "IdpId": d.get("idpId"),
            "Comment": d.get("comments"),
            "Deleted": d.get("deleted"),
        }
        for d in departments
    ]
    readable_output = tableToMarkdown(f"ZIA Departments ({len(departments)})", hr_rows, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.Department",
        outputs_key_field="id",
        outputs=departments,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_sandbox_report_get_command(client: Client, args: dict) -> CommandResults:
    """Retrieves a Sandbox analysis report for a file identified by MD5 hash.

    Calculates a DBotScore based on the classification type:
        - MALICIOUS → BAD
        - SUSPICIOUS → SUSPICIOUS
        - BENIGN → GOOD
        - Other/unknown → NONE

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - md5: The MD5 hash of the file analyzed by Sandbox (required).
            - report_type: "full" or "summary" (default "summary").

    Returns:
        A CommandResults object with the sandbox report, a File indicator,
        and a DBotScore.

    Raises:
        DemistoException: If md5 is not provided.
    """
    md5 = args.get("md5", "")
    if not md5:
        raise DemistoException("The 'md5' argument is required.")
    report_type = args.get("report_type", "summary")

    response = client.get_sandbox_report(md5, report_type)

    report_key = "Full Details" if report_type.lower() == "full" else "Summary"
    classification_type = demisto.get(response, f"{report_key}.Classification.Type")
    if classification_type == "MALICIOUS":
        dbot_score = Common.DBotScore.BAD
    elif classification_type == "SUSPICIOUS":
        dbot_score = Common.DBotScore.SUSPICIOUS
    elif classification_type == "BENIGN":
        dbot_score = Common.DBotScore.GOOD
    else:
        dbot_score = Common.DBotScore.NONE

    file_type = demisto.get(response, f"{report_key}.File Properties.File Type")
    detected_malware = demisto.get(response, f"{report_key}.Classification.DetectedMalware")
    zscaler_score = demisto.get(response, f"{report_key}.Classification.Score")
    category = demisto.get(response, f"{report_key}.Classification.Category")

    malicious_description = None
    if dbot_score == Common.DBotScore.BAD:
        malicious_description = f"Classified as Malicious, with threat score: {zscaler_score} Zscaler ZIA Score"

    dbot = Common.DBotScore(
        indicator=md5,
        indicator_type=DBotScoreType.FILE,
        integration_name=INTEGRATION_NAME,
        score=dbot_score,
        malicious_description=malicious_description,
        reliability=demisto.params().get("reliability"),
    )

    file_indicator = Common.File(
        md5=md5,
        file_type=file_type,
        dbot_score=dbot,
    )

    hr_data = {
        "DBotScore": dbot_score,
        "Detected Malware": detected_malware,
        "Zscaler ZIA Score": zscaler_score,
        "Category": category,
    }
    readable_output = tableToMarkdown("ZIA Sandbox Report", hr_data, removeNull=True)

    return CommandResults(
        outputs_prefix="ZIA.SandboxReport",
        outputs_key_field="md5",
        outputs=response,
        indicator=file_indicator,
        readable_output=readable_output,
        raw_response=response,
    )


def zia_activate_changes_command(client: Client, args: dict) -> CommandResults:
    """Activates saved ZIA configuration changes.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict (no arguments required for this command).

    Returns:
        A CommandResults object with the activation status.
    """
    response = client.activate_changes()
    hr = tableToMarkdown("ZIA Activation Status", {"Status": response.get("status")}, removeNull=True)
    return CommandResults(
        outputs_prefix="ZIA.ActivationStatus",
        outputs=response,
        readable_output=hr,
        raw_response=response,
    )


def url_command(client: Client, args: dict) -> list[CommandResults]:
    """Looks up the classification for a list of URLs and creates URL indicators.

    Restores the original URL with protocol prefix in the output if the protocol
    was stripped before sending to the ZIA API.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - url: Comma-separated list of URLs to classify (required).
                Maximum 100 URLs per request.

    Returns:
        A list of CommandResults objects, one per URL, each containing a URL
        indicator with DBotScore. Returns a single "No results found" result
        if the API returns an empty response.
    """
    url_arg = args.get("url", "")
    urls = argToList(url_arg)
    response = client.url_lookup(urls)
    results: list[CommandResults] = []

    for data in response:
        res_url = data.get("url", "")
        # Restore original URL with protocol if it was stripped
        for original_url in urls:
            if "http://" + res_url in original_url or "https://" + res_url in original_url:
                data["url"] = original_url
                res_url = original_url
                break

        url_classifications = "".join(data.get("urlClassifications", []))
        url_classifications_with_security_alert = "".join(data.get("urlClassificationsWithSecurityAlert", []))

        score = _dbot_score_for_url(url_classifications, url_classifications_with_security_alert, client.suspicious_categories)

        url_indicator = Common.URL(
            url=res_url,
            dbot_score=Common.DBotScore(
                indicator=res_url,
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=url_classifications_with_security_alert or None,
                reliability=client.reliability,
            ),
        )

        context_data = {
            "Address": res_url,
            "Data": res_url,
            "urlClassifications": url_classifications,
            "urlClassificationsWithSecurityAlert": url_classifications_with_security_alert,
        }

        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.URL",
                outputs_key_field="Data",
                indicator=url_indicator,
                readable_output=tableToMarkdown(f"Zscaler URL Lookup for {res_url}", data, removeNull=True),
                outputs=createContext(data=context_data, removeNull=True),
                raw_response=data,
            )
        )

    return results or [CommandResults(readable_output="No results found.")]


def ip_command(client: Client, args: dict) -> list[CommandResults]:
    """Looks up the classification for a list of IP addresses and creates IP indicators.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - ip: Comma-separated list of IP addresses to classify (required).
                Maximum 100 IPs per request.

    Returns:
        A list of CommandResults objects, one per IP address, each containing
        an IP indicator with DBotScore. Returns a single "No results found"
        result if the API returns an empty response.
    """
    ip_arg = args.get("ip", "")
    ips = argToList(ip_arg)
    response = client.url_lookup(ips)
    results: list[CommandResults] = []

    for data in response:
        ip_addr = data.get("url", "")
        ip_classifications = "".join(data.get("urlClassifications", []))
        ip_classifications_with_security_alert = "".join(data.get("urlClassificationsWithSecurityAlert", []))

        score = _dbot_score_for_url(ip_classifications, ip_classifications_with_security_alert, client.suspicious_categories)

        ip_indicator = Common.IP(
            ip=ip_addr,
            dbot_score=Common.DBotScore(
                indicator=ip_addr,
                indicator_type=DBotScoreType.IP,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=ip_classifications_with_security_alert or None,
                reliability=client.reliability,
            ),
        )

        context_data = {
            "Address": ip_addr,
            "Classifications": ip_classifications,
            "ClassificationsWithSecurityAlert": ip_classifications_with_security_alert,
        }

        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.IP",
                outputs_key_field="Address",
                indicator=ip_indicator,
                readable_output=tableToMarkdown(f"Zscaler IP Lookup for {ip_addr}", data, removeNull=True),
                outputs=createContext(data=context_data, removeNull=True),
                raw_response=data,
            )
        )

    return results or [CommandResults(readable_output="No results found.")]


def domain_command(client: Client, args: dict) -> list[CommandResults]:
    """Looks up the classification for a list of domains and creates Domain indicators.

    Args:
        client: The authenticated ZIA Client instance.
        args: Command arguments dict with keys:
            - domain: Comma-separated list of domains to classify (required).
                Maximum 100 domains per request.

    Returns:
        A list of CommandResults objects, one per domain, each containing a
        Domain indicator with DBotScore. Returns a single "No results found"
        result if the API returns an empty response.
    """
    domain_arg = args.get("domain", "")
    domains = argToList(domain_arg)
    response = client.url_lookup(domains)
    results: list[CommandResults] = []

    for data in response:
        domain_val = data.get("url", "")
        domain_classifications = "".join(data.get("urlClassifications", []))
        domain_classifications_with_security_alert = "".join(data.get("urlClassificationsWithSecurityAlert", []))

        score = _dbot_score_for_url(
            domain_classifications, domain_classifications_with_security_alert, client.suspicious_categories
        )

        domain_indicator = Common.Domain(
            domain=domain_val,
            dbot_score=Common.DBotScore(
                indicator=domain_val,
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=domain_classifications_with_security_alert or None,
                reliability=client.reliability,
            ),
        )

        context_data = {
            "Data": domain_val,
            "Address": domain_val,
            "Classifications": domain_classifications,
            "ClassificationsWithSecurityAlert": domain_classifications_with_security_alert,
        }

        results.append(
            CommandResults(
                outputs_prefix=f"{INTEGRATION_NAME}.Domain",
                outputs_key_field="Data",
                indicator=domain_indicator,
                readable_output=tableToMarkdown(f"Zscaler Domain Lookup for {domain_val}", data, removeNull=True),
                outputs=createContext(data=context_data, removeNull=True),
                raw_response=data,
            )
        )

    return results or [CommandResults(readable_output="No results found.")]


""" MAIN """


def main() -> None:  # pragma: no cover
    """Entry point for the integration.

    Reads instance parameters, constructs the Client, dispatches the command,
    and handles auto-activation of ZIA changes after write commands.
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    server_url = params.get("server_url", "")
    client_id = params.get("credentials", {}).get("identifier", "")
    client_secret = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("reliability", "C - Fairly reliable")
    auto_activate = argToBoolean(params.get("auto_activate", True))

    suspicious_categories_param = params.get("suspicious_categories", "")
    if suspicious_categories_param:
        suspicious_categories = argToList(suspicious_categories_param)
    else:
        suspicious_categories = SUSPICIOUS_CATEGORIES

    add_sensitive_log_strs(client_secret)

    client = Client(
        server_url=server_url,
        client_id=client_id,
        client_secret=client_secret,
        verify=verify,
        proxy=proxy,
        reliability=reliability,
        auto_activate=auto_activate,
        suspicious_categories=suspicious_categories,
    )

    demisto.debug(f"Command is: {command}")

    try:
        if command == "test-module":
            return_results(test_module_command(client))
        elif command == "zia-denylist-list":
            return_results(zia_denylist_list_command(client, args))
        elif command == "zia-denylist-update":
            return_results(zia_denylist_update_command(client, args))
        elif command == "zia-allowlist-list":
            return_results(zia_allowlist_list_command(client, args))
        elif command == "zia-allowlist-update":
            return_results(zia_allowlist_update_command(client, args))
        elif command == "zia-category-list":
            return_results(zia_category_list_command(client, args))
        elif command == "zia-category-update":
            return_results(zia_category_update_command(client, args))
        elif command == "zia-url-quota-get":
            return_results(zia_url_quota_get_command(client, args))
        elif command == "zia-ip-destination-group-list":
            return_results(zia_ip_destination_group_list_command(client, args))
        elif command == "zia-ip-destination-group-update":
            return_results(zia_ip_destination_group_update_command(client, args))
        elif command == "zia-ip-destination-group-add":
            return_results(zia_ip_destination_group_add_command(client, args))
        elif command == "zia-ip-destination-group-delete":
            return_results(zia_ip_destination_group_delete_command(client, args))
        elif command == "zia-user-list":
            return_results(zia_user_list_command(client, args))
        elif command == "zia-user-update":
            return_results(zia_user_update_command(client, args))
        elif command == "zia-groups-list":
            return_results(zia_groups_list_command(client, args))
        elif command == "zia-departments-list":
            return_results(zia_departments_list_command(client, args))
        elif command == "zia-sandbox-report-get":
            return_results(zia_sandbox_report_get_command(client, args))
        elif command == "zia-activate-changes":
            return_results(zia_activate_changes_command(client, args))
        elif command == "url":
            return_results(url_command(client, args))
        elif command == "ip":
            return_results(ip_command(client, args))
        elif command == "domain":
            return_results(domain_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute '{command}' command.\nError: {e}")
    finally:
        if auto_activate and command in AUTO_ACTIVATE_CHANGES_COMMANDS:
            try:
                demisto.debug(f"Auto-activating changes after command: {command}")
                client.activate_changes()
            except Exception as err:
                demisto.error(f"Failed to auto-activate changes: {err}")
                return_warning(
                    f"Auto-activation of changes failed: {err}\n"
                    "Your changes were saved but are not yet active. "
                    "Run the 'zia-activate-changes' command to apply them manually."
                )


if __name__ in ("__builtin__", "builtins", "__main__"):  # pragma: no cover
    main()
