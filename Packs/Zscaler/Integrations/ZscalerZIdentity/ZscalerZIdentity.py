import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import re

""" CONSTANTS """

INTEGRATION_NAME = "ZscalerZIA"
BASE_API_URL = "https://api.zsapi.net/zia/api/v1"
TOKEN_URL_TEMPLATE = "https://{domain}.zslogin.net/oauth2/v1/token"
AUDIENCE = "https://api.zscaler.com"
SUSPICIOUS_CATEGORIES = ["SUSPICIOUS_DESTINATION", "SPYWARE_OR_ADWARE"]

ERROR_CODES_DICT = {
    400: "Invalid or bad request",
    401: "Session is not authenticated or timed out",
    403: (
        "One of the following permission errors occurred:\n"
        "-The API key was disabled by your service provider\n"
        "-User role has no access permissions or functional scope\n"
        "-A required SKU subscription is missing\n"
        "Contact support or your account team for assistance."
    ),
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
    """Client for Zscaler ZIA via ZIdentity OAuth 2.0."""

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
        reliability: str,
        auto_activate: bool,
        suspicious_categories: list[str],
    ):
        super().__init__(base_url=BASE_API_URL, verify=verify, proxy=proxy)
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.reliability = reliability
        self.auto_activate = auto_activate
        self.suspicious_categories = suspicious_categories
        self._access_token: str | None = None

    def _get_access_token(self) -> str:
        """Obtain an OAuth 2.0 access token from ZIdentity using client credentials flow.
        Caches the token in integration context to avoid redundant requests.
        """
        ctx = get_integration_context() or {}
        token = ctx.get("access_token")
        expires_at = ctx.get("token_expires_at", 0)

        if token and time.time() < expires_at - 30:
            demisto.debug("Using cached ZIdentity access token.")
            return token

        demisto.debug("Fetching new ZIdentity access token.")
        token_url = TOKEN_URL_TEMPLATE.format(domain=self.domain)
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
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _error_handler(self, res) -> None:
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

    def api_request(
        self,
        method: str,
        url_suffix: str,
        data: dict | list | None = None,
        params: dict | None = None,
        resp_type: str = "json",
    ):
        """Make an authenticated API request to the ZIA API."""
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

    def activate_changes(self) -> dict:
        return self.api_request("POST", "/status/activate")

    # ---- Denylist ----

    def get_denylist(self) -> dict:
        return self.api_request("GET", "/security/advanced")

    def update_denylist(self, urls: list[str], ips: list[str], action: str) -> None:
        """Update the denylist. action: ADD_TO_LIST | REMOVE_FROM_LIST | OVERWRITE"""
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
        return self.api_request("GET", "/security")

    def update_allowlist(self, urls: list[str], action: str) -> None:
        """Update the allowlist. action: ADD_TO_LIST | REMOVE_FROM_LIST | OVERWRITE"""
        current = self.get_allowlist()
        existing = current.get("whitelistUrls", [])
        if action == "ADD_TO_LIST":
            # Only add URLs not already present
            new_urls = [u for u in urls if u not in existing]
            current["whitelistUrls"] = existing + new_urls
        elif action == "REMOVE_FROM_LIST":
            current["whitelistUrls"] = [u for u in existing if u not in urls]
        else:  # OVERWRITE
            current["whitelistUrls"] = urls
        self.api_request("PUT", "/security", data=current, resp_type="response")

    # ---- URL Categories ----

    def get_url_categories(
        self,
        category_id: str | None = None,
        custom_only: bool = False,
        include_only_url_keyword_counts: bool = False,
        lite: bool = False,
    ) -> list | dict:
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
        return self.api_request("PUT", f"/ipDestinationGroups/{group_id}", data=payload)

    def add_ip_destination_group(self, payload: dict) -> dict:
        return self.api_request("POST", "/ipDestinationGroups", data=payload)

    def delete_ip_destination_group(self, group_id: int) -> None:
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
        if user_id:
            return self.api_request("GET", f"/users/{user_id}")
        params: dict = {"page": page, "pageSize": page_size}
        if dept:
            params["dept"] = dept
        if group:
            params["group"] = group
        return self.api_request("GET", "/users", params=params)

    def update_user(self, user_id: str, payload: dict) -> dict:
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
        details = "full" if report_type.lower() == "full" else "summary"
        return self.api_request("GET", f"/sandbox/report/{md5}?details={details}")

    # ---- URL Lookup ----

    def url_lookup(self, ioc_list: list[str]) -> list:
        # Strip protocol prefixes as Zscaler expects bare URLs
        cleaned = [u.replace("https://", "").replace("http://", "") for u in ioc_list]
        return self.api_request("POST", "/urlLookup", data=cleaned)


""" HELPER FUNCTIONS """


def _filter_and_limit(items: list, filter_: str, query: str, limit: int, all_results: bool) -> list:
    """Apply filter/query/limit to a list of URL/IP strings."""
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
    """Calculate DBotScore for a URL/IP/Domain based on Zscaler classifications."""
    if url_classifications == "MISCELLANEOUS_OR_UNKNOWN":
        return Common.DBotScore.NONE
    if url_classifications_with_security_alert:
        if url_classifications_with_security_alert in suspicious_list:
            return Common.DBotScore.SUSPICIOUS
        return Common.DBotScore.BAD
    return Common.DBotScore.GOOD


""" COMMAND FUNCTIONS """


def test_module_command(client: Client) -> str:
    """Test connectivity by fetching the ZIA status endpoint."""
    client.api_request("GET", "/status")
    return "ok"


def zia_denylist_list_command(client: Client, args: dict) -> CommandResults:
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
    urls = argToList(args.get("url", ""))
    action = args.get("action", "")

    if not urls:
        raise DemistoException("The 'url' argument is required.")
    if not action:
        raise DemistoException("The 'action' argument is required.")

    client.update_allowlist(urls, action)
    return CommandResults(readable_output="The allowlist has been successfully updated.")


def zia_category_list_command(client: Client, args: dict) -> CommandResults:
    category_id = args.get("category_id")
    custom_only = argToBoolean(args.get("custom_only", False))
    include_only_url_keyword_counts = argToBoolean(args.get("include_only_url_keyword_counts", False))
    lite = argToBoolean(args.get("lite", False))
    limit = arg_to_number(args.get("limit", 50)) or 50
    all_results = argToBoolean(args.get("all_results", False))
    display_url = argToBoolean(args.get("display_URL", False))

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
    group_id = arg_to_number(args.get("group_id"))
    if group_id is None:
        raise DemistoException("The 'group_id' argument is required.")

    # Fetch existing group to merge
    existing = client.list_ip_destination_groups(group_id=group_id)
    if isinstance(existing, list):
        existing = existing[0] if existing else {}

    payload: dict = {
        "id": group_id,
        "name": args.get("group_name", existing.get("name", "")),
        "type": args.get("group_type", existing.get("type", "")),
        "addresses": argToList(args.get("address", existing.get("addresses", []))),
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
    group_id = arg_to_number(args.get("group_id"))
    if group_id is None:
        raise DemistoException("The 'group_id' argument is required.")

    client.delete_ip_destination_group(group_id)
    return CommandResults(readable_output="The Ip Destination Group Resource has been successfully deleted.")


def zia_user_list_command(client: Client, args: dict) -> CommandResults:
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
    response = client.activate_changes()
    hr = tableToMarkdown("ZIA Activation Status", {"Status": response.get("status")}, removeNull=True)
    return CommandResults(
        outputs_prefix="ZIA.ActivationStatus",
        outputs=response,
        readable_output=hr,
        raw_response=response,
    )


def url_command(client: Client, args: dict) -> list[CommandResults]:
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
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    domain = params.get("domain", "")
    client_id = params.get("credentials", {}).get("identifier", "")
    client_secret = params.get("credentials", {}).get("password", "")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    reliability = params.get("reliability", "C - Fairly reliable")
    auto_activate = argToBoolean(params.get("auto_activate", True))

    suspicious_categories_param = params.get("suspicious_categories", "")
    if suspicious_categories_param:
        suspicious_categories = [c.strip() for c in suspicious_categories_param.split(",") if c.strip()]
    else:
        suspicious_categories = SUSPICIOUS_CATEGORIES

    add_sensitive_log_strs(client_secret)

    client = Client(
        domain=domain,
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


if __name__ in ("__builtin__", "builtins", "__main__"):  # pragma: no cover
    main()
