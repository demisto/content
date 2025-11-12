from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

# from CommonServerUserPython import *  # noqa
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

REQUIRED_PERMISSIONS = (
    "offline_access",  # allows device-flow login
    "ThreatIntelligence.Read.All",  # Threat Intelligence specific permission
)

""" CLIENT CLASS """


class Client:
    def __init__(
        self,
        app_id: str,
        verify: bool,
        proxy: bool,
        azure_ad_endpoint: str = "https://login.microsoftonline.com",
        client_credentials: bool = False,
        tenant_id: str = None,
        enc_key: str = None,
        managed_identities_client_id: Optional[str] = None,
        private_key: Optional[str] = None,
        certificate_thumbprint: Optional[str] = None,
    ):
        if app_id and "@" in app_id:
            app_id, refresh_token = app_id.split("@")
            integration_context = get_integration_context()
            integration_context["current_refresh_token"] = refresh_token
            set_integration_context(integration_context)
        elif client_credentials and (not enc_key and not (certificate_thumbprint and private_key)):
            raise DemistoException(
                "Either enc_key or (Certificate Thumbprint and Private Key) must be provided. For further "
                "information see "
                "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
            )
        args = {
            "azure_ad_endpoint": azure_ad_endpoint,
            "self_deployed": True,
            "auth_id": app_id,
            "grant_type": CLIENT_CREDENTIALS if client_credentials else DEVICE_CODE,
            "base_url": "https://graph.microsoft.com",
            "verify": verify,
            "proxy": proxy,
            "tenant_id": tenant_id,
            "enc_key": enc_key,
            "managed_identities_client_id": managed_identities_client_id,
            "managed_identities_resource_uri": Resources.graph,
            "certificate_thumbprint": certificate_thumbprint,
            "private_key": private_key,
            "command_prefix": "msg-defender-threat-intel",
        }
        if not client_credentials:
            args["scope"] = " ".join(REQUIRED_PERMISSIONS)
            args["token_retrieval_url"] = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
        self.ms_client = MicrosoftClient(**args)  # type: ignore

    def article_list(self, article_id: str, odata: str, limit: int) -> list:
        """
        Retrieve threat intelligence articles from Microsoft Defender.
        Docs:
        https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-articles?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/graph/api/security-article-get?view=graph-rest-1.0&tabs=http

        Args:
            article_id (str): Specific article ID to retrieve. If empty, retrieves all articles.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of articles to return.

        Returns:
            list: List of article objects. If article_id is provided, returns a single article
                    in a list format. If article_id is empty, returns multiple articles from
                    the 'value' field of the response.
        """
        odata_query = ""

        if not article_id:
            odata_query = f"?$top={limit}&{odata}"
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/articles{odata_query}",
            )
            return response.get("value", [])

        if odata:
            odata_query += f"?{odata}"

        return [
            self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/articles/{article_id}{odata_query}",
            )
        ]

    def article_indicator_list(self, article_id: str, article_indicator_id: str, odata: str, limit: int) -> list:
        """
        Retrieve threat intelligence indicators from Microsoft Defender.
        Docs:
        https://learn.microsoft.com/en-us/graph/api/security-articleindicator-get?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/graph/api/security-article-list-indicators?view=graph-rest-1.0&tabs=http

        Args:
            article_id (str): The ID of the article to retrieve indicators from.
            article_indicator_id (str): The specific indicator ID to retrieve.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of indicators to return.

        Returns:
            list: List of article indicator objects from the 'value' field of the response.
        """

        odata_query = ""

        if not article_id:
            if odata:
                odata_query += f"?{odata}"

            return [
                self.ms_client.http_request(
                    method="GET",
                    url_suffix=f"v1.0/security/threatIntelligence/articleIndicators/{article_indicator_id}{odata_query}",
                )
            ]

        odata_query = f"?$top={limit}&{odata}"

        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/articles/{article_id}/indicators{odata_query}",
        )

        return response.get("value", [])

    def profile_list(self, intel_profile_id: str, odata: str, limit: int) -> list:
        """
        Retrieve threat intelligence profiles from Microsoft Defender.
        Docs:
        https://learn.microsoft.com/en-us/graph/api/security-threatintelligence-list-intelprofiles?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofile-get?view=graph-rest-1.0&tabs=http

        Args:
            intel_profile_id (str): The ID of the specific intelligence profile to retrieve.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of profiles to return.

        Returns:
            list: List of intelligence profile objects from the 'value' field of the response.
        """
        odata_query = ""

        if intel_profile_id:
            if odata:
                odata_query += f"?{odata}"

            return [
                self.ms_client.http_request(
                    method="GET",
                    url_suffix=f"v1.0/security/threatIntelligence/intelProfiles/{intel_profile_id}{odata_query}",
                )
            ]

        odata_query = f"?$top={limit}&{odata}"

        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/intelProfiles{odata_query}",
        )

        return response.get("value", [])

    def profile_indicators_list(self, intel_profile_id: str, intel_profile_indicator_id: str, odata: str, limit: int) -> list:
        """
        Retrieve intelligence profile indicators.
        Docs:
        https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofileindicator-get?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/graph/api/security-intelligenceprofile-list-indicators?view=graph-rest-1.0&tabs=http

        Args:
            intel_profile_id (str): The ID of the intelligence profile.
            intel_profile_indicator_id (str): The ID of a specific intelligence profile indicator.
            odata (str): OData query parameters for filtering and formatting the response.
            limit (int): Maximum number of indicators to return.

        Returns:
            list: A list of intelligence profile indicators, each containing information such as
                    ID, source, first/last seen timestamps, and associated artifacts.
        """

        odata_query = ""

        if not intel_profile_indicator_id:
            odata_query = f"?$top={limit}&{odata}"

            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/intelProfiles/{intel_profile_id}/indicators{odata_query}",
            )
            return response.get("value", [])

        if odata:
            odata_query += f"?{odata}"

        return [
            self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/intelligenceProfileIndicators/{intel_profile_indicator_id}{odata_query}",
            )
        ]

    def host(self, host_id: str, odata: str) -> dict:
        """
        Retrieve host information by host ID.
        Docs: https://learn.microsoft.com/en-us/graph/api/security-host-get?view=graph-rest-1.0&tabs=http

        Args:
            host_id (str): The ID (host name or ip address) of the host to retrieve information for.
            odata (str): OData query parameters for filtering and formatting the response.

        Returns:
            dict: A dictionary containing host information including ID, first/last seen timestamps,
                    registrar, and registrant details.
        """
        odata_query = f"?{odata}" if odata else ""

        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}{odata_query}",
        )

    def host_whois(self, host_id: str, whois_record_id: str, odata: str) -> dict:
        """
        Retrieve WHOIS record information for a host or specific WHOIS record.
        Docs: https://learn.microsoft.com/en-us/graph/api/security-whoisrecord-get?view=graph-rest-1.0&tabs=http

        Args:
            host_id (str): The ID (host name or ip address) of the host to retrieve WHOIS information for.
            whois_record_id (str): The specific WHOIS record ID to retrieve.
            odata (str): OData query parameters for filtering and formatting the response.

        Returns:
            dict: A dictionary containing WHOIS record information including registration details,
                    contact information (admin, technical, registrant), nameservers, and timestamps.
        """

        odata_query = f"?{odata}" if odata else ""

        if host_id:
            return self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}/whois{odata_query}",
            )

        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}{odata_query}",
        )

    def host_whois_history(self, host_id: str, whois_record_id: str, odata: str, limit: str) -> list:
        """
        Retrieves WHOIS history records for a host or specific WHOIS record.
        Docs:
        https://learn.microsoft.com/en-us/graph/api/security-whoisrecord-list-history?view=graph-rest-1.0&tabs=http
        https://learn.microsoft.com/en-us/graph/api/security-whoishistoryrecord-get?view=graph-rest-1.0

        Args:
            host_id (str): The ID (host name or ip address) of the host to get WHOIS history for.
            whois_record_id (str): The ID of a specific WHOIS record to get history for.
            odata (str): OData query parameters for filtering and formatting results.
            limit (str): Maximum number of records to return (used when whois_history_record_id is not provided).

        Returns:
            list: A list of WHOIS history records containing registration details, contact information,
                    nameservers, and other domain registration data.
        """
        odata_query = f"?$top={limit}&{odata}"

        if host_id:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}/whois/history{odata_query}",
            )

            return response.get("value", [])

        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}/history{odata_query}",
        )

        return response.get("value", [])

    def host_reputation(self, host_id: str, odata: str) -> dict:
        """
        Retrieve host reputation information by host ID.
        Docs: https://learn.microsoft.com/en-us/graph/api/security-host-get-reputation?view=graph-rest-1.0&tabs=http

        Args:
            host_id (str): The ID (host name or ip address) of the host to retrieve reputation information for.
            odata (str): OData query parameters for filtering and formatting the response.

        Returns:
            dict: A dictionary containing host reputation information including reputation score,
                    classification, rules, and other reputation-related details.
        """
        odata_query = f"?{odata}" if odata else ""

        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}/reputation{odata_query}",
        )


""" HELPER FUNCTIONS """


def ensure_only_one_argument_provided(**kwargs):
    """
    Ensures that exactly one of the provided keyword arguments has a non-empty value.

    Raises:
        ValueError: If none or more than one arguments are provided.
    """
    provided_keys = [key for key, value in kwargs.items() if value]
    total_provided = len(provided_keys)
    allowed_keys = ", ".join(kwargs.keys())

    if total_provided == 0:
        raise ValueError(f"You must provide one of the following arguments: {allowed_keys}.\nNone were provided.")
    elif total_provided > 1:
        raise ValueError(
            f"Only one of the following arguments should be provided: {allowed_keys}.\n"
            f"Currently provided: {', '.join(provided_keys)}."
        )


""" COMMAND FUNCTIONS """


def start_auth(client: Client) -> CommandResults:  # pragma: no cover
    """
    Initiates the authentication process for Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for authentication.

    Returns:
        CommandResults: Command results containing the authentication start response.
    """
    result = client.ms_client.start_auth("!msg-defender-threat-intel-auth-complete")
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:  # pragma: no cover
    """
    Completes the authentication process for Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for authentication.

    Returns:
        str: Success message indicating that authorization was completed successfully.
    """
    client.ms_client.get_access_token()
    return "✅ Authorization completed successfully."


def test_connection(client: Client) -> str:  # pragma: no cover
    """
    Tests the connection to Microsoft Defender Threat Intelligence by attempting to retrieve an access token.

    Args:
        client (Client): The client instance used for connection testing.

    Returns:
        str: Success message indicating that the connection test passed.
    """
    client.ms_client.get_access_token()
    return "✅ Success!"


def article_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of articles from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - article_id (str, optional): Specific article ID to retrieve.
            - odata (str, optional): OData query parameters for filtering.
            - limit (int, optional): Maximum number of articles to return. Defaults to 50.

    Returns:
        CommandResults: Command results containing the list of articles with ID and title information.
    """
    article_id = args.get("article_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    response = client.article_list(article_id, odata, limit)

    if len(response) == 0:
        return CommandResults(readable_output="No articles were found.")

    display_data = [{"Article Id": article.get("id"), "Title": article.get("title")} for article in response]
    return CommandResults(
        "MSGDefenderThreatIntel.Article",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Articles:",
            display_data,
            removeNull=True,
        ),
    )


def article_indicators_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of indicators associated with articles from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - article_id (str, optional): Specific article ID to retrieve indicators for.
            - article_indicator_id (str, optional): Specific article indicator ID to retrieve.
            - odata (str, optional): OData query parameters for filtering.
            - limit (int, optional): Maximum number of indicators to return. Defaults to 50.

    Returns:
        CommandResults: Command results containing the list of article indicators with ID and artifact ID information.
    """
    article_id = args.get("article_id", "")
    article_indicator_id = args.get("article_indicator_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)
    ensure_only_one_argument_provided(article_id=article_id, article_indicator_id=article_indicator_id)
    response = client.article_indicator_list(article_id, article_indicator_id, odata, limit)

    if len(response) == 0:
        return CommandResults(readable_output="No article indicators were found.")

    display_data = [
        {
            "ID": indicator.get("id"),
            "Artifact Id": indicator.get("artifact").get("id") if isinstance(indicator.get("artifact"), dict) else None,
        }
        for indicator in response
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.ArticleIndicator",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Indicators:",
            display_data,
            removeNull=True,
        ),
    )


def profile_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of intelligence profiles from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - intel_profile_id (str, optional): Specific intelligence profile ID to retrieve.
            - odata (str, optional): OData query parameters for filtering.
            - limit (int, optional): Maximum number of profiles to return. Defaults to 50.

    Returns:
        CommandResults: Command results containing the list of intelligence profiles with ID and title information.
    """
    intel_profile_id = args.get("intel_profile_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    response = client.profile_list(intel_profile_id, odata, limit)

    if len(response) == 0:
        return CommandResults(readable_output="No profiles were found.")

    display_data = [{"Profile ID": profile.get("id"), "Title": profile.get("title")} for profile in response]

    return CommandResults(
        "MSGDefenderThreatIntel.Profile",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Profiles:",
            display_data,
            removeNull=True,
        ),
    )


def profile_indicators_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a list of intelligence profile indicators from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - intel_profile_id (str, optional): Specific intelligence profile ID to retrieve indicators for.
            - intel_profile_indicator_id (str, optional): Specific intelligence profile indicator ID to retrieve.
            - odata (str, optional): OData query parameters for filtering.
            - limit (int, optional): Maximum number of profile indicators to return. Defaults to 50.

    Returns:
        CommandResults: Command results containing the list of intelligence profile indicators
        with ID and artifact ID information.
    """
    intel_profile_id = args.get("intel_profile_id", "")
    intel_profile_indicator_id = args.get("intel_profile_indicator_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)
    ensure_only_one_argument_provided(intel_profile_id=intel_profile_id, intel_profile_indicator_id=intel_profile_indicator_id)
    response = client.profile_indicators_list(intel_profile_id, intel_profile_indicator_id, odata, limit)

    if len(response) == 0:
        return CommandResults(readable_output="No profile indicators were found.")

    display_data = [
        {
            "ID": profileIndicator.get("id"),
            "Artifact Id": profileIndicator.get("artifact").get("id")
            if isinstance(profileIndicator.get("artifact"), dict)
            else None,
        }
        for profileIndicator in response
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.ProfileIndicator",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Profiles Indicators:",
            display_data,
            removeNull=True,
        ),
    )


def host_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves host information from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - host_id (str, required): Specific host ID to retrieve information for.
            - odata (str, optional): OData query parameters for filtering.

    Returns:
        CommandResults: Command results containing the host information with ID, registrar, and registrant details.
    """
    host_id = args.get("host_id", "")
    odata = args.get("odata", "")
    response = client.host(host_id, odata)
    display_data = [
        {
            "Host Id": response.get("id"),
            "Host Registrar": response.get("registrar"),
            "Host Registrant": response.get("registrant"),
        }
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.Host",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Host:",
            display_data,
            removeNull=True,
        ),
    )


def host_whois_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves WHOIS record information for a host from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - host_id (str, optional): Specific host ID to retrieve WHOIS information for.
            - whois_record_id (str, optional): Specific WHOIS record ID to retrieve.
            - odata (str, optional): OData query parameters for filtering.

    Returns:
        CommandResults: Command results containing the WHOIS record information with ID, WHOIS server, and domain status details.
    """
    host_id = args.get("host_id", "")
    whois_record_id = args.get("whois_record_id", "")
    odata = args.get("odata", "")
    ensure_only_one_argument_provided(host_id=host_id, whois_record_id=whois_record_id)
    response = client.host_whois(host_id, whois_record_id, odata)
    display_data = [
        {"Id": response.get("id"), "Whois Server": response.get("whoisServer"), "Domain Status": response.get("domainStatus")}
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.Whois",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Whois:",
            display_data,
            removeNull=True,
        ),
    )


def host_whois_history_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves WHOIS history records for a host from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - host_id (str, optional): Specific host ID to retrieve WHOIS history for.
            - whois_record_id (str, optional): Specific WHOIS record ID to retrieve history for.
            - odata (str, optional): OData query parameters for filtering.
            - limit (int, optional): Maximum number of records to return. Defaults to 50.

    Returns:
        CommandResults: Command results containing the WHOIS history records with ID, WHOIS server, and domain status details.
    """
    host_id = args.get("host_id", "")
    whois_record_id = args.get("whois_record_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    ensure_only_one_argument_provided(host_id=host_id, whois_record_id=whois_record_id)

    response = client.host_whois_history(host_id, whois_record_id, odata, limit)

    if len(response) == 0:
        return CommandResults(readable_output="No WHOIS history records found.")

    display_data = [
        {
            "Id": whois_record.get("id"),
            "Whois Server": whois_record.get("whoisServer"),
            "Domain Status": whois_record.get("domainStatus"),
        }
        for whois_record in response
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.WhoisHistory",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Whois:",
            display_data,
            removeNull=True,
        ),
    )


def host_reputation_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves host reputation information from Microsoft Defender Threat Intelligence.

    Args:
        client (Client): The client instance used for API communication.
        args (dict[str, Any]): Command arguments containing:
            - host_id (str, required): Specific host ID to retrieve reputation information for.
            - odata (str, optional): OData query parameters for filtering.

    Returns:
        CommandResults: Command results containing the host reputation information with ID, classification, and score details.
    """
    host_id = args.get("host_id", "")
    odata = args.get("odata", "")
    response = client.host_reputation(host_id, odata)
    display_data = [
        {
            "Host Id": response.get("id"),
            "Host Classification": response.get("classification"),
            "Host Score": response.get("score"),
        }
    ]

    return CommandResults(
        "MSGDefenderThreatIntel.HostReputation",
        "id",
        outputs=response,
        readable_output=tableToMarkdown(
            "Host Reputation:",
            display_data,
            removeNull=True,
        ),
    )


def main():
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        params = demisto.params()
        args = demisto.args()
        handle_proxy()
        client = Client(
            app_id=params.get("app_id"),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            azure_ad_endpoint=params.get("azure_ad_endpoint", "https://login.microsoftonline.com")
            or "https://login.microsoftonline.com",
            tenant_id=params.get("tenant_id"),
            client_credentials=params.get("client_credentials", False),
            enc_key=(params.get("credentials") or {}).get("password"),
            managed_identities_client_id=get_azure_managed_identities_client_id(params),
            certificate_thumbprint=params.get("creds_certificate", {}).get("identifier"),
            private_key=(replace_spaces_in_credential(params.get("creds_certificate", {}).get("password"))),
        )
        if command == "test-module":
            if client.ms_client.managed_identities_client_id or client.ms_client.grant_type == CLIENT_CREDENTIALS:
                test_connection(client=client)
                return_results("ok")
            else:
                return_results("The test module is not functional, run the msg-defender-threat-intel-auth-start command instead.")
        elif command == "msg-defender-threat-intel-auth-start":
            return_results(start_auth(client))
        elif command == "msg-defender-threat-intel-auth-complete":
            return_results(complete_auth(client))
        elif command == "msg-defender-threat-intel-auth-test":
            return_results(test_connection(client))
        elif command == "msg-defender-threat-intel-auth-reset":
            return_results(reset_auth())
        elif command == "msg-defender-threat-intel-article-list":
            return_results(article_list_command(client, args))
        elif command == "msg-defender-threat-intel-article-indicators-list":
            return_results(article_indicators_list_command(client, args))
        elif command == "msg-defender-threat-intel-profile-list":
            return_results(profile_list_command(client, args))
        elif command == "msg-defender-threat-intel-profile-indicators-list":
            return_results(profile_indicators_list_command(client, args))
        elif command == "msg-defender-threat-intel-host":
            return_results(host_command(client, args))
        elif command == "msg-defender-threat-intel-host-whois":
            return_results(host_whois_command(client, args))
        elif command == "msg-defender-threat-intel-host-whois-history":
            return_results(host_whois_history_command(client, args))
        elif command == "msg-defender-threat-intel-host-reputation":
            return_results(host_reputation_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
