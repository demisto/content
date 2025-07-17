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

        Args:
            article_id (str): Specific article ID to retrieve. If empty, retrieves all articles.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of articles to return.

        Returns:
            list: List of article objects. If article_id is provided, returns a single article
                    in a list format. If article_id is empty, returns multiple articles from
                    the 'value' field of the response.
        """
        odata_query = "?"
        odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata

        if not article_id:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/articles{odata_query}",
            )
            return response.get("value", [])

        """NEED TO CHECK IF LIMIT IS VALID HERE"""
        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/articles/{article_id}{odata_query}",
        )

        return [response]

    def article_indicator_list(self, article_id: str, article_indicator_id: str, odata: str, limit: int) -> list:
        """
        Retrieve threat intelligence indicators from Microsoft Defender.

        Args:
            article_id (str): The ID of the article to retrieve indicators from.
            article_indicator_id (str): The specific indicator ID to retrieve.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of indicators to return.

        Returns:
            list: List of article indicator objects from the 'value' field of the response.
        """
        odata_query = "?"
        odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        """NEED TO CHECK IF LIMIT IS VALID HERE"""
        if not article_id:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/articleIndicators/{article_indicator_id}{odata_query}",
            )
            if response:
                return [response]

        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/articles/{article_id}/indicators{odata_query}",
        )
        return response.get("value", [])

    def profile_list(self, intel_profile_id: str, odata: str, limit: int) -> list:
        """
        Retrieve threat intelligence profiles from Microsoft Defender.

        Args:
            intel_profile_id (str): The ID of the specific intelligence profile to retrieve.
            odata (str): Additional OData query parameters for filtering and sorting.
            limit (int): Maximum number of profiles to return.

        Returns:
            list: List of intelligence profile objects from the 'value' field of the response.
        """
        odata_query = "?"
        odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        if not intel_profile_id:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/intelProfiles{odata_query}",
            )
            return response.get("value", [])

        """NEED TO CHECK IT LIMIT IS VALID HERE"""
        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/intelProfiles/{intel_profile_id}{odata_query}",
        )

        return [response]

    def profile_indicators_list(self, intel_profile_id: str, intel_profile_indicator_id: str, odata: str, limit: int) -> list:
        """
        Retrieve intelligence profile indicators.

        Args:
            intel_profile_id (str): The ID of the intelligence profile.
            intel_profile_indicator_id (str): The ID of a specific intelligence profile indicator.
            odata (str): OData query parameters for filtering and formatting the response.
            limit (int): Maximum number of indicators to return.

        Returns:
            list: A list of intelligence profile indicators, each containing information such as
                    ID, source, first/last seen timestamps, and associated artifacts.
        """
        odata_query = f"?$top={limit}&"
        if odata:
            odata_query += odata

        if not intel_profile_indicator_id:
            response = self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/intelProfiles/{intel_profile_id}/indicators{odata_query}",
            )
            return response.get("value", [])

        """NEED TO CHECK IF LIMIT IS VALID HERE"""
        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/intelligenceProfileIndicators/{intel_profile_indicator_id}{odata_query}",
        )
        return [response]

    def host(self, host_id: str, odata: str) -> dict:
        """
        Retrieve host information by host ID.

        Args:
            host_id (str): The ID of the host to retrieve information for.
            odata (str): OData query parameters for filtering and formatting the response.

        Returns:
            dict: A dictionary containing host information including ID, first/last seen timestamps,
                    registrar, and registrant details.
        """
        odata_query = "?"
        if odata:
            odata_query += odata

        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}{odata_query}",
        )

    def host_whois(self, host_id: str, whois_record_id: str, odata: str) -> dict:
        """
        Retrieve WHOIS record information for a host or specific WHOIS record.

        Args:
            host_id (str): The ID of the host to retrieve WHOIS information for.
            whois_record_id (str): The specific WHOIS record ID to retrieve.
            odata (str): OData query parameters for filtering and formatting the response.

        Returns:
            dict: A dictionary containing WHOIS record information including registration details,
                    contact information (admin, technical, registrant), nameservers, and timestamps.
        """
        odata_query = "?"
        if odata:
            odata_query += odata
        if host_id:
            return self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/{host_id}/whois{odata_query}",
            )

        return self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}{odata_query}",
        )

    def host_whois_history(
        self, host_id: str, whois_record_id: str, whois_history_record_id: str, odata: str, limit: str
    ) -> list:
        """
        Retrieves WHOIS history records for a host or specific WHOIS record.

        Args:
            host_id (str): The ID of the host to get WHOIS history for.
            whois_record_id (str): The ID of a specific WHOIS record to get history for.
            whois_history_record_id (str): The ID of a specific WHOIS history record.
            odata (str): OData query parameters for filtering and formatting results.
            limit (str): Maximum number of records to return (used when whois_history_record_id is not provided).

        Returns:
            list: A list of WHOIS history records containing registration details, contact information,
                    nameservers, and other domain registration data.
        """
        odata_query = "?"
        if not whois_history_record_id:
            odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata
        if host_id:
            return self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/hosts/{host_id}/whois/history{odata_query}",
            )

        elif whois_record_id:
            return self.ms_client.http_request(
                method="GET",
                url_suffix=f"v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}/history{odata_query}",
            )

        response = self.ms_client.http_request(
            method="GET",
            url_suffix=f"v1.0/security/threatIntelligence/whoisHistoryRecord/{whois_history_record_id}{odata_query}",
        )

        return [response]


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
    result = client.ms_client.start_auth("!msg-defender-threat-intel-auth-complete")
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:  # pragma: no cover
    client.ms_client.get_access_token()
    return "✅ Authorization completed successfully."


def test_connection(client: Client) -> str:  # pragma: no cover
    client.ms_client.get_access_token()
    return "✅ Success!"


def article_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    article_id = args.get("article_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    response = client.article_list(article_id, odata, limit)
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
    article_id = args.get("article_id", "")
    article_indicator_id = args.get("article_indicator_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)
    ensure_only_one_argument_provided(article_id=article_id, article_indicator_id=article_indicator_id)
    response = client.article_indicator_list(article_id, article_indicator_id, odata, limit)
    display_data = [{"ID": indicator.get("id"), "Artifact Id": indicator.get("artifact", {}).get("id")} for indicator in response]
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
    intel_profile_id = args.get("intel_profile_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    response = client.profile_list(intel_profile_id, odata, limit)

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
    intel_profile_id = args.get("intel_profile_id", "")
    intel_profile_indicator_id = args.get("intel_profile_indicator_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    ensure_only_one_argument_provided(intel_profile_id=intel_profile_id, intel_profile_indicator_id=intel_profile_indicator_id)

    response = client.profile_indicators_list(intel_profile_id, intel_profile_indicator_id, odata, limit)
    display_data = [
        {"ID": profileIndicator.get("id"), "Artifact Id": profileIndicator.get("artifact", {}).get("id")}
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
    host_id = args.get("host_id", "")
    whois_record_id = args.get("whois_record_id", "")
    whois_history_record_id = args.get("whois_history_record_id", "")
    odata = args.get("odata", "")
    limit = args.get("limit", 50)

    ensure_only_one_argument_provided(
        host_id=host_id, whois_record_id=whois_record_id, whois_history_record_id=whois_history_record_id
    )

    response = client.host_whois_history(host_id, whois_record_id, whois_history_record_id, odata, limit)
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


def main():
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        params = demisto.params()
        args = demisto.args()
        handle_proxy()
        client = Client(
            app_id = params.get("app_id"),
            verify = not params.get("insecure", False),
            proxy = params.get("proxy", False),
            azure_ad_endpoint = params.get("azure_ad_endpoint", "https://login.microsoftonline.com")
            or "https://login.microsoftonline.com",
            tenant_id = params.get("tenant_id"),
            client_credentials = params.get("client_credentials", False),
            enc_key = (params.get("credentials") or {}).get("password"),
            managed_identities_client_id = get_azure_managed_identities_client_id(params),
            certificate_thumbprint = params.get("creds_certificate", {}).get("identifier"),
            private_key = (replace_spaces_in_credential(params.get("creds_certificate", {}).get("password"))),
        )
        if command == "test-module":
            if client.ms_client.managed_identities_client_id or client.ms_client.grant_type == CLIENT_CREDENTIALS:
                test_connection(client=client)
                return_results("ok")
            else:
                return_results("The test module is not functional, run the msgraph-identity-auth-start command instead.")
        elif command == "msg-defender-threat-intel-auth-start":
            return_results(start_auth(client))
        elif command == "msg-defender-threat-intel-auth-complete":
            return_results(complete_auth(client))
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
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
