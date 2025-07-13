"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
#from CommonServerUserPython import *  # noqa
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

'''NEED TO CHANGE TO THE CORRECT PERMISSION SET'''
REQUIRED_PERMISSIONS = (
    "offline_access",  # allows device-flow login
    "ThreatIntelligence.Read.All",  # Threat Intelligence specific permission
    "Application.Read.All",
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
            method='GET',
            url_suffix='v1.0/security/threatIntelligence/articles{odata_query}',
            )
            return response.get('value', [])

        """NEED TO CHECK IF LIMIT IS VALID HERE"""
        response = self.ms_client.http_request(
            method='GET',
            url_suffix=f'v1.0/security/threatIntelligence/articles/{article_id}{odata_query}',
        )

        
        return [response]
        '''
        response = {
            "value": [
                {
                    "@odata.context": "$metadata#articles/$entity",
                    "id": "a272d5ab",
                    "createdDateTime": "2023-03-03T18:20:22.677Z",
                    "lastUpdatedDateTime": "2023-03-03T18:20:22.677Z",
                    "title": "Batloader Malware Abuses Legitimate Tools Uses Obfuscated JavaScript Files in Q4 2022 Attacks",
                    "summary": {
                        "content": "Trend Micro discusses Batloader campaigns that were observed in the last quarter of 2022.",
                        "format": "markdown",
                    },
                    "isFeatured": False,
                    "body": {"content": "#### Description\r\nTrend Micro discusses Batloader...", "format": "markdown"},
                    "tags": ["OSINT", "Batloader", "RoyalRansomware", "Python", "JavaScript", "MSI", "PowerShell"],
                    "imageUrl": None,
                }
            ]
        }
        
        return response.get("value", [])
        '''

    def indicator_list(self, article_id: str, article_indicator_id: str, odata: str, limit: int) -> list:
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
        # if not article_id:
        #     response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix='v1.0//security/threatIntelligence/articleIndicators/{article_indicator_id}{odata_query}',
        #     )
        # if response:
        #   return [response]

        # response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0//security/threatIntelligence/articles/{article_id}/indicators{odata_query}',
        # )
        # return response.get('value', [])

        response = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.security.articleIndicator",
                    "id": "ZmFrZS1tYWxpY2lvdXMuc2l0ZQ==",
                    "source": "microsoft",
                    "artifact": {"@odata.type": "#microsoft.graph.security.hostname", "id": "fake-malicious.site"},
                }
            ]
        }

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
        # if not intel_profile_id:
        #     response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix='v1.0//security/threatIntelligence/intelProfiles{odata_query}',
        #     )
        #     return response.get('value', [])

        """NEED TO CHECK IT LIMIT IS VALID HERE"""
        # response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0//security/threatIntelligence/intelProfiles/{intel_profile_id}{odata_query}',
        # )
        #
        # if response:
        #   return [response]

        response = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.security.intelligenceProfile",
                    "id": "9b01de37bf66d1760954a16dc2b52fed2a7bd4e093dfc8a4905e108e4843da80",
                    "kind": "actor",
                    "title": "Aqua Blizzard",
                    "firstActiveDateTime": "2020-02-24T00:00:00Z",
                    "aliases": ["Primitive Bear", "ACTINIUM", "SectorC08", "shuckworm", "Gamaredon", "UNC530", "Armageddon"],
                    "targets": [
                        "Government Agencies & Services: Defense",
                        "Government Agencies & Services: Law Enforcement",
                        "Non-Government Organization: Human Rights Organization",
                    ],
                    "countriesOrRegionsOfOrigin": [
                        {
                            "@odata.type": "microsoft.graph.security.intelligenceProfileCountryOrRegionOfOrigin",
                            "label": "Country/Region",
                            "code": "Country/Region code",
                        }
                    ],
                    "summary": {
                        "@odata.type": "microsoft.graph.security.formattedContent",
                        "content": "The actor that Microsoft tracks as Aqua Blizzard (ACTINIUM) is a nation-state activity group based out of ...",
                        "format": "text",
                    },
                    "description": {
                        "@odata.type": "microsoft.graph.security.formattedContent",
                        "content": "## Snapshot\r\nThe actor that Microsoft tracks as Aqua Blizzard (ACTINIUM) is a nation-state activity group based out of ...",
                        "format": "markdown",
                    },
                    "tradecraft": {
                        "@odata.type": "microsoft.graph.security.formattedContent",
                        "content": "Aqua Blizzard (ACTINIUM) primarily uses spear phishing emails to infect targets. These emails harness remote template injection to load malicious code or content. Typically, ...",
                        "format": "markdown",
                    },
                }
            ]
        }

        return response.get("value", [])

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
        odata_query = "?"
        odata_query += f"$top={limit}&"
        if odata:
            odata_query += odata

        # if not intel_profile_indicator_id:
        #     response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix='v1.0//security/threatIntelligence/intelProfiles/{intel_profile_id}/indicators{odata_query}',
        #     )
        #     return response.get('value', [])

        """NEED TO CHECK IF LIMIT IS VALID HERE"""
        # response = self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0//security/threatIntelligence/intelligenceProfileIndicators/{intel_profile_indicator_id}{odata_query}',
        # )
        # if response:
        #   return [response]

        response = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.security.intelligenceProfileIndicator",
                    "id": "ff3eecd2-a2be-27c2-8dc0-40d1c0eada55",
                    "source": "microsoft",
                    "firstSeenDateTime": "2022-05-02T23:09:20.000Z",
                    "lastSeenDateTime": "null",
                    "artifact": {"@odata.type": "#microsoft.graph.security.hostname", "id": "fake-malicious.site"},
                }
            ]
        }

        return response.get("value", [])

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

        # return self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0//security/threatIntelligence/hosts/{host_id}{odata_query}',
        # )

        response = {
            "@odata.type": "#microsoft.graph.security.hostname",
            "id": "contoso.com",
            "firstSeenDateTime": "2009-09-02T03:29:10.000Z",
            "lastSeenDateTime": "2009-09-02T03:29:10.000Z",
            "registrar": "MarkMonitor Inc.",
            "registrant": "Microsoft Corporation",
        }

        return response

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
        # if host_id:
        #     return self.ms_client.http_request(
        #         method='GET',
        #         url_suffix=f'v1.0/security/threatIntelligence/{host_id}/whois{odata_query}',
        #     )

        # return self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}{odata_query}',
        # )
        response = {
            "@odata.type": "#microsoft.graph.security.whoisRecord",
            "id": "Y29udG9zby5jb20kJDY5NjQ3ODEyMDc3NDY1NzI0MzM=",
            "expirationDateTime": "2023-08-31T00:00:00Z",
            "registrationDateTime": "2022-07-30T09:43:19Z",
            "firstSeenDateTime": "null",
            "lastSeenDateTime": "null",
            "lastUpdateDateTime": "2023-06-24T08:34:15.984Z",
            "billing": "null",
            "noc": "null",
            "zone": "null",
            "whoisServer": "rdap.markmonitor.com",
            "domainStatus": "client update prohibited,client transfer prohibited,client delete prohibited",
            "rawWhoisText": "Registrar: \n  Handle: 1891582_DOMAIN_COM-VRSN\n  LDH Name: contoso.com\n  Nameserver: \n    LDH Name: ns1.contoso.com\n    Event: \n      Action: last changed\n...",
            "abuse": {
                "email": "noreply@contoso.com",
                "name": "null",
                "organization": "null",
                "telephone": "+1.5555555555",
                "fax": "null",
                "address": {"city": "null", "countryOrRegion": "null", "postalCode": "null", "state": "null", "street": "null"},
            },
            "admin": {
                "email": "noreply@contoso.com",
                "name": "Domain Administrator",
                "organization": "Contoso Org",
                "telephone": "+1.5555555555",
                "fax": "+1.5555555555",
                "address": {
                    "city": "Redmond",
                    "countryOrRegion": "US",
                    "postalCode": "98052",
                    "state": "WA",
                    "street": "123 Fake St.",
                },
            },
            "registrar": {
                "email": "null",
                "name": "null",
                "organization": "MarkMonitor Inc.",
                "telephone": "null",
                "fax": "null",
                "address": "null",
            },
            "registrant": {
                "email": "noreply@contoso.com",
                "name": "Domain Administrator",
                "organization": "Contoso Corporation",
                "telephone": "+1.5555555555",
                "fax": "+1.5555555555",
                "address": {
                    "city": "Redmond",
                    "countryOrRegion": "US",
                    "postalCode": "98052",
                    "state": "WA",
                    "street": "123 Fake St.",
                },
            },
            "technical": {
                "email": "noreply@contoso.com",
                "name": "Hostmaster",
                "organization": "Contoso Corporation",
                "telephone": "+1.5555555555",
                "fax": "+1.5555555555",
                "address": {
                    "city": "Redmond",
                    "countryOrRegion": "US",
                    "postalCode": "98052",
                    "state": "WA",
                    "street": "123 Fake St.",
                },
            },
            "nameservers": [
                {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns1.contoso-dns.com"}},
                {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns2.contoso-dns.com"}},
                {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns3.contoso-dns.com"}},
                {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns4.contoso-dns.com"}},
            ],
            "host": {"id": "contoso.com"},
        }

        return response

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
        # if host_id:
        #     return self.ms_client.http_request(
        #         method='GET',
        #         url_suffix=f'v1.0/security/threatIntelligence/hosts/{host_Id}/whois/history{odata_query}',
        #     )

        # elif whois_record_id:
        #     return self.ms_client.http_request(
        #         method='GET',
        #         url_suffix=f'v1.0/security/threatIntelligence/whoisRecords/{whois_record_id}/history{odata_query}',
        #     )

        # response =  self.ms_client.http_request(
        #     method='GET',
        #     url_suffix=f'v1.0/security/threatIntelligence/whoisHistoryRecord/{whois_history_record_id}{odata_query}',
        # )

        # if response:
        #   return [response]

        response = {
            "value": [
                {
                    "@odata.type": "#microsoft.graph.security.whoisRecord",
                    "id": "Y29udG9zby5jb20kJDY5NjQ3ODEyMDc3NDY1NzI0MzM=",
                    "expirationDateTime": "2023-08-31T00:00:00Z",
                    "registrationDateTime": "2022-07-30T09:43:19Z",
                    "firstSeenDateTime": "null",
                    "lastSeenDateTime": "null",
                    "lastUpdateDateTime": "2023-06-24T08:34:15.984Z",
                    "billing": "null",
                    "noc": "null",
                    "zone": "null",
                    "whoisServer": "rdap.markmonitor.com",
                    "domainStatus": "client update prohibited,client transfer prohibited,client delete prohibited",
                    "rawWhoisText": "Registrar: \n  Handle: 1891582_DOMAIN_COM-VRSN\n  LDH Name: contoso.com\n  Nameserver: \n    LDH Name: ns1.contoso.com\n    Event: \n      Action: last changed\n...",
                    "abuse": {
                        "email": "noreply@contoso.com",
                        "name": "null",
                        "organization": "null",
                        "telephone": "+1.5555555555",
                        "fax": "null",
                        "address": {
                            "city": "null",
                            "countryOrRegion": "null",
                            "postalCode": "null",
                            "state": "null",
                            "street": "null",
                        },
                    },
                    "admin": {
                        "email": "noreply@contoso.com",
                        "name": "Domain Administrator",
                        "organization": "Contoso Org",
                        "telephone": "+1.5555555555",
                        "fax": "+1.5555555555",
                        "address": {
                            "city": "Redmond",
                            "countryOrRegion": "US",
                            "postalCode": "98052",
                            "state": "WA",
                            "street": "123 Fake St.",
                        },
                    },
                    "registrar": {
                        "email": "null",
                        "name": "null",
                        "organization": "MarkMonitor Inc.",
                        "telephone": "null",
                        "fax": "null",
                        "address": "null",
                    },
                    "registrant": {
                        "email": "noreply@contoso.com",
                        "name": "Domain Administrator",
                        "organization": "Contoso Corporation",
                        "telephone": "+1.5555555555",
                        "fax": "+1.5555555555",
                        "address": {
                            "city": "Redmond",
                            "countryOrRegion": "US",
                            "postalCode": "98052",
                            "state": "WA",
                            "street": "123 Fake St.",
                        },
                    },
                    "technical": {
                        "email": "noreply@contoso.com",
                        "name": "Hostmaster",
                        "organization": "Contoso Corporation",
                        "telephone": "+1.5555555555",
                        "fax": "+1.5555555555",
                        "address": {
                            "city": "Redmond",
                            "countryOrRegion": "US",
                            "postalCode": "98052",
                            "state": "WA",
                            "street": "123 Fake St.",
                        },
                    },
                    "nameservers": [
                        {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns1.contoso-dns.com"}},
                        {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns2.contoso-dns.com"}},
                        {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns3.contoso-dns.com"}},
                        {"firstSeenDateTime": "null", "lastSeenDateTime": "null", "host": {"id": "ns4.contoso-dns.com"}},
                    ],
                    "host": {"id": "contoso.com"},
                }
            ]
        }

        return response.get("value", [])


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
        raise ValueError(
            f"You must provide one of the following arguments: {allowed_keys}.\nNone were provided."
        )
    elif total_provided > 1:
        raise ValueError(
            f"Only one of the following arguments should be provided: {allowed_keys}.\n"
            f"Currently provided: {', '.join(provided_keys)}."
        )

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

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

    # Call the Client function and get the raw response
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
    response = client.indicator_list(article_id, article_indicator_id, odata, limit)
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

    # Call the Client function and get the raw response
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

    # Call the Client function and get the raw response
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

    # Call the Client function and get the raw response
    response = client.host(host_id, odata)
    display_data = [
        {
            "Host Id": response.get("id"),
            "Host Registrar": response.get("registrar"),
            "Host Registrant": response.get("registrant"),
        }
    ]
    return CommandResults(
        "MSGDefenderThreatIntel.host",
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

    # Call the Client function and get the raw response
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

    ensure_only_one_argument_provided(host_id=host_id, whois_record_id=whois_record_id,
                                      whois_history_record_id=whois_history_record_id)

    # Call the Client function and get the raw response
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
                return_results("The test module is not functional, run the msgraph-identity-auth-start command instead.")
            # This is the call made when pressing the integration Test button.
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
