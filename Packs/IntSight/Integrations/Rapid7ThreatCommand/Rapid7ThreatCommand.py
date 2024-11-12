import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from http import HTTPStatus
from enum import Enum, StrEnum
from typing import Any, cast
from collections.abc import Callable
import copy
from requests import Response
import pathlib
import re
import csv

DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 600
ISO_8601_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
INTEGRATION_ENTRY_CONTEXT = "ThreatCommand"
BACKOFF_FACTOR = 15  # Consider its double.
RETRIES = 3  # One retry is completed right away, so it should be viewed as a minor attempt.
STATUS_LIST_TO_RETRY = [429] + list(range(500, 600))


class Headers(list, Enum):  # type: ignore[misc]
    GET_ALERT = [
        "id",
        "type",
        "sub_type",
        "title",
        "description",
        "severity",
        "found_date",
        "is_closed",
        "Tags",
        "assignees",
    ]
    LIST_CYBER_TERM = [
        "id",
        "name",
        "severity",
        "overview",
        "target_countries",
        "sectors",
        "ttp",
        "related_malware",
        "related_campaigns",
    ]
    GET_IOC = [
        "value",
        "type",
        "status",
        "is_whitelisted",
        "score",
        "severity",
        "last_update_date",
    ]
    MENTION = [
        "author",
        "original_url",
        "url",
        "type",
        "id",
        "short_content",
        "title",
        "date",
    ]
    ENRICH_IOC = [
        "value",
        "Source",
        "status",
        "is_known_ioc",
        "update_seen",
        "is_whitelisted",
        "Severity",
    ]


class ReadableOutputs(str, Enum):
    CYBER_TERM_CVES = "Related CVEs to Cyber term {0}"
    CYBER_TERM_IOCS = "Related IOCs to Cyber term {0}"
    CYBER_TERM = "Cyber terms"
    IOC_SOURCE = "IOC sources"
    SYSTEM_MODULES = "System modules"
    ASSET_TYPES = "Asset types."
    LIST_ASSET = "Asset list."
    CREATE_ASSET = 'Asset "{0}" successfully added to "{1}" asset list.'
    DELETE_ASSET = 'Asset "{0}" successfully deleted from "{1}" asset list.'
    CREATE_IOC = 'IOC "{0}" successfully added to "{1}" document source.'
    DOCUMENT_CREATE = "Source document successfully created."
    DOCUMENT_DELETE = 'Source document "{0}" successfully deleted.'
    CREATE_IOC_SUCCESS = 'IOCs "{0}" successfully added to "{1}" source document.'
    CREATE_IOC_FAIL = 'Failed to add IOCs "{0}" to "{1}" source document.'
    CVES = "CVE list."
    CVE_NEXT_OFFSET = "CVE next offset."
    ADD_CVE_SUCCESS = 'The "{0}" CVEs successfully added.'
    ADD_CVE_FAIL = 'Failed to add the "{0}" CVEs.'
    DELETE_CVE_SUCCESS = 'The "{0}" CVEs successfully deleted.'
    DELETE_CVE_FAIL = 'Failed to delete the "{0}" CVEs.'
    ALERT_LIST = "Alert list"
    ALERT_GET = 'Alert "{0}"'
    ALERT_CREATE = "Alert successfully created"
    ALERT_CLOSE = 'Alert "{0}" successfully closed'
    ALERT_SEVERITY = 'Alert "{0}" severity successfully updated to "{1}".'
    ALERT_ASSIGN = 'Alert "{0}" successfully assign to user "{1}".'
    ALERT_UNASSIGN = "Alert '{0}' successfully unassigned from any user."
    ALERT_REOPEN = 'Alert "{0}" successfully re-opened.'
    ALERT_TAG_ADD = 'The tag "{1}" successfully added to "{0}" Alert.'
    ALERT_TAG_REMOVE = 'The tag "{1}" successfully removed from "{0}" Alert.'
    ALERT_MAIL = 'The alert "{0}" successfully send to "{1}".'
    ALERT_ANALYST = 'The alert "{0}" successfully sent to the analyst.'
    ALERT_CONVERSATION_LIST = "Alert conversation with analyst:"
    ALERT_NO_CONVERSATION_LIST = "There is no conversation with analyst."
    ALERT_ADD_NOTE = 'Note successfully add to alert "{0}".'
    ALERT_BLOCKLIST_GET = 'Blocklist for alert "{0}".'
    ALERT_BLOCKLIST_UPDATE = 'IOC successfully updated to status "{0}".'
    ALERT_IMAGES = 'Alert "{0}" Images list.'
    ALERT_NO_IMAGES = 'Alert "{0}" does not contain images.'
    ALERT_CSV = 'Alert "{0}" CSV file.'
    ALERT_NO_CSV = 'Alert "{0}" does not have a CSV file.'
    ALERT_TAKEDOWN = 'Successfully sent takedown request for alert "{0}".'
    ALERT_TAKEDOWN_STATUS = 'Takedown status for alert "{0}".'
    ALERT_REPORT = 'Alert "{0}" successfully reported'
    ALERT_ACTIVITY = 'Alert "{0}" activity log'
    ALERT_TYPES = "Alert types"
    ALERT_SOURCE_TYPES = "Alert source types"
    IOC_LIST = "IOC list"
    IOC_GET = 'IOC "{0}"'
    ENRICH_GET = 'Enrichment data for IOC "{0}"'
    IOC_TAG_ADD = 'The tags "{1}" successfully added to "{0}" IOC.'
    UPDATE_IOC_SEVERITY = 'The severity "{1}" successfully updated to "{0}" IOCs.'
    ADD_IOC_COMMENT = 'The comment "{1}" successfully updated to "{0}" IOCs.'
    UPDATE_ACCOUNT_WHITELIST = (
        'The status "{1}" successfully updated to "{0}" IOCs in the account whitelist.'
    )
    REMOVE_ACCOUNT_WHITELIST = (
        'The IOCs "{0}" successfully removed from the account whitelist.'
    )
    ADD_IOC_BLOCKLIST = (
        'The IOCs "{0}" successfully added to the remediation blocklist.'
    )
    REMOVE_IOC_BLOCKLIST = (
        'The IOCs "{0}" successfully removed from the remediation blocklist.'
    )
    ACCOUNT_USER_LIST = "Account user list"
    MSSP_USER_LIST = "MSSP user list"
    MSSP_CUSTOMER_LIST = "MSSP customer list"
    SCENARIO_LIST = "Alert scenario list"
    MENTIONS = 'Mentions for "{0}" (page number {1}).'
    ENRICH_QUOTA = "Current API enrichment credits (quota)."


class ReadableErrors(str, Enum):
    MISSING_IOCS = "Missing IOCs. Please insert."
    SOURCE_NOT_EXIST = "The source does not exist."
    GENERAL = "General error with the request."
    NOT_FOUND = "The object does not exist."
    WRONG_PARAMETERS = "Wrong parameters."
    NO_CONTENT = "No content - there is no data to show."
    UNAUTHORIZED = "Authorization Error: Make sure that the Account ID and API key are correctly set."
    ENRICH_FAIL = 'Enrichment failed. Status is "{0}"".'
    INSERT_VALUE = "Please insert {0}."
    NO_IOCS = "Please insert at least one IOC."
    WRONG_IOC = "Please insert correct IOC value."
    EMAIL = '"{0}" is not correct email, please insert correct email.'
    DOMAIN = '"{0}" is not correct domain, please insert correct domain.'
    URL = '"{0}" is not correct URL, please insert correct URL.'
    IP = '"{0}" is not correct IP, please insert correct IP.'
    HASH = '"{0}" is not correct hash, please insert correct hash.'
    SOURCE_ALREADY_EXIST = "The source already exist."
    CONFIDENCE_LEVEL = "confidence_level is a number in range 1-3"
    RATE = "rate is a number in range 0-5"
    ALERT_LIST = "You can't choose alert_id and retrieve_ids_only."
    SCENARIO_TYPES = "You have to insert scenario or type and sub-type."
    ALERT_TYPE = "You have to insert type or remove the sub_type and insert scenario."
    ALERT_SUB_TYPE = (
        "You have to insert sub_type or remove the type and insert scenario."
    )
    ARGUMENT = "{0} argument should be {1}"
    NUMBER = "Please insert a valid number."
    LIMIT = "Limit has to be positive number."
    MODULE_NOT_AVAILABLE = "The module is not available."
    ACCOUNT_ID_HEADER = "Missing Account ID."
    IS_HIDDEN = 'You can use is_hidden=True only in case the reason is "False Positive"'
    USER_EMAIL = "The user email is invalid."
    USER_ID = "The user ID is invalid."
    SOURCE_TYPE = "The source type is invalid."
    SUB_TYPE = "The sub-type is invalid."
    EXTERNAL_SOURCE = "The external source is invalid."
    ASSET_TYPE = "The asset type is invalid."
    TAG_ID = "The tag ID is invalid."
    ASSET_COUNTRY = "The country is invalid."
    ASSET_SECTOR = "The sector is invalid."
    ASSET_DOMAIN = "The domain is invalid."
    TAG_EXIST = "The tag is already exist."
    INVALID_EMAIL = "The email is invalid."
    IOC_NOT_EXIST = "The IOC does not exist."
    FIRST_FETCH_NOT_EXIST = "Failed to get first fetch time."
    MAX_FETCH_INVALID = "Maximum incidents per fetch must be a positive integer ranging from 1 to 200."


ERROR_RESPONSE_MAPPER: dict[str, str] = {
    "MissingIocs": ReadableErrors.MISSING_IOCS.value,
    "SourceDoesNotExist": ReadableErrors.SOURCE_NOT_EXIST.value,
    "SourceNameAlreadyExists": ReadableErrors.SOURCE_ALREADY_EXIST.value,
    "InvaliduserEmail": ReadableErrors.USER_EMAIL.value,
    "InvaliduserId": ReadableErrors.USER_ID.value,
    "InvalidAssigneeID": ReadableErrors.USER_ID.value,
    "InvalidSourceType": ReadableErrors.SOURCE_TYPE.value,
    "InvalidSubAlertType": ReadableErrors.SUB_TYPE.value,
    "InvalidExternalSources": ReadableErrors.EXTERNAL_SOURCE.value,
    "InvalidAssetType": ReadableErrors.ASSET_TYPE.value,
    "InvalidTagID": ReadableErrors.TAG_ID.value,
    "InvalidCountryOfActivityAsset": ReadableErrors.ASSET_COUNTRY.value,
    "InvalidSectorAsset": ReadableErrors.ASSET_SECTOR.value,
    "InvalidDomainAsset": ReadableErrors.ASSET_DOMAIN.value,
    "MissingAccountIdHeader": ReadableErrors.ACCOUNT_ID_HEADER.value,
    "ModuleNotAvailable": ReadableErrors.MODULE_NOT_AVAILABLE.value,
    "TagExist": ReadableErrors.TAG_EXIST.value,
    "InvalidEmails": ReadableErrors.INVALID_EMAIL.value,
    "IocDoesNotExist": ReadableErrors.IOC_NOT_EXIST.value,
}


ERROR_CODE_MAPPER: dict[int, str] = {
    HTTPStatus.NOT_FOUND: ReadableErrors.NOT_FOUND.value,
    HTTPStatus.UNPROCESSABLE_ENTITY: ReadableErrors.WRONG_PARAMETERS.value,
    HTTPStatus.INTERNAL_SERVER_ERROR: ReadableErrors.GENERAL.value,
    HTTPStatus.UNAUTHORIZED: ReadableErrors.UNAUTHORIZED.value,
    HTTPStatus.NO_CONTENT: ReadableErrors.NO_CONTENT.value,
}


class IOCType(str, Enum):
    FILE = "FILE"
    URL = "URL"
    IP = "IP"
    HASH = "HASH"
    EMAIL = "EMAIL"
    DOMAIN = "DOMAIN"


pattern_and_readable_error_by_ioc_type = {
    IOCType.URL: (urlRegex, ReadableErrors.URL),
    IOCType.IP: (ipv4Regex, ReadableErrors.IP),
    IOCType.HASH: (hashRegex, ReadableErrors.HASH),
    IOCType.EMAIL: (emailRegex, ReadableErrors.EMAIL),
}

WHITELIST_ADD = "Add to the user whitelist"
WHITELIST_DO_NOT = "Do not whitelist"


class ArgumentValues(list, Enum):  # type: ignore[misc]
    WHITELIST_STATUS = [WHITELIST_ADD, WHITELIST_DO_NOT]
    BOOLEAN = ["true", "false"]
    ALERT_TYPE = [
        "Attack Indication",
        "Data Leakage",
        "Phishing",
        "Brand Security",
        "Exploitable Data",
        "vip",
    ]
    ALERT_IOC_AND_DOCUMENT_SEVERITY = ["High", "Medium", "Low"]
    ALERT_SOURCE_NETWORK = ["Clear Web", "Dark Web"]
    ALERT_CLOSE_REASON = [
        "Problem Solved",
        "Informational Only",
        "Problem We Are Already Aware Of",
        "Company Owned Domain",
        "Legitimate Application/Profile",
        "Not Related To My Company",
        "False Positive",
        "Other",
    ]
    ALERT_BLOCKLIST = ["Sent", "Not Sent"]
    CVE_SEVERITY = ["High", "Medium", "Low", "Critical"]
    USER_TYPE = ["Admin", "Analyst"]
    MENTION_SOURCE_TYPE = [
        "Social Media",
        "Paste Site",
        "Hacking Forum",
        "Instant Message",
        "Black Market",
        "Cyber Security Blog",
        "Web Page",
    ]
    SOURCE_TYPE = [
        "Application Stores",
        "Black Market",
        "Hacking Forum",
        "Others",
        "Paste Site",
        "Social Media",
    ]


V1_PREFIX = "v1"
V2_PREFIX = "v2"
V3_PREFIX = "v3"
API_MAX_LIMIT = 1000
FETCH_LIMIT = 50
XSOAR_SEVERITY = {
    "Low": IncidentSeverity.LOW,
    "Medium": IncidentSeverity.MEDIUM,
    "High": IncidentSeverity.HIGH,
}
ALERT_WHITELIST = {
    WHITELIST_ADD: True,
    WHITELIST_DO_NOT: False,
}


class UrlPrefix(StrEnum):
    CYBER_TERM = "threat-library/cyber-terms"
    IOC_SOURCE = "iocs"
    ACCOUNT = "account"
    ASSET = "data/assets"
    CVE = "cves"
    ALERT = "data/alerts"
    IOC = "iocs"
    MSSP = "mssp"


class Parser:
    """
    This class will handle the objects input arguments API response outputs.
    """

    def cyber_term_cve_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse Cyber-term CVE response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Cyber-term CVE response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "id": obj.get("CveId"),
            "publish_date": obj.get("PublishedDate"),
            "vendor_product": obj.get("VendorProducts"),
        }

    def cyber_term_ioc_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse Cyber-term IOC response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Cyber-term IOC response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "value": obj.get("Value"),
            "type": obj.get("Type"),
            "updated_date": obj.get("UpdateDate"),
            "status": obj.get("Status"),
            "is_whitelisted": obj.get("Whitelisted"),
            "severity": obj.get("Severity"),
            "reporting_feeds": obj.get("ReportingFeeds"),
        }

    def cyber_term_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse Cyber-term response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Cyber-term response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "id": obj.get("ID"),
            "name": obj.get("Value"),
            "type": obj.get("Type"),
            "severity": obj.get("Severity"),
            "aliases": obj.get("Aliases"),
            "origins": obj.get("Origins"),
            "target_countries": obj.get("TargetCountries"),
            "sectors": obj.get("TargetSectors"),
            "created_date": obj.get("CreatedDate"),
            "updated_date": obj.get("UpdatedDate"),
            "ttp": obj.get("TTPs"),
            "overview": obj.get("Overview"),
            "additional_information": obj.get("AdditionalInformation"),
            "related_malware": obj.get("RelatedMalware"),
            "related_threat_actor": obj.get("RelatedThreatActors"),
            "related_campaigns": obj.get("RelatedCampaigns"),
            "MitreAttack": [
                {
                    "tactic": attack.get("ReportingFeeds"),
                    "Techniques": [
                        {
                            "name": tech.get("ReportingFeeds"),
                            "url": tech.get("ReportingFeeds"),
                        }
                        for tech in attack.get("Techniques", [])
                    ],
                }
                for attack in obj.get("MitreAttack", [])
            ],
        }

    def cve_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse CVE response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): CVE response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "id": obj.get("cveId"),
            "cpe": [
                {
                    "value": cpe.get("Value"),
                    "title": cpe.get("Title"),
                    "vendor_product": cpe.get("VendorProduct"),
                }
                for cpe in obj.get("cpe", [])
            ],
            "published_date": obj.get("publishedDate"),
            "update_date": obj.get("updateDate"),
            "severity": obj.get("severity"),
            "intsights_score": obj.get("intsightsScore"),
            "cvss_score": obj.get("cvssScore"),
            "social_media_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "SocialMedia"]
            ),
            "paste_site_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "PasteSite"]
            ),
            "hacking_forum_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "HackingForum"]
            ),
            "instant_message_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "InstantMessage"]
            ),
            "dark_web_mentions": dict_safe_get(obj, ["mentionsPerSource", "DarkWeb"]),
            "code_repositories_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "CodeRepositories"]
            ),
            "exploit_mentions": dict_safe_get(obj, ["mentionsPerSource", "Exploit"]),
            "clear_web_cyber_blogs_mentions": dict_safe_get(
                obj, ["mentionsPerSource", "ClearWebCyberBlogs"]
            ),
            "poc_mentions": dict_safe_get(obj, ["mentionsPerSource", "POC"]),
            "first_mention_date": obj.get("firstMentionDate"),
            "last_mention_date": obj.get("lastMentionDate"),
            "exploit_availability": obj.get("exploitAvailability"),
            "vulnerability_origin": obj.get("vulnerabilityOrigin"),
            "related_threat_actors": obj.get("relatedThreatActors"),
            "related_malware": obj.get("relatedMalware"),
            "related_campaigns": obj.get("relatedCampaigns"),
        }

    def alert_get_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse complete Alert response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Alert response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "id": obj.get("_id"),
            "assets": [
                {
                    "type": asset.get("Type"),
                    "value": asset.get("Value"),
                }
                for asset in obj.get("Assets", [])
            ],
            "assignees": obj.get("Assignees"),
            "type": dict_safe_get(obj, ["Details", "Type"]),
            "sub_type": dict_safe_get(obj, ["Details", "SubType"]),
            "title": dict_safe_get(obj, ["Details", "Title"]),
            "description": dict_safe_get(obj, ["Details", "Description"]),
            "severity": dict_safe_get(obj, ["Details", "Severity"]),
            "images": dict_safe_get(obj, ["Details", "Images"]),
            "source_type": dict_safe_get(obj, ["Details", "Source", "Type"]),
            "source_url": str(dict_safe_get(obj, ["Details", "Source", "URL"], "")),
            "source_email": "",
            "source_network_type": dict_safe_get(
                obj, ["Details", "Source", "NetworkType"]
            ),
            "source_date": str(dict_safe_get(obj, ["Details", "Source", "Date"], "")),
            "Tags": [
                {
                    "created_by": tag.get("CreatedBy"),
                    "name": tag.get("Name"),
                    "id": tag.get("_id"),
                }
                for tag in dict_safe_get(obj, ["Details", "Tags"], [])
            ],
            "related_iocs": obj.get("RelatedIocs"),
            "found_date": obj.get("FoundDate"),
            "update_date": obj.get("UpdateDate"),
            "takedown_status": obj.get("TakedownStatus"),
            "is_closed": dict_safe_get(obj, ["Closed", "IsClosed"]),
            "is_flagged": obj.get("IsFlagged"),
            "related_threat_ids": obj.get("RelatedThreatIDs"),
        }

    def alert_fetch_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse complete Alert response from the API to fetch XSOAR outputs.

        Args:
            obj (dict[str, Any]): Alert response from the API.

        Returns:
            dict[str, Any]: fetch XSOAR outputs.
        """
        return remove_empty_elements(
            {
                "id": obj.get("_id"),
                "found_date": obj.get("FoundDate"),
                "type": dict_safe_get(obj, ["Details", "Type"]),
                "severity": XSOAR_SEVERITY[dict_safe_get(obj, ["Details", "Severity"])],
                "title": dict_safe_get(obj, ["Details", "Title"]),
                "description": dict_safe_get(obj, ["Details", "Description"]),
                "update_date": obj.get("UpdateDate"),
                "Source": {
                    "type": dict_safe_get(obj, ["Details", "Source", "Type"]),
                    "network_type": dict_safe_get(
                        obj, ["Details", "Source", "NetworkType"]
                    ),
                    "email": "",
                    "url": dict_safe_get(obj, ["Details", "Source", "URL"]),
                    "date": dict_safe_get(obj, ["Details", "Source", "Date"]),
                },
                "related_iocs": obj.get("RelatedIocs"),
                "takedown_status": obj.get("TakedownStatus"),
                "Assets": [
                    {
                        "type": asset.get("Type"),
                        "value": asset.get("Value"),
                    }
                    for asset in obj.get("Assets", [])
                ],
                "related_threat_ids": obj.get("RelatedThreatIDs"),
                "Tags": [
                    {
                        "created_by": tag.get("CreatedBy"),
                        "name": tag.get("Name"),
                        "id": tag.get("_id"),
                    }
                    for tag in dict_safe_get(obj, ["Details", "Tags"], [])
                ],
                "is_closed": dict_safe_get(obj, ["Closed", "IsClosed"]),
                "sub_type": dict_safe_get(obj, ["Details", "SubType"]),
            }
        )

    def parse_incident(self, alert: dict) -> dict:
        """
        Parse alert to XSOAR Incident.
        Args:
            alert (dict): alert item.
        Returns:
            dict: XSOAR Incident.
        """
        incident = {
            "name": alert.get("id"),
            "occurred": alert.get("found_date"),
            "rawJSON": json.dumps(alert),
        }
        return incident

    def alert_activity_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse complete Alert activity response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Alert activity response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return remove_empty_elements(
            {
                "rate": dict_safe_get(obj, ["AdditionalInformation", "Status", "Rate"]),
                "type": obj.get("Type"),
                "sub_types": obj.get("SubTypes"),
                "initiator": obj.get("Initiator"),
                "created_date": obj.get("CreatedDate"),
                "update_date": obj.get("UpdateDate"),
                "read_by": obj.get("ReadBy"),
                "id": obj.get("_id"),
                "tag_names": dict_safe_get(obj, ["AdditionalInformation", "TagNames"]),
                "tag_ids": dict_safe_get(obj, ["AdditionalInformation", "TagIDs"]),
                "Mail": {
                    "note_id": dict_safe_get(
                        obj, ["AdditionalInformation", "Mail", "NoteId"]
                    ),
                    "question": dict_safe_get(
                        obj, ["AdditionalInformation", "Mail", "Question"]
                    ),
                    "Replies": [
                        {
                            "email": reply.get("Email"),
                            "token": reply.get("Token"),
                            "date": reply.get("Date"),
                            "read_by": reply.get("ReadBy"),
                            "is_token_valid": reply.get("IsTokenValid"),
                        }
                        for reply in dict_safe_get(
                            obj, ["AdditionalInformation", "Mail", "Replies"], []
                        )
                    ],
                },
                "Messages": [
                    {
                        "initiator_id": dict_safe_get(msg, ["Initiator", "_id"]),
                        "initiator_is_support": dict_safe_get(
                            msg, ["Initiator", "IsSupport"]
                        ),
                        "date": msg.get("Date"),
                        "content": msg.get("Content"),
                    }
                    for msg in dict_safe_get(
                        obj, ["AdditionalInformation", "AskTheAnalyst", "Messages"], []
                    )
                ],
            }
        )

    def ioc_get_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse IOC response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): IOC response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return {
            "value": obj.get("value"),
            "type": obj.get("type"),
            "status": obj.get("status"),
            "severity": obj.get("severity"),
            "score": obj.get("score"),
            "last_update_date": obj.get("lastUpdateDate"),
            "last_seen": obj.get("lastSeen"),
            "first_seen": obj.get("firstSeen"),
            "related_malware": obj.get("relatedMalware"),
            "related_campaigns": obj.get("relatedCampaigns"),
            "related_threat_actors": obj.get("relatedThreatActors"),
            "ReportedFeeds": [
                {
                    "id": feed.get("id"),
                    "name": feed.get("name"),
                    "confidence_level": feed.get("confidenceLevel"),
                }
                for feed in obj.get("reportedFeeds", [])
            ],
            "is_whitelisted": obj.get("whitelisted"),
            "tags": obj.get("tags"),
        }

    def ioc_enrich_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse IOC enrich response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): IOC enrich response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return remove_empty_elements(
            {
                "value": obj.get("Value"),
                "type": obj.get("Type"),
                "Sources": [
                    {
                        "name": source.get("Name"),
                        "confidence_level": source.get("ConfidenceLevel"),
                    }
                    for source in obj.get("Sources", [])
                ],
                "system_tags": obj.get("SystemTags"),
                "tags": obj.get("Tags"),
                "status": obj.get("Status"),
                "is_known_ioc": obj.get("IsKnownIoc"),
                "related_threat_actors": obj.get("RelatedThreatActors"),
                "related_campaign": obj.get("RelatedCampaigns"),
                "first_seen": obj.get("FirstSeen"),
                "last_seen": obj.get("LastSeen"),
                "update_seen": obj.get("UpdateDate"),
                "is_whitelisted": obj.get("Whitelisted"),
                "Severity": {
                    "value": dict_safe_get(obj, ["Severity", "Value"]),
                    "score": dict_safe_get(obj, ["Severity", "Score"]),
                    "origin": dict_safe_get(obj, ["Severity", "Origin"]),
                },
                "DnsRecord": [
                    {
                        "value": record.get("Value"),
                        "type": record.get("Type"),
                        "first_resolved": record.get("FirstResolved"),
                        "last_resolved": record.get("LastResolved"),
                        "count": record.get("Count"),
                    }
                    for record in obj.get("DnsRecords", [])
                ],
                "subdomains": obj.get("Subdomains"),
                "History": [
                    {
                        "status": source.get("Statuses"),
                        "name_servers": source.get("NameServers"),
                    }
                    for source in dict_safe_get(obj, ["Whois", "History"], [])
                ],
                "Current": {
                    "status": dict_safe_get(obj, ["Whois", "Current", "Statuses"]),
                    "name_servers": dict_safe_get(
                        obj, ["Whois", "Current", "NameServers"]
                    ),
                },
                "Resolution": [
                    {
                        "resolved_ip_address": res.get("ResolvedIpAddress"),
                        "resolved_domain": res.get("ResolvedDomain"),
                        "reporting_sources": res.get("ReportingSources"),
                    }
                    for res in obj.get("Resolutions", [])
                ],
                "RelatedHash": {
                    "downloaded": dict_safe_get(obj, ["RelatedHashes", "downloaded"]),
                    "communicating": dict_safe_get(
                        obj, ["RelatedHashes", "communicating"]
                    ),
                    "referencing": dict_safe_get(obj, ["RelatedHashes", "referencing"]),
                    "Hashes": [
                        {
                            "type": res.get("Type"),
                            "value": res.get("Value"),
                        }
                        for res in obj["RelatedHashes"]
                    ]
                    if isinstance(obj["RelatedHashes"], list)
                    else None,
                },
                "antivirus_scan_date": obj.get("AntivirusScanDate"),
                "file_name": obj.get("FileName"),
                "file_type": obj.get("FileType"),
                "file_author": obj.get("FileAuthor"),
                "file_description": obj.get("FileDescription"),
                "file_size": obj.get("FileSize"),
                "antivirus_detection_ratio": obj.get("AntivirusDetectionRatio"),
                "antivirus_detected_engines": obj.get("AntivirusDetectedEngines"),
                "ip_range": dict_safe_get(obj, ["Whois", "NetworkDetails", "IPRange"]),
                "AntivirusDetection": [
                    {
                        "name": res.get("Name"),
                        "version": res.get("Version"),
                        "detected": res.get("Detected"),
                        "result": res.get("Result"),
                    }
                    for res in obj.get("AntivirusDetections", [])
                ],
            }
        )

    def mention_parser(self, obj: dict[str, Any]) -> dict[str, Any]:
        """
        Parse mention response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Mention response from the API.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        return remove_empty_elements(
            {
                "author": obj.get("Author"),
                "comment_number": obj.get("CommentNumber"),
                "original_url": obj.get("OriginalUrl"),
                "source_date": obj.get("SourceDate"),
                "url": obj.get("Url"),
                "insertion_date": obj.get("InsertionDate"),
                "type": obj.get("Type"),
                "Tags": obj.get("Tags"),
                "id": obj.get("id"),
                "short_content": obj.get("ShortContent"),
                "title": obj.get("Title"),
                "date": obj.get("Date"),
            }
        )

    def file_reputation_parser(
        self, obj: dict[str, Any], reliability, hash_
    ) -> dict[str, Any]:
        """
        Parse hash enrichment response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Hash enrichment response from the API.
            reliability (_type_): Reliability of the source providing the intelligence data.
            hash_ (bool): Hash value.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        related_hashes = get_enrich_hashes(obj)
        is_known_ioc = dict_safe_get(obj, ["Data", "IsKnownIoc"])
        dbot_score = get_dbotscore(reliability, hash_, is_known_ioc)
        tags = dict_safe_get(obj, ["Data", "Tags"], []) + dict_safe_get(
            obj, ["Data", "SystemTags"], []
        )
        return remove_empty_elements(
            {
                "md5": related_hashes.get("md5"),
                "sha1": related_hashes.get("SHA1"),
                "sha256": related_hashes.get("SHA256"),
                "sha512": related_hashes.get("SHA512"),
                "name": dict_safe_get(obj, ["Data", "FileName"]),
                "description": dict_safe_get(obj, ["Data", "FileDescription"]),
                "size": dict_safe_get(obj, ["Data", "FileSize"]),
                "file_type": dict_safe_get(obj, ["Data", "FileType"]),
                "tags": tags,
                "actor": dict_safe_get(obj, ["Data", "RelatedThreatActors"]),
                "campaign": dict_safe_get(obj, ["Data", "RelatedCampaigns"]),
                "associated_file_names": get_enrich_file_nams(obj),
                "dbot_score": dbot_score,
            }
        )

    def ip_reputation_parser(
        self, obj: dict[str, Any], reliability, ip
    ) -> dict[str, Any]:
        """
        Parse IP enrichment response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): IP enrichment response from the API.
            reliability (_type_): Reliability of the source providing the intelligence data.
            ip (bool): IP value.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        is_known_ioc = dict_safe_get(obj, ["Data", "IsKnownIoc"])
        dbot_score = get_dbotscore(reliability, ip, is_known_ioc)
        tags = dict_safe_get(obj, ["Data", "Tags"], []) + dict_safe_get(
            obj, ["Data", "SystemTags"], []
        )
        return remove_empty_elements(
            {
                "ip": ip,
                "asn": dict_safe_get(obj, ["Data", "IpDetails", "ASN"]),
                "region": dict_safe_get(obj, ["Data", "IpDetails", "Country"]),
                "updated_date": dict_safe_get(obj, ["Data", "UpdateDate"]),
                "campaign": dict_safe_get(obj, ["Data", "RelatedCampaigns"]),
                "tags": tags,
                # "whois_records": dict_safe_get(
                #     obj, ["Data", "Whois", "RegistrantDetails"]
                # ),
                "dbot_score": dbot_score,
            }
        )

    def url_reputation_parser(
        self, obj: dict[str, Any], reliability, url
    ) -> dict[str, Any]:
        """
        Parse url enrichment response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Url enrichment response from the API.
            reliability (_type_): Reliability of the source providing the intelligence data.
            url (bool): url value.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        is_known_ioc = dict_safe_get(obj, ["Data", "IsKnownIoc"])
        dbot_score = get_dbotscore(reliability, url, is_known_ioc)
        antivirus_detected_engines: str = dict_safe_get(
            obj, ["Data", "AntivirusDetectedEngines"]
        )
        if len(antivirus_detected_engines.split("/")) == 2:
            detection_engines = antivirus_detected_engines.split("/")[1]
            positive_detections = antivirus_detected_engines.split("/")[0]
        else:
            detection_engines = None
            positive_detections = None

        tags = dict_safe_get(obj, ["Data", "Tags"], []) + dict_safe_get(
            obj, ["Data", "SystemTags"], []
        )
        return remove_empty_elements(
            {
                "url": url,
                "detection_engines": detection_engines,
                "positive_detections": positive_detections,
                "campaign": dict_safe_get(obj, ["Data", "RelatedCampaigns"]),
                "tags": tags,
                "dbot_score": dbot_score,
            }
        )

    def domain_reputation_parser(
        self, obj: dict[str, Any], reliability, domain
    ) -> dict[str, Any]:
        """
        Parse domain enrichment response from the API to XSOAR outputs.

        Args:
            obj (dict[str, Any]): Domain enrichment response from the API.
            reliability (_type_): Reliability of the source providing the intelligence data.
            domain (bool): domain value.

        Returns:
            dict[str, Any]: XSOAR outputs.
        """
        is_known_ioc = dict_safe_get(obj, ["Data", "IsKnownIoc"])
        dbot_score = get_dbotscore(reliability, domain, is_known_ioc)
        tags = dict_safe_get(obj, ["Data", "Tags"], []) + dict_safe_get(
            obj, ["Data", "SystemTags"], []
        )
        dns_records: List[Common.DNSRecord] = []
        for dns in dict_safe_get(obj, ["Data", "DnsRecords"], []):
            dns_records.append(
                Common.DNSRecord(
                    dns_record_type=dns["Type"], dns_record_data=dns["Value"]
                )
            )
        return remove_empty_elements(
            {
                "domain": domain,
                # "whois_records": dict_safe_get(obj, ["Data", "Whois"]),
                "dns_records": dns_records,
                "updated_date": dict_safe_get(obj, ["Data", "UpdateDate"]),
                "tags": tags,
                "sub_domains": dict_safe_get(obj, ["Data", "Subdomains"]),
                "campaign": dict_safe_get(obj, ["Data", "RelatedCampaigns"]),
                "dbot_score": dbot_score,
            }
        )
        # ) | {"dns_records": dns_records}


class Client(BaseClient):
    """Client class to interact with Threat Command API."""

    def __init__(
        self,
        base_url: str,
        account_id: str,
        api_key: str,
        mssp_sub_account: str | None,
        reliability: str,
        verify: bool,
        proxy: bool,
    ):
        self.reliability = reliability
        base_url = urljoin(base_url, "public")
        self.parser = Parser()
        super().__init__(
            base_url=base_url,
            headers=remove_empty_elements({"Account-Id": mssp_sub_account}),
            verify=verify,
            proxy=proxy,
            auth=(account_id, api_key),
        )

    def _http_request(self, *args, **kwargs):
        """
        Warp to _http_request command. I use it because sometimes the API response code is 200
        but there is an error with the request. The error flag located in the response body.

        Raises:
            DemistoException: Error response.
            DemistoException: Error response.

        Returns:
            Response | dict[str,Any]: API response from Threat Command API.
        """
        kwargs["error_handler"] = self.error_handler
        demisto.debug(f'Making API request at {kwargs.get("method")} {kwargs.get("url_suffix")} '
                      f'with params:{kwargs.get("params")} and body:{kwargs.get("json_data")}')
        res = super()._http_request(backoff_factor=BACKOFF_FACTOR, retries=RETRIES,  # type: ignore
                                    status_list_to_retry=STATUS_LIST_TO_RETRY, raise_on_status=True,  # type: ignore
                                    *args, **kwargs)  # type: ignore
        if isinstance(res, dict):
            if (
                res.get("Success") is False
                and (data := res.get("Data"))
                and ERROR_RESPONSE_MAPPER.get(data)
            ):
                raise DemistoException(message=ERROR_RESPONSE_MAPPER.get(data))
            if dict_safe_get(res, ["content", "success"]) is False:
                raise DemistoException(message=res)
        return res

    def error_handler(self, res: Response):
        """
        Handling with request errors.

        Args:
            res (Response): API response from Threat Command API.

        Raises:
            DemistoException: Error response.
            DemistoException: Error response.
            DemistoException: Error response.
            DemistoException: Error response.
        """
        error_str = f"Status Code: {res.status_code}, Message: {res.text}"
        if isinstance(res, Response):
            if ERROR_RESPONSE_MAPPER.get(res.content.decode()):
                raise DemistoException(ERROR_RESPONSE_MAPPER.get(res.content.decode()))
            if ERROR_CODE_MAPPER.get(res.status_code):
                raise DemistoException(f"Status Code: {res.status_code}, {ERROR_CODE_MAPPER.get(res.status_code)}")
        raise DemistoException(message=error_str)

    def list_cyber_term_cve(self, cyber_term_id: str) -> dict[str, Any]:
        """
        List the Cyber-term CVEs.

        Args:
            cyber_term_id (str): The ID of the cyber-term.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CYBER_TERM}/{cyber_term_id}/cves"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def list_cyber_term_ioc(
        self,
        cyber_term_id: str,
        limit: int,
        ioc_type: str | None,
        offset: str | None,
    ) -> dict[str, Any]:
        """
        List the Cyber-term IOCs.

        Args:
            cyber_term_id (str | None): The ID of the cyber-term.
            limit (int): The maximum number of records to retrieve.
            ioc_type (str | None): IOC type to filter.
            offset (str | None): Offset for pagination.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """

        params = remove_empty_elements(
            {
                "iocType": remove_whitespaces(ioc_type),
                "limit": limit,
                "offset": offset,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CYBER_TERM}/{cyber_term_id}/iocs"
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def list_cyber_term(
        self,
        search: str | None,
        types_: List[str] | None,
        severities: List[str] | None,
        sectors: List[str] | None,
        countries: List[str] | None,
        origin: List[str] | None,
        ttp: List[str] | None,
        last_update_from: str | None,
        last_update_to: str | None,
        limit: int,
        offset: str | None,
    ) -> dict[str, Any]:
        """List Cyber terms.

        Args:
            search (str | None): Filter by free text, which can be the cyber term name or ID.
            types_ (str | None): Filter by one or more cyber term types.
            severities (str | None): Filter by one or more cyber term severities.
            sectors (List[str] | None): Filter by one or more targeted sectors.
            countries (List[str] | None): Filter by one or more targeted countries.
            origin (List[str] | None): Filter by one or more nationalities.
            ttp (List[str] | None): Filter by one or more TTPs.
            last_update_from (str | None): Filter by last update date is greater than (in ISO 8601 format).
            last_update_to (str | None): Filter by last update date is less than (in ISO 8601 format).
            limit (int): The maximum number of records to retrieve.
            offset (str | None): Offset for pagination.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {
                "search": search,
                "type": [remove_whitespaces(type_) for type_ in types_]
                if types_
                else None,
                "severity": severities,
                "target-sector": sectors,
                "target-country": countries,
                "origin": origin,
                "ttp": ttp,
                "last-update-from": last_update_from,
                "last-update-to": last_update_to,
                "limit": limit,
                "offset": offset,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CYBER_TERM}"
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def list_source(self) -> dict[str, Any]:
        """
        List the IOC sources.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/sources"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def create_document_source(
        self,
        name: str,
        description: str,
        confidence_level: int,
        share: bool | None,
        severity: str | None,
        tags: List[str],
        domains: List[str],
        urls: List[str],
        ips: List[str],
        hashes: List[str],
        emails: List[str],
    ) -> dict[str, Any]:
        """
        Create document source.

        Args:
            name (str): Source name.
            description (str): Source description.
            confidence_level (int): Source confidence level.
            share (bool | None): Share this source with all tenants (available for MSSP users only).
            severity (str | None): Source severity level.
            tags (List[str]): A list of user tags for the document.
            domains (List[str]): A list of domain IOC values to add.
            urls (str): A list of URL IOC values to add.
            ips (List[str]): A list of IP IOC values to add.
            hashes (List[str]): A list hash domain IOC values to add.
            emails (List[str]): A list of email IOC values to add.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = remove_empty_elements(
            {
                "DocumentDetails": {
                    "Name": name,
                    "Description": description,
                    "ConfidenceLevel": confidence_level,
                    "Share": share,
                    "Severity": severity.lower() if severity else None,
                    "Tags": tags,
                },
                "Iocs": map_ioc_list(
                    domains=domains, urls=urls, ips=ips, hashes=hashes, emails=emails
                ),
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/add-source"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
        )

    def delete_document_source(self, source_id: str) -> Response:
        """
        Delete document source.

        Args:
            source_id (str): The ID of the document source.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/delete-source/{source_id}"
        return self._http_request(
            method="DELETE",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            resp_type="response",
        )

    def create_document_source_ioc(
        self,
        source_id: str,
        domains: List[str],
        urls: List[str],
        ips: List[str],
        hashes: List[str],
        emails: List[str],
    ) -> Response:
        """
        Create new IOCs to existing IOC source documents.

        Args:
            source_id (str): The ID of the document source.
            domains (List[str]): A list of domain IOC values to add.
            urls (str): A list of URL IOC values to add.
            ips (List[str]): A list of IP IOC values to add.
            hashes (List[str]): A list hash domain IOC values to add.
            emails (List[str]): A list of email IOC values to add.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = remove_empty_elements(
            {
                "Iocs": map_ioc_list(
                    domains=domains,
                    urls=urls,
                    ips=ips,
                    hashes=hashes,
                    emails=emails,
                )
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/add-iocs-to-source/{source_id}"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            ok_codes=[HTTPStatus.OK],
            resp_type="response",
        )

    def list_system_modules(self) -> dict[str, Any]:
        """
        List the system modules.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ACCOUNT}/system-modules"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def add_asset(self, asset_type: str, asset_value: str) -> Response:
        """
        Add a new asset to asset list.

        Args:
            asset_type (str): The type of the asset.
            asset_value (str): The asset value.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"AssetType": asset_type, "AssetValue": asset_value}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ASSET}/add-asset"
        return self._http_request(
            method="PUT",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            json_data=payload,
            resp_type="response",
        )

    def delete_asset(self, asset_type: str, asset_value: str) -> Response:
        """
        Delete an asset to asset list.

        Args:
            asset_type (str): The type of the asset.
            asset_value (str): The asset value.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"AssetType": asset_type, "AssetValue": asset_value}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ASSET}/delete-asset"
        return self._http_request(
            method="DELETE",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            json_data=payload,
            resp_type="response",
        )

    def list_assets(self, asset_types: List[str] | None) -> dict[str, Any]:
        """
        List assets.

        Args:
            asset_types (List[str] | None): Type for filter.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {"assetTypes": asset_types if asset_types else None}
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ASSET}/account-assets"
        return self._http_request(
            method="GET", url_suffix=url_suffix, ok_codes=[HTTPStatus.OK], params=params
        )

    def list_asset_types(self) -> List[str]:
        """
        List asset types.

        Returns:
            List[str]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ASSET}/assets-types"
        return self._http_request(
            method="GET", url_suffix=url_suffix, ok_codes=[HTTPStatus.OK]
        )

    def list_cve(
        self,
        offset: str | None,
        publish_date_from: str | None,
        publish_date_to: str | None,
        update_date_from: str | None,
        update_date_to: str | None,
        severity_list: List[str] | None,
        cpe_list: List[str] | None,
        cve_ids: List[str] | None,
    ) -> dict[str, Any]:
        """
        List of CVEs.

        Args:
            offset (str | None): Offset for pagination.
            publish_date_from (str | None): Publish date from.
            publish_date_to (str | None): Publish date to.
            update_date_from (str | None): Update date from.
            update_date_to (str | None): Update date to.
            severity_list (List[str] | None): Severity list.
            cpe_list (List[str] | None): CPE list.
            cve_ids (List[str] | None): CVE IDs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {
                "publishDateFrom": publish_date_from,
                "publishDateTo": publish_date_to,
                "updateDateFrom": update_date_from,
                "updateDateTo": update_date_to,
                "severity": severity_list if severity_list else None,
                "cpe": cpe_list if cpe_list else None,
                "cveId": cve_ids if cve_ids else None,
                "offset": offset,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CVE}/get-cves-list"
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def add_cve(self, cve_ids: List[str]) -> dict[str, Any]:
        """
        Add CVEs to account.

        Args:
            cve_ids (List[str]): List of CVE IDs to add.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = {"cveIds": cve_ids}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CVE}/add-cves"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            json_data=payload,
        )

    def delete_cve(self, cve_ids: List[str]) -> dict[str, Any]:
        """
        Delete CVEs from account.

        Args:
            cve_ids (List[str]): List of CVE IDs to delete.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = {"cveIds": cve_ids}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.CVE}/delete-cves"
        return self._http_request(
            method="DELETE",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            json_data=payload,
        )

    def list_alert(
        self,
        limit: int,
        is_closed: bool,
        offset: str | None = None,
        last_updated_from: str | None = None,
        last_updated_to: str | None = None,
        alert_type: List[str] | None = None,
        severity: List[str] | None = None,
        source_type: List[str] | None = None,
        network_type: List[str] | None = None,
        matched_asset_value: List[str] | None = None,
        source_date_from: str | None = None,
        source_date_to: str | None = None,
        found_date_from: str | None = None,
        found_date_to: str | None = None,
        assigned: bool | None = None,
        is_flagged: bool | None = None,
        has_ioc: bool | None = None,
    ) -> dict[str, Any]:
        """
        List alerts with updated date.

        Args:
            limit (int): Limit for pagination.
            is_closed (bool): Whether the alert is closed.
            offset (str | None): Offset for pagination.
            last_updated_from (str | None): Last updated from date for filter.
            last_updated_to (str | None): Last updated to date for filter.
            alert_type (List[str] | None): Alert types for filter.
            severity (List[str] | None): Alert severities for filter.
            source_type (List[str] | None): Alert source types for filter.
            network_type (List[str] | None): Alert network types for filter.
            matched_asset_value (List[str] | None): Alert matched asset values for filter.
            source_date_from (str | None): Source date from for filter.
            source_date_to (str | None): Source date to for filter.
            found_date_from (str | None): Found date from for filter.
            found_date_to (str | None): Found date from for filter.
            assigned (bool | None): Assigned user for filter.
            is_flagged (bool | None): Whether the alert is flagged.
            has_ioc (bool | None): Whether the alert has IOCs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {
                "lastUpdatedFrom": last_updated_from,
                "lastUpdatedTo": last_updated_to,
                "alertType": [remove_whitespaces(_type) for _type in alert_type]
                if alert_type
                else None,
                "severity": severity if severity else None,
                "sourceType": [remove_whitespaces(_type) for _type in source_type]
                if source_type
                else None,
                "networkType": [remove_whitespaces(_type) for _type in network_type]
                if network_type
                else None,
                "matchedAssetValue": matched_asset_value
                if matched_asset_value
                else None,
                "sourceDateFrom": source_date_from,
                "sourceDateTo": source_date_to,
                "foundDateFrom": found_date_from,
                "foundDateTo": found_date_to,
                "assigned": str(assigned).lower() if assigned else None,
                "isFlagged": str(is_flagged).lower() if is_flagged else None,
                "isClosed": str(is_closed).lower() if is_closed else None,
                "hasIoc": str(has_ioc).lower() if has_ioc else None,
                "limit": limit,
                "offset": offset,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/update-alerts"
        return self._http_request(
            method="GET", url_suffix=url_suffix, params=params, ok_codes=[HTTPStatus.OK]
        )

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """
        Get alert with complete details.

        Args:
            alert_id (str): Alert ID.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/get-complete-alert/{alert_id}"
        return self._http_request(
            method="GET", url_suffix=url_suffix, ok_codes=[HTTPStatus.OK]
        )

    def create_alert(
        self,
        title: str,
        description: str,
        type_: str | None,
        sub_type: str | None,
        severity: str,
        source_type: str,
        source_network_type: str,
        source_date: str | None,
        found_date: str | None,
        image_entry_ids: List[str],
        scenario: str | None,
        source_url: str | None,
    ) -> Response:
        """
        Create a new alert.

        Args:
            title (str): Title for the alert.
            description (str): Description for the alert.
            type_ (str | None): Type for the alert.
            sub_type (str | None): Sub-type for the alert.
            severity (str): Severity.
            source_type (str): Source type.
            source_network_type (str): Source network.
            source_date (str | None): Source date.
            found_date (str | None): Found date.
            image_entry_ids (List[str]]): Images data.
            scenario (str | None): Scenario.
            source_url (str | None): Source URL.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = remove_empty_elements(
            {
                "FoundDate": found_date,
                "Details": {
                    "Title": title,
                    "Description": description,
                    "Type": remove_whitespaces(type_),
                    "SubType": sub_type,
                    "Severity": severity,
                    "Source": {
                        "Type": source_type,
                        "NetworkType": remove_whitespaces(source_network_type),
                        "URL": source_url,
                        "Date": source_date if source_date else "",
                    },
                    "Images": files_handler(file_ids=image_entry_ids, is_image=True),
                },
                "Scenario": scenario,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/add-alert"

        return self._http_request(
            method="PUT",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK],
            json_data=payload,
            resp_type="response",
        )

    def close_alert(
        self,
        alert_id: str,
        reason: str,
        comment: str | None,
        is_hidden: bool,
        rate: int | None,
    ) -> Response:
        """
        Close alert.

        Args:
            alert_id (str): Alert ID.
            reason (str): Close reason.
            comment (str | None): Close comment.
            is_hidden (bool): Alerts' hidden status.
            rate (int | None): Alert's rate

        Returns:
            Response: API response from Threat Command API.
        """
        payload = remove_empty_elements(
            {
                "Reason": remove_whitespaces(reason),
                "FreeText": comment,
                "IsHidden": is_hidden,
                "Rate": rate,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/close-alert/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def update_alert_severity(self, alert_id: str, severity: str) -> Response:
        """
        Update alert severity.

        Args:
            alert_id (str): Alert ID.
            severity (str): Alert severity.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"Severity": severity}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/change-severity/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def assign_alert(self, alert_id: str, user_id: str, is_mssp: bool) -> Response:
        """
        Assign alert to user.

        Args:
            alert_id (str): Alert ID.
            user_id (str): User ID.
            is_mssp (bool): Whether to user is MSSP.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {
            "AssigneeID": user_id,
            "IsMssp": is_mssp,
        }
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/assign-alert/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def unassign_alert(self, alert_id: str) -> Response:
        """
        Unassign alert.

        Args:
            alert_id (str): Alert ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/unassign-alert/{alert_id}"
        return self._http_request(
            method="PATCH", url_suffix=url_suffix, resp_type="response"
        )

    def reopen_alert(self, alert_id: str) -> Response:
        """
        Re-open alert.

        Args:
            alert_id (str): Alert ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/reopen-alert/{alert_id}"
        return self._http_request(
            method="PATCH", url_suffix=url_suffix, resp_type="response"
        )

    def tag_alert(self, alert_id: str, tag_name: str) -> Response:
        """
        Add a tag to alert.

        Args:
            alert_id (str): Alert ID.
            tag_name (str): Tag to add.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {
            "TagName": tag_name,
        }
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/add-tag/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def untag_alert(self, alert_id: str, tag_id: str) -> Response:
        """
        Remove a tag to alert.

        Args:
            alert_id (str): Alert ID.
            tag_id (str): Tag ID to remove.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {
            "TagID": tag_id,
        }
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/remove-tag/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def send_mail_alert(
        self, alert_id: str, email_addresses: List[str], content: str
    ) -> Response:
        """
        Send mail with the alert details and a question.


        Args:
            alert_id (str): Alert ID.
            email_addresses (List[str]): List of mails to send.
            content (str): Content.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"Emails": email_addresses, "Content": content}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/send-mail/{alert_id}"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def analyst_ask_alert(self, alert_id: str, question: str) -> Response:
        """
        Send a question to an analyst about the requested alert.

        Args:
            alert_id (str): Alert ID.
            question (str): Question to ask.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"Question": question}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/ask-the-analyst/{alert_id}"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def list_alert_conversation(self, alert_id: str) -> Response:
        """
        List alert's analyst response.

        Args:
            alert_id (str): Alert ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/ask-the-analyst-conversation/{alert_id}"
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            ok_codes=[HTTPStatus.OK, HTTPStatus.NO_CONTENT],
            resp_type="response",
        )

    def list_alert_activity(self, alert_id: str) -> List[dict[str, Any]]:
        """
        Get alert activity log.

        Args:
            alert_id (str): Alert ID.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/activity-log/{alert_id}"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def add_alert_note(
        self, alert_id: str, note: str, file_entry_ids: List[str]
    ) -> Response:
        """
        Add note to alert.

        Args:
            alert_id (str): Alert ID.
            note (str): Note text to add.
            file_entry_ids (List[str]): File entry ids.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"Note": note, "Files": files_handler(file_ids=file_entry_ids)}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/add-note/{alert_id}"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def get_alert_blocklist(self, alert_id: str) -> List[dict[str, Any]]:
        """
        Get alert blocklist.

        Args:
            alert_id (str): Alert ID.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/blocklist-status/{alert_id}"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def update_alert_blocklist(
        self,
        alert_id: str,
        domains: List[str],
        urls: List[str],
        ips: List[str],
        emails: List[str],
        blocklist_status: str,
    ) -> Response:
        """
        Update alert blocklist.

        Args:
            alert_id (str): Alert ID.
            domains (List[str]): Domains IOCs.
            urls (List[str]): URL IOCs.
            ips (List[str]): IP IOCs.
            emails (List[str]): Email IOCs.
            blocklist_status (str): Blocklist status.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = remove_empty_elements(
            {
                "Iocs": map_ioc_list(
                    domains=domains,
                    urls=urls,
                    ips=ips,
                    emails=emails,
                    blocklist_status=remove_whitespaces(blocklist_status),
                )
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/change-iocs-blocklist-status/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            ok_codes=[HTTPStatus.OK],
            resp_type="response",
        )

    def get_alert_image(self, image_id: str) -> Response:
        """
        Get alert image.

        Args:
            image_id (str): Image ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/alert-image/{image_id}"
        return self._http_request(
            method="GET", url_suffix=url_suffix, resp_type="response"
        )

    def takedown_alert(
        self, alert_id: str, target: str, close_alert_after_success: bool
    ) -> Response:
        """
        Takedown alert.

        Args:
            alert_id (str): Alert ID.
            target (str): Target.
            close_alert_after_success (bool): Whether to close after success.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {
            "Target": target,
            "ShouldCloseAlertAfterSuccess": close_alert_after_success,
        }
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/takedown-request/{alert_id}"
        return self._http_request(
            method="PATCH",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def get_takedown_alert(self, alert_id: str) -> Response:
        """
        Get takedown status.

        Args:
            alert_id (str): Alert ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/takedown-status/{alert_id}"
        return self._http_request(
            method="GET", url_suffix=url_suffix, resp_type="response"
        )

    def list_alert_type(self) -> dict[str, Any]:
        """
        List alert types.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/types-subtypes-relations"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def list_alert_source_type(self) -> List[dict[str, Any]]:
        """
        List alert sub-types.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/source-types"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def list_alert_scenario(
        self, type_: str | None, sub_type: str | None
    ) -> List[dict[str, Any]]:
        """
        List alert scenarios.

        Args:
            type_ (str | None): Filter by type.
            sub_type (str | None): Filter by sub-type.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {"type": remove_whitespaces(type_), "subType": sub_type}
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/scenario-relations"
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def report_alert_ioc(self, alert_id: str, external_sources: List[str]) -> Response:
        """
        List alert scenarios.

        Args:
            alert_id (str): Alert ID.
            external_sources (List[str]): External sources to report.

        Returns:
            Response: API response from Threat Command API.
        """
        payload = {"ExternalSources": external_sources}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/report-iocs/{alert_id}"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            resp_type="response",
        )

    def list_account_user(
        self, user_type: str | None, user_email: str | None, user_id: str | None
    ) -> List[dict[str, Any]]:
        """List account users.

        Args:
            user_type (str | None): User type for filter.
            user_email (str | None): User Emails for filter.
            user_id (str | None): User ID for filter.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {
                "userType": user_type,
                "userEmail": user_email,
                "userId": user_id,
            }
        )
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ACCOUNT}/users-details"
        return self._http_request(
            method="GET", url_suffix=url_suffix, params=params, ok_codes=[HTTPStatus.OK]
        )

    def get_ioc(self, ioc_value: str) -> dict[str, Any]:
        """
        Get IOC.

        Args:
            ioc_value (str): IOC value.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = {
            "iocValue": ioc_value,
        }
        url_suffix = f"{V3_PREFIX}/{UrlPrefix.IOC}/ioc-by-value"
        return self._http_request(
            method="GET", url_suffix=url_suffix, params=params, ok_codes=[HTTPStatus.OK]
        )

    def list_ioc(
        self,
        last_updated_from: str | None,
        last_updated_to: str | None,
        last_seen_from: str | None,
        last_seen_to: str | None,
        first_seen_from: str | None,
        first_seen_to: str | None,
        status: str | None,
        type_list: List[str] | None,
        severity_list: List[str] | None,
        whitelisted: bool | None,
        source_ids: List[str] | None,
        kill_chain_phases: List[str] | None,
        limit: str,
        offset: str | None,
    ) -> dict[str, Any]:
        """
        List IOCs.

        Args:
            last_updated_from (str | None): Last updated from filter.
            last_updated_to (str | None): Last updated to filter.
            last_seen_from (str | None): Last seen from filter.
            last_seen_to (str | None): Last seen to filter.
            first_seen_from (str | None): First seen from filter.
            first_seen_to (str | None): First seen to filter.
            status (str | None): Status filter.
            type_list (List[str] | None): List of types for filter.
            severity_list (List[str] | None): List of severities for filter.
            whitelisted (bool | None): Whitelist filter.
            source_ids (List[str] | None): List of source IDs for filter.
            kill_chain_phases (List[str] | None): List of phases for filter.
            limit (str): limit gor pagination.
            offset (str | None): Offset for pagination.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        params = remove_empty_elements(
            {
                "lastUpdatedFrom": last_updated_from,
                "lastUpdatedTo": last_updated_to,
                "lastSeenFrom": last_seen_from,
                "lastSeenTo": last_seen_to,
                "firstSeenFrom": first_seen_from,
                "firstSeenTo": first_seen_to,
                "status": status,
                "type": [remove_whitespaces(type) for type in type_list]
                if type_list
                else None,
                "severity": severity_list if severity_list else None,
                "whitelisted": whitelisted,
                "sourceIds": source_ids if source_ids else None,
                "killChainPhases": [
                    remove_whitespaces(phase) for phase in kill_chain_phases
                ]
                if kill_chain_phases
                else None,
                "limit": limit,
                "offset": offset,
            }
        )
        url_suffix = f"{V3_PREFIX}/{UrlPrefix.IOC}"
        return self._http_request(
            method="GET", url_suffix=url_suffix, params=params, ok_codes=[HTTPStatus.OK]
        )

    def tags_ioc(self, ioc_value: str, tag_values: List[str]) -> dict[str, Any]:
        """
        Add tags for IOC.

        Args:
            ioc_value (str): IOC value.
            tag_values (List[str]): Tag to add.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = [{"iocValue": ioc_value, "tag": tag} for tag in tag_values]
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC}/tags"
        return self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=payload,
            ok_codes=[HTTPStatus.OK],
        )

    def update_ioc_severity(
        self, severity: str, ioc_values: List[str]
    ) -> dict[str, Any]:
        """
        Update severity to IOCs.

        Args:
            severity (str): Severity to update.
            ioc_values (List[str]): IOC values.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = [{"iocValue": ioc, "severity": severity} for ioc in ioc_values]
        url_suffix = f"{V2_PREFIX}/{UrlPrefix.IOC_SOURCE}/severity"
        return self._http_request(
            method="PATCH", url_suffix=url_suffix, json_data=payload
        )

    def add_ioc_comment(self, comment: str, ioc_values: List[str]) -> dict[str, Any]:
        """
        Add comment to IOCs.

        Args:
            comment (str): Comment to add.
            ioc_values (List[str]): IOC values.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = [{"iocValue": ioc, "comment": comment} for ioc in ioc_values]
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/comments"
        return self._http_request(
            method="POST", url_suffix=url_suffix, json_data=payload
        )

    def update_account_whitelist(
        self, is_whitelisted: str, ioc_values: List[str]
    ) -> dict[str, Any]:
        """
        Update account whitelist.

        Args:
            is_whitelisted (str): IOC status.
            ioc_values (List[str]): List of IOCs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """

        payload = {
            "iocs": [
                {
                    "value": ioc,
                    "whitelisted": ALERT_WHITELIST[is_whitelisted],
                }
                for ioc in ioc_values
            ]
        }
        url_suffix = f"{V2_PREFIX}/{UrlPrefix.IOC_SOURCE}/user-whitelist"
        return self._http_request(
            method="POST", url_suffix=url_suffix, json_data=payload
        )

    def remove_account_whitelist(self, ioc_values: List[str]) -> dict[str, Any]:
        """
        Remove IOCs from account whitelist.

        Args:
            ioc_values (List[str]): List of IOCs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = {"iocs": ioc_values}
        url_suffix = f"{V2_PREFIX}/{UrlPrefix.IOC_SOURCE}/user-whitelist"
        return self._http_request(
            method="DELETE", url_suffix=url_suffix, json_data=payload
        )

    def add_ioc_blocklist(self, ioc_values: List[str]) -> dict[str, Any]:
        """
        Add IOCs to remediation blocklist.

        Args:
            ioc_values (List[str]): List of IOCs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = {"iocs": ioc_values}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/blocklist"
        return self._http_request(
            method="POST", url_suffix=url_suffix, json_data=payload
        )

    def remove_ioc_blocklist(self, ioc_values: List[str]) -> dict[str, Any]:
        """
        Remove IOCs from remediation blocklist.

        Args:
            ioc_values (List[str]): List of IOCs.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        payload = {"iocs": ioc_values}
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC_SOURCE}/blocklist"
        return self._http_request(
            method="DELETE", url_suffix=url_suffix, json_data=payload
        )

    def search_mention(
        self,
        search: str,
        report_date: str | None,
        page_number: int,
        source_types: str | None,
        only_dark_web: bool,
        highlight_tags: bool,
    ) -> dict[str, Any]:
        """
        Search for mentions.

        Args:
            search (str): Text for search.
            report_date (str | None): Report date
            page_number (int): Page number.
            source_types (str | None): Search source types.
            only_dark_web (bool): Show only mentions from the dark web or not.
            highlight_tags (bool): Show highlight tags (<em>) in the content or not.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """

        params = remove_empty_elements(
            {
                "search": search,
                "report-date": report_date,
                "page-number": page_number,
                "source-type": [remove_whitespaces(type_) for type_ in source_types]
                if source_types
                else None,
                "only-dark-web": only_dark_web,
                "highlight-tags": highlight_tags,
            }
        )
        url_suffix = f"{V2_PREFIX}/intellifind"
        return self._http_request(method="GET", url_suffix=url_suffix, params=params)

    def usage_quota_enrichment(self) -> dict[str, Any]:
        """
        Gets the current API enrichment credits.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC}/quota"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def enrich_ioc(self, ioc_value: str) -> dict[str, Any]:
        """
        Enrich IOC.

        Args:
            ioc_value (str): IOC value.

        Returns:
            dict[str, Any]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.IOC}/enrich/{ioc_value}"
        return self._http_request(method="GET", url_suffix=url_suffix)

    def list_mssp_user(self) -> List[dict[str, Any]]:
        """
        List MSSP users.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.MSSP}/users-details"
        return self._http_request(
            method="GET", url_suffix=url_suffix, ok_codes=[HTTPStatus.OK]
        )

    def list_mssp_customer(self) -> List[dict[str, Any]]:
        """
        List MSSP customer.

        Returns:
            List[dict[str, Any]]: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.MSSP}/customers"
        return self._http_request(
            method="GET", url_suffix=url_suffix, ok_codes=[HTTPStatus.OK]
        )

    def get_alert_csv(self, alert_id: str) -> Response:
        """
        Get alert csv.

        Args:
            alert_id (str): Alert ID.

        Returns:
            Response: API response from Threat Command API.
        """
        url_suffix = f"{V1_PREFIX}/{UrlPrefix.ALERT}/csv-file/{alert_id}"
        return self._http_request(
            method="GET",
            url_suffix=url_suffix,
            resp_type="response",
            ok_codes=[HTTPStatus.OK, HTTPStatus.BAD_REQUEST],
        )


def list_cyber_term_cve_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List the Cyber-term CVEs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    cyber_term_id = args["cyber_term_id"]

    response = client.list_cyber_term_cve(cyber_term_id=cyber_term_id)
    paginated_response = manual_pagination(response["content"], args)
    mapped_response = list_parser(
        paginated_response, client.parser.cyber_term_cve_parser
    )

    return command_result_generate(
        readable_message=ReadableOutputs.CYBER_TERM_CVES.value.format(cyber_term_id),
        outputs=mapped_response,
        headers=["id", "publish_date", "vendor_product"],
        prefix="CVE",
        key_field="id",
        raw_response=response,
    )


def list_cyber_term_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List the Cyber-term IOCs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    cyber_term_id = args["cyber_term_id"]
    paginated_response = auto_pagination(
        request_command=client.list_cyber_term_ioc,
        offset_path=["content", "nextOffset"],
        limit=arg_to_number(args.get("limit", 50)),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        cyber_term_id=args["cyber_term_id"],
        ioc_type=args.get("ioc_type"),
    )
    mapped_response = list_parser(
        values=dict_safe_get(paginated_response, ["content", "iocs"]),
        mapper_command=client.parser.cyber_term_ioc_parser,
    )

    return command_result_generate(
        readable_message=ReadableOutputs.CYBER_TERM_IOCS.value.format(cyber_term_id),
        outputs=mapped_response,
        headers=["value", "type", "is_whitelisted", "updated_date"],
        prefix="IOC",
        key_field="id",
        raw_response=paginated_response,
    )


def list_cyber_term_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List Cyber-terms.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    paginated_response = auto_pagination(
        request_command=client.list_cyber_term,
        offset_path=["nextOffset"],
        limit=arg_to_number(args.get("limit", 50)),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        search=args.get("search"),
        types_=argToList(args.get("types")),
        severities=argToList(args.get("severities")),
        sectors=argToList(args.get("sectors")),
        countries=argToList(args.get("countries")),
        origin=argToList(args.get("origins")),
        ttp=argToList(args.get("ttps")),
        last_update_from=args.get("last_update_from"),
        last_update_to=args.get("last_update_to"),
    )

    mapped_response = list_parser(
        values=paginated_response["content"],
        mapper_command=client.parser.cyber_term_parser,
    )

    return command_result_generate(
        readable_message=ReadableOutputs.CYBER_TERM.value,
        outputs=mapped_response,
        headers=Headers.LIST_CYBER_TERM.value,
        prefix="CyberTerm",
        key_field="id",
        raw_response=paginated_response,
    )


def list_source_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List IOC sources.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_source()
    fixed_response = [
        member | {"type": object_type}
        for object_type in response
        for member in response[object_type]
    ]

    paginated_response = manual_pagination(fixed_response, args)
    mapped_response = list_parser(paginated_response, response_obj_parser)
    return command_result_generate(
        readable_message=ReadableOutputs.IOC_SOURCE.value,
        outputs=mapped_response,
        headers=["id", "name", "confidence_level", "is_enable", "type"],
        prefix="Source",
        key_field="id",
        raw_response=response,
    )


def create_source_document_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Create a document source.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    args = validate_create_source_document(args)

    name = args["name"]
    response = client.create_document_source(
        name=name,
        description=args["description"],
        confidence_level=args["confidence_level"],
        share=argToBoolean(args.get("share")) if args.get("share") else None,
        severity=args["severity"].lower() if args.get("severity") else None,
        tags=argToList(args.get("tags")),
        domains=argToList(args.get("domains")),
        urls=argToList(args.get("urls")),
        ips=argToList(args.get("ips")),
        hashes=argToList(args.get("hashes")),
        emails=argToList(args.get("emails")),
    )
    source_id = dict_safe_get(response, ["Data", "sourceDetails", "_id"])
    outputs = {"Files": {"id": source_id, "name": name}}
    return command_result_generate(
        readable_message=ReadableOutputs.DOCUMENT_CREATE.value,
        readable_outputs=outputs["Files"],
        outputs=outputs,
        headers=["id", "name"],
        prefix="Source",
        key_field="id",
        raw_response=response,
    )


def delete_source_document_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Delete a document source.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    source_id = args["source_id"]
    client.delete_document_source(source_id=source_id)

    return CommandResults(
        readable_output=ReadableOutputs.DOCUMENT_DELETE.value.format(source_id)
    )


def create_source_document_ioc_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Create a document source IOCs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    iocs = handle_iocs(args=args)

    source_id = args["source_id"]

    client.create_document_source_ioc(
        source_id=source_id,
        domains=argToList(args.get("domains")),
        urls=argToList(args.get("urls")),
        ips=argToList(args.get("ips")),
        hashes=argToList(args.get("hashes")),
        emails=argToList(args.get("emails")),
    )

    return CommandResults(
        readable_output=ReadableOutputs.CREATE_IOC.value.format(iocs, source_id)
    )


def list_system_modules_command(client: Client, *_) -> CommandResults:
    """
    List system modules.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_system_modules()
    fixed_response = dict_to_lowercase(response)
    readable_outputs = [
        {"module_name": module, "status": status}
        for module, status in fixed_response.items()
    ]
    return command_result_generate(
        readable_message=ReadableOutputs.SYSTEM_MODULES.value,
        outputs=readable_outputs,
        headers=["module_name", "status"],
        prefix="SystemModule",
        key_field="module_name",
        raw_response=response,
    )


def add_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a new asset to asset list.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    asset_type = args["asset_type"]
    asset_value = args["asset_value"]

    client.add_asset(asset_type=asset_type, asset_value=asset_value)
    outputs = {'type': asset_type, 'value': asset_value}
    return command_result_generate(
        readable_message=ReadableOutputs.CREATE_ASSET.value.format(
            asset_value, asset_type
        ),
        outputs=outputs,
        headers=['type', 'value'],
        prefix="Asset",
        key_field="value",
        raw_response=outputs,
    )


def delete_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Delete an asset from asset list.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    asset_type = args["asset_type"]
    asset_value = args["asset_value"]

    client.delete_asset(asset_type=asset_type, asset_value=asset_value)

    return CommandResults(
        readable_output=ReadableOutputs.DELETE_ASSET.value.format(
            asset_value, asset_type
        )
    )


def list_assets_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List assets.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_assets(asset_types=argToList(args.get("asset_types")))
    fixed_response = [
        {"value": asset} | {"type": object_type}
        for object_type in response
        for asset in response[object_type]
    ]
    paginated_response = manual_pagination(fixed_response, args)

    return command_result_generate(
        readable_message=ReadableOutputs.LIST_ASSET.value,
        outputs=paginated_response,
        headers=["type", "value"],
        prefix="Asset",
        key_field="value",
        raw_response=response,
    )


def list_asset_types_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List the asset types.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_asset_types()
    paginated_response = manual_pagination(response, args)

    return command_result_generate(
        readable_message=ReadableOutputs.ASSET_TYPES.value,
        outputs=paginated_response,
        headers=["type"],
        prefix="AssetType",
        key_field="value",
        raw_response=response,
    )


def list_cve_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    List the account CVEs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_list_cve(args)
    response = client.list_cve(
        offset=args.get("offset"),
        publish_date_from=args.get("publish_date_from"),
        publish_date_to=args.get("publish_date_to"),
        update_date_from=args.get("update_date_from"),
        update_date_to=args.get("update_date_to"),
        severity_list=argToList(args.get("severity_list", [])),
        cpe_list=argToList(args.get("cpe_list", [])),
        cve_ids=argToList(args.get("cve_ids", [])),
    )
    paginated_response = manual_pagination(response["content"], args)
    mapped_response = list_parser(paginated_response, client.parser.cve_parser)
    return remove_empty_elements(
        [
            command_result_generate(
                readable_message=ReadableOutputs.CVES.value,
                outputs=mapped_response,
                headers=[
                    "id",
                    "published_date",
                    "update_date",
                    "severity",
                    "intsights_score",
                    "cvss_score",
                ],
                prefix="CVE",
                key_field="id",
                raw_response=response,
            ),
            response.get("nextOffset")
            and command_result_generate(
                readable_message=ReadableOutputs.CVE_NEXT_OFFSET.value,
                outputs=response["nextOffset"],
                headers=["offset"],
                prefix="CveNextOffset",
            ),
        ]
    )


def add_cve_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Add CVEs to account list.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    cve_ids = argToList(args["cve_ids"])
    response = client.add_cve(cve_ids=cve_ids)
    return multi_status_handler(
        res=response,
        objects=cve_ids,
        object_key="cveId",
        success_readable=ReadableOutputs.ADD_CVE_SUCCESS.value,
        fail_readable=ReadableOutputs.ADD_CVE_FAIL.value,
    )


def delete_cve_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Delete CVEs from the account list.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
    """
    cve_ids = argToList(args["cve_ids"])
    response = client.delete_cve(cve_ids=cve_ids)
    return multi_status_handler(
        res=response,
        objects=cve_ids,
        object_key="cveId",
        success_readable=ReadableOutputs.DELETE_CVE_SUCCESS.value,
        fail_readable=ReadableOutputs.DELETE_CVE_FAIL.value,
    )


def list_alert_handler_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List alerts handler.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_list_alert(args=args)
    params = {
        "last_updated_from": args.get("last_updated_from"),
        "last_updated_to": args.get("last_updated_to"),
        "alert_type": argToList(args.get("alert_type")),
        "severity": argToList(args.get("severity")),
        "source_type": argToList(args.get("source_type")),
        "network_type": argToList(args.get("network_type")),
        "matched_asset_value": argToList(args.get("matched_asset_value")),
        "source_date_from": args.get("source_date_from"),
        "source_date_to": args.get("source_date_to"),
        "found_date_from": args.get("found_date_from"),
        "found_date_to": args.get("found_date_to"),
        "assigned": arg_to_optional_bool(args.get("assigned")),
        "is_flagged": arg_to_optional_bool(args.get("is_flagged")),
        "is_closed": arg_to_optional_bool(args.get("is_closed")),
        "has_ioc": arg_to_optional_bool(args.get("has_ioc")),
    }

    if alert_id := args.get("alert_id"):
        return get_alert_details_command(client=client, alert_id=alert_id)

    if argToBoolean(args["retrieve_ids_only"]):
        return list_alert_command(client=client, args=args, **params)

    return list_alerts_details_command(client=client, args=args, **params)


def list_alerts_details_command(
    client: Client, args: dict[str, Any], **params
) -> CommandResults:
    """
    Get alerts with complete details.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    paginated_response = auto_pagination(
        request_command=client.list_alert,
        offset_path=["nextOffset"],
        limit=arg_to_number(args.get("limit", 50)),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        **params,
    )

    alert_ids = [obj["_id"] for obj in paginated_response["content"]]
    data = [
        client.parser.alert_get_parser(client.get_alert(alert_id=alert_id))
        for alert_id in alert_ids
    ]
    readable_outputs = [
        alert_readable_outputs_handler(response=alert) for alert in data
    ]
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_LIST.value,
        readable_outputs=readable_outputs,
        outputs=data,
        headers=Headers.GET_ALERT.value,
        prefix="Alert",
        key_field="id",
        raw_response=data,
    )


def list_alert_command(
    client: Client, args: dict[str, Any], **params
) -> CommandResults:
    """
    list alert ids and updated date.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    paginated_response = auto_pagination(
        request_command=client.list_alert,
        offset_path=["nextOffset"],
        limit=arg_to_number(args.get("limit", 50)),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        **params,
    )

    mapped_response = list_parser(
        values=paginated_response.get("content", []),
        mapper_command=response_obj_parser,
    )

    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_LIST.value,
        outputs=mapped_response,
        headers=["id", "update_date"],
        prefix="Alert",
        key_field="id",
        raw_response=paginated_response,
    )


def get_alert_details_command(client: Client, alert_id: str) -> CommandResults:
    """
    Get alert with complete details.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.get_alert(alert_id=alert_id)
    mapped_response = client.parser.alert_get_parser(response)
    readable_outputs = alert_readable_outputs_handler(response=mapped_response)

    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_GET.value.format(alert_id),
        readable_outputs=readable_outputs,
        outputs=mapped_response,
        headers=Headers.GET_ALERT.value,
        prefix="Alert",
        key_field="id",
        raw_response=response,
    )


def create_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Create a new alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_create_alert(args=args)
    response = client.create_alert(
        title=args["title"],
        description=args["description"],
        type_=args.get("type"),
        sub_type=args.get("sub_type"),
        severity=args["severity"],
        source_type=args["source_type"],
        source_network_type=args["source_network_type"],
        source_date=args.get("source_date"),
        found_date=args.get("found_date"),
        image_entry_ids=argToList(args.get("image_entry_ids")),
        scenario=args.get("scenario"),
        source_url=args.get("source_url"),
    )
    outputs = {"id": response.content.decode()}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_CREATE.value,
        outputs=outputs,
        headers=["id"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
    )


def close_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Close alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_close_alert(args)

    alert_id = args["alert_id"]

    client.close_alert(
        alert_id=alert_id,
        reason=args["reason"],
        comment=args.get("comment"),
        is_hidden=argToBoolean(args["is_hidden"]),
        rate=arg_to_number(args.get("rate")),
    )
    outputs = {'id': alert_id, 'is_closed': True}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_CLOSE.value.format(alert_id),
        outputs=outputs,
        headers=["id", "is_closed"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
    )


def update_alert_severity_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Update the alert severity.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_alert_ioc_severity(args)

    alert_id = args["alert_id"]
    severity = args["severity"]

    client.update_alert_severity(alert_id=alert_id, severity=severity)
    outputs = {'id': alert_id, 'severity': severity}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_SEVERITY.value.format(alert_id, severity),
        outputs=outputs,
        headers=["id", "severity"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
    )


def assign_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Assign alert to user.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_assign_alert(args)
    alert_id = args["alert_id"]
    user_id = args["user_id"]

    client.assign_alert(
        alert_id=alert_id, user_id=user_id, is_mssp=argToBoolean(args.get("is_mssp"))
    )
    outputs = {'id': alert_id, 'assignees': [user_id]}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_ASSIGN.value.format(alert_id, user_id),
        outputs=outputs,
        headers=["id", "assignees"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
    )


def unassign_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Unassign alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]

    client.unassign_alert(alert_id=alert_id)

    outputs = {'id': alert_id, 'assignees': None}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_UNASSIGN.value.format(alert_id),
        outputs=outputs,
        headers=["id", "assignees"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
    )


def reopen_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Re-open closed alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]

    client.reopen_alert(alert_id=alert_id)
    return CommandResults(
        readable_output=ReadableOutputs.ALERT_REOPEN.value.format(alert_id)
    )


def tag_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add tag to alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    tag_name = args["tag_name"]

    client.tag_alert(alert_id=alert_id, tag_name=tag_name)

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_TAG_ADD.value.format(alert_id, tag_name)
    )


def untag_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Remove tag from alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    tag_id = args["tag_id"]

    client.untag_alert(alert_id=alert_id, tag_id=tag_id)

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_TAG_REMOVE.value.format(alert_id, tag_id)
    )


def send_mail_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Send a mail with alert details.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    email_addresses = argToList(args["email_addresses"])
    content = args["content"]

    client.send_mail_alert(
        alert_id=alert_id, email_addresses=email_addresses, content=content
    )

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_MAIL.value.format(
            alert_id, email_addresses
        )
    )


def analyst_ask_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Send a question to an analyst about the requested alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    question = args["question"]

    client.analyst_ask_alert(alert_id=alert_id, question=question)
    return CommandResults(
        readable_output=ReadableOutputs.ALERT_ANALYST.value.format(alert_id)
    )


def list_alert_conversation_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    List alert's analyst messages.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]

    response = client.list_alert_conversation(alert_id=alert_id)
    if response.status_code == HTTPStatus.NO_CONTENT:
        return CommandResults(
            readable_output=ReadableOutputs.ALERT_NO_CONVERSATION_LIST.value
        )
    response_json = response.json()
    mapped_response = [dict_to_lowercase(msg) for msg in response_json]
    outputs = {"id": alert_id, "Message": mapped_response}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_CONVERSATION_LIST.value,
        outputs=outputs,
        headers=["initiator", "message", "date"],
        prefix="Alert",
        key_field="id",
        raw_response=response_json,
        readable_outputs=mapped_response,
    )


def list_alert_activity_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List alert activity logs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]

    response = client.list_alert_activity(alert_id=alert_id)
    mapped_response = list_parser(response, client.parser.alert_activity_parser)
    outputs = {"ActivityLog": mapped_response, "id": alert_id}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_ACTIVITY.value.format(alert_id),
        readable_outputs=mapped_response,
        outputs=outputs,
        headers=["id", "type", "update_date", "sub_types", "initiator"],
        prefix="Alert",
        key_field="id",
        raw_response=response,
    )


def add_alert_note_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add a note to alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    client.add_alert_note(
        alert_id=alert_id,
        note=args["note"],
        file_entry_ids=argToList(args.get("entry_ids")),
    )
    return CommandResults(
        readable_output=ReadableOutputs.ALERT_ADD_NOTE.value.format(alert_id)
    )


def get_alert_blocklist_status_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Get alert's blocklist status.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]

    response = client.get_alert_blocklist(alert_id=alert_id)
    mapped_response = [dict_to_lowercase(msg) for msg in response]
    outputs = {"id": alert_id, "BlockList": mapped_response}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_BLOCKLIST_GET.value.format(alert_id),
        outputs=outputs,
        headers=["value", "status"],
        prefix="Alert",
        key_field="id",
        raw_response=response,
        readable_outputs=mapped_response,
    )


def update_alert_blocklist_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Change selected IOCs blocklist status.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_update_alert_blocklist(args)

    alert_id = args["alert_id"]
    blocklist_status = args["blocklist_status"]

    client.update_alert_blocklist(
        alert_id=alert_id,
        domains=argToList(args.get("domains")),
        urls=argToList(args.get("urls")),
        ips=argToList(args.get("ips")),
        emails=argToList(args.get("emails")),
        blocklist_status=blocklist_status,
    )

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_BLOCKLIST_UPDATE.value.format(
            blocklist_status
        )
    )


def list_alert_image_command(
    client: Client, args: dict[str, Any]
) -> List[CommandResults | List[Dict[str, Any]]] | CommandResults:
    """
    List alert images by alert ID.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    images = []
    alert_id = args["alert_id"]
    complete_alert = client.get_alert(alert_id=alert_id)
    img_ids = dict_safe_get(complete_alert, ["Details", "Images"], [])
    images = [
        fileResult(filename=f"{img}.png",
                   data=client.get_alert_image(img).content,
                   file_type=EntryType.ENTRY_INFO_FILE)
        for img in img_ids
    ]
    return (
        [
            CommandResults(
                readable_output=ReadableOutputs.ALERT_IMAGES.value.format(alert_id)
            ),
            images,
        ]
        if images
        else CommandResults(
            readable_output=ReadableOutputs.ALERT_NO_IMAGES.value.format(alert_id)
        )
    )


def takedown_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Send a takedown request for alert.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    client.takedown_alert(
        alert_id=alert_id,
        target=args["target"],
        close_alert_after_success=argToBoolean(args["close_alert_after_success"]),
    )

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_TAKEDOWN.value.format(alert_id)
    )


def get_takedown_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get the alert's takedown status.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    response = client.get_takedown_alert(alert_id=alert_id)
    outputs = {"id": alert_id, "takedown_status": response.content.decode()}
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_TAKEDOWN_STATUS.value.format(alert_id),
        outputs=outputs,
        headers=["takedown_status"],
        prefix="Alert",
        key_field="id",
        raw_response=outputs,
        readable_outputs=outputs,
    )


def list_alert_type_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List alert types.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_alert_type()
    fixed_response = [
        {"type": object_type, "sub_type": member}
        for object_type in response
        for member in response[object_type]
    ]
    paginated_response = manual_pagination(fixed_response, args)

    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_TYPES.value,
        outputs=paginated_response,
        headers=["type", "sub_type"],
        prefix="AlertType",
        key_field="sub_type",
        raw_response=response,
    )


def list_alert_source_type_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    List alert source types.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_alert_source_type()
    paginated_response = manual_pagination(response, args)
    return command_result_generate(
        readable_message=ReadableOutputs.ALERT_SOURCE_TYPES.value,
        outputs=paginated_response,
        headers=["source_type"],
        prefix="AlertSourceType",
        raw_response=response,
    )


def list_alert_scenario_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List alert scenarios.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_alert_scenario(
        type_=args.get("type"), sub_type=args.get("sub_type")
    )
    paginated_response = manual_pagination(response, args)
    fixed_response = [dict_to_lowercase(obj) for obj in paginated_response]
    return command_result_generate(
        readable_message=ReadableOutputs.SCENARIO_LIST.value,
        outputs=fixed_response,
        headers=["scenario", "description", "type", "subtype"],
        prefix="Scenario",
        key_field="scenario",
        raw_response=response,
    )


def report_alert_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Report alert IOC.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    client.report_alert_ioc(
        alert_id=alert_id, external_sources=argToList(args["external_sources"])
    )

    return CommandResults(
        readable_output=ReadableOutputs.ALERT_REPORT.value.format(alert_id)
    )


def list_account_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List account users.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    validate_list_account_user(args)
    response = client.list_account_user(
        user_type=args.get("user_type"),
        user_email=args.get("user_email"),
        user_id=args.get("user_id"),
    )
    paginated_response = manual_pagination(response, args)
    mapped_response = list_parser(paginated_response, response_obj_parser)

    return command_result_generate(
        readable_message=ReadableOutputs.ACCOUNT_USER_LIST.value,
        outputs=mapped_response,
        headers=["id", "email", "first_name", "last_name", "role", "is_deleted"],
        prefix="AccountUser",
        key_field="id",
        raw_response=response,
    )


@polling_function(
    name="threat-command-ioc-search",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def search_ioc_handler_command(args: dict[str, Any], client: Client, execution_metrics: ExecutionMetrics) -> PollResult:
    """
    List IOCs handler.
    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    # validate_list_alert(args=args)
    if argToBoolean(args["enrichment"]):
        # Enrich IOC - Blocked.
        return enrich_ioc_handler(client=client, args=args, execution_metrics=execution_metrics)

    if ioc_value := args.get("ioc_value"):
        # Get IOC by value
        return PollResult(
            response=get_ioc_handler(client=client, ioc_value=ioc_value),
            continue_to_poll=False,
        )

    # Get IOC By filter
    validate_list_ioc(args)
    return PollResult(
        response=list_ioc_handler(client=client, args=args),
        continue_to_poll=False,
    )


def enrich_ioc_handler(client: Client, args: dict[str, Any], execution_metrics: ExecutionMetrics) -> PollResult:
    """
    Enrich IOC with details.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ioc_value = args["ioc_value"]
    response = client.enrich_ioc(ioc_value=ioc_value)
    command_results = []
    status = response["Status"]
    if status == "QuotaExceeded":
        execution_metrics.quota_error += 1
        command_results.append(
            CommandResults(
                readable_output=ReadableErrors.ENRICH_FAIL.value.format(status)
            )
        )
        command_results.append(cast(CommandResults, execution_metrics.metrics))
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )
    if status == "Failed":
        execution_metrics.general_error += 1
        command_results.append(
            CommandResults(
                readable_output=ReadableErrors.ENRICH_FAIL.value.format(status)
            )
        )
        command_results.append(cast(CommandResults, execution_metrics.metrics))
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )
    if response["Status"] == "Done":
        execution_metrics.success += 1
        filtered_response = client.parser.ioc_enrich_parser(response["Data"])
        command_results.append(
            command_result_generate(
                readable_message=ReadableOutputs.ENRICH_GET.value.format(ioc_value),
                outputs=filtered_response,
                prefix="IOC",
                headers=Headers.ENRICH_IOC.value,
                key_field="value",
                raw_response=response,
            )
        )
        command_results.append(cast(CommandResults, execution_metrics.metrics))
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )
    return PollResult(
        response=response["Status"],
        continue_to_poll=True,
        args_for_next_run=args,
    )


def get_ioc_handler(client: Client, ioc_value: str) -> CommandResults:
    """
    Get IOC with details.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.get_ioc(ioc_value=ioc_value)
    mapped_response = client.parser.ioc_get_parser(response)
    return command_result_generate(
        readable_message=ReadableOutputs.IOC_GET.value.format(ioc_value),
        outputs=mapped_response,
        headers=Headers.GET_IOC.value,
        prefix="IOC",
        key_field="id",
        raw_response=response,
    )


def list_ioc_handler(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List IOC by filters.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    paginated_response = auto_pagination(
        request_command=client.list_ioc,
        offset_path=["nextOffset"],
        limit=arg_to_number(args.get("limit", 50)),
        page=arg_to_number(args.get("page")),
        page_size=arg_to_number(args.get("page_size")),
        last_updated_from=args.get("last_updated_from"),
        last_updated_to=args.get("last_updated_to"),
        last_seen_from=args.get("last_seen_from"),
        last_seen_to=args.get("last_seen_to"),
        first_seen_from=args.get("first_seen_from"),
        first_seen_to=args.get("first_seen_to"),
        status=args.get("status"),
        type_list=argToList(args.get("type_list")),
        severity_list=argToList(args.get("severity_list")),
        whitelisted=args.get("whitelisted"),
        source_ids=argToList(args.get("source_ids")),
        kill_chain_phases=argToList(args.get("kill_chain_phases")),
    )
    mapped_response = list_parser(
        paginated_response["content"], client.parser.ioc_get_parser
    )

    return command_result_generate(
        readable_message=ReadableOutputs.IOC_LIST.value,
        outputs=mapped_response,
        headers=Headers.GET_IOC.value,
        prefix="IOC",
        key_field="id",
        raw_response=paginated_response,
    )


def add_tags_ioc_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add tags to IOC.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ioc_value = args["ioc_value"]
    tag_values = argToList(args["tag_values"])

    client.tags_ioc(ioc_value=ioc_value, tag_values=tag_values)

    return CommandResults(
        readable_output=ReadableOutputs.IOC_TAG_ADD.value.format(ioc_value, tag_values)
    )


def update_ioc_severity_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Update severity for IOCs.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    severity = args["severity"]

    iocs = handle_iocs(args=args)

    validate_alert_ioc_severity(args)
    client.update_ioc_severity(
        severity=severity,
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.UPDATE_IOC_SEVERITY.value.format(iocs, severity)
    )


def add_ioc_comment_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add comment to IOCs.

    Args:

        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    comment = args["comment"]

    iocs = handle_iocs(args=args)
    client.add_ioc_comment(
        comment=comment,
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.ADD_IOC_COMMENT.value.format(iocs, comment)
    )


def update_account_whitelist_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Update account whitelist.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    is_whitelisted = args["is_whitelisted"]

    iocs = handle_iocs(args=args)
    validate_update_account_whitelist(args)
    client.update_account_whitelist(
        is_whitelisted=is_whitelisted,
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.UPDATE_ACCOUNT_WHITELIST.value.format(
            iocs, is_whitelisted
        )
    )


def remove_account_whitelist_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Remove IOCs from account whitelist.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    iocs = handle_iocs(args=args)
    client.remove_account_whitelist(
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.REMOVE_ACCOUNT_WHITELIST.value.format(iocs)
    )


def add_ioc_blocklist_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Add IOCs to remediation blocklist.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    iocs = handle_iocs(args=args)
    client.add_ioc_blocklist(
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.ADD_IOC_BLOCKLIST.value.format(iocs)
    )


def remove_ioc_blocklist_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """
    Remove IOCs from remediation blocklist.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    iocs = handle_iocs(args=args)
    client.remove_ioc_blocklist(
        ioc_values=iocs,
    )

    return CommandResults(
        readable_output=ReadableOutputs.REMOVE_IOC_BLOCKLIST.value.format(iocs)
    )


def search_mention_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Search mentions.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    search = args["search"]
    page_number = arg_to_number(args["page_number"])
    validate_search_mentions(args)
    if not isinstance(page_number, int):
        raise ValueError(ReadableErrors.NUMBER.value)
    response = client.search_mention(
        search=search,
        report_date=args.get("report_date"),
        page_number=page_number,
        source_types=argToList(args.get("source_types")),
        only_dark_web=argToBoolean(args.get("only_dark_web")),
        highlight_tags=argToBoolean(args.get("highlight_tags")),
    )
    mapped_response = list_parser(response["Data"], client.parser.mention_parser)
    return command_result_generate(
        readable_message=ReadableOutputs.MENTIONS.value.format(search, page_number),
        outputs=mapped_response,
        headers=Headers.MENTION.value,
        prefix="Mentions",
        key_field="id",
        raw_response=response,
    )


def usage_quota_enrichment_command(client: Client, *_) -> CommandResults:
    """
    Get enrichment quota.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.usage_quota_enrichment()
    mapped_response = response_obj_parser(dict_=response["EnrichIocsQuota"])
    return command_result_generate(
        readable_message=ReadableOutputs.ENRICH_QUOTA.value,
        outputs=mapped_response,
        headers=["time_period", "total", "remaining"],
        prefix="IOCsQuota",
        raw_response=response,
    )


def list_mssp_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List MSSP users.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_mssp_user()
    paginated_response = manual_pagination(response, args)
    mapped_response = list_parser(paginated_response, response_obj_parser)
    return command_result_generate(
        readable_message=ReadableOutputs.MSSP_USER_LIST.value,
        outputs=mapped_response,
        headers=["id", "email", "role", "is_deleted"],
        prefix="MsspUser",
        key_field="id",
        raw_response=response,
    )


def list_mssp_customer_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    List MSSP customers.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    response = client.list_mssp_customer()
    paginated_response = manual_pagination(response, args)
    mapped_response = list_parser(paginated_response, response_obj_parser)
    return command_result_generate(
        readable_message=ReadableOutputs.MSSP_CUSTOMER_LIST.value,
        outputs=mapped_response,
        headers=["id", "company_name", "status", "note"],
        prefix="MsspCustomer",
        key_field="id",
        raw_response=response,
    )


def get_alert_csv_command(
    client: Client, args: dict[str, Any]
) -> List[CommandResults | Dict[str, Any]] | CommandResults:
    """
    Get alert CSV file if exists.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[CommandResults | Dict[str, Any]] | CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    alert_id = args["alert_id"]
    csv_response = client.get_alert_csv(alert_id)
    if csv_response.status_code != HTTPStatus.OK:
        return CommandResults(
            readable_output=ReadableOutputs.ALERT_NO_CSV.value.format(alert_id)
        )
    csv_file = fileResult(filename=f"{alert_id}.csv", data=csv_response.content, file_type=EntryType.ENTRY_INFO_FILE)
    decoded_content = csv_response.content.decode()
    tab_based_content = list(csv.DictReader(decoded_content.splitlines(), delimiter="\t"))
    content = list(csv.DictReader(decoded_content.splitlines(), delimiter=","))
    if tab_based_content and content and (len(tab_based_content[0]) > len(content[0])):
        content = tab_based_content
    outputs = {"alert_id": alert_id, 'content': content}
    return [
        CommandResults(
            readable_output=ReadableOutputs.ALERT_CSV.value.format(alert_id),
            outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.CSV",
            outputs_key_field='alert_id',
            outputs=outputs,
            raw_response=outputs,
        ),
        csv_file,
    ]


@polling_function(
    name="file",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def file_command(args: dict[str, Any], client: Client, execution_metrics: ExecutionMetrics) -> PollResult:
    """
    Enrich file IOC (Generic reputation command).

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    return reputation_handler(
        args, client, file_reputation_handler, IOCType.FILE.value.lower(), execution_metrics
    )


@polling_function(
    name="ip",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def ip_command(args: dict[str, Any], client: Client, execution_metrics: ExecutionMetrics) -> PollResult:
    """
    Enrich ip IOC (Generic reputation command).

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    return reputation_handler(
        args, client, ip_reputation_handler, IOCType.IP.value.lower(), execution_metrics
    )


@polling_function(
    name="url",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def url_command(args: dict[str, Any], client: Client, execution_metrics: ExecutionMetrics) -> PollResult:
    """
    Enrich URL IOC (Generic reputation command).

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """

    return reputation_handler(
        args, client, url_reputation_handler, IOCType.URL.value.lower(), execution_metrics
    )


@polling_function(
    name="domain",
    interval=arg_to_number(demisto.args().get("interval_in_seconds", DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def domain_command(args: dict[str, Any], client: Client, execution_metrics: ExecutionMetrics) -> PollResult:
    """
    Enrich domain IOC (Generic reputation command).

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    return reputation_handler(
        args, client, domain_reputation_handler, IOCType.DOMAIN.value.lower(), execution_metrics
    )


def reputation_handler(
    args: dict[str, Any], client: Client, handler_command: Callable, key: str, execution_metrics: ExecutionMetrics
) -> PollResult:
    """
    Handle with all reputation commands.

    Args:
        client (Client): Threat Command API client.
        args (Dict[str, Any]): Command arguments from XSOAR.
        handler_command (Callable): Handler command for each command.
        key (str): Key for the IOC.
        execution_metrics (ExecutionMetrics): Execution metrics.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    ioc_values: List[str] = argToList(args[key])

    responses = [client.enrich_ioc(ioc_value=ioc_value) for ioc_value in ioc_values]

    command_results = []
    done_responses = list(filter(
        lambda response: response["Status"] == "Done",
        responses
    ))
    failed_responses = list(filter(
        lambda response: response["Status"] == "Failed",
        responses
    ))
    quota_responses = list(filter(
        lambda response: response["Status"] == "QuotaExceeded",
        responses
    ))
    for response in done_responses + failed_responses + quota_responses:
        ioc_values.remove(response['OriginalValue'])

    if not ioc_values:
        execution_metrics.success += len(done_responses)
        execution_metrics.general_error += len(failed_responses)
        execution_metrics.quota_error += len(quota_responses)
        for response in done_responses:
            command_results.append(handler_command(client=client, obj=response, obj_id=response['OriginalValue']))
        for response in failed_responses + quota_responses:
            command_results.append(
                CommandResults(readable_output=ReadableErrors.ENRICH_FAIL.value.format(response["Status"])))

        command_results.append(cast(CommandResults, execution_metrics.metrics))

        return PollResult(
            response=command_results,
            continue_to_poll=False,
            args_for_next_run=args
        )

    return PollResult(
        partial_result=CommandResults(
            readable_output=f'Waiting for "{ioc_values}" to finish...'),
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=args
    )


""" HELPER FUNCTIONS """


def file_reputation_handler(
    client: Client, obj: dict[str, Any], obj_id: str
) -> CommandResults:
    """
    Handle with file enrichment response.

    Args:
        client (Client): Threat Command API client.
        obj (dict[str, Any]): File response.
        obj_id (str): File value.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    command_args = client.parser.file_reputation_parser(
        obj=obj, hash_=obj_id, reliability=client.reliability
    )
    file_indicator = Common.File(**command_args)
    command_args.pop("dbot_score")
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.File",
        outputs_key_field="sha256",
        indicator=file_indicator,
        readable_output=tableToMarkdown(
            f"Rapid7 Threat Command - Hash Reputation for: {obj_id}", t=command_args
        ),
        outputs=command_args,
        raw_response=obj,
    )


def ip_reputation_handler(
    client: Client, obj: Dict[str, Any], obj_id: str
) -> CommandResults:
    """
    Handle with IP enrichment response.

    Args:
        client (Client): Threat Command API client.
        obj (dict[str, Any]): IP response.
        obj_id (str): IP value.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    command_args = client.parser.ip_reputation_parser(
        obj=obj, ip=obj_id, reliability=client.reliability
    )
    ip_indicator = Common.IP(**command_args)
    command_args.pop("dbot_score")
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.IP",
        outputs_key_field="ip",
        indicator=ip_indicator,
        readable_output=tableToMarkdown(
            f"Rapid7 Threat Command - IP Reputation for: {obj_id}", command_args
        ),
        outputs=command_args,
        raw_response=obj,
    )


def url_reputation_handler(
    client: Client, obj: Dict[str, Any], obj_id: str
) -> CommandResults:
    """
    Handle with URL enrichment response.

    Args:
        client (Client): Threat Command API client.
        obj (dict[str, Any]): URL response.
        obj_id (str): URL value.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    command_args = client.parser.url_reputation_parser(
        obj=obj, url=obj_id, reliability=client.reliability
    )
    url_indicator = Common.URL(**command_args)
    command_args.pop("dbot_score")

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.URL",
        outputs_key_field="url",
        indicator=url_indicator,
        readable_output=tableToMarkdown(
            f"Rapid7 Threat Command - URL Reputation for: {obj_id}", command_args
        ),
        outputs=command_args,
        raw_response=obj,
    )


def domain_reputation_handler(
    client: Client, obj: Dict[str, Any], obj_id: str
) -> CommandResults:
    """
    Handle with domain enrichment response.

    Args:
        client (Client): Threat Command API client.
        obj (dict[str, Any]): Domain response.
        obj_id (str): Domain value.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    command_args = client.parser.domain_reputation_parser(
        obj=obj, domain=obj_id, reliability=client.reliability
    )
    domain_indicator = Common.Domain(**command_args)
    del command_args["dbot_score"]
    del command_args["dns_records"]
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.Domain",
        outputs_key_field="domain",
        indicator=domain_indicator,
        readable_output=tableToMarkdown(
            f"Rapid7 Threat Command - domain Reputation for: {obj_id}",
            command_args,
        ),
        outputs=command_args,
        raw_response=obj,
    )


def get_dbotscore(
    reliability: str, indicator: str = None, is_known_ioc: bool | None = None
) -> Common.DBotScore:
    """
    Get XSOAR score for the indicator.
    Args:
        reliability (str): Reliability of the source providing the intelligence data.
        indicator (str, optional): Indicator response.
            Defaults to None.
        is_known_ioc (bool, optional): Whether the IOC is known to Threat Command.
            Defaults to None.
    Returns:
        Common.DBotScore: DBot Score according to the disposition.
    """
    if is_known_ioc:
        score = Common.DBotScore.BAD

    elif is_known_ioc:
        score = Common.DBotScore.GOOD

    else:
        score = Common.DBotScore.NONE

    return Common.DBotScore(
        indicator=indicator,
        indicator_type=DBotScoreType.FILE,
        integration_name="ThreatCommand",
        reliability=reliability,
        score=score,
    )


def get_enrich_hashes(response: dict[str, Any]) -> dict[str, Any]:
    """
    Get hashes values from hash enrichment response.

    Args:
        response (dict[str, Any]): Hash enrichment response from Threat Command API.

    Returns:
        dict[str, Any]: Hashes dictionary.
    """
    return (
        {
            hash["Type"]: hash["Value"]
            for hash in dict_safe_get(response, ["Data", "RelatedHashes"], [])
        }
        if isinstance(dict_safe_get(response, ["Data", "RelatedHashes"]), list)
        else {}
    )


def get_enrich_file_nams(response: dict[str, Any]) -> List[str]:
    """
    Get file names from enrichment response.

    Args:
        response (dict[str, Any]): Hash enrichment response from Threat Command API.

    Returns:
        List[str]: File names.
    """
    return remove_empty_elements(
        [
            detection.get("Result") if detection.get("Result") != "" else None
            for detection in dict_safe_get(
                response, ["Data", "AntivirusDetections"], []
            )
        ]
    )


def remove_whitespaces(str_: str | None) -> str | None:
    """
    Remove whitespaces from string.

    Args:
        str_ (str | None): String to remove whitespaces from.

    Returns:
        str | None: String without whitespaces.
    """
    if str_:
        return str_.replace(" ", "")
    return None


def files_handler(file_ids: List[str], is_image: bool = False) -> List[dict[str, Any]]:
    """
    Read XSOAR file ids and organized them in list.

    Args:
        file_ids (List[str]): XSOAR file ids.
        is_image (bool, optional): is the file are images for creating alert?. Defaults to False.

    Returns:
        List[dict[str, Any]]: List of the files with data.
    """
    files_data = []
    for image_id in file_ids:
        file_data = demisto.getFilePath(image_id)
        file_type = pathlib.Path(file_data["name"]).suffix[1:]
        with open(file_data["path"], "rb") as f:
            files_data.append(
                {
                    "Data": base64.b64encode(f.read()).decode(),
                    "Type": "jpeg" if file_type == "jpg" else file_type,
                    "Name": file_data["name"] if not is_image else None,
                }
            )
    return remove_empty_elements(files_data)


def command_result_generate(
    readable_message: str,
    outputs: Dict[str, Any] | List[Any],
    headers: List[str],
    prefix: str,
    readable_outputs: Dict[str, Any] | List | None = None,
    key_field: str | None = None,
    raw_response: Dict[str, Any] | List[Any] | None = None,
) -> CommandResults:
    """
    Generate CommandResults object with readable output.

    Args:
        readable_message (str): Readable output message.
        outputs (Dict[str, Any] | List[Any]): Outputs to XSOAR outputs.
        headers (List[str]): Headers for readable outputs table.
        prefix (str): Outputs prefix.
        readable_outputs (Dict[str, Any] | List | None, optional): Readable outputs to show. Defaults to None.
        key_field (str): Outputs key field.
        raw_response (Dict[str, Any] | List[Any]): Raw response to XSOAR outputs.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    return CommandResults(
        readable_output=tableToMarkdown(
            name=readable_message,
            t=readable_outputs if readable_outputs else outputs,
            headers=headers,
            headerTransform=string_to_table_header,
            removeNull=True,
        ),
        outputs_prefix=f"{INTEGRATION_ENTRY_CONTEXT}.{prefix}",
        outputs_key_field=key_field,
        outputs=outputs,
        raw_response=raw_response,
    )


def manual_pagination(response: List[Any], args: dict[str, Any]) -> List[Any]:
    """
    Executing Manual paginate_results (using the limit argument).

    Args:
        response (List[dict[str, Any]]): API response.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[dict[str, Any]]: Paginated results.
    """

    if argToBoolean(args.get("all_results", False)):
        return response

    limit = arg_to_number(args.get("limit", 50))

    if limit and limit < 1:
        raise ValueError(ReadableErrors.LIMIT.value)

    return response[:limit]


def list_parser(
    values: List[dict[str, Any]], mapper_command: Callable
) -> List[dict[str, Any]]:
    """
    Handle with parse list of objects.

    Args:
        values (List[dict[str, Any]]): List of objects to map.
        mapper_command (Callable): The object parse command.

    Returns:
        List[dict[str, Any]]: Parsed list.
    """
    return [mapper_command(obj) for obj in values]


def auto_pagination(
    request_command: Callable,
    offset_path: List[str],
    limit: int | None,
    page: int | None,
    page_size: int | None,
    offset: str | None = None,
    **kwargs,
) -> dict[str, Any]:
    """
    Handle with pagination when the API supports pagination.

    Args:
        request_command (Callable): List request command.
        offset_path (List[str]): The path to the offset arg (in order to handle with page, page_size).
        limit (int): Limit for pagination.
        page (int | None): Page for pagination
        page_size (int | None): Page size for pagination
        offset (str | None, optional): Offset for pagination. Defaults to None.

    Raises:
        ValueError: Error with pagination when there is no offset arg.

    Returns:
        dict[str, Any]: Paginated response.
    """
    command_args = copy.deepcopy(kwargs)
    command_args["offset"] = offset
    if page and page_size:
        if page == 1:
            command_args["limit"] = page_size
            return request_command(**command_args)
        calculate = (page - 1) * page_size
        command_args["limit"] = (
            calculate
            if calculate < API_MAX_LIMIT
            else calculate - calculate % page_size
        )
        offset = dict_safe_get(request_command(**command_args), offset_path)
        if calculate > API_MAX_LIMIT:
            auto_pagination(
                request_command=request_command,
                offset_path=offset_path,
                page=int(page - command_args["limit"] / page_size),
                page_size=page_size,
                **command_args,
            )
        if offset is None:
            raise ValueError("Error with pagination.")

        command_args["limit"] = page_size
        command_args["offset"] = offset
        return request_command(**command_args)
    command_args["limit"] = limit
    return request_command(**command_args)


def map_ioc_list(
    domains: List[str] | None = None,
    urls: List[str] | None = None,
    ips: List[str] | None = None,
    hashes: List[str] | None = None,
    emails: List[str] | None = None,
    blocklist_status: str = None,
) -> List[dict[str, Any]]:
    """
    Map lists of IOCs to Threat Command API form.

    Args:
        domains (List[str] | None, optional): A list of domain IOC values to add.. Defaults to None.
        urls (List[str] | None, optional): A list of URL IOC values to add.. Defaults to None.
        ips (List[str] | None, optional): A list of IP IOC values to add.. Defaults to None.
        hashes (List[str] | None, optional): A list of hash IOC values to add.. Defaults to None.
        emails (List[str] | None, optional): A list of email IOC values to add.. Defaults to None.
        blocklist_status (str, optional): Blocklist status in case of using blocklist command. Defaults to None.

    Returns:
        List[dict[str, Any]]: Mapped list of IOCs with types.
    """
    mapped_domains = [
        {
            "Type": "Domains",
            "Value": domain,
        }
        for domain in domains or []
    ]
    mapped_hashes = (
        [{"Type": "Hashes", "Value": hash} for hash in hashes] if hashes else []
    )

    mapped_urls = [
        {"Type": "URLs" if blocklist_status else "Urls", "Value": url}
        for url in urls or []
    ]
    mapped_ips = [
        {"Type": "IPs" if blocklist_status else "IpAddresses", "Value": ip}
        for ip in ips or []
    ]
    mapped_emails = [
        {"Type": "EmailAddresses" if blocklist_status else "Emails", "Value": email}
        for email in emails or []
    ]
    mapped_iocs = (
        mapped_domains + mapped_urls + mapped_ips + mapped_hashes + mapped_emails
    )
    if blocklist_status:
        for ioc in mapped_iocs:
            ioc |= {"BlocklistStatus": blocklist_status}
    return mapped_iocs


def handle_iocs(args: dict[str, Any]) -> List[str]:
    """
    Validate IOC values.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR..

    Raises:
        ValueError: Insert correct domain.
        ValueError: Insert correct url.
        ValueError: Insert correct ip.
        ValueError: Insert correct hash.
        ValueError: Insert correct email.

    Returns:
        List[str]: List of IOCs.

    """
    domains = argToList(args.get("domains"))
    urls = argToList(args.get("urls"))
    ips = argToList(args.get("ips"))
    hashes = argToList(args.get("hashes"))
    emails = argToList(args.get("emails"))

    if all([not domains, not urls, not ips, not hashes, not emails]):
        raise ValueError(ReadableErrors.NO_IOCS.value)
    for iocs, ioc_type in [
        (urls, IOCType.URL),
        (ips, IOCType.IP),
        (hashes, IOCType.HASH),
        (emails, IOCType.EMAIL),
    ]:
        for ioc in iocs:
            if not re.match(pattern_and_readable_error_by_ioc_type[ioc_type][0], ioc):
                raise ValueError(
                    pattern_and_readable_error_by_ioc_type[ioc_type][1].value.format(
                        ioc
                    )
                )

    return domains + urls + ips + hashes + emails


def validate_create_source_document(args: dict[str, Any]) -> dict[str, Any]:
    """
    Validate create source document arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: Error with one of the arguments.

    Returns:
        dict[str, Any]: Updated args.
    """
    validate_argument(
        args=args, key_="severity", values=ArgumentValues.ALERT_IOC_AND_DOCUMENT_SEVERITY.value
    )
    validate_argument(args=args, key_="share", values=ArgumentValues.BOOLEAN.value)
    confidence_level = arg_to_number(args["confidence_level"])
    if not confidence_level or any([confidence_level < 0, confidence_level > 3]):
        raise ValueError(ReadableErrors.CONFIDENCE_LEVEL.value)

    handle_iocs(args=args)
    return args | {"confidence_level": confidence_level}


def multi_status_handler(
    res: dict[str, Any],
    objects: List[str],
    object_key: str,
    success_readable: str,
    fail_readable: str,
) -> List[CommandResults]:
    """
    Handle with multi status request.

    Args:
        res (dict[str, Any]): Response from the API.
        objects (List[str]): List of objects that sent with the request.
        object_key (str): Object key in the response.
        success_readable (str): Readable text for objects that succeeded.
        fail_readable (str): Readable text for objects that failed.

    Returns:
        List[CommandResults]: outputs, readable outputs and raw response for XSOAR.
    """
    succeeded = objects
    failed = []
    if (failure := res.get("failure")) and isinstance(failure, list):
        for obj in failure:
            reason = obj["failReason"]
            obj_id = obj[object_key]
            succeeded = list(set(succeeded) - {obj_id})
            failed.append(f"{obj_id} ({reason})")
    if not succeeded:
        raise ValueError(fail_readable.format((",").join(failed)))
    return remove_empty_elements(
        [
            CommandResults(
                readable_output=success_readable.format((",").join(succeeded))
            )
            if succeeded
            else None,
            CommandResults(readable_output=fail_readable.format((",").join(failed)))
            if failed
            else None,
        ]
    )


def validate_create_alert(args: dict[str, Any]):
    """
    Validator for create alerts arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    scenario = args.get("scenario")
    type_ = args.get("type")
    sub_type = args.get("sub_type")

    if any(
        [
            not any([scenario, type_, sub_type]),
            all([scenario, type_, sub_type]),
            all([scenario, sub_type]) or all([scenario, type_]),
        ]
    ):
        raise ValueError(ReadableErrors.SCENARIO_TYPES.value)
    if all([type_, not sub_type]):
        raise ValueError(ReadableErrors.ALERT_SUB_TYPE.value)
    if all([not type_, sub_type]):
        raise ValueError(ReadableErrors.ALERT_TYPE.value)

    validate_argument(args=args, key_="type", values=ArgumentValues.ALERT_TYPE.value)
    validate_argument(
        args=args, key_="severity", values=ArgumentValues.ALERT_IOC_AND_DOCUMENT_SEVERITY.value
    )
    validate_argument(
        args=args,
        key_="source_network_type",
        values=ArgumentValues.ALERT_SOURCE_NETWORK.value,
    )


def validate_list_alert(args: dict[str, Any]):
    """
    Validator for list alert arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(
        args=args, key_="network_type", values=ArgumentValues.ALERT_SOURCE_NETWORK.value
    )
    validate_argument(
        args=args, key_="source_type", values=ArgumentValues.SOURCE_TYPE.value
    )
    validate_argument(
        args=args, key_="alert_type", values=ArgumentValues.ALERT_TYPE.value
    )

    if args.get("alert_id") and argToBoolean(args["retrieve_ids_only"]):
        raise ValueError(ReadableErrors.ALERT_LIST.value)


def validate_close_alert(args: dict[str, Any]):
    """
    Validator for close alert arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(
        args=args, key_="reason", values=ArgumentValues.ALERT_CLOSE_REASON.value
    )
    validate_argument(args=args, key_="is_hidden", values=ArgumentValues.BOOLEAN.value)
    if argToBoolean(args["is_hidden"]) and args.get("reason") != "False Positive":
        raise ValueError(ReadableErrors.IS_HIDDEN.value)

    rate = arg_to_number(args.get("rate"))

    if rate and not 0 <= rate <= 5:
        raise ValueError(ReadableErrors.RATE.value)


def validate_update_alert_blocklist(args: dict[str, Any]):
    """
    Validator for upadte alert blocklist arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    handle_iocs(args=args)
    validate_argument(
        args=args, key_="blocklist_status", values=ArgumentValues.ALERT_BLOCKLIST.value
    )


def validate_assign_alert(args: dict[str, Any]):
    """
    Validator for assign alert.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(args=args, key_="is_mssp", values=ArgumentValues.BOOLEAN.value)


def validate_list_cve(args: dict[str, Any]):
    """
    Validator for list CVEs.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    severity_list = argToList(args.get("severity_list"))
    if severity_list and not set(severity_list).issubset(ArgumentValues.CVE_SEVERITY.value):
        raise ValueError(
            ReadableErrors.ARGUMENT.value.format(
                "severity_list", ArgumentValues.CVE_SEVERITY.value
            )
        )


def validate_list_account_user(args: dict[str, Any]):
    """
    Validator for list account users.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(
        args=args, key_="user_type", values=ArgumentValues.USER_TYPE.value
    )


def validate_alert_ioc_severity(args: dict[str, Any]):
    """
    Validator for alert IOC severity arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(
        args=args, key_="severity", values=ArgumentValues.ALERT_IOC_AND_DOCUMENT_SEVERITY.value
    )


def validate_update_account_whitelist(args: dict[str, Any]):
    """
    Validator for update account whitelist arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    validate_argument(
        args=args, key_="is_whitelisted", values=ArgumentValues.WHITELIST_STATUS.value
    )


def validate_list_ioc(args: dict[str, Any]):
    """
    Validator for list IOC arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    if not args.get("last_updated_from"):
        raise ValueError(ReadableErrors.INSERT_VALUE.value.format("last_updated_from"))


def validate_search_mentions(args: dict[str, Any]):
    """
    Validator for search mentions arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case of wrong arguments.
    """
    if not isinstance(arg_to_number(args["page_number"]), int):
        raise ValueError(ReadableErrors.NUMBER.value)
    validate_argument(
        args=args, key_="source_type", values=ArgumentValues.MENTION_SOURCE_TYPE.value
    )
    validate_argument(
        args=args, key_="only_dark_web", values=ArgumentValues.BOOLEAN.value
    )
    validate_argument(
        args=args, key_="highlight_tags", values=ArgumentValues.BOOLEAN.value
    )


def validate_argument(args: dict[str, Any], key_: str, values: List[str]):
    """
    Validate for XSOAR input arguments.

    Args:
        args (dict[str, Any]): XSOAR arguments.
        key_ (str): The key of the argument.
        values (List[str]): Optional values.

    Raises:
        ValueError: In case that the input is wrong.
    """
    if args.get(key_) and args[key_] not in values:
        raise ValueError(ReadableErrors.ARGUMENT.value.format(key_, values))


def dict_to_lowercase(dict_: dict[str, Any]) -> dict[str, Any]:
    """
    Return a dictionary with lowercase keys.

    Args:
        dict_ (dict[str, Any]): Dictionary.

    Returns:
        dict[str, Any]: Dictionary with lowercase keys.
    """
    return {k.lower(): v for k, v in dict_.items()}


def alert_readable_outputs_handler(response: dict[str, Any]) -> dict[str, Any]:
    """
    Create readable outputs for alert.

    Args:
        response (dict[str, Any]): Alert respose

    Returns:
        dict[str, Any]: Alert readable dictionary.
    """
    return copy.deepcopy(response) | {
        "Tags": [tag["name"] for tag in response.get("Tags", [])]
    }


def arg_to_optional_bool(bool_: str | None) -> bool | None:
    """
    Returns the boolean value of the argument.

    Args:
        bool_ (str | None): Argument value.

    Returns:
        bool | None: Boolean argument.
    """
    if bool_ is None:
        return None
    return argToBoolean(bool_)


def response_obj_parser(dict_: dict[str, Any]) -> dict[str, Any]:
    """
    Parse dictionary keys to lowercase.

    Args:
        dict_ (dict[str, Any]): Dictionary to parse.

    Returns:
        dict[str, Any]: Parsed dictionary.
    """
    return {
        camel_case_to_underscore(k if k != "_id" else "id"): v
        for k, v in dict_.items()
    }


def minimum_severity_handler(severity: str | None) -> List[str]:
    """
    Replace minimum severity to list of the relevant severities.

    Args:
        severity (str | None): Severity value.

    Returns:
        List[str]: List of the relevant severities.
    """
    if not severity:
        return ["High", "Medium", "Low"]
    if severity == "High":
        return ["High"]
    if severity == "Medium":
        return ["High", "Medium"]
    return ["High", "Medium", "Low"]


def test_module(client: Client, params: Dict) -> str:
    """
    Test module.

    Args:
        client (Client): Threat Command client.
        params (Dict): Integration parameters.

    Returns:
        str: Output message.
    """
    try:
        if params.get('isFetch'):
            first_fetch = arg_to_datetime(params.get("first_fetch"), arg_name="First fetch timestamp")
            max_fetch = arg_to_number(params["max_fetch"])
            if not max_fetch or not isinstance(max_fetch, int) or max_fetch < 1 or max_fetch > 200:
                raise ValueError(ReadableErrors.MAX_FETCH_INVALID.value)
            if not isinstance(first_fetch, datetime):
                raise ValueError(ReadableErrors.FIRST_FETCH_NOT_EXIST.value)
        client.list_system_modules()
    except Exception as error:
        demisto.debug(str(error))
        return f"Error: {error}"
    return "ok"


def fetch_incidents(
    client: Client,
    last_run: Dict[str, Any],
    first_fetch: str,
    max_fetch: int,
    alert_types: List[str] | None,
    network_types: List[str] | None,
    alert_severities: List[str] | None,
    source_types: List[str] | None,
    fetch_csv: bool | None,
    is_closed: bool,
    fetch_attachments: bool | None,
) -> tuple[Dict[str, Any], List[dict]]:
    """
    Retrieves new alerts every interval (default is 1 minute).
    By default it's invoked by XSOAR every minute.
    It will use last_run to save the time of the last incident it processed and previous incident IDs.
    If last_run is not provided, first_fetch_time will be used to determine when to start fetching the first time.
    Args:
        client (Client): Cisco AMP client to run desired requests
        last_run (Dict[str, Any]):
            offset: Offset of the last fetched alert.
        first_fetch (str): Determines the time of when fetching has been started.
        max_fetch (int): Max number of incidents to fetch in a single run.

        alert_types (List[str], optional): Alert types to filter by.
        network_types (List[str], optional): Network types to filter by.
        alert_severities (List[str], optional): Alert severities to filter by.
        source_types (List[str], optional): Alert source types to filter by.
        fetch_csv (bool, optional): Whether to fetch CSV file if exist.
        is_closed (bool): Whether to fetch closed alerts.
        fetch_attachments (bool, optional): Whether to fetch images if exist.
    Returns:
        Tuple[Dict[str, Any], List[dict]]:
            next_run: Contains information that will be used in the next run.
            incidents: List of incidents that will be created in XSOAR.
    """
    incidents = []
    offset = None
    if (offset_time := last_run.get("time")) and (offset_id := last_run.get("last_id")):
        try:
            datetime.fromisoformat(offset_time.replace("Z", "+00:00"))
            offset = f"{offset_time}::{offset_id}"
        except ValueError:
            demisto.debug(f'Error occurred while transforming offset time "{offset_time}" from last run.')
            offset = None

    list_response = client.list_alert(
        offset=offset,
        limit=max_fetch,
        last_updated_from=first_fetch,
        alert_type=alert_types,
        network_type=network_types,
        severity=alert_severities,
        source_type=source_types,
        is_closed=is_closed,
    )
    if not list_response.get("content"):
        demisto.debug(f'Alerts not found with the provided parameters and with the offset "{offset}".')
        return last_run, []

    alert_ids = [alert["_id"] for alert in list_response["content"]]
    alert_ids_list = ', '.join(alert_ids)
    demisto.debug(
        f'List of alert IDs "{alert_ids_list}" found with the provided parameters and with the offset "{offset}".')
    for alert_id in alert_ids:
        alert_details = client.get_alert(alert_id=alert_id)
        incident = client.parser.alert_fetch_parser(alert_details)
        incident["fetch_csv"] = fetch_csv
        incident["fetch_attachments"] = fetch_attachments
        incidents.append(client.parser.parse_incident(alert=incident))

    offset_date = list_response["content"][-1].get("updateDate")
    offset_id = list_response["content"][-1].get("_id")
    next_run = {"time": offset_date, "last_id": offset_id}
    return next_run, incidents


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    base_url = params["base_url"]
    account_id = dict_safe_get(params, ["credentials", "identifier"])
    api_key = dict_safe_get(params, ["credentials", "password"])
    mssp_sub_account = params.get("mssp_sub_account")
    reliability = params.get("integrationReliability", DBotScoreReliability.C)
    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    execution_metrics = ExecutionMetrics()

    if DBotScoreReliability.is_valid_type(reliability):
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            reliability
        )
    else:
        raise ValueError(
            "Please provide a valid value for the Source Reliability parameter."
        )

    command = demisto.command()
    demisto.debug(f'The command being called is {command}.')
    commands: Dict[str, Callable] = {
        "threat-command-cyber-term-list": list_cyber_term_command,
        "threat-command-cyber-term-cve-list": list_cyber_term_cve_command,
        "threat-command-cyber-term-ioc-list": list_cyber_term_ioc_command,
        "threat-command-source-list": list_source_command,
        "threat-command-source-document-create": create_source_document_command,
        "threat-command-source-document-delete": delete_source_document_command,
        "threat-command-source-document-ioc-create": create_source_document_ioc_command,
        "threat-command-ioc-tags-add": add_tags_ioc_command,
        "threat-command-ioc-severity-update": update_ioc_severity_command,
        "threat-command-ioc-comment-add": add_ioc_comment_command,
        "threat-command-enrichment-quota-usage": usage_quota_enrichment_command,
        "threat-command-account-whitelist-update": update_account_whitelist_command,
        "threat-command-account-whitelist-remove": remove_account_whitelist_command,
        "threat-command-ioc-blocklist-add": add_ioc_blocklist_command,
        "threat-command-ioc-blocklist-remove": remove_ioc_blocklist_command,
        "threat-command-alert-list": list_alert_handler_command,
        "threat-command-alert-takedown-request": takedown_alert_command,
        "threat-command-alert-takedown-request-status-get": get_takedown_alert_command,
        "threat-command-alert-create": create_alert_command,
        "threat-command-alert-close": close_alert_command,
        "threat-command-alert-severity-update": update_alert_severity_command,
        "threat-command-alert-blocklist-get": get_alert_blocklist_status_command,
        "threat-command-alert-blocklist-update": update_alert_blocklist_command,
        "threat-command-alert-ioc-report": report_alert_ioc_command,
        "threat-command-alert-assign": assign_alert_command,
        "threat-command-alert-unassign": unassign_alert_command,
        "threat-command-alert-reopen": reopen_alert_command,
        "threat-command-alert-tag-add": tag_alert_command,
        "threat-command-alert-tag-remove": untag_alert_command,
        "threat-command-alert-send-mail": send_mail_alert_command,
        "threat-command-alert-analyst-ask": analyst_ask_alert_command,
        "threat-command-alert-analyst-conversation-list": list_alert_conversation_command,
        "threat-command-alert-activity-log-get": list_alert_activity_command,
        "threat-command-alert-csv-get": get_alert_csv_command,
        "threat-command-alert-note-add": add_alert_note_command,
        "threat-command-alert-image-list": list_alert_image_command,
        "threat-command-cve-list": list_cve_command,
        "threat-command-cve-add": add_cve_command,
        "threat-command-cve-delete": delete_cve_command,
        "threat-command-asset-add": add_asset_command,
        "threat-command-asset-list": list_assets_command,
        "threat-command-asset-type-list": list_asset_types_command,
        "threat-command-asset-delete": delete_asset_command,
        "threat-command-account-system-modules-list": list_system_modules_command,
        "threat-command-mention-search": search_mention_command,
        "threat-command-mssp-customer-list": list_mssp_customer_command,
        "threat-command-mssp-user-list": list_mssp_user_command,
        "threat-command-account-user-list": list_account_user_command,
        "threat-command-alert-type-list": list_alert_type_command,
        "threat-command-alert-source-type-list": list_alert_source_type_command,
        "threat-command-alert-scenario-list": list_alert_scenario_command,
    }
    polling_commands = {
        "threat-command-ioc-search": search_ioc_handler_command,
        "file": file_command,
        "ip": ip_command,
        "url": url_command,
        "domain": domain_command,
    }

    try:
        client: Client = Client(
            base_url=base_url,
            account_id=account_id,
            api_key=api_key,
            mssp_sub_account=mssp_sub_account,
            reliability=reliability,
            verify=verify_certificate,
            proxy=proxy,
        )
        if command == "test-module":
            return_results(test_module(client, params))
        elif command in polling_commands:
            return_results(polling_commands[command](args, client, execution_metrics))
        elif command in commands:
            return_results(commands[command](client, args))
        elif command == "fetch-incidents":
            first_fetch = arg_to_datetime(params.get("first_fetch"))
            max_fetch = arg_to_number(params["max_fetch"])
            if isinstance(max_fetch, int) and max_fetch > 200:
                demisto.debug(f"The max fetch value is {max_fetch}, which is greater than the maximum allowed value "
                              "of 200. Setting it to 200.")
                max_fetch = 200
            alert_types = argToList(params.get("alert_types"))
            network_types = argToList(params.get("network_types"))
            alert_severities = minimum_severity_handler(params.get("alert_severity"))
            source_types = argToList(params.get("source_types"))
            is_closed = argToBoolean(params["fetch_closed_incidents"])
            fetch_csv = argToBoolean(params["fetch_csv"])
            fetch_attachments = argToBoolean(params["fetch_attachments"])
            if not max_fetch or max_fetch < 1:
                raise ValueError("max_fetch must be a positive integer.")

            if not isinstance(first_fetch, datetime):
                raise ValueError(ReadableErrors.FIRST_FETCH_NOT_EXIST.value)

            first_fetch_time = first_fetch.strftime(ISO_8601_FORMAT)

            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=last_run,
                first_fetch=first_fetch_time,
                max_fetch=max_fetch,
                alert_types=alert_types,
                network_types=network_types,
                alert_severities=alert_severities,
                source_types=source_types,
                is_closed=is_closed,
                fetch_csv=fetch_csv,
                fetch_attachments=fetch_attachments,
            )
            demisto.info(f'Fetched {len(incidents)} new incidents.')
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
