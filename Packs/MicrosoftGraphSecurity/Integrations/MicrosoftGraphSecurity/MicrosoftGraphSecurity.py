import re
from datetime import timezone
from enum import Enum
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from MicrosoftApiModule import *  # noqa: E402
from requests import Response

from CommonServerUserPython import *

DEFAULT_KEYS_TO_REPLACE = {"createdDateTime": "CreatedDate"}

APP_NAME = "ms-graph-security"
CMD_URL = "security/alerts_v2"
PAGE_SIZE_LIMIT = 2000
THREAT_ASSESSMENT_URL_PREFIX = "informationProtection/threatAssessmentRequests"
MAX_ITEMS_PER_RESPONSE = 50
FETCH_INCIDENTS_TIMEOUT = 60
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
# Graph severity -> XSOAR severity.
SEVERITY_MAP = {
    "low": IncidentSeverity.LOW,
    "medium": IncidentSeverity.MEDIUM,
    "high": IncidentSeverity.HIGH,
    "unknown": IncidentSeverity.UNKNOWN,
    "informational": IncidentSeverity.INFO,
    "unknownFutureValue": IncidentSeverity.UNKNOWN,
}

""" MIRRORING CONSTANTS """

INCIDENTS_URL = "security/incidents"
PREFER_UNKNOWN_ENUM_HEADER = {"Prefer": "include-unknown-enum-members"}
MIRROR_DIRECTION = {"Incoming": "In", "Outgoing": "Out", "Incoming And Outgoing": "Both"}
MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR = "Mirrored from Cortex XSOAR"
# Classifier discriminator key added to every raw alert/incident.
MIRROR_TYPE_KEY = "mirror_type"
MIRROR_TYPE_ALERT = "alert"
MIRROR_TYPE_INCIDENT = "incident"

# Error message that stops the current mirroring sync cycle.
RATE_LIMIT_ERROR_MESSAGE = "API rate limit"
GRAPH_RESOLVED_STATUS = "resolved"
# Incident merged into another incident (redirectIncidentId).
GRAPH_REDIRECTED_STATUS = "redirected"
REDIRECTED_CLOSE_REASON = "Resolved"
XSOAR_INVESTIGATION_STATUS_CLOSED = 1
GRAPH_DEFAULT_REOPEN_STATUS = {MIRROR_TYPE_INCIDENT: "active", MIRROR_TYPE_ALERT: "new"}
# Graph statuses that reopen the XSOAR incident.
GRAPH_ACTIVE_STATUSES = {
    MIRROR_TYPE_INCIDENT: {"active", "inProgress", "awaitingAction"},
    MIRROR_TYPE_ALERT: {"new", "inProgress"},
}
# Delta keys that mark an outgoing close (closingUserId is used only for reopen detection).
CLOSE_FIELD_KEYS = ("closeReason", "closeNotes", "resolvingComment")
# Close comment format: "<reason prefix><reason>\n<notes prefix><notes>".
CLOSE_COMMENT_REASON_PREFIX = "Closed in Cortex XSOAR as: "
CLOSE_COMMENT_NOTES_PREFIX = "Comment: "
# Close comment sent when there is no close reason or close notes.
DEFAULT_CLOSE_COMMENT = "Closed in Cortex XSOAR."
# Incoming close notes when the resolved Microsoft object has no resolvingComment.
INCOMING_DEFAULT_CLOSE_NOTES = "Resolved in Microsoft Graph Security."
# Graph placeholder enum member, never sent in a PATCH.
UNKNOWN_FUTURE_VALUE = "unknownFutureValue"
UNKNOWN_FUTURE_VALUE_KEYS = {"status", "classification", "determination"}

# XSOAR severity -> Graph severity (outgoing incidents only; Critical is not sent).
XSOAR_TO_GRAPH_SEVERITY = {
    IncidentSeverity.UNKNOWN: "unknown",
    IncidentSeverity.INFO: "informational",
    IncidentSeverity.LOW: "low",
    IncidentSeverity.MEDIUM: "medium",
    IncidentSeverity.HIGH: "high",
}
GRAPH_SEVERITY_VALUES = set(XSOAR_TO_GRAPH_SEVERITY.values())

# Combined "classification - determination" label -> Graph (classification, determination).
CLASSIFICATION_LABEL_TO_GRAPH = {
    "Unclassified": ("unknown", "unknown"),
    "True positive - Multi staged attack": ("truePositive", "multiStagedAttack"),
    "True positive - Malware": ("truePositive", "malware"),
    "True positive - Malicious user activity": ("truePositive", "maliciousUserActivity"),
    "True positive - Unwanted software": ("truePositive", "unwantedSoftware"),
    "True positive - Phishing": ("truePositive", "phishing"),
    "True positive - Compromised account": ("truePositive", "compromisedAccount"),
    "True positive - Other": ("truePositive", "other"),
    "Informational - Security testing": ("informationalExpectedActivity", "securityTesting"),
    "Informational - Confirmed activity": ("informationalExpectedActivity", "confirmedActivity"),
    "Informational - Line of business application": ("informationalExpectedActivity", "lineOfBusinessApplication"),
    "Informational - Other": ("informationalExpectedActivity", "other"),
    "False positive - Not malicious": ("falsePositive", "notMalicious"),
    "False positive - Not enough data to validate": ("falsePositive", "notEnoughDataToValidate"),
    "False positive - Other": ("falsePositive", "other"),
}

MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON = {
    "unknown": "Other",
    "truePositive": "Resolved",
    "falsePositive": "False Positive",
    "informationalExpectedActivity": "Resolved",
}

# closeReason is mapped only for the close comment; determination is derived from the classification label.
CLOSE_REASON_FIELD_DESCRIPTION = (
    "The close reason of the Cortex XSOAR incident. Used only for the close comment, not sent as a field."
)
OUTGOING_ALERT_FIELDS = {
    "closeReason": CLOSE_REASON_FIELD_DESCRIPTION,
    "closeNotes": "The close notes of the Cortex XSOAR incident. Used only for the close comment, not sent as a field.",
    "status": "The status of the alert. Possible values are: new, inProgress, resolved. "
    "Sent only when 'Close Mirrored Microsoft Alert/Incident' (close_out) is enabled.",
    "classification": "The specification for the alert (combined classification and determination label).",
    "customDetails": "User defined custom fields with string values.",
}
OUTGOING_INCIDENT_FIELDS = {
    "closeReason": CLOSE_REASON_FIELD_DESCRIPTION,
    "status": "The status of the incident. Possible values are: active, inProgress, resolved. "
    "Sent only when 'Close Mirrored Microsoft Alert/Incident' (close_out) is enabled.",
    "classification": "The specification for the incident (combined classification and determination label).",
    "severity": "Indicates the possible impact on assets. Possible values are: unknown, informational, low, medium, high.",
    "displayName": "The incident name.",
    "description": "A description of the incident.",
    "customTags": "Array of custom tags associated with an incident.",
    "resolvingComment": "User input that explains the resolution of the incident and the classification choice.",
}

# assignedTo is mirrored in only.
INCIDENT_PATCH_KEYS = {
    "classification",
    "determination",
    "severity",
    "status",
    "displayName",
    "description",
    "customTags",
    "resolvingComment",
}
# Alert severity is mirrored in only (Graph rejects alert severity updates).
ALERT_PATCH_KEYS = {"status", "classification", "determination", "customDetails"}
# XSOAR field cliName -> Graph key, for deltas that hold raw field names.
XSOAR_FIELD_TO_GRAPH_KEY: dict[str, dict[str, str]] = {
    MIRROR_TYPE_INCIDENT: {
        "microsoftgraphsecurityincidentstatus": "status",
        "microsoftgraphsecurityclassification": "classification",
        "name": "displayName",
        "microsoftgraphsecurityincidenttags": "customTags",
    },
    MIRROR_TYPE_ALERT: {
        "microsoftgraphsecurityalertstatus": "status",
        "microsoftgraphsecurityclassification": "classification",
        "additionaldata": "customDetails",
    },
}
# Values treated as "not set" in a PATCH body.
EMPTY_PATCH_VALUES: tuple = (None, "", [], {})
# Typed empty values sent when a field is cleared in Cortex XSOAR.
CLEARABLE_PATCH_KEYS: dict[str, dict[str, Any]] = {
    MIRROR_TYPE_INCIDENT: {"customTags": [], "description": ""},
    MIRROR_TYPE_ALERT: {"customDetails": {}},
}
# Alert customDetails <-> "Additional Data" items.
CUSTOM_DETAILS_LIST_KEY = "customDetailsList"
CUSTOM_DETAILS_SEPARATOR = ": "
XSOAR_TAGS_KEY = "xsoarTags"
XSOAR_TAGS_JOINER = ", "


def build_graph_comment_body(comment: str) -> dict:
    """Builds the request body for creating an alert/incident comment in Microsoft Graph."""
    return {"@odata.type": "microsoft.graph.security.alertComment", "comment": comment}


def add_mirror_marker(text: str) -> str:
    """Appends the mirrored-out marker, so mirror-in can skip comments that came from Cortex XSOAR."""
    return f"{text}\n\n {MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR}"


def split_xsoar_tags(value: Any) -> list[str]:
    """Splits the reserved `xsoarTags` value ("a, b") into its non-empty, stripped plain items."""
    return [tag.strip() for tag in str(value or "").split(XSOAR_TAGS_JOINER) if tag.strip()]


def custom_details_to_list(custom_details: Any) -> list[str]:
    """
    Converts alert customDetails into "Additional Data" items: "key: value" per entry, `xsoarTags` split into plain items.
    E.g. {"a": "1", "xsoarTags": "x, y"} -> ["a: 1", "x", "y"]. Returns [] if the input is not a dict.
    """
    if not isinstance(custom_details, dict):
        return []
    items: list[str] = []
    for key, value in custom_details.items():
        if key == XSOAR_TAGS_KEY:
            items.extend(split_xsoar_tags(value))
            continue
        items.append(f"{key}{CUSTOM_DETAILS_SEPARATOR}{'' if value is None else value}")
    return items


def split_custom_details_item(item: str) -> tuple[str, str] | None:
    """
    Splits one Additional Data item into a stripped (key, value) pair.
    Splits on the first ": " only, so values may contain colons (e.g. "url: https://fake-url.com/a:b").
    An item ending with ":" (and no ": ") gives an empty value ("key:" -> ("key", "")).
    Returns None when there is no separator or the key is empty (e.g. "https://fake-url.com", "10:30", ": v");
    the caller then puts the item in xsoarTags.
    """
    key, separator, value = item.partition(CUSTOM_DETAILS_SEPARATOR)
    if not separator and item.endswith(":"):
        key, separator, value = item[:-1], ":", ""
    key = key.strip()
    return (key, value.strip()) if separator and key else None


def normalize_additional_data(value: Any) -> list[str] | dict:
    """
    Normalizes outgoing "Additional Data": a dict / JSON object string stays a dict, anything else becomes a list of
    non-empty string items (a plain string is one item).
    """
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = [value]
    if isinstance(value, dict):
        return value
    if not isinstance(value, list):
        value = [value]
    return [str(item).strip() for item in value if item is not None and str(item).strip()]


def additional_data_to_custom_details(value: Any) -> dict[str, str]:
    """
    Converts "Additional Data" into alert customDetails (string values; duplicate keys: last wins).
    Plain items are joined under `xsoarTags`: ["owner: SOC", "malware"] -> {"owner": "SOC", "xsoarTags": "malware"}.
    """
    normalized = normalize_additional_data(value)
    if isinstance(normalized, dict):
        return {str(key): "" if item is None else str(item) for key, item in normalized.items()}
    custom_details: dict[str, str] = {}
    plain_items: list[str] = []
    for item in normalized:
        split_item = split_custom_details_item(item)
        if not split_item:
            demisto.debug(f"[Mirroring] Additional Data item {item!r} has no 'key: value' separator, adding to {XSOAR_TAGS_KEY}.")
            plain_items.append(item)
        elif split_item[0] == XSOAR_TAGS_KEY:
            plain_items.extend(split_xsoar_tags(split_item[1]))
        else:
            custom_details[split_item[0]] = split_item[1]
    if plain_items:
        custom_details[XSOAR_TAGS_KEY] = XSOAR_TAGS_JOINER.join(plain_items)
    return custom_details


DataSourceType = {
    "USER": {
        "type": "User",
        "url_suffix": "userSources",
        "unique_table_headers": ["IncludedSources"],
        "outputs_prefix": "CustodianUserSource",
    },
    "SITE": {"type": "Site", "url_suffix": "siteSources", "unique_table_headers": [], "outputs_prefix": "CustodianSiteSource"},
    "NON_CUSTODIAL": {
        "type": "Data",
        "url_suffix": "noncustodialDataSources",
        "unique_table_headers": ["LastModifiedDateTime", "ReleasedDateTime", "Status"],
        "outputs_prefix": "NoncustodialDataSource",
    },
}

EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"


class HoldAction(Enum):
    APPLY = "apply"
    REMOVE = "remove"


RELEVANT_DATA_TO_UPDATE = {
    "assigned_to": "assignedTo",
    "determination": "determination",
    "classification": "classification",
    "status": "status",
}


def is_rate_limit_error(error: Exception) -> bool:
    """True when the error is an HTTP 429 (Too Many Requests) API error."""
    return getattr(getattr(error, "res", None), "status_code", None) == 429 or "[429]" in str(error)


class MsGraphClient:
    """
    Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
    """

    def __init__(self, tenant_id, proxy, certificate_thumbprint: str | None = None, **kwargs):
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id,
            proxy=proxy,
            certificate_thumbprint=certificate_thumbprint,
            managed_identities_resource_uri=Resources.graph,
            command_prefix=APP_NAME,
            **kwargs,
        )

    def get(self, url, **kwargs):
        return self.ms_client.http_request(method="GET", url_suffix=url, **kwargs)

    def search_alerts(self, params):
        cmd_url = CMD_URL
        headers = {"Prefer": "include-unknown-enum-members"}
        # This header maps unknownFutureValue value to the appropriate service resource.
        # https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0#:~:text=microsoftThreatIntelligence.%20Use%20the%20Prefer%3A-,include%2Dunknown%2Denum%2Dmembers,-request%20header%20to%20get%20the
        demisto.debug(f"Fetching MS Graph Security alerts with params: {params} and header: {headers}")
        response = self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params, headers=headers)
        return response

    def get_alert_details(self, alert_id):
        cmd_url = f"{CMD_URL}/{alert_id}"
        response = self.ms_client.http_request(method="GET", url_suffix=cmd_url)
        return response

    def update_alert(self, alert_id, params):
        cmd_url = f"{CMD_URL}/{alert_id}"
        self.ms_client.http_request(method="PATCH", url_suffix=cmd_url, json_data=params, resp_type="text")

    def get_users(self):
        cmd_url = "users"
        response = self.ms_client.http_request(method="GET", url_suffix=cmd_url)
        return response

    def get_user(self, user_id):
        cmd_url = f"users/{user_id}"
        response = self.ms_client.http_request(method="GET", url_suffix=cmd_url)
        return response

    def create_alert_comment(self, alert_id: str, body: dict) -> dict:
        """
        Creates an alert comment (POST security/alerts_v2/{id}/comments). `body` is the full comment body.
        """
        cmd_url = f"{CMD_URL}/{alert_id}/comments"
        response = self.http_request_fail_on_429("POST", url_suffix=cmd_url, json_data=body)
        return response

    def create_incident_comment(self, incident_id: str, body: dict) -> dict:
        """
        Creates an incident comment (POST security/incidents/{id}/comments). `body` is the full comment body.
        """
        cmd_url = f"{INCIDENTS_URL}/{incident_id}/comments"
        response = self.http_request_fail_on_429("POST", url_suffix=cmd_url, json_data=body)
        return response

    def http_request_fail_on_429(self, method: str, **request_kwargs) -> Any:
        """
        Sends a request via MicrosoftClient.http_request, used by the mirroring commands. HTTP 429 is not retried here
        (no sleep in mirroring): it is raised at once as an "API rate limit" DemistoException, so the current sync cycle
        stops and the next cycle retries. Any other error is raised as-is.
        Note: MicrosoftClient.http_request already lets urllib3 retry a 429 that has a Retry-After header (retries=3).
        """
        try:
            return self.ms_client.http_request(method=method, **request_kwargs)
        except Exception as e:
            if not is_rate_limit_error(e):
                raise
            demisto.debug(
                f"[Mirroring] HTTP 429 from Microsoft Graph ({method}); failing this sync cycle without retrying: {e!s}"
            )
            raise DemistoException(
                f"{RATE_LIMIT_ERROR_MESSAGE}: Microsoft Graph returned HTTP 429 (Too Many Requests). {e!s}",
                exception=e,
                res=getattr(e, "res", None),
            )

    def http_get_with_rate_limit(self, **request_kwargs) -> dict:
        """
        GET with the `Prefer: include-unknown-enum-members` header and FETCH_INCIDENTS_TIMEOUT, with the 429 handling of
        http_request_fail_on_429.
        """
        return self.http_request_fail_on_429(
            "GET", headers=PREFER_UNKNOWN_ENUM_HEADER, timeout=FETCH_INCIDENTS_TIMEOUT, **request_kwargs
        )

    def get_alert_by_id(self, alert_id: str) -> dict:
        """Gets a single alert by ID (GET security/alerts_v2/{id}), with the mirroring rate-limit handling."""
        cmd_url = f"{CMD_URL}/{alert_id}"
        return self.http_get_with_rate_limit(url_suffix=cmd_url)

    def get_incident_by_id(self, incident_id: str, expand_alerts: bool = False) -> dict:
        """Gets a single incident by ID (GET security/incidents/{id}), optionally with `?$expand=alerts`."""
        cmd_url = f"{INCIDENTS_URL}/{incident_id}"
        if expand_alerts:
            cmd_url += "?$expand=alerts"
        return self.http_get_with_rate_limit(url_suffix=cmd_url)

    def update_alert_by_id(self, alert_id: str, body: dict) -> None:
        """PATCHes an alert (security/alerts_v2/{id}) with the given body."""
        cmd_url = f"{CMD_URL}/{alert_id}"
        self.http_request_fail_on_429(
            "PATCH", url_suffix=cmd_url, json_data=body, resp_type="text", timeout=FETCH_INCIDENTS_TIMEOUT
        )

    def update_incident_by_id(self, incident_id: str, body: dict) -> None:
        """PATCHes an incident (security/incidents/{id}) with the given body."""
        cmd_url = f"{INCIDENTS_URL}/{incident_id}"
        self.http_request_fail_on_429(
            "PATCH", url_suffix=cmd_url, json_data=body, resp_type="text", timeout=FETCH_INCIDENTS_TIMEOUT
        )

    def list_modified_object_ids(self, object_url: str, last_update_iso: str) -> list[str]:
        """
        Lists the IDs of alerts/incidents modified since `last_update_iso`, oldest change first
        ($orderby=lastUpdateDateTime asc), following @odata.nextLink until the last page.

        Returns:
            The IDs of the modified objects.
        """
        request: dict[str, Any] = {
            "url_suffix": f"{object_url}?$filter=lastUpdateDateTime ge {last_update_iso}"
            f"&$orderby=lastUpdateDateTime asc&$top={MAX_ITEMS_PER_RESPONSE}"
        }
        modified_ids: list[str] = []
        pages = 0
        while request:
            response = self.http_get_with_rate_limit(**request)
            modified_ids.extend(str(obj["id"]) for obj in response.get("value", []) if obj.get("id"))
            pages += 1
            next_link = response.get("@odata.nextLink")
            request = {"full_url": next_link} if next_link else {}
        demisto.debug(f"[Mirroring] Listed {len(modified_ids)} modified IDs from {object_url} in {pages} page(s).")
        return modified_ids

    def list_ediscovery_cases(self, case_id: str | None):
        url = "security/cases/ediscoveryCases"
        if case_id:
            url += f"/{case_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def create_edsicovery_case(self, display_name, description, external_id):
        url = "security/cases/ediscoveryCases"
        return self.ms_client.http_request(
            method="POST",
            url_suffix=url,
            json_data={"displayName": display_name, "description": description, "externalId": external_id},
        )

    def update_edsicovery_case(self, case_id, display_name, description, external_id):
        url = f"security/cases/ediscoveryCases/{case_id}"
        req = {"displayName": display_name, "description": description, "externalId": external_id}

        remove_nulls_from_dictionary(req)
        self.ms_client.http_request(ok_codes=[204], method="PATCH", url_suffix=url, json_data=req, resp_type="text")

    def close_edsicovery_case(self, case_id):
        url = f"security/cases/ediscoveryCases/{case_id}/close"
        self.ms_client.http_request(ok_codes=[204], method="POST", url_suffix=url, resp_type="text")

    def reopen_edsicovery_case(self, case_id):
        url = f"security/cases/ediscoveryCases/{case_id}/reopen"
        self.ms_client.http_request(ok_codes=[204], method="POST", url_suffix=url, resp_type="text")

    def release_edsicovery_custodian(self, case_id, custodian_id):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/release"
        self.ms_client.http_request(ok_codes=[202], method="POST", url_suffix=url, resp_type="text")

    def activate_edsicovery_custodian(self, case_id, custodian_id):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/activate"
        self.ms_client.http_request(ok_codes=[202], method="POST", url_suffix=url, resp_type="text")

    def delete_edsicovery_case(self, case_id):
        url = f"security/cases/ediscoveryCases/{case_id}"
        self.ms_client.http_request(ok_codes=[204], method="DELETE", url_suffix=url, resp_type="text")

    def create_edsicovery_custodian(self, case_id, email):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians"
        return self.ms_client.http_request(method="POST", url_suffix=url, json_data={"email": email})

    def list_ediscovery_custodians(self, case_id, custodian_id):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians"
        if custodian_id:
            url += f"/{custodian_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def create_edsicovery_custodian_user_source(self, case_id, custodian_id, email, included_sources):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/userSources"
        return self.ms_client.http_request(
            method="POST", url_suffix=url, json_data={"email": email, "includedSources": included_sources}
        )

    def create_edsicovery_custodian_site_source(self, case_id, custodian_id, site):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/siteSources"
        return self.ms_client.http_request(
            method="POST",
            url_suffix=url,
            json_data={
                "site": {
                    "webUrl": site,
                }
            },
        )

    def list_ediscovery_custodians_sources(self, case_id, custodian_id, source_id, source_type):
        url = f'security/cases/ediscoveryCases/{case_id}/custodians/{custodian_id}/{source_type["url_suffix"]}'
        if source_id:
            url += f"/{source_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def create_ediscovery_non_custodial_data_source(self, case_id, site, email):
        url = f"security/cases/ediscoveryCases/{case_id}/noncustodialDataSources"
        body = (
            {"dataSource": {"@odata.type": "microsoft.graph.security.userSource", "email": email}}
            if email
            else {"dataSource": {"@odata.type": "microsoft.graph.security.siteSource", "site": {"webUrl": site}}}
        )
        return self.ms_client.http_request(method="POST", url_suffix=url, json_data=body)

    def list_ediscovery_noncustodial_datasources(self, case_id, source_id):
        url = f"security/cases/ediscoveryCases/{case_id}/noncustodialDataSources"
        if source_id:
            url += f"/{source_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def update_hold_ediscovery_custodian(self, case_id: str, custodian_id: str, hold_action: HoldAction):
        url = f"security/cases/ediscoveryCases/{case_id}/custodians/{hold_action.value}Hold"
        body = {"ids": custodian_id.split(",")}
        return self.ms_client.http_request(method="POST", url_suffix=url, resp_type="response", json_data=body)

    def create_ediscovery_search(self, case_id, display_name, description, query, data_source_scopes):
        url = f"/security/cases/ediscoveryCases/{case_id}/searches"
        body = {
            "displayName": display_name,
            "description": description,
            "contentQuery": query,
            "dataSourceScopes": data_source_scopes,
        }
        return self.ms_client.http_request(method="POST", url_suffix=url, json_data=body)

    def update_ediscovery_search(self, case_id, search_id, display_name, description, query, data_source_scopes):
        url = f"/security/cases/ediscoveryCases/{case_id}/searches/{search_id}"
        body = {
            "displayName": display_name,
            "description": description,
            "contentQuery": query,
            "dataSourceScopes": data_source_scopes,
        }
        remove_nulls_from_dictionary(body)
        self.ms_client.http_request(ok_codes=[204], method="PATCH", url_suffix=url, json_data=body, resp_type="text")

    def list_ediscovery_search(self, case_id, search_id):
        url = f"security/cases/ediscoveryCases/{case_id}/searches"
        if search_id:
            url += f"/{search_id}"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def delete_ediscovery_search(self, case_id, search_id):
        url = f"security/cases/ediscoveryCases/{case_id}/searches/{search_id}"
        self.ms_client.http_request(ok_codes=[204], method="DELETE", url_suffix=url, resp_type="text")

    def purge_ediscovery_data(self, case_id, search_id, purge_type, purge_areas):
        url = f"security/cases/ediscoveryCases/{case_id}/searches/{search_id}/purgeData"
        body = {"purgeType": purge_type, "purgeAreas": purge_areas}
        return self.ms_client.http_request(method="POST", url_suffix=url, json_data=body, resp_type="response")

    def start_estimate_statistics_request(self, case_id, search_id, statistics_options=None):
        url = f"security/cases/ediscoveryCases/{case_id}/searches/{search_id}/estimateStatistics"
        body = {}
        if statistics_options:
            # Handle lists or single values safely
            if isinstance(statistics_options, list):
                statistics_options = ",".join(statistics_options)
            body["statisticsOptions"] = statistics_options

        response = self.ms_client.http_request(
            method="POST",
            url_suffix=url,
            json_data=body,
            resp_type="response",
            ok_codes=[202],
        )

        # Get the Location header which contains the location of the microsoft.graph.security.estimateStatisticsOperation
        # that was created to handle the estimate.
        location_url = response.headers.get("Location")
        if not location_url:
            raise DemistoException("Estimate statistics is not available for this search_id.")

        # Fetch operation status
        operation = self.ms_client.http_request(method="GET", full_url=location_url)

        return operation

    def get_last_estimate_statistics_operation(self, case_id: str, search_id: str):
        url = f"security/cases/ediscoveryCases/{case_id}/searches/{search_id}/lastEstimateStatisticsOperation"
        return self.ms_client.http_request(method="GET", url_suffix=url)

    def create_ediscovery_case_hold_policy(
        self,
        case_id: str,
        display_name: str,
        description: Any,
        content_query: Any,
    ) -> Any:
        """
        Create a legal hold policy for an eDiscovery case.

        Args:
            case_id: The ID of the eDiscovery case.
            display_name: The display name of the hold policy.
            description: Description of the hold policy.
            content_query: KQL query defining content to be held.

        Returns:
            The created hold policy object.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/legalHolds"
        body = assign_params(
            displayName=display_name,
            description=description,
            contentQuery=content_query,
        )
        return self.ms_client.http_request(method="POST", url_suffix=url, json_data=body)

    def delete_ediscovery_case_hold_policy(
        self,
        case_id: str,
        hold_policy_id: str,
    ) -> None:
        """
        Delete a legal hold policy from an eDiscovery case.

        Args:
            case_id: The ID of the eDiscovery case.
            hold_policy_id: The ID of the hold policy to delete.

        Returns:
            None.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/legalHolds/{hold_policy_id}"
        self.ms_client.http_request(
            ok_codes=[204],
            method="DELETE",
            url_suffix=url,
            return_empty_response=True,
        )

    def update_ediscovery_case_policy(
        self,
        case_id: str,
        hold_policy_id: str,
        description: Any,
        content_query: Any,
    ) -> None:
        """
        Update an existing legal hold policy.

        Args:
            case_id: The ID of the eDiscovery case.
            hold_policy_id: The ID of the hold policy to update.
            description: Updated description.
            content_query: Updated content query.

        Returns:
            None.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/legalHolds/{hold_policy_id}"
        body = assign_params(
            description=description,
            contentQuery=content_query,
        )
        self.ms_client.http_request(
            ok_codes=[204],
            method="PATCH",
            url_suffix=url,
            json_data=body,
            return_empty_response=True,
        )

    def list_ediscovery_case_hold_policy(
        self,
        case_id: str,
        limit: int | None,
    ) -> Any:
        """
        List legal hold policies for an eDiscovery case.

        Args:
            case_id: The ID of the eDiscovery case.
            limit: Maximum number of results to return.

        Returns:
            A list of hold policy objects.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/legalHolds"
        if limit:
            url += f"?$top={limit}"
        return self.ms_client.http_request(ok_codes=[200], method="GET", url_suffix=url)

    def get_ediscovery_case_hold_policy(
        self,
        case_id: str,
        hold_policy_id: str,
    ) -> Any:
        """
        Retrieve a specific legal hold policy.

        Args:
            case_id: The ID of the eDiscovery case.
            hold_policy_id: The ID of the hold policy.

        Returns:
            The hold policy object.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/legalHolds/{hold_policy_id}"
        return self.ms_client.http_request(ok_codes=[200], method="GET", url_suffix=url)

    def list_case_operation(
        self,
        case_id: str,
        limit: int | None,
    ) -> Any:
        """
        List operations for an eDiscovery case.

        Args:
            case_id: The ID of the eDiscovery case.
            limit: Maximum number of results to return.

        Returns:
            A list of case operation objects.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/operations"
        if limit:
            url += f"?$top={limit}"
        return self.ms_client.http_request(ok_codes=[200], method="GET", url_suffix=url)

    def get_case_operation(
        self,
        case_id: str,
        operation_id: str,
    ) -> Any:
        """
        Retrieve a specific eDiscovery case operation.

        Args:
            case_id: The ID of the eDiscovery case.
            operation_id: The ID of the operation.

        Returns:
            The operation object.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/operations/{operation_id}"
        return self.ms_client.http_request(ok_codes=[200], method="GET", url_suffix=url)

    def export_result_ediscovery_data(
        self,
        case_id: str,
        search_id: str,
        additional_options: str,
        export_criteria: str,
        export_format: str,
        cloud_attachment_version: str,
        description: str,
        display_name: str,
        document_version: str,
        export_location: str,
    ) -> Any:
        """
        Export search results from an eDiscovery case.

        Args:
            case_id: The ID of the eDiscovery case.
            search_id: The ID of the eDiscovery search.
            additional_options: Additional export options.
            export_criteria: Criteria defining what to export.
            export_format: Export format.
            cloud_attachment_version: Cloud attachment version.
            description: Export description.
            display_name: Display name of the export.
            document_version: Document version.
            export_location: Export destination.

        Returns:
            HTTP response object for the export request.
        """
        url = f"security/cases/ediscoveryCases/{case_id}/searches/{search_id}/exportResult"
        body = assign_params(
            additionalOptions=additional_options,
            exportCriteria=export_criteria,
            exportFormat=export_format,
            cloudAttachmentVersion=cloud_attachment_version,
            description=description,
            displayName=display_name,
            documentVersion=document_version,
            exportLocation=export_location,
        )
        headers = {"Prefer": "include-unknown-enum-members"}
        return self.ms_client.http_request(
            method="POST",
            url_suffix=url,
            json_data=body,
            headers=headers,
            ok_codes=[202],
            return_empty_response=True,
            resp_type="response",
        )

    def create_mail_assessment_request(self, recipient_email, expected_assessment, category, user_id, message_id):
        body = {
            "@odata.type": "#microsoft.graph.mailAssessmentRequest",
            "recipientEmail": recipient_email,
            "expectedAssessment": expected_assessment,
            "category": category,
            "messageUri": urljoin(self.ms_client._base_url, "users/{user_id}/messages/{message_id}"),
        }
        return self.ms_client.http_request(method="POST", url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def get_user_id(self, email):
        return self.ms_client.http_request(method="GET", url_suffix="users", params={"$filter": f"mail eq '{email}'"})

    def get_threat_assessment_request(self, request_id):
        return self.ms_client.http_request(
            method="GET", url_suffix=f"{THREAT_ASSESSMENT_URL_PREFIX}/{request_id}", params={"$expand": "results"}
        )

    def get_threat_assessment_request_status(self, request_id):
        return self.ms_client.http_request(
            method="GET", url_suffix=f"{THREAT_ASSESSMENT_URL_PREFIX}/{request_id}", params={"$select": "status"}
        )

    def create_email_file_assessment_request(self, recipient_email, expected_assessment, category, content_data):
        body = {
            "@odata.type": "#microsoft.graph.emailFileAssessmentRequest",
            "recipientEmail": recipient_email,
            "expectedAssessment": expected_assessment,
            "category": category,
            "contentData": content_data,
        }
        return self.ms_client.http_request(method="POST", url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def create_file_assessment_request(self, expected_assessment, category, file_name, content_data):
        body = {
            "@odata.type": "#microsoft.graph.fileAssessmentRequest",
            "expectedAssessment": expected_assessment,
            "category": category,
            "fileName": file_name,
            "contentData": content_data,
        }
        return self.ms_client.http_request(method="POST", url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def create_url_assessment_request(self, expected_assessment, category, url):
        body = {
            "@odata.type": "#microsoft.graph.urlAssessmentRequest",
            "expectedAssessment": expected_assessment,
            "category": category,
            "url": url,
        }
        return self.ms_client.http_request(method="POST", url_suffix=THREAT_ASSESSMENT_URL_PREFIX, json_data=body)

    def list_threat_assessment_requests(self, filters=None, order_by=None, sort_order=None, next_token=None):
        params = {}
        if next_token:
            return self.ms_client.http_request(
                method="GET",
                url_suffix=THREAT_ASSESSMENT_URL_PREFIX,
                params={"$skipToken": next_token},
            )
        if filters:
            params["$filter"] = filters
        if order_by:
            params["$orderby"] = order_by
            if sort_order:
                params["$orderby"] = f"{order_by} {sort_order}"

        return self.ms_client.http_request(method="GET", url_suffix=THREAT_ASSESSMENT_URL_PREFIX, params=params)

    def advanced_hunting_request(self, query: str, timeout: int):
        """
        POST request to the advanced hunting API:
        Args:
            query (str): query advanced hunting query language
            timeout (int): The amount of time (in seconds) that a request will wait for a client to
                     establish a connection to a remote machine before a timeout occurs.

        Returns:
            The response object contains three top-level properties:

                Stats - A dictionary of query performance statistics.
                Schema - The schema of the response, a list of Name-Type pairs for each column.
                Results - A list of advanced hunting events.
        """
        return self.ms_client.http_request(
            method="POST", url_suffix="security/runHuntingQuery", json_data={"Query": query}, timeout=timeout
        )

    def get_incidents_request(
        self,
        url_suffix: str,
        timeout: int,
        headers: dict | None = None,
    ) -> dict:
        """
        Perform a GET request to retrieve incidents.

        Args:
            url_suffix (str): The URL suffix for the request, including any filters or additional parameters.
            timeout (int): The timeout for the request in seconds.
            headers (dict | None): Optional request headers to send with the request.

        Returns:
            dict: The request results as a dictionary, containing:
                - '@odata.context'
                - 'value': The updated incident(s).
        """

        incident = self.ms_client.http_request(method="GET", url_suffix=url_suffix, timeout=timeout, headers=headers)
        return incident

    def update_incident_request(
        self,
        incident_id: int,
        status: str | None,
        assigned_to: str | None,
        classification: str | None,
        determination: str | None,
        severity: str | None,
        resolving_comment: str | None,
        custom_tags: List[str] | None,
        timeout: int,
    ) -> dict:
        """
         PATCH request to update single incident.
         Args:
             incident_id (int): incident's id
             status (str): Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
             assigned_to (str): Owner of the incident.
             classification (str): Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
             determination (str):  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                  Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
             severity (str): Indicates the possible impact on assets. The higher the severity, the bigger the impact.
                 Typically, higher severity items require the most immediate attention. The possible values are: unknown,
                 informational, low, medium, high, unknownFutureValue.
             resolving_comment (str): User input that explains the resolution of the incident and the classification choice.
                 It contains free editable text.
             tags (list): Custom tags associated with an incident. Separated by commas without spaces (CSV)
                  for example: tag1,tag2,tag3.
             timeout (int): The amount of time (in seconds) that a request will wait for a client to
                 establish a connection to a remote machine before a timeout occurs.
             comment (str): Comment to be added to the incident
        Returns( Dict): request results as dict:
                     { '@odata.context',
                       'value': updated incident,
                     }

        """
        body = assign_params(
            status=status,
            assignedTo=assigned_to,
            classification=classification,
            determination=determination,
            severity=severity,
            resolvingComment=resolving_comment,
            customTags=custom_tags,
        )

        updated_incident = self.ms_client.http_request(
            method="PATCH", url_suffix=f"security/incidents/{incident_id}", json_data=body, timeout=timeout
        )
        return updated_incident

    def download_export_file(self, download_url: str):
        """
        Download an eDiscovery export file using the download URL returned by Microsoft Graph.

        Args:
            download_url (str): The pre-authorized download URL returned in the
                `exportFileMetadata` property of an export operation.

        Returns:
            requests.Response: The raw HTTP response object (resp_type="response"),
                which can be streamed or saved to disk by the caller.
        """
        response = self.ms_client.http_request(
            method="GET",
            headers={"X-AllowWithAADToken": "true"},
            full_url=download_url,
            resp_type="response",
            scope="b26e684c-5068-4120-a679-64a5d2c909d9/.default",
        )
        # Force refresh token reset to default scope and avoid token-scope drift.
        self.ms_client.get_access_token(scope=self.ms_client.scope)
        return response


""" HELPER FUNCTIONS """


def get_status_of_operation(client: MsGraphClient, res: Response) -> str:
    """
    Some responses from MSG where an action is called return a url in the headers that we can use to retrieve the status
    Args:
        client: Microsoft
        GraphClient
        res: the response from the api

    Returns:
        The status
    """
    location = res.headers.get("Location")
    status = "success"  # if no location is returned then the custodian is already in this state/theres no data sources
    if location:
        location = "security" + location.split("/security")[1]  # chop off the baseurl
        resp = client.get(location)
        demisto.debug(f"response from location get: {resp}")
        status = resp.get("status")
    return status


def create_search_alerts_filters(args, is_fetch=False):
    """
    Creates the relevant filters for the search_alerts function.
    Args:
        args (Dict): The command's arguments dictionary.
        is_fetch (bool): whether the search_alerts function is being called from fetch alerts or not.
    Returns:
        Dict: The filter dictionary to use
    """
    last_modified = args.get("last_modified")
    severity = args.get("severity")
    category = args.get("category")
    time_from = args.get("time_from")
    time_to = args.get("time_to")
    filter_query = args.get("filter")
    page = args.get("page")
    page_size = int(args.get("page_size", 50)) if (is_fetch and args.get("page_size")) or not is_fetch else 0
    filters = []
    params: dict[str, str] = {}
    if last_modified:
        filters.append(f"lastUpdateDateTime gt {get_timestamp(last_modified)}")
    if category:
        filters.append(f"category eq '{category}'")
    if severity:
        filters.append(f"severity eq '{severity}'")
    if time_from:  # changed to ge and le in order to solve issue #27884
        filters.append(f"createdDateTime ge {time_from}")
    if time_to:
        filters.append(f"createdDateTime le {time_to}")
    if filter_query:
        # Wrap in parentheses so an `or` clause can't escape the createdDateTime time window (OData `and` binds before `or`).
        filters.append(f"({filter_query})")
    if page_size:
        if page_size > PAGE_SIZE_LIMIT:
            raise DemistoException(f"Please note that the page size limit is {PAGE_SIZE_LIMIT}")
        params["$top"] = str(page_size)
    if page and page_size:
        page = int(page)
        page = page * page_size
        params["$skip"] = page
    relevant_filters_v2 = {
        "classification": "classification",
        "service_source": "serviceSource",
        "status": "status",
    }
    for arg_name, odata_property in relevant_filters_v2.items():
        if val := args.get(arg_name):
            filters.append(f"{odata_property} eq '{val}'")
    filters = " and ".join(filters)
    params["$filter"] = filters
    if is_fetch:
        params["$orderby"] = "createdDateTime asc"
    return params


def created_by_fields_to_hr(ret_context: dict):
    hr = ret_context.copy()
    hr["CreatedByName"] = dict_safe_get(ret_context, ["CreatedBy", "User", "DisplayName"])
    hr["CreatedByUPN"] = dict_safe_get(ret_context, ["CreatedBy", "User", "UserPrincipalName"])
    hr["CreatedByAppName"] = dict_safe_get(ret_context, ["CreatedBy", "Application", "DisplayName"])
    hr.pop("CreatedBy", None)
    return hr


def create_data_to_update(args):
    """
    Creates the data dictionary to update alert for the update_alert function.
    Args:
        args (Dict): The command's arguments dictionary.
    Returns:
        Dict: A dictionary object containing the alert's fields to update.
    """
    if all(not args.get(key) for key in list(RELEVANT_DATA_TO_UPDATE.keys())):
        raise DemistoException(
            f"No data to update was provided, please provide at least one of the"
            f" following: {(', ').join(list(RELEVANT_DATA_TO_UPDATE.keys()))}."
        )
    data: dict[str, Any] = {}
    for relevant_args_key, relevant_data_key in RELEVANT_DATA_TO_UPDATE.items():
        if val := args.get(relevant_args_key):
            data[relevant_data_key] = val
    return data


def get_timestamp(time_description):
    if time_description == "Last24Hours":
        time_delta = 1
    elif time_description == "Last48Hours":
        time_delta = 2
    else:
        time_delta = 7
    return datetime.strftime(datetime.now() - timedelta(time_delta), "%Y-%m-%d")


def capitalize_dict_keys_first_letter(response, keys_to_replace: dict = DEFAULT_KEYS_TO_REPLACE):
    """
    Recursively creates a data dictionary where all key starts with capital letters.
    Args:
        keys_to_replace: keys that should have custom replacements not according to capitalize_first_letter
        response (Dict / str): The dictionary to update.
    Returns:
        Dict: The updated dictionary.
    """
    if isinstance(response, str):
        return response
    parsed_dict: dict = {}
    if isinstance(response, dict):
        for key, value in response.items():
            if keys_to_replace and key in keys_to_replace:
                parsed_dict[keys_to_replace[key]] = value
            elif key == "id":
                parsed_dict["ID"] = value
            elif isinstance(value, dict):
                parsed_dict[capitalize_first_letter(key)] = capitalize_dict_keys_first_letter(value)
            elif isinstance(value, list):
                parsed_dict[capitalize_first_letter(key)] = [capitalize_dict_keys_first_letter(list_item) for list_item in value]
            else:
                parsed_dict[capitalize_first_letter(key)] = value
    return parsed_dict


def capitalize_first_letter(string):
    return string[:1].upper() + string[1:]


def list_ediscovery_custodian_sources(client: MsGraphClient, args, source_type):
    raw_res = client.list_ediscovery_custodians_sources(
        args.get("case_id"), args.get("custodian_id"), args.get(f"{source_type['type']}_source_id".lower()), source_type
    )
    if source_list := raw_res.get("value"):
        demisto.info(f"returned {len(source_list)} results from the api")
    else:
        source_list = [raw_res]  # api doesnt return a list if only 1 result

    if not argToBoolean(args.get("all_results", "false")):
        source_list = source_list[: arg_to_number(args.get("limit", 50))]
    return ediscovery_source_command_results(source_list, source_type, raw_res)


def create_filter_query(filter_param: str, service_sources_param: str):
    """
    Creates the relevant filters to the query filter according to the user's configured filter.
    Args:
        filter_param (str): configured user filter.
        service_sources_param (str): comma separated list of service_sources to fetch alerts by.
    Returns:
        str: filter query to use
    """
    filter_query = ""
    if filter_param:
        filter_query = filter_param
    elif service_sources_param:
        demisto.debug("Using service sources param for filter")
        service_sources_lst = [source.strip() for source in service_sources_param.split(",")]
        # This creates a string like: "serviceSource in ('source1','source2')"
        # see docs supporting this operation: https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http
        quoted_sources = [f"'{source}'" for source in service_sources_lst]
        filter_query = f"serviceSource in ({','.join(quoted_sources)})"
    demisto.debug("filter query: " + str(filter_query))
    return filter_query


def to_cases_hr(ret_context: dict):
    hr = ret_context.copy()
    hr["LastModifiedByName"] = dict_safe_get(ret_context, ["LastModifiedBy", "User", "DisplayName"])
    hr["ClosedByName"] = dict_safe_get(ret_context, ["ClosedBy", "User", "DisplayName"])
    return hr


def ediscovery_cases_command_results(raw_case_list: list, raw_res=None) -> CommandResults:
    """
    Returns the CommandResults for a list of eDiscoveryCases from the API
    Args:
        raw_res: the raw_response to be used. If not provided assumed response==raw_res
        limit: max number of entries to return. Does not affect raw_result
        raw_case_list: the raw response from the api, as a list


    Returns: A CommandResults object

    """
    return to_msg_command_results(
        raw_object_list=raw_case_list,
        raw_res=raw_res,
        outputs_prefix="MsGraph.eDiscoveryCase",
        output_key_field="CaseId",
        raw_keys_to_replace={"status": "CaseStatus", "id": "CaseId"},
        table_headers=[
            "DisplayName",
            "Description",
            "ExternalId",
            "CaseStatus",
            "CaseId",
            "CreatedDateTime",
            "LastModifiedDateTime",
            "LastModifiedByName",
            "ClosedByName",
        ],
        to_hr=to_cases_hr,
    )


def custodian_to_hr(ret_context: dict):
    hr = ret_context.copy()
    hr["LastModifiedByName"] = dict_safe_get(ret_context, ["LastModifiedBy", "User", "DisplayName"])
    hr["ClosedByName"] = dict_safe_get(ret_context, ["ClosedBy", "User", "DisplayName"])
    return hr


def ediscovery_custodian_command_results(raw_custodian_list, raw_res=None):
    return to_msg_command_results(
        raw_object_list=raw_custodian_list,
        raw_res=raw_res,
        outputs_prefix="MsGraph.eDiscoveryCustodian",
        output_key_field="CustodianId",
        raw_keys_to_replace={"status": "CustodianStatus", "id": "CustodianId"},
        table_headers=[
            "DisplayName",
            "Email",
            "CustodianStatus",
            "CustodianId",
            "CreatedDateTime",
            "LastModifiedDateTime",
            "LastModifiedByName",
            "ClosedByName",
            "AcknowledgedDateTime",
            "HoldStatus",
            "ReleasedDateTime",
        ],
        to_hr=custodian_to_hr,
    )


def to_msg_command_results(
    raw_object_list, outputs_prefix, output_key_field, raw_keys_to_replace, raw_res=None, table_headers=[], to_hr=lambda x: x
):
    """
    General function to return command results for Microsoft Graph.

    Keys beginning with @ will be stripped from the response.
    Keys will be converted to CapitalCaseFormat
    Empty elements will be removed

    Args:
        raw_object_list: the list of objects from the api. One item will be converted to a list of one
        outputs_prefix: The outputs prefix for the command
        output_key_field: The key field for the CommandResults
        raw_keys_to_replace: Keys to replace with a specific alternative. EG { 'id' : 'CustomID' }
        raw_res: The raw response exactly as received from the API. Will assume same as raw_object_list if not provided
        table_headers: Headers to show in the human readable output
        to_hr: A function that will take a context dictionary as input and convert it to a human readable dictionary.
        Default is identity function

    Returns:
        A CommandResults object
    """
    raw_res = raw_res or raw_object_list
    if not isinstance(raw_object_list, list):
        raw_object_list = [raw_object_list]
    context_list = []
    human_readable_list = []
    for res in raw_object_list:
        context = capitalize_dict_keys_first_letter(res, keys_to_replace=raw_keys_to_replace)
        keys_to_del = [key for key in context if key.startswith("@")]
        for key in keys_to_del:
            del context[key]
        context = remove_empty_elements(context)
        context_list.append(context)
        human_readable_list.append(to_hr(context))
    return CommandResults(
        outputs_prefix=outputs_prefix,
        outputs_key_field=output_key_field,
        raw_response=raw_res,
        outputs=context_list,
        readable_output=tableToMarkdown(
            "Results:", human_readable_list, headers=table_headers, headerTransform=pascalToSpace, removeNull=True
        ),
    )


def to_ediscovery_search_command_results(resp, raw_res=None):
    return to_msg_command_results(
        resp,
        raw_res=raw_res,
        output_key_field="SearchId",
        outputs_prefix="MsGraph.eDiscoverySearch",
        raw_keys_to_replace={"id": "SearchId"},
        table_headers=[
            "DisplayName",
            "Description",
            "DataSourceScopes",
            "SearchId",
            "CreatedByName",
            "CreatedByAppName",
            "CreatedByUPN",
            "CreatedDateTime",
            "LastModifiedDateTime",
            "AdditionalSources",
        ],
        to_hr=created_by_fields_to_hr,
    )


def ediscovery_source_command_results(raw_case_list: list, source_type, raw_res=None):
    type_name = source_type["type"]
    demisto.debug(f"Returning command results for source {type_name}")

    output_key_field = f"{type_name}SourceId"
    return to_msg_command_results(
        raw_object_list=raw_case_list,
        raw_res=raw_res,
        outputs_prefix=f'MsGraph.{source_type["outputs_prefix"]}',
        output_key_field=output_key_field,
        raw_keys_to_replace={"id": output_key_field},
        table_headers=[
            "DisplayName",
            "Email",
            output_key_field,
            "HoldStatus",
            "CreatedDateTime",
            "CreatedByName",
            "CreatedByUPN",
            "CreatedByAppName",
            "SiteWebUrl",
        ]
        + source_type["unique_table_headers"],
        to_hr=created_by_fields_to_hr,
    )


def query_set_limit(query: str, limit: int) -> str:
    """
    Set the limit of a query if it doesn't already have a limit set.

    Args:
        query (str): The query string.
        limit (int): The limit to set.

    Returns:
        str: The modified query string with the limit set,
        or the original query if it already had a limit set or if the limit is less than 0.
    """
    if limit < 0 or "limit " in query or "take " in query:
        return query

    return f"{query} | limit {limit}"


def convert_list_incidents_to_readable(incidents_list: list) -> list:
    """
    Convert a list of raw incidents to a list of readable incidents.

    Args:
        incidents_list (list): The list of raw incidents to convert, expected to be in the format [incident1, incident2, ...].

    Returns:
        list: A list containing the converted readable incidents.
    """
    readable_incidents = []
    for incident in incidents_list:
        readable_incident = convert_single_incident_to_readable(incident)
        readable_incidents.append(readable_incident)
    return readable_incidents


def convert_single_incident_to_readable(raw_incident: dict) -> dict:
    """
    Converts incident received from Microsoft Graph Security to readable format
    Args:
        raw_incident (Dict): The incident as received from Microsoft Graph Security

    Returns: new dictionary with keys mapping.

    """
    if not raw_incident:
        raw_incident = {}

    return {
        "Display name": raw_incident.get("displayName"),
        "id": raw_incident.get("id"),
        "Severity": raw_incident.get("severity"),
        "Status": raw_incident.get("status"),
        "Assigned to": raw_incident.get("assignedTo", "Unassigned"),
        "Custom tags": ", ".join(raw_incident.get("customTags", [])),
        "System tags": ", ".join(raw_incident.get("systemTags", [])),
        "Classification": raw_incident.get("classification"),
        "Determination": raw_incident.get("determination"),
        "Created date time": raw_incident.get("createdDateTime"),
        "Updated date time": raw_incident.get("lastUpdateDateTime"),
    }


def get_list_incidents(client: MsGraphClient, args: dict) -> list:
    """
    Retrieve a list of security incidents based on the provided arguments.

    Args:
        client (MsGraphClient): The Microsoft Graph client instance.
        args (dict): A dictionary containing the command arguments

    Returns:
        list: A list of security incidents.
    """
    timeout = arg_to_number(args["timeout"])  # default value is defined
    limit = arg_to_number(args["limit"])  # default value is defined
    url_suffix = set_url_suffix_list_incidents(args)  # type:ignore[arg-type]
    incidents_response = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
    incidents_list: list = incidents_response.get("value", [])

    count_incidents = len(incidents_list)
    nextLink = incidents_response.get("@odata.nextLink")

    while nextLink and count_incidents < limit:  # type:ignore[operator]
        url_suffix = f'security/{nextLink.split("/")[-1]}'
        top = limit - count_incidents  # type:ignore[operator]
        if top <= MAX_ITEMS_PER_RESPONSE:
            url_suffix += f"&$top={top}"
        new_incidents_respond = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
        incidents_list.extend(new_incidents_respond.get("value", []))
        count_incidents = len(incidents_list)
        nextLink = new_incidents_respond.get("@odata.nextLink")

    return incidents_list


def set_url_suffix_list_incidents(args: dict) -> str:
    """
    Set the URL suffix for retrieving a list of security incidents based on the provided arguments.

    Args:
        args (dict): A dictionary containing the command arguments:
            - 'limit' (str): The maximum number of incidents to retrieve.
            - 'status' (str): Filter by status.
            - 'assigned_to' (str): Filter by assigned user.
            - 'severity' (str): Filter by severity.
            - 'classification' (str): Filter by classification.
            - 'odata' (str): Filter by odata.
            - 'extra_data' (bool): Whether to include each incident's related alerts.

    Returns:
        str: The URL suffix for the request.
    """
    limit = arg_to_number(args["limit"])  # default value is defined
    top = limit if limit <= MAX_ITEMS_PER_RESPONSE else None  # type:ignore[operator]
    # Typed args are wrapped as "{property} eq '{value}'" clauses.
    args_for_filter = {
        "status": args.get("status"),
        "assigned_to": args.get("assigned_to"),
        "severity": args.get("severity"),
        "classification": args.get("classification"),
    }
    # The "odata" arg is a raw OData $filter expression and is appended as-is (not wrapped).
    odata = args.get("odata")

    filters = []
    url_suffix = "security/incidents?"
    if argToBoolean(args.get("extra_data", False)):
        # Include each incident's related alerts as part of the response.
        url_suffix += "$expand=alerts&"
    if top:
        url_suffix += f"$top={top!s}"
    if any(args_for_filter.values()) or odata:
        url_suffix += "&$filter="
        for key, value in args_for_filter.items():
            if value:
                filters.append(f"{key} eq '{value}'")
        if odata:
            filters.append(odata)
        url_suffix += " and ".join(filters)

    return url_suffix


""" COMMAND FUNCTIONS """


def fetch_incidents_and_alerts(client: MsGraphClient, params: dict) -> list:
    """
    Fetches Alerts and/or Incidents, based on the "Fetch incidents type" parameter.
    Each type has its own last run time, so fetching both does not affect one another.
    Args:
        client (MsGraphClient): MsGraphClient client object.
        params (dict): the integration parameters.
    Returns:
        list: all the fetched items (alerts and/or incidents) together.
    """
    fetch_time = params.get("fetch_time", "3 days")
    fetch_limit = params.get("fetch_limit", MAX_ITEMS_PER_RESPONSE) or MAX_ITEMS_PER_RESPONSE
    fetch_service_sources = params.get("fetch_service_sources", "")
    fetch_alerts_filter = params.get("fetch_filter", "")
    fetch_incidents_filter = params.get("fetch_incidents_filter", "")
    fetch_incidents_type = argToList(params.get("fetch_incidents_type"))
    last_run = demisto.getLastRun() or {}

    # Migrate the old flat last_run format ({"time": "..."}) to the new nested format,
    # so upgraded instances don't re-fetch the entire window and create duplicate incidents.
    if "time" in last_run and "alerts_last_run" not in last_run and "incidents_last_run" not in last_run:
        demisto.debug("Migrating old last_run format to the new nested format.")
        old_time = {"time": last_run["time"]}
        last_run = {"alerts_last_run": old_time, "incidents_last_run": old_time}

    new_last_run: dict = dict(last_run)
    fetched: list = []
    demisto.debug(f"Starting fetch. Types: {fetch_incidents_type}. Limit per type: {fetch_limit}.")

    if "Alerts" in fetch_incidents_type:
        alerts, alerts_last_run = fetch_alerts(
            client,
            fetch_time=fetch_time,
            fetch_limit=int(fetch_limit),
            extra_filter=fetch_alerts_filter,
            service_sources=fetch_service_sources,
            last_run=last_run.get("alerts_last_run", {}),
            params=params,
        )
        demisto.debug(f"Fetched {len(alerts)} alerts. New alerts last run: {alerts_last_run}.")
        fetched.extend(alerts)
        new_last_run["alerts_last_run"] = alerts_last_run

    if "Incidents" in fetch_incidents_type:
        incidents, incidents_last_run = fetch_incidents(
            client,
            fetch_time=fetch_time,
            fetch_limit=int(fetch_limit),
            extra_filter=fetch_incidents_filter,
            last_run=last_run.get("incidents_last_run", {}),
            params=params,
        )
        demisto.debug(f"Fetched {len(incidents)} incidents. New incidents last run: {incidents_last_run}.")
        fetched.extend(incidents)
        new_last_run["incidents_last_run"] = incidents_last_run
    demisto.setLastRun(new_last_run)
    return fetched


def to_utc_datetime(val: Any) -> datetime | None:
    """
    Parses a timestamp string or object into a timezone-aware UTC datetime.
    Ensures safe chronological comparison and sorting across timestamps with varying fractional second precision.
    """
    if not val:
        return None
    try:
        if dt := arg_to_datetime(val):
            return dt.astimezone(timezone.utc) if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)  # noqa: UP017
    except (ValueError, TypeError):
        return None
    return None


def get_mirror_direction(params: dict) -> str | None:
    """Returns the server mirroring direction ("In", "Out" or "Both"), or None when mirroring is off."""
    return MIRROR_DIRECTION.get(params.get("mirror_direction") or "")


def get_mirroring_fields(params: dict, mirror_type: str) -> dict:
    """Builds the mirroring fields (direction, instance, tags, `mirror_type` discriminator) for a fetched alert/incident."""
    return {
        "mirror_direction": get_mirror_direction(params),
        "mirror_instance": demisto.integrationInstance(),
        # Empty tag params are dropped, so dbotMirrorTags never contains None or "".
        "mirror_tags": [
            tag for tag in (params.get("comment_tag"), params.get("comment_tag_from_microsoft_graph_security")) if tag
        ],
        MIRROR_TYPE_KEY: mirror_type,
    }


def fetch_incidents(
    client: MsGraphClient, fetch_time: str, fetch_limit: int, extra_filter: str, last_run: dict, params: dict
) -> tuple[list, dict]:
    """
    Fetches up to `fetch_limit` incidents created within the fetch time window.
    Each fetched incident includes its related alerts as raw data.
    Args:
        client (MsGraphClient): MsGraphClient client object.
        fetch_time (str): how far back to fetch on the first run (e.g. "1 day").
        fetch_limit (int): the maximum number of incidents to fetch.
        extra_filter (str): an optional extra filter to add to the time window.
        last_run (dict): the incidents last run from the previous fetch.
        params (dict): the integration parameters (for the mirroring fields).
    Returns:
        tuple[list, dict]: the fetched incidents, and the updated incidents last run.
    """
    mirroring_fields = get_mirroring_fields(params, MIRROR_TYPE_INCIDENT)
    # Copy the input last_run so we never mutate the caller's argument.
    new_last_run: dict[str, Any] = (
        dict(last_run) if last_run else {"time": parse_date_range(fetch_time, date_format=TIMESTAMP_FORMAT)[0]}
    )
    demisto_incidents: list = []
    time_from = new_last_run.get("time")
    time_to = datetime.now().strftime(TIMESTAMP_FORMAT)

    # Fetch incidents within the time window (plus the optional user filter), and include their alerts.
    # $top is increased by the number of already fetched IDs to prevent pagination deadlocks.
    last_fetched_ids_count = len(last_run.get("last_fetched_ids", [])) if last_run else 0
    request_limit = min(fetch_limit + last_fetched_ids_count, PAGE_SIZE_LIMIT)
    filter_expression = f"createdDateTime ge {time_from} and createdDateTime le {time_to}"
    if extra_filter:
        # Wrap in parentheses so an `or` clause can't escape the createdDateTime time window (OData `and` binds before `or`).
        filter_expression += f" and ({extra_filter})"
    url_suffix = (
        f"security/incidents?$expand=alerts&$top={request_limit}&$filter={filter_expression}&$orderby=createdDateTime asc"
    )
    # This header maps unknownFutureValue enum values to the appropriate real value (e.g. new service sources).
    headers = {"Prefer": "include-unknown-enum-members"}

    demisto.debug(
        f"[Fetch] Fetching MS Graph Security incidents. From: {time_from}. To: {time_to}. "
        f"Limit: {fetch_limit}. Request limit: {request_limit}."
    )
    demisto.debug(f"[Fetch] Current last_run state: {last_run}")

    incidents = client.get_incidents_request(url_suffix, FETCH_INCIDENTS_TIMEOUT, headers=headers).get("value", [])
    demisto.debug(f"[Fetch] API returned {len(incidents)} incidents.")

    if incidents:
        count = 0
        incidents = sorted(
            incidents,
            key=lambda k: to_utc_datetime(k.get("createdDateTime")) or datetime.min.replace(tzinfo=timezone.utc),  # noqa: UP017
        )

        has_last_ids = "last_fetched_ids" in last_run
        last_incident_dt = to_utc_datetime(last_run.get("time"))
        last_fetched_ids = set(last_run.get("last_fetched_ids", []))

        demisto.debug(f"[Fetch] Incidents times from API: {[i.get('createdDateTime') for i in incidents]}")
        demisto.debug(
            f"[Fetch] Deduplication start -> Last incident DT: {last_incident_dt}, Cached IDs count: {len(last_fetched_ids)}"
        )

        ingested_records: list[tuple[str, datetime | None]] = []
        for incident in incidents:
            incident_time_str = incident.get("createdDateTime")
            incident_dt = to_utc_datetime(incident_time_str)
            incident_id = incident.get("id")

            is_newer = last_incident_dt is None or (incident_dt is not None and incident_dt > last_incident_dt)
            is_same_time_unseen = (
                has_last_ids
                and last_incident_dt is not None
                and incident_dt == last_incident_dt
                and incident_id not in last_fetched_ids
            )

            if (is_newer or is_same_time_unseen) and count < fetch_limit:
                demisto.debug(
                    f"Ingesting incident {incident_id} at {incident_time_str} "
                    f"(Newer: {is_newer}, Same-time unseen: {is_same_time_unseen})"
                )
                ingested_records.append((incident_id, incident_dt))
                incident.update(mirroring_fields)
                demisto_incidents.append(
                    {
                        "name": f'{incident.get("displayName")} - {incident.get("id")}',
                        "occurred": incident.get("createdDateTime"),
                        "severity": SEVERITY_MAP.get(incident.get("severity", ""), 0),
                        "rawJSON": json.dumps(incident),
                    }
                )
                count += 1
            else:
                limit_reached = count >= fetch_limit
                demisto.debug(
                    f"Skipping incident {incident_id} at {incident_time_str} "
                    f"(Newer: {is_newer}, Same-time unseen: {is_same_time_unseen}, Limit reached: {limit_reached})"
                )

        if demisto_incidents:
            latest_time_str = demisto_incidents[-1].get("occurred")
            latest_dt = to_utc_datetime(latest_time_str)
            ids_at_latest_time = [rec_id for rec_id, rec_dt in ingested_records if rec_id and rec_dt == latest_dt]
            if last_incident_dt and latest_dt == last_incident_dt:
                ids_at_latest_time = list(last_fetched_ids.union(ids_at_latest_time))

            new_last_run.update(
                {
                    "time": latest_time_str,
                    "last_fetched_ids": ids_at_latest_time,
                }
            )

    demisto.info(
        f"[Fetch] Fetch incidents complete. Ingested {len(demisto_incidents)} incidents. Updated last_run: {new_last_run}"
    )
    return demisto_incidents, new_last_run


def fetch_alerts(
    client: MsGraphClient,
    fetch_time: str,
    fetch_limit: int,
    extra_filter: str,
    service_sources: str,
    last_run: dict,
    params: dict,
) -> tuple[list, dict]:
    """
    Fetches up to `fetch_limit` alerts created within the fetch time window, matching the given filters.
    Args:
        client (MsGraphClient): MsGraphClient client object.
        fetch_time (str): how far back to fetch on the first run (e.g. "1 day").
        fetch_limit (int): the maximum number of alerts to fetch.
        extra_filter (str): an optional user filter.
        service_sources (str): a comma separated list of service sources to fetch alerts by.
        last_run (dict): the alerts last run from the previous fetch.
        params (dict): the integration parameters (for the mirroring fields).
    Returns:
        tuple[list, dict]: the fetched alerts, and the updated alerts last run.
    """
    mirroring_fields = get_mirroring_fields(params, MIRROR_TYPE_ALERT)
    filter_query = create_filter_query(extra_filter, service_sources)

    # Copy the input last_run so we never mutate the caller's argument.
    new_last_run: dict[str, Any] = (
        dict(last_run) if last_run else {"time": parse_date_range(fetch_time, date_format=TIMESTAMP_FORMAT)[0]}
    )
    demisto_alerts: list = []
    time_from = new_last_run.get("time")
    time_to = datetime.now().strftime(TIMESTAMP_FORMAT)

    # Get alerts from MS Graph Security. Increase page_size by the number of already fetched IDs to prevent pagination deadlocks.
    last_fetched_ids_count = len(last_run.get("last_fetched_ids", [])) if last_run else 0
    request_limit = min(fetch_limit + last_fetched_ids_count, PAGE_SIZE_LIMIT)
    demisto.debug(
        f"[Fetch] Fetching MS Graph Security alerts. From: {time_from}. To: {time_to}. "
        f"Limit: {fetch_limit}. Request limit: {request_limit}. Filter: {filter_query}"
    )
    demisto.debug(f"[Fetch] Current last_run state: {last_run}")

    args = {"time_to": time_to, "time_from": time_from, "filter": filter_query, "page_size": request_limit}
    query_params = create_search_alerts_filters(args, is_fetch=True)
    alerts = client.search_alerts(query_params)["value"]

    demisto.debug(f"[Fetch] API returned {len(alerts)} alerts.")

    if alerts:
        count = 0
        alerts = sorted(
            alerts,
            key=lambda k: to_utc_datetime(k.get("createdDateTime")) or datetime.min.replace(tzinfo=timezone.utc),  # noqa: UP017
        )
        has_last_ids = "last_fetched_ids" in last_run
        last_alert_dt = to_utc_datetime(last_run.get("time"))
        last_fetched_ids = set(last_run.get("last_fetched_ids", []))

        demisto.debug(f"[Fetch] Alerts times from API: {[a.get('createdDateTime') for a in alerts]}")
        demisto.debug(f"[Fetch] Deduplication start -> Last alert DT: {last_alert_dt}, Cached IDs count: {len(last_fetched_ids)}")

        ingested_records: list[tuple[str, datetime | None]] = []
        for alert in alerts:
            alert_time_str = alert.get("createdDateTime")
            alert_dt = to_utc_datetime(alert_time_str)
            alert_id = alert.get("id")

            is_newer = last_alert_dt is None or (alert_dt is not None and alert_dt > last_alert_dt)
            is_same_time_unseen = (
                has_last_ids and last_alert_dt is not None and alert_dt == last_alert_dt and alert_id not in last_fetched_ids
            )

            if (is_newer or is_same_time_unseen) and count < fetch_limit:
                demisto.debug(
                    f"Ingesting alert {alert_id} at {alert_time_str} "
                    f"(Newer: {is_newer}, Same-time unseen: {is_same_time_unseen})"
                )
                ingested_records.append((alert_id, alert_dt))
                alert.update(mirroring_fields)
                alert[CUSTOM_DETAILS_LIST_KEY] = custom_details_to_list(alert.get("customDetails"))
                demisto_alerts.append(
                    {
                        "name": f'{alert.get("title", "Unknown")} - {alert.get("id", "Unknown")}',
                        "occurred": alert.get("createdDateTime"),
                        "severity": SEVERITY_MAP.get(alert.get("severity", ""), 0),
                        "rawJSON": json.dumps(alert),
                    }
                )
                count += 1
            else:
                limit_reached = count >= fetch_limit
                demisto.debug(
                    f"Skipping alert {alert_id} at {alert_time_str} "
                    f"(Newer: {is_newer}, Same-time unseen: {is_same_time_unseen}, Limit reached: {limit_reached})"
                )

        if demisto_alerts:
            latest_time_str = demisto_alerts[-1].get("occurred")
            latest_dt = to_utc_datetime(latest_time_str)
            ids_at_latest_time = [rec_id for rec_id, rec_dt in ingested_records if rec_id and rec_dt == latest_dt]
            if last_alert_dt and latest_dt == last_alert_dt:
                ids_at_latest_time = list(last_fetched_ids.union(ids_at_latest_time))

            new_last_run.update(
                {
                    "time": latest_time_str,
                    "last_fetched_ids": ids_at_latest_time,
                }
            )

    demisto.info(f"[Fetch] Fetch alerts complete. Ingested {len(demisto_alerts)} alerts. Updated last_run: {new_last_run}")
    return demisto_alerts, new_last_run


def search_alerts_command(client: MsGraphClient, args):
    """
    Retrieve a list of alerts filtered by the given filter arguments.

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: table of returned alerts, parsed outputs and request's response.
    """
    params = create_search_alerts_filters(args, is_fetch=False)
    alerts = client.search_alerts(params)["value"]
    limit = int(args.get("limit"))
    if limit < len(alerts):
        alerts = alerts[:limit]
    outputs = [capitalize_dict_keys_first_letter(alert) for alert in alerts]
    table_headers = [
        "ID",
        "DetectionSource",
        "ServiceSource",
        "Title",
        "Category",
        "Severity",
        "CreatedDate",
        "LastUpdateDateTime",
        "Status",
        "IncidentId",
    ]
    ec = {"MsGraph.Alert(val.ID && val.ID === obj.ID)": outputs}
    human_readable = tableToMarkdown("Microsoft Security Graph Alerts", outputs, table_headers, removeNull=True)
    return human_readable, ec, alerts


def get_alert_details_command(client: MsGraphClient, args):
    """
    Retrieve information about an alert with the given id.

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: Human readable output with information about the alert, parsed outputs and request's response.
    """
    alert_id = args.get("alert_id")

    alert_details = client.get_alert_details(alert_id)

    hr = f"## Microsoft Security Graph Alert Details - {alert_id}\n"
    outputs = capitalize_dict_keys_first_letter(alert_details)
    table_headers = [
        "ID",
        "DetectionSource",
        "ServiceSource",
        "Title",
        "Category",
        "Severity",
        "CreatedDate",
        "LastUpdateDateTime",
        "Status",
        "IncidentId",
    ]
    ec = {"MsGraph.Alert(val.ID && val.ID === obj.ID)": outputs}
    hr += tableToMarkdown("", outputs, table_headers, removeNull=True)
    return hr, ec, alert_details


def update_alert_command(client: MsGraphClient, args):
    alert_id = args.get("alert_id")
    status: str = args.get("status", "")
    if status == "newAlert":
        args["status"] = "new"
        status = "new"
    params = create_data_to_update(args)
    client.update_alert(alert_id, params)
    context = {"ID": alert_id}
    if status:
        context["Status"] = status
    ec = {"MsGraph.Alert(val.ID && val.ID === obj.ID)": context}
    human_readable = f"Alert {alert_id} has been successfully updated."
    return human_readable, ec, context


def get_users_command(client: MsGraphClient, args):
    users = client.get_users()["value"]
    outputs = []
    for user in users:
        outputs.append({"Name": user["displayName"], "Title": user["jobTitle"], "Email": user["mail"], "ID": user["id"]})
    ec = {"MsGraph.User(val.ID && val.ID === obj.ID)": outputs}
    table_headers = ["Name", "Title", "Email", "ID"]
    human_readable = tableToMarkdown("Microsoft Graph Users", outputs, table_headers, removeNull=True)
    return human_readable, ec, users


def get_user_command(client: MsGraphClient, args):
    user_id = args.get("user_id")
    raw_user = client.get_user(user_id)
    user = {"Name": raw_user["displayName"], "Title": raw_user["jobTitle"], "Email": raw_user["mail"], "ID": raw_user["id"]}
    ec = {"MsGraph.User(val.ID && val.ID === obj.ID)": user}
    table_headers = ["Name", "Title", "Email", "ID"]
    human_readable = tableToMarkdown("Microsoft Graph User " + user_id, user, table_headers, removeNull=True)
    return human_readable, ec, raw_user


def create_alert_comment_command(client: MsGraphClient, args):
    """
    Adds a comment to an alert with the given id

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (Dict): The command's arguments dictionary.

    Returns:
        str, Dict, Dict: the human readable, parsed outputs and request's response.
    """
    alert_id = args.get("alert_id", "")
    comment = args.get("comment", "")
    params = {"comment": comment}
    res = client.create_alert_comment(alert_id, params)
    comments = [capitalize_dict_keys_first_letter(comment) for comment in res.get("value", [])]
    context = {"ID": alert_id, "Comments": comments}
    ec = {"MsGraph.AlertComment(val.ID && val.ID == obj.ID)": context}
    header = f"Microsoft Security Graph Create Alert Comment - {alert_id}\n"
    human_readable = tableToMarkdown(header, comments, removeNull=True)
    return human_readable, ec, res


def create_ediscovery_case_command(client: MsGraphClient, args: dict):
    """ """
    res = client.create_edsicovery_case(args.get("display_name"), args.get("description"), args.get("external_id"))
    return ediscovery_cases_command_results([res], res)


def close_ediscovery_case_command(client: MsGraphClient, args):
    """ """
    client.close_edsicovery_case(args.get("case_id"))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was closed successfully.')


def reopen_ediscovery_case_command(client: MsGraphClient, args):
    """ """
    client.reopen_edsicovery_case(args.get("case_id"))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was reopened successfully.')


def update_ediscovery_case_command(client: MsGraphClient, args):
    """ """
    client.update_edsicovery_case(args.get("case_id"), args.get("display_name"), args.get("description"), args.get("external_id"))
    return CommandResults(readable_output=f'Case with id {args.get("case_id")} was updated successfully.')


def release_ediscovery_custodian_command(client: MsGraphClient, args):
    """ """
    client.release_edsicovery_custodian(args.get("case_id"), args.get("custodian_id"))
    return CommandResults(
        readable_output=f'Custodian with id {args.get("custodian_id")} was released from '
        f'case with id {args.get("case_id")} successfully.'
    )


def activate_ediscovery_custodian_command(client: MsGraphClient, args):
    """ """
    client.activate_edsicovery_custodian(args.get("case_id"), args.get("custodian_id"))
    return CommandResults(
        readable_output=f'Custodian with id {args.get("custodian_id")} Case was reactivated on '
        f'case with id {args.get("case_id")} successfully.'
    )


def create_ediscovery_custodian_user_source_command(client: MsGraphClient, args):
    """ """
    resp = client.create_edsicovery_custodian_user_source(
        args.get("case_id"), args.get("custodian_id"), args.get("email"), args.get("included_sources")
    )
    return ediscovery_source_command_results(resp, DataSourceType["USER"])


def create_ediscovery_custodian_site_source_command(client: MsGraphClient, args):
    resp = client.create_edsicovery_custodian_site_source(args.get("case_id"), args.get("custodian_id"), args.get("site"))
    return ediscovery_source_command_results(resp, DataSourceType["SITE"])


def create_ediscovery_non_custodial_data_source_command(client: MsGraphClient, args):
    site = args.get("site")
    email = args.get("email")
    if not (bool(site) ^ bool(email)):
        raise ValueError("One of either the site argument or the email argument must be provided, not both")

    resp = client.create_ediscovery_non_custodial_data_source(args.get("case_id"), site, email)

    return to_msg_command_results(
        raw_object_list=resp,
        outputs_prefix="MsGraph.NoncustodialDataSource",
        output_key_field="DataSourceId",
        raw_keys_to_replace={"status": "DataSourceStatus", "id": "DataSourceId"},
    )


def delete_ediscovery_case_command(client: MsGraphClient, args):
    client.delete_edsicovery_case(args.get("case_id"))
    return CommandResults(readable_output="Case was deleted successfully.")


def create_ediscovery_custodian_command(client: MsGraphClient, args):
    res = client.create_edsicovery_custodian(args.get("case_id"), args.get("email"))
    return ediscovery_custodian_command_results(res)


def list_ediscovery_case_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_cases(args.get("case_id"))
    if case_list := raw_res.get("value"):
        demisto.info(f'returned {raw_res.get("@odata.count")} results from the api')
    else:
        case_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get("all_results", "false")):
        case_list = case_list[: arg_to_number(args.get("limit", 50))]
    return ediscovery_cases_command_results(case_list, raw_res)


def list_ediscovery_custodian_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_custodians(args.get("case_id"), args.get("custodian_id"))
    if custodian_list := raw_res.get("value"):
        demisto.info(f'returned {raw_res.get("@odata.count")} results from the api')
    else:
        custodian_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get("all_results", "false")):
        custodian_list = custodian_list[: arg_to_number(args.get("limit", 50))]
    return ediscovery_custodian_command_results(custodian_list, raw_res)


def list_ediscovery_custodian_user_sources_command(client: MsGraphClient, args):
    return list_ediscovery_custodian_sources(client, args, DataSourceType["USER"])


def list_ediscovery_custodian_site_sources_command(client: MsGraphClient, args):
    return list_ediscovery_custodian_sources(client, args, DataSourceType["SITE"])


def list_ediscovery_non_custodial_data_source_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_noncustodial_datasources(args.get("case_id"), args.get("data_source_id"))
    if source_list := raw_res.get("value"):
        demisto.info(f"returned {len(source_list)} results from the api")
    else:
        source_list = [raw_res]  # api doesnt return a list if only 1 result
    if not argToBoolean(args.get("all_results", "false")):
        source_list = source_list[: arg_to_number(args.get("limit"))]
    return ediscovery_source_command_results(source_list, DataSourceType["NON_CUSTODIAL"], raw_res)


def update_hold_ediscovery_custodian_command(client: MsGraphClient, args, hold_action: HoldAction):
    demisto.debug(f"{hold_action.value=}")
    res = client.update_hold_ediscovery_custodian(args.get("case_id"), args.get("custodian_id"), hold_action)
    status = get_status_of_operation(client, res)
    return CommandResults(readable_output=f"{hold_action.value.capitalize()} hold status is {status}.")


def apply_hold_ediscovery_custodian_command(client: MsGraphClient, args):
    return update_hold_ediscovery_custodian_command(client, args, HoldAction.APPLY)


def remove_hold_ediscovery_custodian_command(client: MsGraphClient, args):
    return update_hold_ediscovery_custodian_command(client, args, HoldAction.REMOVE)


def update_ediscovery_search_command(client: MsGraphClient, args):
    client.update_ediscovery_search(
        args.get("case_id"),
        args.get("search_id"),
        args.get("display_name"),
        args.get("description"),
        args.get("content_query"),
        args.get("data_source_scopes"),
    )

    return CommandResults(readable_output=f'eDiscovery search {args.get("search_id")} was updated successfully.')


def delete_ediscovery_search_command(client: MsGraphClient, args):
    client.delete_ediscovery_search(args.get("case_id"), args.get("search_id"))

    return CommandResults(readable_output=f'eDiscovery search {args.get("search_id")} was deleted successfully.')


def get_operation_id_from_location_header(location_url: str | None) -> str | None:
    """
    Extract the operation ID from a Microsoft Graph Location header URL.

    The Location header can appear in one of two formats:
        - .../ediscoveryCases('<caseId>')/operations('<operationId>')
        - .../ediscoveryCases/<caseId>/operations/<operationId>

    Args:
        location_url: The value of the Location header returned by the API.

    Returns:
        The extracted operation ID, or None if it could not be parsed.
    """
    if not location_url:
        return None
    operation_id_match = re.search(r"operations\('([^']+)'\)", location_url) or re.search(r"operations/([^/?]+)", location_url)
    return operation_id_match.group(1) if operation_id_match else None


def purge_ediscovery_data_command(client: MsGraphClient, args):
    resp = client.purge_ediscovery_data(
        args.get("case_id"), args.get("search_id"), args.get("purge_type"), args.get("purge_areas")
    )
    status = get_status_of_operation(client, resp)

    operation_id = get_operation_id_from_location_header(resp.headers.get("Location"))

    readable_output = f"eDiscovery purge status is {status}.\n- Operation ID: {operation_id}"
    outputs = {"OperationID": operation_id, "Status": status}
    remove_nulls_from_dictionary(outputs)
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        outputs_prefix="MsGraph.eDiscoveryCase.Purge",
        outputs_key_field="OperationID",
    )


def run_estimate_statistics_command(client: MsGraphClient, args) -> CommandResults:
    case_id = args.get("case_id")
    search_id = args.get("search_id")
    statistics_options = argToList(args.get("statistics_options", []))

    # Start the estimate statistics operation
    client.start_estimate_statistics_request(case_id, search_id, statistics_options)

    demisto.info(f"[run_estimate_statistics_command] Estimate statistics started for case {case_id}, search {search_id}.")

    # Return confirmation only
    return CommandResults(
        readable_output=f"Estimate statistics request initiated for case `{case_id}`, search `{search_id}`.",
    )


def create_ediscovery_case_hold_policy_command(
    client: MsGraphClient,
    args,
) -> CommandResults:
    """
    Create a legal hold policy for an eDiscovery case.

    Args:
        client: Microsoft Graph client.
        args: Command arguments.

    Returns:
        CommandResults containing the created hold policy.
    """
    raw_resp = client.create_ediscovery_case_hold_policy(
        args.get("case_id"),
        args.get("display_name"),
        args.get("description"),
        args.get("content_query"),
    )
    human_readable = tableToMarkdown(
        name="Created eDiscovery Hold Policy",
        t={
            "Display Name": raw_resp.get("displayName"),
            "Id": raw_resp.get("id"),
            "Status": raw_resp.get("status"),
        },
    )
    return CommandResults(
        outputs_prefix="MsGraph.eDiscoveryCase.HoldPolicy",
        outputs_key_field="ID",
        outputs=capitalize_dict_keys_first_letter(raw_resp),
        readable_output=human_readable,
        raw_response=raw_resp,
    )


def delete_ediscovery_case_hold_policy_command(
    client: MsGraphClient,
    args: Any,
) -> CommandResults:
    """
    Delete a legal hold policy from an eDiscovery case.

    Args:
        client: Microsoft Graph client.
        args: Command arguments.

    Returns:
        CommandResults with a success message.
    """
    hold_policy_id = args.get("hold_policy_id")
    case_id = args.get("case_id")

    client.delete_ediscovery_case_hold_policy(
        case_id,
        hold_policy_id,
    )
    return CommandResults(
        readable_output=(f"The deletion request for hold policy {hold_policy_id} in case {case_id} was sent successfully."),
    )


def update_ediscovery_case_policy_command(
    client: MsGraphClient,
    args,
) -> CommandResults:
    """
    Update a legal hold policy for an eDiscovery case.

    Args:
        client: Microsoft Graph client.
        args: Command arguments.

    Returns:
        CommandResults with a success message.
    """
    case_id = args.get("case_id")
    hold_policy_id = args.get("hold_policy_id")
    description = args.get("description")
    content_query = args.get("content_query")

    if not description and not content_query:
        raise DemistoException("Please provide at least one field to update: description and/or content_query.")

    try:
        client.update_ediscovery_case_policy(
            case_id,
            hold_policy_id,
            description,
            content_query,
        )
    except DemistoException as e:
        err = str(e)

        # Only enrich message when the user tried to update contentQuery and we recognize the failure
        if content_query and "ErrorRuleNotFoundException" in err:
            raise DemistoException(
                f"Failed to update hold policy '{hold_policy_id}' content query.\n\n"
                "This can happen when the hold policy was created using the legacy Security & Compliance (PowerShell/RPS) flow "
                "and the underlying hold rule is not available to be updated via Microsoft Graph yet.\n\n"
                "Recommended actions:\n"
                "1) Retry the hold policy in Purview (Policy actions → Retry) and try again.\n"
                "2) If the issue persists, recreate the hold policy using Microsoft Graph Security and "
                "then manage it via the Graph commands.\n\n"
                f"Error message: {err}"
            ) from e

        raise e
    return CommandResults(readable_output=f'Hold policy {args.get("hold_policy_id")} was updated successfully.')


def list_ediscovery_case_hold_policy_command(
    client: MsGraphClient,
    args,
) -> CommandResults:
    """
    List or retrieve legal hold policies for an eDiscovery case.

    Args:
        client: Microsoft Graph client.
        args: Command arguments.

    Returns:
        CommandResults containing hold policy data.
    """
    case_id = args.get("case_id")
    hold_policy_id = args.get("hold_policy_id")
    limit = None if argToBoolean(args.get("all_results")) else int(args.get("limit", 50))

    if hold_policy_id:
        raw_res = client.get_ediscovery_case_hold_policy(case_id, hold_policy_id)
        hold_list = [raw_res]
    else:
        raw_res = client.list_ediscovery_case_hold_policy(case_id, limit)
        hold_list = raw_res.get("value", [])

    demisto.debug(f"returned {len(hold_list)} results from the api")

    hr = [
        {
            "Display Name": hold.get("displayName"),
            "Id": hold.get("id"),
            "Status": hold.get("status"),
        }
        for hold in hold_list
    ]

    return CommandResults(
        outputs_prefix="MsGraph.eDiscoveryCase.HoldPolicy",
        outputs_key_field="ID",
        outputs=[capitalize_dict_keys_first_letter(hold) for hold in hold_list],
        readable_output=tableToMarkdown(name="eDiscovery Case Hold Policies", t=hr),
        raw_response=raw_res,
    )


def list_case_operation_command(
    client: MsGraphClient,
    args,
) -> CommandResults | list[dict | CommandResults]:
    """
    List or retrieve operations for an eDiscovery case.
    Optionally downloads the export file when operation_id is provided and ediscovery-export-file=true.
    """
    case_id = args.get("case_id")
    operation_id = args.get("operation_id")

    download_file = argToBoolean(args.get("download_file", "false"))
    all_results = argToBoolean(args.get("all_results", "false"))
    limit = None if all_results else int(args.get("limit", 50))

    file_result = None

    if operation_id:
        raw_res = client.get_case_operation(case_id, operation_id)
        operation_list = [raw_res]
        if download_file and operation_list:
            file_result = _download_operation_export_file(client, operation_list[0])
    else:
        raw_res = client.list_case_operation(case_id, limit)
        operation_list = raw_res.get("value") or []
        if isinstance(operation_list, dict):
            operation_list = [operation_list]

    demisto.debug(f"returned {len(operation_list)} results from the api")

    hr = [
        {
            "ID": op.get("id"),
            "Action": op.get("action"),
            "Status": op.get("status"),
            "Created By": op.get("createdBy"),
            "Link to download a file": _extract_export_download_url(op),
        }
        for op in operation_list
    ]

    command_result = CommandResults(
        outputs_prefix="MsGraph.eDiscoveryCase.Operation",
        outputs_key_field="ID",
        outputs=[capitalize_dict_keys_first_letter(op) for op in operation_list],
        readable_output=tableToMarkdown(
            name="eDiscovery Case Operations",
            t=hr,
            headers=["ID", "Action", "Status", "Created By", "Link to download a file"],
            removeNull=True,
        ),
        raw_response=raw_res,
    )

    return [file_result, command_result] if file_result else command_result


def _extract_export_download_url(operation: dict) -> str | None:
    """
    exportFileMetadata can be a dict or a list of dicts (sometimes).
    Return downloadUrl if present.
    """
    meta = operation.get("exportFileMetadata")

    if isinstance(meta, dict):
        return meta.get("downloadUrl")
    if isinstance(meta, list) and meta and isinstance(meta[0], dict):
        return meta[0].get("downloadUrl")

    return None


def _extract_filename_from_headers(
    headers: dict[str, str] | None = None,
    default: str = "ediscovery_export.zip",
) -> str:
    """
    Extract a filename from the Content-Disposition header (expects `filename=...`).

    Args:
        headers: Response headers mapping.
        default: Filename to return if Content-Disposition is missing or unparseable.

    Returns:
        The extracted filename, or `default`.
    """
    headers = headers or {}
    cd = headers.get("Content-Disposition") or headers.get("content-disposition") or ""

    m = re.search(r'(?i)\bfilename\s*=\s*"?([^";]+)"?', cd)
    return (m.group(1).strip() if m else "") or default


def _download_operation_export_file(client: MsGraphClient, operation: dict) -> dict | None:
    """
    Download the export file referenced by an operation and return a fileResult.
    Returns None if the operation has no valid download URL.
    """
    download_url = _extract_export_download_url(operation)
    if not isinstance(download_url, str) or not download_url:
        return None

    res = client.download_export_file(download_url)

    status = getattr(res, "status_code", None)
    ok = bool(getattr(res, "ok", False))
    if not ok:
        text = (getattr(res, "text", "") or "")[:500]
        raise DemistoException(f"Failed to download export file. HTTP {status}. {text}")

    file_bytes = getattr(res, "content", None) or b""
    if len(file_bytes) == 0:
        raise DemistoException(f"Downloaded export file is empty. HTTP {status}.")

    filename = _extract_filename_from_headers(getattr(res, "headers", None), default="ediscovery_export.zip")
    return fileResult(filename=filename, data=file_bytes)


def export_result_ediscovery_data_command(
    client: MsGraphClient,
    args: Any,
) -> CommandResults:
    """
    Export search results from an eDiscovery case.

    Args:
        client: Microsoft Graph client.
        args: Command arguments.

    Returns:
        CommandResults containing the export operation location.
    """
    resp = client.export_result_ediscovery_data(
        args.get("case_id"),
        args.get("search_id"),
        args.get("additional_options"),
        args.get("export_criteria"),
        args.get("export_format"),
        args.get("cloud_attachment_version"),
        args.get("description"),
        args.get("display_name"),
        args.get("document_version"),
        args.get("export_location"),
    )

    operation_url = resp.headers.get("Location")
    if not operation_url:
        raise DemistoException("Missing Location header in exportResult response")

    case_id_from_url = re.search(r"ediscoveryCases\('([^']+)'\)", operation_url) or re.search(
        r"ediscoveryCases/([^/]+)/", operation_url
    )

    case_id = (case_id_from_url.group(1) if case_id_from_url else args.get("case_id")) or "N/A"
    operation_id = get_operation_id_from_location_header(operation_url) or None

    readable_output = (
        "eDiscovery export request was submitted successfully.\n" f"- Case ID: {case_id}\n" f"- Operation ID: {operation_id}\n"
    )
    outputs = {"Location": operation_url, "OperationID": operation_id, "CaseID": case_id}
    return CommandResults(readable_output=readable_output, outputs=outputs, outputs_prefix="MsGraph.eDiscoveryCase.Export")


# @polling_function(
#     "msg-get-last-estimate-statistics-operation",
#     timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 600)),
#     requires_polling_arg=False,
# )
def _get_last_estimate_statistics_command(args, client: MsGraphClient) -> PollResult:
    case_id = args.get("case_id")
    search_id = args.get("search_id")

    resp = client.get_last_estimate_statistics_operation(case_id, search_id)
    status = (resp.get("status") or "").lower()

    if status not in ("succeeded", "completed"):
        demisto.debug(f"[get_last_estimate_statistics_command] Status: {status}, scheduling next poll.")
        return PollResult(
            continue_to_poll=True,
            args_for_next_run=args,
            response=None,
            partial_result=CommandResults(
                readable_output=f"Estimate statistics operation is still running... (Status: {status})"
            ),
        )

    # Completed — return final statistics
    stats_info = {
        "Operation ID": resp.get("id"),
        "Status": resp.get("status"),
        "Progress": resp.get("percentProgress"),
        "Created": resp.get("createdDateTime"),
        "Last Modified": resp.get("lastActionDateTime"),
        "Indexed Items": resp.get("indexedItemCount"),
        "Indexed Size (bytes)": resp.get("indexedItemsSize"),
        "Unindexed Items": resp.get("unindexedItemCount"),
        "Unindexed Size (bytes)": resp.get("unindexedItemsSize"),
        "Total Items": resp.get("totalItemCount"),
        "Total Size (bytes)": resp.get("totalItemsSize"),
        "Mailbox Count": resp.get("mailboxCount"),
        "Site Count": resp.get("siteCount"),
    }

    readable_output = tableToMarkdown(
        f"eDiscovery Estimate Statistics for Search `{search_id}`",
        stats_info,
        removeNull=True,
    )

    return PollResult(
        response=CommandResults(
            readable_output=readable_output,
            outputs_prefix="MsGraph.eDiscovery.EstimateStatistics",
            outputs_key_field="id",
            outputs=resp,
            raw_response=resp,
        )
    )


# Decorated version for XSOAR runtime
get_last_estimate_statistics_command = polling_function(
    "msg-get-last-estimate-statistics-operation",
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 600)),
    requires_polling_arg=False,
)(_get_last_estimate_statistics_command)


def create_ediscovery_search_command(client: MsGraphClient, args):
    resp = client.create_ediscovery_search(
        args.get("case_id"),
        args.get("display_name"),
        args.get("description"),
        args.get("content_query"),
        args.get("data_source_scopes"),
    )

    return to_ediscovery_search_command_results(resp)


def list_ediscovery_search_command(client: MsGraphClient, args):
    raw_res = client.list_ediscovery_search(args.get("case_id"), args.get("search_id"))
    if case_list := raw_res.get("value"):
        demisto.info(f"returned {len(case_list)} results from the api")
    else:
        case_list = [raw_res]
    if not argToBoolean(args.get("all_results", "false")):
        case_list = case_list[: arg_to_number(args.get("limit"))]
    return to_ediscovery_search_command_results(case_list, raw_res)


def test_auth_code_command(client: MsGraphClient, args):
    """
    Called to test authorization code flow (since integration context cant be accessed during test_module)
    Calls list cases with no arguments
    """
    permissions = args.get("permission_type", "all")
    if permissions == "all":
        permissions = "ediscovery, alerts, threat assessment"
    for permission in argToList(permissions):
        try:
            demisto.debug(f"checking permission {permission}")
            match permission:
                case "ediscovery":
                    list_ediscovery_case_command(client, {})
                case "alerts":
                    test_function(client, args, True)
                case "threat assessment":
                    list_threat_assessment_requests_command(client, {})
        except Exception as e:
            raise DemistoException(
                f"Authorization was not successful for permission {permission} Check that you have the required permissions"
            ) from e
    return CommandResults(readable_output="Authentication was successful.")


def advanced_hunting_command(client: MsGraphClient, args: dict) -> list[CommandResults] | CommandResults:
    """
    Sends a query for the advanced hunting tool.
    Args:
        client(Client): Microsoft Graph Security's client to preform the API calls.
        args(Dict): Demisto arguments:
              - query (str) - The query to run (required)
              - limit (int) - number of entries in the result, -1 for no limit.
              - timeout (int) - waiting time for command execution.
    Returns:

    """
    query = args["query"]  # required argument
    limit = arg_to_number(args["limit"])  # default value is defined
    timeout = arg_to_number(args["timeout"])  # default value is defined

    query = query_set_limit(query, limit)  # type:ignore[arg-type]

    response = client.advanced_hunting_request(query=query, timeout=timeout)  # type:ignore[arg-type]
    results = response.get("results")
    schema = response.get("schema", {})
    headers = [item.get("name") for item in schema]
    context_result = {"query": query, "results": results}
    human_readable_table = tableToMarkdown(name=f" Result of query: {query}:", t=results, headers=headers)

    microsoft_365_defender_context = demisto.params().get("microsoft_365_defender_context")

    command_result_ms_graph = CommandResults(
        outputs_prefix="MsGraph.Hunt", outputs_key_field="query", outputs=context_result, readable_output=human_readable_table
    )

    if microsoft_365_defender_context:
        command_result_microsoft_defender = CommandResults(
            outputs_prefix="Microsoft365Defender.Hunt",
            outputs_key_field="query",
            outputs=context_result,
            readable_output="See Results Above",
        )
        return [command_result_ms_graph, command_result_microsoft_defender]

    return command_result_ms_graph


def get_list_security_incident_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Retrieve a list of security incidents or a single incident based on the provided arguments.

    Args:
        client (MsGraphClient): The Microsoft Graph client object.
        args (dict): A dictionary containing the command arguments:
            - 'timeout' (str): The timeout for the request in seconds.
            - 'incident_id' (str): The ID of the incident to retrieve. If None, retrieves a list of incidents.

    Returns:
        CommandResults: The command results object containing the outputs and readable output.
    """
    timeout = arg_to_number(args["timeout"])  # default value is defined
    incident_id = arg_to_number(args.get("incident_id"))

    extra_data = argToBoolean(args.get("extra_data", False))
    if incident_id:  # Case of single incident
        url_suffix = f"security/incidents/{incident_id}"
        if extra_data:
            # Include the incident's related alerts as part of the response.
            url_suffix += "?$expand=alerts"
        incident_response = client.get_incidents_request(url_suffix, timeout)  # type:ignore[arg-type]
        if incident_response.get("@odata.context"):
            del incident_response["@odata.context"]

        name = f"Incident No. {incident_id}:"
        readable_incident = convert_single_incident_to_readable(incident_response)
        headers = list(readable_incident)
        outputs = incident_response

    else:  # Case of list incidents
        incidents_list = get_list_incidents(client, args)
        name = "Incidents:"
        readable_incident = convert_list_incidents_to_readable(incidents_list)  # type:ignore[assignment]
        headers = list(readable_incident[0])
        outputs = incidents_list  # type:ignore[assignment]

    human_readable_table = tableToMarkdown(name=name, t=readable_incident, headers=headers)
    return CommandResults(
        outputs_prefix="MsGraph.Incident", outputs_key_field="id", outputs=outputs, readable_output=human_readable_table
    )


def update_incident_command(client: MsGraphClient, args: dict) -> CommandResults:
    """
    Update an incident.
    Args:
        client(Client): Microsoft Graph Security's client to preform the API calls.
        args(Dict): Demisto arguments:
              - incident_id (int) - incident's id (required)
              - status (str) - Specifies the current status of the alert. Possible values are: (Active, Resolved or Redirected)
              - assigned_to (str) - Owner of the incident.
              - classification (str) - Specification of the alert. Possible values are: Unknown, FalsePositive, TruePositive.
              - determination (str) -  Specifies the determination of the alert. Possible values are: NotAvailable, Apt,
                                 Malware, SecurityPersonnel, SecurityTesting, UnwantedSoftware, Other.
              - severity (str): Indicates the possible impact on assets. The higher the severity, the bigger the impact.
                 Typically, higher severity items require the most immediate attention. The possible values are: unknown,
                 informational, low, medium, high, unknownFutureValue.
              - resolving_comment (str): User input that explains the resolution of the incident and the classification choice.
                 It contains free editable text.
              - custom_tags - Custom tags associated with an incident. Separated by commas without spaces (CSV)
                       for example: tag1,tag2,tag3.

    Returns: CommandResults
    """
    incident_id = arg_to_number(args["incident_id"])  # required argument
    status = args.get("status")
    assigned_to = args.get("assigned_to")
    determination = args.get("determination")
    classification = args.get("classification")
    severity = args.get("severity")
    resolving_comment = args.get("resolving_comment")
    custom_tags = argToList(args.get("custom_tags"))
    timeout = arg_to_number(args["timeout"])  # default value is defined
    updated_incident = client.update_incident_request(
        incident_id=incident_id,  # type:ignore[arg-type]
        status=status,  # type:ignore[arg-type]
        assigned_to=assigned_to,
        classification=classification,
        determination=determination,
        severity=severity,
        resolving_comment=resolving_comment,
        custom_tags=custom_tags,
        timeout=timeout,  # type:ignore[arg-type]
    )

    if updated_incident.get("@odata.context"):
        del updated_incident["@odata.context"]

    readable_incident = convert_single_incident_to_readable(updated_incident)
    human_readable_table = tableToMarkdown(
        name=f"Updated incident No. {incident_id}:", t=readable_incident, headers=list(readable_incident)
    )
    return CommandResults(
        outputs_prefix="MsGraph.Incident", outputs_key_field="id", outputs=updated_incident, readable_output=human_readable_table
    )


def validate_mirroring_comment_tags(params: dict) -> None:
    """
    Validates that both comment tags are set and that they are different, only when mirroring is enabled.
    The tags have no code defaults (only the YML defaults), so an empty value is rejected here.
    If the tags are equal, comments mirrored in from Microsoft would be mirrored back out as duplicates.
    When the mirroring direction is None, the tags are not used, so nothing is validated.

    Args:
        params (dict): The integration parameters.
    Raises:
        DemistoException: If mirroring is enabled and a comment tag is empty, or both comment tags have the same value.
    """
    if not get_mirror_direction(params):
        return
    comment_tag_to_microsoft = params.get("comment_tag")
    comment_tag_from_microsoft = params.get("comment_tag_from_microsoft_graph_security")
    if not comment_tag_to_microsoft or not comment_tag_from_microsoft:
        raise DemistoException(
            "The 'Comment Entry Tag (to Microsoft)' and 'Comment Entry Tag (from Microsoft)' parameters must not be empty."
        )
    if comment_tag_to_microsoft == comment_tag_from_microsoft:
        raise DemistoException(
            "The 'Comment Entry Tag (to Microsoft)' and 'Comment Entry Tag (from Microsoft)' parameters "
            "cannot have the same value."
        )


def test_function(client: MsGraphClient, args, has_access_to_context=False):  # pragma: no cover
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    The test button has no access to the integration context, which the authorization code flow reads and writes,
    so the authorization code flow can only be tested with the msg-auth-test command.

    Args:
        client (MsGraphClient): MsGraphClient client object.
        args (dict): The command's arguments dictionary.
        has_access_to_context (bool): Whether this function is called from a command that can access the integration context.
    Returns:
        'ok' if connection is successful.
    Raises:
        DemistoException: If using the authorization code flow without access to the context, or if mirroring is enabled
            and a comment tag is empty or both comment tags are equal.
    """
    validate_mirroring_comment_tags(demisto.params())

    if (
        not has_access_to_context
        and hasattr(client.ms_client, "grant_type")
        and client.ms_client.grant_type == AUTHORIZATION_CODE
    ):
        raise DemistoException(
            "Test module is not available for the authorization code flow. Use the msg-auth-test command instead."
        )

    response = client.ms_client.http_request(method="GET", url_suffix=CMD_URL, params={"$top": 1}, resp_type="response")
    try:
        data = response.json() if response.text else {}
        if not response.ok:
            return_error(
                f'API call to MS Graph Security failed. Please check authentication related parameters.'
                f' [{response.status_code}] - {demisto.get(data, "error.message")}'
            )

        params: dict = demisto.params()

        if params.get("isFetch"):
            fetch_limit = arg_to_number(params.get("fetch_limit")) or MAX_ITEMS_PER_RESPONSE
            if fetch_limit > MAX_ITEMS_PER_RESPONSE:
                raise DemistoException(
                    f"The fetch limit per type cannot be higher than {MAX_ITEMS_PER_RESPONSE}, "
                    "due to a Microsoft limitation when fetching incidents."
                )

            fetch_time = params.get("fetch_time", "3 days")
            fetch_incidents_type = argToList(params.get("fetch_incidents_type"))
            time_from = parse_date_range(fetch_time, date_format=TIMESTAMP_FORMAT)[0]
            time_to = datetime.now().strftime(TIMESTAMP_FORMAT)

            if "Alerts" in fetch_incidents_type:
                fetch_filter = params.get("fetch_filter", "")
                fetch_service_sources = params.get("fetch_service_sources", "")
                filter_query = create_filter_query(fetch_filter, fetch_service_sources)
                args = {"time_to": time_to, "time_from": time_from, "filter": filter_query}
                alerts_params = create_search_alerts_filters(args, is_fetch=True)
                try:
                    client.search_alerts(alerts_params)["value"]
                except Exception as e:
                    if "Invalid ODATA query filter" in e.args[0]:
                        raise DemistoException(
                            "Wrong alerts filter format, correct usage: {property} eq '{property-value}'\n\n" + e.args[0]
                        )
                    raise e

            if "Incidents" in fetch_incidents_type:
                fetch_incidents_filter = params.get("fetch_incidents_filter", "")
                filter_expression = f"createdDateTime gt {time_from} and createdDateTime le {time_to}"
                if fetch_incidents_filter:
                    # Wrap in parentheses so an `or` clause can't escape the time window (matches the real fetch query).
                    filter_expression += f" and ({fetch_incidents_filter})"
                url_suffix = f"security/incidents?$top=1&$filter={filter_expression}"
                try:
                    client.get_incidents_request(url_suffix, FETCH_INCIDENTS_TIMEOUT)
                except Exception as e:
                    if "Invalid ODATA query filter" in e.args[0]:
                        raise DemistoException(
                            "Wrong incidents filter format, correct usage: {property} eq '{property-value}'\n\n" + e.args[0]
                        )
                    raise e

        return "ok", None, None

    except TypeError as ex:
        demisto.debug(str(ex))
        return_error(
            f"API call to MS Graph Security failed, could not parse result. "
            f"Please check authentication related parameters. [{response.status_code}]"
        )


def get_message_user(client, message_user):
    is_email = re.search(EMAIL_REGEX, message_user)
    if is_email:
        user_result = (client.get_user_id(message_user)).get("value")
        if not user_result:
            raise DemistoException(f"{message_user} is not a valid user")
        return user_result[0].get("id")
    return message_user


def is_base_64(string: str) -> bool:  # pragma: no cover
    """
    Validate if string is base 64 encoded.
    Args:
        string (str): String to validate.

    Returns:
        bool: True if the string is base 64 encoded ,  else False.

    """
    try:
        if isinstance(string, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            string_bytes = bytes(string, "ascii")
        elif isinstance(string, bytes):
            string_bytes = string
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(string_bytes)) == string_bytes
    except Exception:
        return False


def get_content_data(entry_id, content_data):  # pragma: no cover
    if not (entry_id or content_data) or (entry_id and content_data):
        raise DemistoException("Just one of entry_id or content_data arguments has to be provided.")
    try:
        if entry_id:
            file = demisto.getFilePath(entry_id)
            file_path = file["path"]
            with open(file_path, "rb") as fp:
                content = base64.b64encode(fp.read())
                return str(content, encoding="utf-8")
        if content_data:
            return content_data if is_base_64(content_data) else base64.b64encode(content_data)

    except Exception as e:
        raise DemistoException(f"Failed loading content data: {e}")


def get_result_outputs(result) -> Dict:
    output = {
        "ID": result.get("id"),
        "Created DateTime": result.get("createdDateTime"),
        "Content Type": result.get("contentType"),
        "Expected Assessment": result.get("expectedAssessment"),
        "Category": result.get("category"),
        "Status": result.get("status"),
        "Request Source": result.get("requestSource"),
        "Recipient Email": result.get("recipientEmail"),
        "Destination Routing Reason": result.get("destinationRoutingReason"),
        "URL": result.get("url"),
        "File Name": result.get("fileName"),
    }
    if created_by := result.get("createdBy"):
        output["Created User ID"] = created_by.get("user", {}).get("id")
        output["Created Username"] = created_by.get("user", {}).get("displayName")

    if results := result.get("results"):
        output["Result Type"] = results[0].get("resultType")
        output["Result message"] = results[0].get("message")
    return output


def get_threat_assessment_request(client: MsGraphClient, request_id):
    result = client.get_threat_assessment_request(request_id)
    outputs = get_result_outputs(result)
    readable_output = tableToMarkdown("Threat assessment request:", outputs, removeNull=True)

    return [
        CommandResults(
            readable_output=readable_output, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.AssessmentRequest"
        )
    ]


@polling_function(
    "msg-create-mail-assessment-request",
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
    requires_polling_arg=False,
)
def create_mail_assessment_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:
    if not (request_id := args.get("request_id")):
        message_user = get_message_user(client, args.get("message_user"))
        result = client.create_mail_assessment_request(
            args.get("recipient_email"),
            args.get("expected_assessment"),
            args.get("category"),
            message_user,
            args.get("message_id"),
        )
        request_id = result.get("id")

    result = client.get_threat_assessment_request(request_id)
    status = result.get("status")
    demisto.debug(f"status is: {status}")
    if status == "completed" or result.get("results"):
        outputs = get_result_outputs(result)
        outputs["Message ID"] = args.get("message_id")
        readable_output = tableToMarkdown("Mail assessment request:", outputs, removeNull=True)

        results = CommandResults(
            readable_output=readable_output, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.MailAssessment"
        )
        return PollResult(response=results)
    else:
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id, **args},
            response=None,
            partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."),
        )


@polling_function(
    "msg-create-email-file-assessment-request",
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
    requires_polling_arg=False,
)
def create_email_file_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:
    if not (request_id := args.get("request_id")):
        content_data = get_content_data(args.get("entry_id"), args.get("content_data"))
        result = client.create_email_file_assessment_request(
            args.get("recipient_email"), args.get("expected_assessment"), args.get("category"), content_data
        )
        request_id = result.get("id")
    demisto.debug(f"got request id: {request_id}")
    result = client.get_threat_assessment_request(request_id)
    status = result.get("status")
    demisto.debug(f"status is: {status}")
    if status == "completed" or result.get("results"):
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown("Email file assessment request results:", outputs, removeNull=True)

        results = CommandResults(
            readable_output=readable_output, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.EmailAssessment"
        )
        return PollResult(response=results)
    else:
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id, **args},
            response=None,
            partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."),
        )


@polling_function("msg-create-file-assessment-request", requires_polling_arg=False)
def create_file_assessment_request_command(args, client) -> PollResult | CommandResults:
    if not (request_id := args.get("request_id")):
        content_data = get_content_data(args.get("entry_id"), args.get("content_data"))
        demisto.debug(f"got content data: {content_data}")
        result = client.create_file_assessment_request(
            args.get("expected_assessment"), args.get("category"), args.get("file_name"), content_data
        )
        request_id = result.get("id")

    demisto.debug(f"got request id: {request_id}")
    result = client.get_threat_assessment_request_status(request_id)
    status = result.get("status")

    demisto.debug(f"status is: {status}")
    if status == "completed":
        result = client.get_threat_assessment_request(request_id)
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown("File assessment request results:", outputs, removeNull=True)

        results = CommandResults(
            readable_output=readable_output, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.FileAssessment"
        )
        return PollResult(response=results)
    else:
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id, **args},
            response=None,
            partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."),
        )


@polling_function(
    "msg-create-url-assessment-request",
    timeout=arg_to_number(demisto.args().get("timeout_in_seconds", 720)),
    requires_polling_arg=False,
)
def create_url_assessment_request_command(args, client: MsGraphClient) -> PollResult | CommandResults:
    if not (request_id := args.get("request_id")):
        result = client.create_url_assessment_request(args.get("expected_assessment"), args.get("category"), args.get("url"))
        request_id = result.get("id")

    result = client.get_threat_assessment_request_status(request_id)
    status = result.get("status")
    demisto.debug(f"status is : {status}")
    if status == "completed":
        result = client.get_threat_assessment_request(request_id)
        outputs = get_result_outputs(result)
        readable_output = tableToMarkdown("URL assessment request results:", outputs, removeNull=True)

        results = CommandResults(
            readable_output=readable_output, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.UrlAssessment"
        )
        return PollResult(response=results)
    else:
        return PollResult(
            continue_to_poll=True,
            args_for_next_run={"request_id": request_id, **args},
            response=None,
            partial_result=CommandResults(readable_output="The status is pending, still waiting to get results..."),
        )


def list_threat_assessment_requests_command(client: MsGraphClient, args) -> list[CommandResults]:
    command_results = []
    limit = args.get("limit")

    if request_id := args.get("request_id"):
        return get_threat_assessment_request(client, request_id)

    result = client.list_threat_assessment_requests(
        args.get("filter"), args.get("order_by"), args.get("sort_order"), args.get("next_token")
    )
    outputs = []
    requests_list = result.get("value")
    if limit:
        requests_list = requests_list[:limit]
    for req in requests_list:
        outputs.append(get_result_outputs(req))
    readable_outputs = tableToMarkdown("Threat assessment request results:", outputs, removeNull=True)
    command_results.append(
        CommandResults(
            readable_output=readable_outputs, raw_response=result, outputs=outputs, outputs_prefix="MSGraphMail.AssessmentRequest"
        )
    )

    skip_token_field = result.get("@odata.nextLink")
    demisto.debug(f"skip_token_field: {skip_token_field}")
    if skip_token_field:
        next_token_value: List[str] = re.split(r"skip[t|T]oken=", skip_token_field)
        if len(next_token_value) > 1:
            next_token: str = next_token_value[1]

            command_results.append(
                CommandResults(
                    readable_output=f"Next token is: {next_token}\n" if next_token else None,
                    outputs={"next_token": next_token},
                    outputs_prefix="MsGraph.AssessmentRequestNextToken",
                )
            )

    return command_results


""" MIRRORING COMMANDS """


def infer_mirror_type(remote_id: str, type_hint: str | None = None) -> str:
    """
    Resolves whether a remote ID is an alert or an incident.
    Graph incident IDs are numeric, alert IDs are not, so an ID made of digits only is treated as an incident.
    """
    if type_hint in (MIRROR_TYPE_ALERT, MIRROR_TYPE_INCIDENT):
        return type_hint
    return MIRROR_TYPE_INCIDENT if str(remote_id).strip().isdigit() else MIRROR_TYPE_ALERT


def normalize_get_remote_data_args(args: dict) -> tuple[dict, str | None]:
    """
    Maps `id`/`lastUpdate` or the aliases `incident_id`/`alert_id` to GetRemoteDataArgs format.
    Returns (normalized args, type hint from the alias used).
    """
    type_hint: str | None = None
    remote_id = args.get("id")
    if not remote_id and args.get("incident_id"):
        remote_id, type_hint = args.get("incident_id"), MIRROR_TYPE_INCIDENT
    elif not remote_id and args.get("alert_id"):
        remote_id, type_hint = args.get("alert_id"), MIRROR_TYPE_ALERT
    last_update = args.get("lastUpdate") or "0"
    return {"id": remote_id or "", "lastUpdate": last_update}, type_hint


def get_remote_data_wrapper_command(client: MsGraphClient, args: dict, params: dict) -> GetRemoteDataResponse:
    """Normalizes the get-remote-data args, then runs the standard get-remote-data flow."""
    normalized_args, type_hint = normalize_get_remote_data_args(args)
    demisto.debug(f"[Mirroring] get-remote-data normalized args: {normalized_args}, type hint: {type_hint}")
    return get_remote_data_command(client, normalized_args, params, type_hint)


def to_typed_graph_object(response: dict | None, mirror_type: str) -> dict:
    """Copies a Graph alert/incident response, drops `@odata.context` and adds the classifier discriminator key."""
    mirrored_object = dict(response or {})
    mirrored_object.pop("@odata.context", None)
    mirrored_object[MIRROR_TYPE_KEY] = mirror_type
    return mirrored_object


def get_alert_for_mirroring(client: MsGraphClient, alert_id: str) -> dict:
    """Gets a single alert by ID for incoming mirroring, with the computed `customDetailsList` key."""
    alert = to_typed_graph_object(client.get_alert_by_id(alert_id), MIRROR_TYPE_ALERT)
    alert[CUSTOM_DETAILS_LIST_KEY] = custom_details_to_list(alert.get("customDetails"))
    return alert


def get_incident_for_mirroring(client: MsGraphClient, incident_id: str) -> dict:
    """Gets a single incident by ID for incoming mirroring, with its alerts expanded."""
    return to_typed_graph_object(client.get_incident_by_id(incident_id, expand_alerts=True), MIRROR_TYPE_INCIDENT)


def to_xsoar_close_reason(graph_object: dict) -> str:
    """
    Maps the Graph classification to the XSOAR close reason (missing/unknown -> Other).
    Shared by the incoming close entry and the outgoing echo check, so both always agree.
    """
    classification = graph_object.get("classification") or "unknown"
    return MICROSOFT_RESOLVED_CLASSIFICATION_TO_XSOAR_CLOSE_REASON.get(classification, "Other")


def build_close_entry(close_reason: str, close_notes: str) -> dict:
    """Builds the XSOAR entry that closes the mirrored incident with the given close reason and close notes."""
    return {
        "Type": EntryType.NOTE,
        "Contents": {"dbotIncidentClose": True, "closeReason": close_reason, "closeNotes": close_notes},
        "ContentsFormat": EntryFormat.JSON,
    }


def get_resolved_close_entry(mirrored_object: dict) -> dict:
    """Builds the XSOAR close entry for a resolved Graph alert/incident."""
    close_notes = mirrored_object.get("resolvingComment") or INCOMING_DEFAULT_CLOSE_NOTES
    return build_close_entry(to_xsoar_close_reason(mirrored_object), close_notes)


def get_redirected_close_entry(mirrored_object: dict) -> dict:
    """
    Builds the XSOAR close entry for a redirected Graph incident (merged into another incident in Microsoft).
    Closed as Resolved, with the target incident in the close notes.
    """
    target_id = mirrored_object.get("redirectIncidentId")
    close_notes = (
        f"Redirected in Microsoft Defender to incident {target_id}." if target_id else "Redirected in Microsoft Defender."
    )
    if resolving_comment := mirrored_object.get("resolvingComment"):
        close_notes = f"{close_notes}\n{resolving_comment}"
    return build_close_entry(REDIRECTED_CLOSE_REASON, close_notes)


def is_remote_closed(mirrored_object: dict) -> bool:
    """A remote object is closed when it is resolved, or when it is an incident redirected into another incident."""
    status = mirrored_object.get("status")
    if status == GRAPH_RESOLVED_STATUS:
        return True
    return status == GRAPH_REDIRECTED_STATUS and mirrored_object.get(MIRROR_TYPE_KEY) == MIRROR_TYPE_INCIDENT


def is_xsoar_investigation_closed() -> bool | None:
    """
    Returns whether the mirrored XSOAR investigation is closed (status 1), open (any other status),
    or None when the status can't be read (then the caller falls back to the remote status only).
    """
    try:
        investigation = demisto.investigation() or {}
    except Exception as e:
        demisto.debug(
            f"[Mirroring] Could not read the XSOAR investigation, falling back to the remote status: {e!s}\n"
            f"{traceback.format_exc()}"
        )
        return None
    investigation_id, investigation_status = investigation.get("id"), investigation.get("status")
    demisto.debug(f"[Mirroring] XSOAR investigation {investigation_id} status: {investigation_status!r}")
    if investigation_status is None:
        demisto.debug("[Mirroring] The XSOAR investigation status is unknown, falling back to the remote status.")
        return None
    return arg_to_number(investigation_status) == XSOAR_INVESTIGATION_STATUS_CLOSED


def get_close_or_reopen_entries(mirrored_object: dict, close_incident: bool) -> list[dict]:
    """
    Builds the close/reopen entry for a mirrored-in alert/incident (only when close_incident is enabled).
    `resolved` closes the XSOAR incident, and so does an incident `redirected` (as Resolved). Only an explicit active
    status (GRAPH_ACTIVE_STATUSES) reopens it; any other status (missing, unknown, unknownFutureValue, ...) adds no entry.
    No entry is added when the XSOAR investigation is already in the matching state
    (e.g. a comment on an active object must not add a reopen entry to an open XSOAR incident).
    """
    if not close_incident:
        return []
    status = mirrored_object.get("status")
    remote_id = mirrored_object.get("id")
    remote_closed = is_remote_closed(mirrored_object)
    active_statuses = GRAPH_ACTIVE_STATUSES.get(mirrored_object.get(MIRROR_TYPE_KEY, ""), set())
    if not remote_closed and status not in active_statuses:
        demisto.debug(f"[Mirroring] {remote_id} status '{status}' is not actionable; not closing or reopening.")
        return []
    xsoar_closed = is_xsoar_investigation_closed()
    demisto.debug(f"[Mirroring] {remote_id} status: {status}, remote closed: {remote_closed}, XSOAR closed: {xsoar_closed}.")
    if xsoar_closed is not None and xsoar_closed == remote_closed:
        return []
    if not remote_closed:
        return [{"Type": EntryType.NOTE, "Contents": {"dbotIncidentReopen": True}, "ContentsFormat": EntryFormat.JSON}]
    if status == GRAPH_REDIRECTED_STATUS:
        return [get_redirected_close_entry(mirrored_object)]
    return [get_resolved_close_entry(mirrored_object)]


def get_entries_for_comments(comments: list[dict], last_update: datetime, comment_tag: str) -> list[dict]:
    """
    Builds note entries for the Graph comments created after `last_update`, skipping comments mirrored out from XSOAR.
    The entries are tagged with `comment_tag`, or left untagged when it is empty.
    """
    tags = [comment_tag] if comment_tag else []
    entries = []
    for comment in comments or []:
        text = comment.get("comment") or ""
        if MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR in text:
            continue
        comment_time = to_utc_datetime(comment.get("createdDateTime"))
        if not comment_time:
            demisto.debug(f"[Mirroring] Could not parse the comment time of {comment=}")
            continue
        if comment_time <= last_update:
            continue
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": f"Created By: {comment.get('createdByDisplayName', '')}\n"
                f"Created On: {comment.get('createdDateTime', '')}\n{text}",
                "ContentsFormat": EntryFormat.TEXT,
                "Tags": tags,
                "Note": True,
                "EntryContext": {"comments": comment},
            }
        )
    return entries


def get_remote_data_command(
    client: MsGraphClient, args: dict, params: dict, mirror_type_hint: str | None = None
) -> GetRemoteDataResponse:
    """
    Gets a single remote alert/incident and builds its mirror-in entries (close/reopen and comments).
    On HTTP 429, raises "API rate limit" (the mirroring convention) so the server stops this sync cycle and retries later.
    On any other failure, returns the object fetched so far (or {id, mirror_type}) with `in_mirror_error`, and no entries.
    On success, `in_mirror_error` is set to "" so a stale error from a previous failed cycle is cleared on the incident.
    """
    remote_args = GetRemoteDataArgs(args)
    remote_id = str(remote_args.remote_incident_id or "")
    mirror_type = infer_mirror_type(remote_id, mirror_type_hint)
    mirrored_object: dict = {}
    try:
        if not remote_id:
            raise DemistoException("get-remote-data - an alert or incident ID must be provided.")
        last_update = to_utc_datetime(remote_args.last_update) or datetime.fromtimestamp(0, tz=timezone.utc)  # noqa: UP017
        demisto.debug(f"[Mirroring] get-remote-data for {mirror_type} {remote_id}, last update: {last_update}")
        if mirror_type == MIRROR_TYPE_INCIDENT:
            mirrored_object = get_incident_for_mirroring(client, remote_id)
        else:
            mirrored_object = get_alert_for_mirroring(client, remote_id)
        comment_tag = params.get("comment_tag_from_microsoft_graph_security") or ""
        close_incident = argToBoolean(params.get("close_incident", False))
        entries = get_close_or_reopen_entries(mirrored_object, close_incident)
        entries.extend(get_entries_for_comments(mirrored_object.get("comments", []), last_update, comment_tag))
        # Clears an `in_mirror_error` left by a previous failed cycle.
        mirrored_object["in_mirror_error"] = ""
        return GetRemoteDataResponse(mirrored_object, entries)
    except Exception as e:
        demisto.debug(f"[Mirroring] Error in incoming mirror for {mirror_type} {remote_id}: {e!s}\n{traceback.format_exc()}")
        if is_rate_limit_error(e):
            raise DemistoException(RATE_LIMIT_ERROR_MESSAGE) from e
        if not mirrored_object:
            mirrored_object = {"id": remote_id, MIRROR_TYPE_KEY: mirror_type}
        mirrored_object["in_mirror_error"] = str(e)
        return GetRemoteDataResponse(mirrored_object, entries=[])


def to_graph_filter_iso(dt: datetime) -> str:
    """Formats a UTC datetime for an OData filter: whole seconds when there are no microseconds, else with microseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ" if dt.microsecond else "%Y-%m-%dT%H:%M:%SZ")


def get_modified_remote_data_command(client: MsGraphClient, args: dict, params: dict) -> GetModifiedRemoteDataResponse:
    """
    Returns the IDs of the alerts and/or incidents (per `fetch_incidents_type`) modified since `lastUpdate`,
    alert IDs first. All pages are read for each selected type.
    """
    last_update = args.get("lastUpdate")
    parsed_date = to_utc_datetime(last_update)
    if not parsed_date:
        # Raised (not an empty list) so return_error adds "skip update" and the server keeps the same lastUpdate.
        raise DemistoException(f"get-modified-remote-data - failed to parse lastUpdate '{last_update}'.")
    server_last_update = parsed_date.replace(microsecond=0)
    last_update_iso = to_graph_filter_iso(server_last_update)
    fetch_types = argToList(params.get("fetch_incidents_type"))
    modified_ids: list[str] = []
    for fetch_type, object_url in (("Alerts", CMD_URL), ("Incidents", INCIDENTS_URL)):
        if fetch_type in fetch_types:
            modified_ids.extend(client.list_modified_object_ids(object_url, last_update_iso))
    demisto.debug(f"[Mirroring] {len(modified_ids)} objects modified since {last_update_iso} (types: {fetch_types}).")
    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_ids)


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """Returns the outgoing mirroring fields for the Graph Security Alert and Graph Security Incident types."""
    mapping_response = GetMappingFieldsResponse()
    for type_name, fields in (
        ("Graph Security Alert", OUTGOING_ALERT_FIELDS),
        ("Graph Security Incident", OUTGOING_INCIDENT_FIELDS),
    ):
        scheme = SchemeTypeMapping(type_name=type_name)
        for name, description in fields.items():
            scheme.add_field(name=name, description=description)
        mapping_response.add_scheme_type(scheme)
    return mapping_response


def apply_classification_label(delta: dict) -> None:
    """
    Translates a combined classification label (e.g. 'True positive - Malware') into the Graph classification and
    determination. Alerts and incidents use the same determination names. A value that isn't a label is left unchanged.
    """
    label = delta.get("classification")
    if label not in CLASSIFICATION_LABEL_TO_GRAPH:
        return
    delta["classification"], delta["determination"] = CLASSIFICATION_LABEL_TO_GRAPH[label]


def format_close_comment(close_reason: str | None, close_notes: str | None) -> str | None:
    """
    Builds the close comment sent to Microsoft:
        Closed in Cortex XSOAR as: <close reason>
        Comment: <close notes>
    Without a close reason, the notes are returned as-is. Notes that already start with the reason prefix (mirrored back
    in from Microsoft as closeNotes) are returned as-is, so the prefix is never doubled.
    """
    if close_notes and close_notes.startswith(CLOSE_COMMENT_REASON_PREFIX):
        return close_notes
    if not close_reason:
        return close_notes or None
    comment = f"{CLOSE_COMMENT_REASON_PREFIX}{close_reason}"
    return f"{comment}\n{CLOSE_COMMENT_NOTES_PREFIX}{close_notes}" if close_notes else comment


def is_xsoar_incident_closed(inc_status: Any) -> bool:
    """True when the update-remote-system `status` arg is IncidentStatus.DONE. A missing status (None) means open."""
    return inc_status is not None and arg_to_number(inc_status) == IncidentStatus.DONE


def has_close_fields(delta: dict) -> bool:
    """True when the delta holds a non-empty close field (CLOSE_FIELD_KEYS)."""
    return any(delta.get(key) for key in CLOSE_FIELD_KEYS)


def is_open_graph_status(status: Any) -> bool:
    """True for a set, non-resolved Graph status (e.g. inProgress). `unknownFutureValue` is not an open status."""
    return bool(status) and status not in (GRAPH_RESOLVED_STATUS, UNKNOWN_FUTURE_VALUE)


def get_delta_close_notes(delta: dict) -> Any:
    """Returns the XSOAR close notes from the delta: `closeNotes`, else its outgoing-mapped `resolvingComment`."""
    return delta.get("closeNotes") or delta.get("resolvingComment")


def apply_close_out(delta: dict, mirror_type: str, data: dict, post_alert_comment: bool = False) -> str | None:
    """
    Sets status=resolved and the close comment (incident `resolvingComment`, alert comment).
    Returns the alert close comment to POST for a new close or when `post_alert_comment` is set, otherwise None.
    """
    is_new_close = bool(delta.get("closeReason"))
    # The delta can hold close notes without closeReason (e.g. reclosed with the same reason), so the data is checked too.
    close_reason = delta.get("closeReason") or data.get("closeReason")
    delta["status"] = GRAPH_RESOLVED_STATUS
    demisto.debug(f"[Mirroring] Closing out the remote {mirror_type} (close reason: {close_reason}, new close: {is_new_close}).")
    close_notes = format_close_comment(close_reason, get_delta_close_notes(delta))
    if mirror_type != MIRROR_TYPE_INCIDENT:
        return close_notes if (is_new_close or post_alert_comment) else None
    if close_notes:
        delta["resolvingComment"] = close_notes
    return None


def apply_default_close_out(delta: dict, mirror_type: str, data: dict) -> str | None:
    """
    Sets status=resolved with DEFAULT_CLOSE_COMMENT, for an XSOAR close without a close reason or close notes
    (incident `resolvingComment`, alert comment). Returns the alert close comment to POST, if any.
    An existing incident resolvingComment (in the outgoing data) is never overwritten with the default comment.
    """
    delta["status"] = GRAPH_RESOLVED_STATUS
    if mirror_type != MIRROR_TYPE_INCIDENT:
        return DEFAULT_CLOSE_COMMENT
    if not data.get("resolvingComment"):
        delta["resolvingComment"] = DEFAULT_CLOSE_COMMENT
    return None


def to_graph_delta_keys(delta: dict, mirror_type: str) -> dict:
    """
    Returns a copy of the delta with raw XSOAR field names renamed to their Graph keys (XSOAR_FIELD_TO_GRAPH_KEY).
    If the delta holds both the raw field and the Graph key, the Graph key (already mapped) wins.
    """
    renamed = dict(delta)
    for xsoar_field, graph_key in XSOAR_FIELD_TO_GRAPH_KEY[mirror_type].items():
        if xsoar_field not in renamed:
            continue
        value = renamed.pop(xsoar_field)
        renamed.setdefault(graph_key, value)
        demisto.debug(f"[Mirroring] Delta key '{xsoar_field}' renamed to the Graph key '{graph_key}'.")
    return renamed


def is_close_out_needed(delta: dict, inc_status: Any, data: dict) -> bool:
    """
    True when handle_close_out would resolve the remote object: the XSOAR incident is closed and either the delta
    holds close fields (apply_close_out) or the outgoing data doesn't show it resolved (apply_default_close_out).
    """
    if not is_xsoar_incident_closed(inc_status):
        return False
    return has_close_fields(delta) or data.get("status") != GRAPH_RESOLVED_STATUS


def is_xsoar_reopen(delta: dict, inc_status: Any) -> bool:
    """
    True when the XSOAR incident was reopened: it is open and the delta clears `closingUserId`.
    Only a reopen clears `closingUserId` - also after a close without a close reason, where `closeReason` stays empty and
    is not in the delta. Clearing the close reason or notes of an open incident is a normal edit, not a reopen.
    """
    return not is_xsoar_incident_closed(inc_status) and delta.get("closingUserId", None) == ""


def get_remote_object(client: MsGraphClient, remote_id: str, mirror_type: str, action: str) -> dict | None:
    """
    GETs the remote alert/incident to check its current status before a close-out or a reopen.
    The outgoing data isn't used: its status comes from the XSOAR status field, which can be stale right after incoming
    mirroring changed the XSOAR incident. HTTP 429 is raised ("API rate limit"); any other failure is logged and returns
    None, so the `action` (e.g. "closing out", "reopening") isn't blocked.
    """
    try:
        if mirror_type == MIRROR_TYPE_INCIDENT:
            remote_object = client.get_incident_by_id(remote_id)
        else:
            remote_object = client.get_alert_by_id(remote_id)
    except Exception as e:
        if is_rate_limit_error(e):  # http_get_with_rate_limit keeps the 429 response on its "API rate limit" error
            raise
        demisto.debug(
            f"[Mirroring] Failed to get the remote status of {mirror_type} {remote_id}, {action} anyway: {e!s}\n"
            f"{traceback.format_exc()}"
        )
        return None
    return remote_object if isinstance(remote_object, dict) else None


def get_resolved_remote_object(client: MsGraphClient, remote_id: str, mirror_type: str) -> dict | None:
    """GETs the remote alert/incident and returns it when its status is already resolved, otherwise None."""
    remote_object = get_remote_object(client, remote_id, mirror_type, action="closing out")
    if remote_object and remote_object.get("status") == GRAPH_RESOLVED_STATUS:
        return remote_object
    return None


def normalize_close_text(text: Any) -> str:
    """Collapses whitespace, so close texts that differ only in spaces or newlines compare equal."""
    return " ".join(str(text or "").split())


def get_changed_close_fields(delta: dict, remote_object: dict) -> list[str]:
    """
    Returns the close fields that the delta changes compared to the resolved remote object ("close notes", "close reason").
    An empty list means the XSOAR close only echoes the close that incoming mirroring brought from Microsoft:
    - close notes are new when they differ from the remote resolvingComment, and aren't INCOMING_DEFAULT_CLOSE_NOTES
      (set by incoming mirroring when the remote object has no resolvingComment). Whitespace is ignored.
    - the close reason is new when it differs from the one incoming mirroring maps from the remote classification.
    """
    changed_fields = []
    close_notes = normalize_close_text(get_delta_close_notes(delta))
    remote_comment = normalize_close_text(remote_object.get("resolvingComment"))
    if close_notes and close_notes not in (remote_comment, INCOMING_DEFAULT_CLOSE_NOTES):
        changed_fields.append("close notes")
    if delta.get("closeReason") and delta["closeReason"] != to_xsoar_close_reason(remote_object):
        changed_fields.append("close reason")
    return changed_fields


def drop_status_change(delta: dict) -> None:
    """Drops the status and resolvingComment from the delta, so no status change and no closing comment is sent."""
    delta.pop("status", None)
    delta.pop("resolvingComment", None)


def skip_close_out_of_resolved_remote(delta: dict, remote_id: str, mirror_type: str) -> None:
    """Drops the status change from the delta, so the already resolved remote object isn't closed out again."""
    drop_status_change(delta)
    demisto.debug(
        f"[Mirroring] The remote {mirror_type} {remote_id} is already resolved in Microsoft and the XSOAR close reason and "
        "close notes match it (echo of the incoming close); skipping the close-out (no status, resolvingComment or close "
        "comment is sent). Other field changes are still sent."
    )


def has_explicit_open_status(delta: dict, inc_status: Any) -> bool:
    """
    True when the XSOAR incident is closed but the delta holds an explicit non-resolved status (e.g. inProgress).
    The status is then sent as-is, without a close-out (no status=resolved, resolvingComment or close comment).
    """
    return is_xsoar_incident_closed(inc_status) and is_open_graph_status(delta.get("status"))


def handle_outgoing_status_change(
    client: MsGraphClient, remote_id: str, mirror_type: str, delta: dict, inc_status: Any, data: dict
) -> str | None:
    """
    Sets the outgoing status in the delta (close_out on). Returns the alert close comment to POST, if any.
    The first matching case wins:
    1. Closed XSOAR incident with an explicit open status (e.g. inProgress): send that status, no close-out.
    2. XSOAR reopen: reopen the remote object, unless it is already open (echo of an incoming reopen).
    3. Remote object not resolved: close it out.
    4. Remote object already resolved: close it out again only if the close reason or notes changed.
    """
    if has_explicit_open_status(delta, inc_status):
        delta.pop("resolvingComment", None)
        demisto.debug(
            f"[Mirroring] The XSOAR incident is closed, but the delta holds the explicit status '{delta.get('status')}'; "
            f"sending it to the remote {mirror_type} {remote_id} without a close-out."
        )
        return None
    if is_xsoar_reopen(delta, inc_status):
        handle_reopen(client, remote_id, mirror_type, delta, data)
        return None
    remote_object = None
    if is_close_out_needed(delta, inc_status, data):
        remote_object = get_resolved_remote_object(client, remote_id, mirror_type)
    if remote_object is None:
        return handle_close_out(delta, inc_status, mirror_type, data)
    changed_fields = get_changed_close_fields(delta, remote_object)
    if not changed_fields:
        skip_close_out_of_resolved_remote(delta, remote_id, mirror_type)
        return None
    demisto.debug(
        f"[Mirroring] The remote {mirror_type} {remote_id} is already resolved in Microsoft, but the XSOAR {changed_fields} "
        "changed (not an echo of the incoming close); sending the close-out."
    )
    return apply_close_out(delta, mirror_type, data, post_alert_comment=True)


def handle_close_out(delta: dict, inc_status: Any, mirror_type: str, data: dict) -> str | None:
    """
    Closes out the remote object (close_out on only). Returns alert close notes to POST as a comment, if any.
    The remote object isn't resolved here (or its status couldn't be read), so alert close notes are always posted,
    also without a close reason (e.g. `!closeInvestigation closeNotes=...`).
    """
    if not is_xsoar_incident_closed(inc_status):
        return None
    if has_close_fields(delta):
        return apply_close_out(delta, mirror_type, data, post_alert_comment=True)
    if data.get("status") != GRAPH_RESOLVED_STATUS:
        demisto.debug(
            f"[Mirroring] The XSOAR incident is closed without a close reason or close notes; resolving the remote "
            f"{mirror_type} with the default comment '{DEFAULT_CLOSE_COMMENT}'."
        )
        return apply_default_close_out(delta, mirror_type, data)
    return None


def handle_reopen(client: MsGraphClient, remote_id: str, mirror_type: str, delta: dict, data: dict) -> None:
    """
    Reopens the remote object for an XSOAR reopen (close_out on only), unless it is already open in Microsoft.
    An already open remote object means the XSOAR reopen is an echo of a reopen that incoming mirroring brought from
    Microsoft, so its status isn't overwritten (only an explicit non-resolved delta status is kept). If the remote status
    can't be read (other than HTTP 429, which is raised), the remote object is reopened anyway.
    """
    remote_object = get_remote_object(client, remote_id, mirror_type, action="reopening")
    remote_status = remote_object.get("status") if remote_object else None
    if is_open_graph_status(remote_status):
        if not is_open_graph_status(delta.get("status")):
            drop_status_change(delta)
        demisto.debug(
            f"[Mirroring] The remote {mirror_type} {remote_id} is already open in Microsoft (status={remote_status}); "
            "skipping the reopen (echo of the incoming reopen). Other field changes are still sent."
        )
        return
    set_reopen_status(delta, mirror_type, data)


def set_reopen_status(delta: dict, mirror_type: str, data: dict) -> None:
    """
    Sets the status for a reopen of the remote object. A non-resolved status is kept: the explicit delta status (the
    analyst set it in the same change), else the current data status (a reopen echo of an incoming Microsoft reopen to
    e.g. inProgress, where the delta has no status). Otherwise the default reopen status is sent (incident=active, alert=new).
    """
    explicit_status = delta.get("status")
    if is_open_graph_status(explicit_status):
        # The analyst set a non-resolved status in the same change (e.g. inProgress): keep it.
        demisto.debug(
            f"[Mirroring] Reopening the remote {mirror_type}: keeping the explicit status '{explicit_status}' "
            f"instead of the default reopen status '{GRAPH_DEFAULT_REOPEN_STATUS[mirror_type]}'."
        )
        return
    current_status = explicit_status or data.get("status")
    if is_open_graph_status(current_status):
        # data.status may be stale after an XSOAR close-out, but sending a non-resolved status is still a valid reopen.
        delta["status"] = current_status
        demisto.debug(f"[Mirroring] Reopening the remote {mirror_type}, keeping current status={current_status}.")
        return
    delta["status"] = GRAPH_DEFAULT_REOPEN_STATUS[mirror_type]
    demisto.debug(f"[Mirroring] Reopening the remote {mirror_type} (status={delta['status']}).")


def to_graph_severity(value: Any) -> str | None:
    """Maps an XSOAR severity (0-4) to a Graph severity. Graph severity strings are passed through."""
    if isinstance(value, str) and value.lower() in GRAPH_SEVERITY_VALUES:
        return value.lower()
    try:
        return XSOAR_TO_GRAPH_SEVERITY.get(float(value))
    except (TypeError, ValueError):
        return None


def to_graph_patch_value(key: str, value: Any) -> Any:
    """Converts a non-empty delta value to the value Graph expects for `key`. An empty result means "not set"."""
    if key == "severity":
        graph_severity = to_graph_severity(value)
        if graph_severity is None:
            demisto.debug(f"[Mirroring] Severity {value!r} has no Graph value, it is not sent.")
        return graph_severity
    if key == "customTags":
        return [tag for tag in argToList(value) if tag]
    if key == "customDetails":
        custom_details = additional_data_to_custom_details(value)
        if not custom_details:
            demisto.debug("[Mirroring] Additional Data has no customDetails items, sending an empty customDetails.")
        return custom_details
    return value


def build_patch_body(delta: dict, mirror_type: str) -> dict:
    """
    Filters the delta to the keys the Graph object accepts in a PATCH, converts the values, and drops empty values.
    A clearable key (CLEARABLE_PATCH_KEYS) whose value is or converts to empty is sent with its typed empty value.
    `unknownFutureValue` is never sent for status/classification/determination (Graph rejects it).
    """
    allowed_keys = INCIDENT_PATCH_KEYS if mirror_type == MIRROR_TYPE_INCIDENT else ALERT_PATCH_KEYS
    clearable_keys = CLEARABLE_PATCH_KEYS.get(mirror_type, {})
    body: dict[str, Any] = {}
    for key, value in delta.items():
        if key not in allowed_keys or (key in UNKNOWN_FUTURE_VALUE_KEYS and value == UNKNOWN_FUTURE_VALUE):
            continue
        if value not in EMPTY_PATCH_VALUES:
            value = to_graph_patch_value(key, value)
        if value not in EMPTY_PATCH_VALUES:
            body[key] = value
        elif key in clearable_keys:
            # A fresh empty instance, so the CLEARABLE_PATCH_KEYS constant is never shared with the body.
            body[key] = type(clearable_keys[key])()
    return body


def format_mirror_out_comment(entry: dict) -> str:
    """Formats an XSOAR entry as a Graph comment, with the mirrored-out marker."""
    user = entry.get("user") or "dbot"
    contents = str(entry.get("contents", ""))
    if str(entry.get("format")) == "html":
        return f"({user}): <br/><br/>[code]{contents} <br/><br/>[/code] {MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR}"
    return add_mirror_marker(f"({user}): {contents}")


def create_graph_comment(client: MsGraphClient, remote_id: str, mirror_type: str, comment: str) -> None:
    """POSTs a comment on the remote alert/incident."""
    body = build_graph_comment_body(comment)
    if mirror_type == MIRROR_TYPE_INCIDENT:
        client.create_incident_comment(remote_id, body)
    else:
        client.create_alert_comment(remote_id, body)


def mirror_out_entries(client: MsGraphClient, entries: list[dict], comment_tag: str, remote_id: str, mirror_type: str) -> None:
    """
    POSTs the XSOAR entries tagged with `comment_tag` as comments on the remote alert/incident, in order.
    The first failed POST is raised, and the later entries are not posted.
    """
    for entry in entries:
        entry_id = entry.get("id")
        if comment_tag not in (entry.get("tags") or []):
            demisto.debug(
                f"[Mirroring] Skipping entry {entry_id}: its tags {entry.get('tags') or []} do not include the "
                f"outgoing comment tag '{comment_tag}'."
            )
            continue
        create_graph_comment(client, remote_id, mirror_type, format_mirror_out_comment(entry))
        demisto.debug(f"[Mirroring] Mirrored out entry {entry_id} to {mirror_type} {remote_id}.")


def post_alert_close_comment(client: MsGraphClient, alert_id: str, notes: str | None) -> None:
    """POSTs the alert close notes as a marked comment, if any. Failures are raised."""
    if not notes:
        return
    client.create_alert_comment(alert_id, build_graph_comment_body(add_mirror_marker(notes)))


def strip_remote_id_suffix(name: str, remote_id: str) -> str:
    """
    Removes one trailing " - <remote_id>" from an incident name.
    The XSOAR name is "<displayName> - <id>" (fetch and incoming mapper), so the suffix must not be sent to Microsoft.
    """
    suffix = f" - {remote_id}"
    if name and remote_id and name.endswith(suffix):
        return name[: -len(suffix)]
    return name


def is_redirected_incident(mirror_type: str, data: dict) -> bool:
    """True when the target is an incident that Microsoft redirected (merged) into another incident."""
    return mirror_type == MIRROR_TYPE_INCIDENT and data.get("status") == GRAPH_REDIRECTED_STATUS


def apply_outgoing_status(
    client: MsGraphClient, remote_id: str, mirror_type: str, delta: dict, inc_status: Any, data: dict, params: dict
) -> str | None:
    """
    Applies the outgoing status policy to the delta. Returns the alert close notes to POST, if any.
    - A redirected (merged) incident can't be reopened through Graph, so no status change (close-out, reopen or status
      field) and no resolvingComment is sent for it. Alerts are never redirected.
    - close_out off: no status (any value, for alerts and incidents, open or closed XSOAR incidents) and no
      resolvingComment (the outgoing-mapped closeNotes) is sent, so XSOAR never resolves or reopens the remote object.
      The delta keys are already Graph keys here (to_graph_delta_keys), so the raw status field is covered too.
    - close_out on: an open XSOAR incident (also a reopen) never sends resolvingComment, since Graph rejects it on a
      non-resolved incident. Then the explicit status, close-out or reopen is applied (handle_outgoing_status_change).
    """
    if is_redirected_incident(mirror_type, data):
        demisto.debug(f"[Mirroring] Incident {remote_id} is redirected; skipping status update.")
        drop_status_change(delta)
        return None
    if not argToBoolean(params.get("close_out", False)):
        if "status" in delta:
            demisto.debug(f"[Mirroring] close_out is off; status is not sent to the remote {mirror_type} {remote_id}.")
        drop_status_change(delta)
        return None
    if not is_xsoar_incident_closed(inc_status) and "resolvingComment" in delta:
        delta.pop("resolvingComment")
        demisto.debug(
            f"[Mirroring] The XSOAR incident is open; resolvingComment is not sent to the remote {mirror_type} {remote_id}."
        )
    return handle_outgoing_status_change(client, remote_id, mirror_type, delta, inc_status, data)


def update_remote_fields(
    client: MsGraphClient, remote_id: str, mirror_type: str, remote_args: UpdateRemoteSystemArgs, params: dict
) -> None:
    """
    Applies the XSOAR delta to the remote alert/incident: one PATCH, then the alert close notes comment (POST).
    The close notes are posted only after the PATCH succeeds.
    """
    data = remote_args.data or {}
    delta = to_graph_delta_keys(remote_args.delta or {}, mirror_type)
    if mirror_type == MIRROR_TYPE_INCIDENT and isinstance(delta.get("displayName"), str):
        delta["displayName"] = strip_remote_id_suffix(delta["displayName"], remote_id)
    alert_close_notes = apply_outgoing_status(client, remote_id, mirror_type, delta, remote_args.inc_status, data, params)
    apply_classification_label(delta)
    body = build_patch_body(delta, mirror_type)
    cleared_keys = sorted(key for key, value in body.items() if value in EMPTY_PATCH_VALUES)
    if cleared_keys:
        demisto.debug(f"[Mirroring] Clearing the remote {mirror_type} {remote_id} keys {cleared_keys}")
    if body:
        demisto.debug(f"[Mirroring] PATCH {mirror_type} {remote_id} with keys {sorted(body)}")
        if mirror_type == MIRROR_TYPE_INCIDENT:
            client.update_incident_by_id(remote_id, body)
        else:
            client.update_alert_by_id(remote_id, body)
    post_alert_close_comment(client, remote_id, alert_close_notes)


def update_remote_system_command(client: MsGraphClient, args: dict, params: dict) -> str:
    """
    Mirrors out the XSOAR changes to the remote alert/incident and returns the remote ID, in this order:
    fields (PATCH, then the alert close notes comment), then the tagged entries (one POST each).
    Raises a DemistoException when `remoteId` is missing (a manual run).
    """
    remote_args = UpdateRemoteSystemArgs(args)
    remote_id = str(remote_args.remote_incident_id or "")
    if not remote_id:
        raise DemistoException("update-remote-system - the remoteId argument is required.")
    # The outgoing data holds only outgoing-mapped fields (no type key), so the type comes from the ID format.
    mirror_type = infer_mirror_type(remote_id)
    demisto.debug(
        f"[Mirroring] update-remote-system {mirror_type} {remote_id}, delta keys: {sorted(remote_args.delta or {})}, "
        f"changed: {remote_args.incident_changed}, status: {remote_args.inc_status}"
    )
    # A close without a close reason or close notes changes no outgoing-mapped field, so the delta can be empty: the
    # field update still runs for a closed incident, so close-out can resolve the remote object (with the default comment).
    if remote_args.incident_changed and (remote_args.delta or is_xsoar_incident_closed(remote_args.inc_status)):
        update_remote_fields(client, remote_id, mirror_type, remote_args, params)
    comment_tag: str = params.get("comment_tag") or ""
    if remote_args.entries and not comment_tag:
        demisto.error("[Mirroring] The 'Comment Entry Tag (to Microsoft)' parameter is empty, no entries are mirrored out.")
    elif remote_args.entries:
        mirror_out_entries(client, remote_args.entries, comment_tag, remote_id, mirror_type)
    return remote_id


def main():
    params: dict = demisto.params()
    args: dict = demisto.args()
    tenant = params.get("creds_tenant_id", {}).get("password") or params.get("tenant_id")
    auth_and_token_url = params.get("creds_auth_id", {}).get("password") or params.get("auth_id", "")
    enc_key = params.get("creds_enc_key", {}).get("password") or params.get("enc_key")
    use_ssl = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    certificate_thumbprint = params.get("creds_certificate", {}).get("identifier") or params.get("certificate_thumbprint")
    private_key = replace_spaces_in_credential(params.get("creds_certificate", {}).get("password")) or params.get("private_key")
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get("self_deployed", False) or managed_identities_client_id is not None
    azure_cloud = get_azure_cloud(params, "MicrosoftGraphSecurity")

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException(
                "Key must be provided. For further information see "
                "https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication"
            )
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException("Key or Certificate Thumbprint and Private Key must be provided.")

    commands = {
        "test-module": test_function,
        "msg-auth-test": test_auth_code_command,
        "msg-search-alerts": search_alerts_command,
        "msg-get-alert-details": get_alert_details_command,
        "msg-update-alert": update_alert_command,
        "msg-get-users": get_users_command,
        "msg-get-user": get_user_command,
        "msg-create-alert-comment": create_alert_comment_command,
        # eDiscovery commands
        "msg-create-ediscovery-case": create_ediscovery_case_command,
        "msg-list-ediscovery-cases": list_ediscovery_case_command,
        "msg-update-ediscovery-case": update_ediscovery_case_command,
        "msg-close-ediscovery-case": close_ediscovery_case_command,
        "msg-reopen-ediscovery-case": reopen_ediscovery_case_command,
        "msg-delete-ediscovery-case": delete_ediscovery_case_command,
        "msg-create-ediscovery-custodian": create_ediscovery_custodian_command,
        "msg-list-ediscovery-custodians": list_ediscovery_custodian_command,
        "msg-release-ediscovery-custodian": release_ediscovery_custodian_command,
        "msg-activate-ediscovery-custodian": activate_ediscovery_custodian_command,
        "msg-create-ediscovery-custodian-user-source": create_ediscovery_custodian_user_source_command,
        "msg-list-ediscovery-custodian-user-sources": list_ediscovery_custodian_user_sources_command,
        "msg-create-ediscovery-custodian-site-source": create_ediscovery_custodian_site_source_command,
        "msg-list-ediscovery-custodian-site-sources": list_ediscovery_custodian_site_sources_command,
        "msg-create-ediscovery-non-custodial-data-source": create_ediscovery_non_custodial_data_source_command,
        "msg-list-ediscovery-non-custodial-data-sources": list_ediscovery_non_custodial_data_source_command,
        "msg-apply-hold-ediscovery-custodian": apply_hold_ediscovery_custodian_command,
        "msg-remove-hold-ediscovery-custodian": remove_hold_ediscovery_custodian_command,
        "msg-create-ediscovery-search": create_ediscovery_search_command,
        "msg-update-ediscovery-search": update_ediscovery_search_command,
        "msg-list-ediscovery-searchs": list_ediscovery_search_command,
        "msg-delete-ediscovery-search": delete_ediscovery_search_command,
        "msg-purge-ediscovery-data": purge_ediscovery_data_command,
        "msg-run-estimate-statistics": run_estimate_statistics_command,
        "msg-advanced-hunting": advanced_hunting_command,
        "msg-list-security-incident": get_list_security_incident_command,
        "msg-update-security-incident": update_incident_command,
        "msg-create-ediscovery-case-hold-policy": create_ediscovery_case_hold_policy_command,
        "msg-delete-ediscovery-case-hold-policy": delete_ediscovery_case_hold_policy_command,
        "msg-update-ediscovery-case-hold-policy": update_ediscovery_case_policy_command,
        "msg-list-ediscovery-case-hold-policy": list_ediscovery_case_hold_policy_command,
        "msg-list-case-operation": list_case_operation_command,
        "msg-export-result-ediscovery-data": export_result_ediscovery_data_command,
    }
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        auth_code = params.get("auth_code", {}).get("password")
        redirect_uri = params.get("redirect_uri")
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS

        client: MsGraphClient = MsGraphClient(
            tenant_id=tenant,
            auth_code=auth_code,
            auth_id=auth_and_token_url,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            app_name=APP_NAME,
            azure_cloud=azure_cloud,
            azure_ad_endpoint=azure_cloud.endpoints.active_directory,
            token_retrieval_url=urljoin(azure_cloud.endpoints.active_directory, f"/{tenant}/oauth2/v2.0/token"),
            base_url=urljoin(azure_cloud.endpoints.microsoft_graph_resource_id, "/v1.0/"),
            verify=use_ssl,
            proxy=proxy,
            self_deployed=self_deployed,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            grant_type=grant_type,
        )
        if command == "fetch-incidents":
            incidents_and_alerts = fetch_incidents_and_alerts(client, params)
            demisto.incidents(incidents_and_alerts)
        elif command == "get-remote-data":
            return_results(get_remote_data_wrapper_command(client, args, params))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args, params))
        elif command == "update-remote-system":
            return_results(update_remote_system_command(client, args, params))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command == "msg-create-mail-assessment-request":
            return_results(create_mail_assessment_request_command(args, client))
        elif command == "msg-create-email-file-assessment-request":
            return_results(create_email_file_request_command(args, client))
        elif command == "msg-create-file-assessment-request":
            return_results(create_file_assessment_request_command(args, client))
        elif command == "msg-create-url-assessment-request":
            return_results(create_url_assessment_request_command(args, client))
        elif command == "msg-list-threat-assessment-requests":
            return_results(list_threat_assessment_requests_command(client, args))
        elif command == "msg-get-last-estimate-statistics-operation":
            return_results(get_last_estimate_statistics_command(args, client))
        elif command == "ms-graph-security-auth-reset":
            return_results(reset_auth())
        elif demisto.command() == "msg-generate-login-url":
            return_results(generate_login_url(client.ms_client))

        else:
            if command not in commands:
                raise NotImplementedError(f"The provided command {command} was not implemented.")
            command_res = commands[command](client, args)  # type: ignore
            if isinstance(command_res, (CommandResults | list)):
                return_results(command_res)
            else:
                human_readable, entry_context, raw_response = command_res  # pylint: disable=E0633  # type: ignore
                return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
