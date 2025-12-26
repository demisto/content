try:
    import demistomock as demisto
    from CommonServerPython import *
    from CommonServerUserPython import *
except Exception:
    pass

import urllib3
import traceback
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta

urllib3.disable_warnings()

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
SOCRADAR_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
DEFAULT_MAX_FETCH = 10000  # Default max incidents to fetch
MAX_INCIDENTS_PER_PAGE = 100  # API limit per page

STATUS_REASON_MAP = {
    "OPEN": 0,
    "INVESTIGATING": 1,
    "RESOLVED": 2,
    "PENDING_INFO": 4,
    "LEGAL_REVIEW": 5,
    "VENDOR_ASSESSMENT": 6,
    "FALSE_POSITIVE": 9,
    "DUPLICATE": 10,
    "PROCESSED_INTERNALLY": 11,
    "MITIGATED": 12,
    "NOT_APPLICABLE": 13
}

MESSAGES = {
    "BAD_REQUEST_ERROR": "An error occurred while fetching the data.",
    "AUTHORIZATION_ERROR": "Authorization Error: make sure API Key is correctly set.",
    "RATE_LIMIT_EXCEED_ERROR": "Rate limit exceeded.",
}


def convert_to_demisto_severity(severity: str) -> int:
    """Convert SOCRadar severity to Demisto severity level"""
    return {
        "LOW": IncidentSeverity.LOW,
        "MEDIUM": IncidentSeverity.MEDIUM,
        "HIGH": IncidentSeverity.HIGH,
        "CRITICAL": IncidentSeverity.CRITICAL,
    }.get(severity.upper(), IncidentSeverity.UNKNOWN)


class Client(BaseClient):
    def __init__(self, base_url: str, api_key: str, company_id: int, verify: bool, proxy: bool):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self.api_key = api_key
        self.company_id = company_id

    def _get_headers(self) -> Dict[str, str]:
        """Get API request headers"""
        return {"API-Key": self.api_key}

    def search_incidents(
        self,
        status: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        alarm_main_types: Optional[List[str]] = None,
        alarm_sub_types: Optional[List[str]] = None,
        alarm_type_ids: Optional[List[int]] = None,
        excluded_alarm_type_ids: Optional[List[int]] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = 20,
        page: int = 1,
        company_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Search incidents from SOCRadar API

        Args:
            status: List of status filters (OPEN, CLOSED, ON_HOLD) - multi-select
            severities: List of severity levels to filter
            alarm_main_types: List of main alarm types to filter
            alarm_sub_types: List of alarm subtypes to filter
            alarm_type_ids: List of alarm type IDs to include
            excluded_alarm_type_ids: List of alarm type IDs to exclude
            start_date: Start date for filtering (YYYY-MM-DD)
            end_date: End date for filtering (YYYY-MM-DD)
            limit: Number of results per page (max 100)
            page: Page number for pagination
            company_id: Company ID (optional, uses default if not provided)

        API Response Structure:
        {
          "data": {
            "alarms": [...],
            "total_pages": 3077,
            "total_records": 6153
          },
          "is_success": true,
          "message": "Success"
        }
        """
        # Use provided company_id or fall back to default
        target_company_id = company_id if company_id is not None else self.company_id

        params: Dict[str, Any] = {
            "limit": min(limit, 100),
            "page": page,
            "include_total_records": "true"
        }

        # Handle multi-select status filter
        if status:
            if isinstance(status, list) and len(status) > 0:
                params["status"] = status
            elif isinstance(status, str):
                params["status"] = [status]

        if severities:
            params["severities"] = severities
        if alarm_main_types:
            params["alarm_main_types"] = alarm_main_types
        if alarm_sub_types:
            params["alarm_sub_types"] = alarm_sub_types
        if alarm_type_ids:
            params["alarm_type_ids"] = alarm_type_ids
        if excluded_alarm_type_ids:
            params["excluded_alarm_type_ids"] = excluded_alarm_type_ids
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        url_suffix = f"/company/{target_company_id}/incidents/v4"

        demisto.debug(f"[SOCRadar V4.0] Requesting incidents from: {url_suffix}")
        demisto.debug(f"[SOCRadar V4.0] Request params: {params}")

        try:
            response = self._http_request(
                method="GET",
                url_suffix=url_suffix,
                params=params,
                headers=self._get_headers(),
                timeout=60,
                resp_type='json'
            )

            demisto.debug(f"[SOCRadar V4.0] Response type: {type(response)}")

            if isinstance(response, dict):
                demisto.debug(f"[SOCRadar V4.0] Response keys: {list(response.keys())}")

                # Check API success flag
                if not response.get("is_success", True):
                    error_msg = response.get("message", "Unknown error")
                    demisto.error(f"[SOCRadar V4.0] API Error: {error_msg}")
                    raise DemistoException(f"API Error: {error_msg}")

                # Get data object
                data_obj = response.get("data", {})

                # Extract alarms from data.alarms
                alarms = data_obj.get("alarms", [])
                total_pages = data_obj.get("total_pages", 1)
                total_records = data_obj.get("total_records", len(alarms))

                # Add company_id to each alarm for tracking
                for alarm in alarms:
                    if isinstance(alarm, dict):
                        alarm["company_id"] = target_company_id

                demisto.debug(f"[SOCRadar V4.0] Received {len(alarms)} alarms from page {page}")
                demisto.debug(f"[SOCRadar V4.0] Total records: {total_records}, Total pages: {total_pages}")

                # Log sample alarm structure
                if alarms and len(alarms) > 0:
                    sample = alarms[0]
                    demisto.debug(f"[SOCRadar V4.0] Sample alarm keys: {list(sample.keys())}")
                    demisto.debug(f"[SOCRadar V4.0] Sample alarm_id: {sample.get('alarm_id')}")
                    demisto.debug(f"[SOCRadar V4.0] Sample company_id: {sample.get('company_id')}")

                # Return normalized response
                return {
                    "is_success": response.get("is_success"),
                    "message": response.get("message"),
                    "response_code": response.get("response_code"),
                    "data": alarms,
                    "total_pages": total_pages,
                    "total_records": total_records,
                    "current_page": page
                }
            else:
                demisto.error(f"[SOCRadar V4.0] Unexpected response type: {type(response)}")
                raise DemistoException("Unexpected response format from API")

        except Exception as e:
            demisto.error(f"[SOCRadar V4.0] HTTP Request failed: {str(e)}")
            demisto.error(f"[SOCRadar V4.0] Traceback: {traceback.format_exc()}")
            raise

    def change_alarm_status(
        self,
        alarm_ids: List[int],
        status_reason: str,
        comments: Optional[str] = None,
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Change status of alarms

        API Endpoint: POST /company/{company_id}/alarms/status/change
        Body: {
            "alarm_ids": ["123", "456"],  # Array of strings
            "status": 10,  # Integer status code
            "comments": "test"
        }
        """
        if status_reason not in STATUS_REASON_MAP:
            raise ValueError(
                f"Invalid status_reason: {status_reason}. "
                f"Valid options: {', '.join(STATUS_REASON_MAP.keys())}"
            )

        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/alarms/status/change"

        # API expects alarm_ids as array of strings!
        body = {
            "alarm_ids": [str(aid) for aid in alarm_ids],
            "status": STATUS_REASON_MAP[status_reason],
        }

        if comments:
            body["comments"] = comments

        demisto.debug(f"[SOCRadar V4.0] Changing status for alarms: {alarm_ids}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")
        demisto.debug(f"[SOCRadar V4.0] Request body: {body}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response

    def add_alarm_comment(
        self,
        alarm_id: int,
        user_email: str,
        comment: str,
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Add comment to an alarm

        API Endpoint: POST /company/{company_id}/alarm/add/comment/v2
        Body: {
            "alarm_id": 54232,
            "user_email": "test@test.com",
            "comment": "Investigating by legal team"
        }
        """
        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/alarm/add/comment/v2"

        body = {
            "alarm_id": alarm_id,
            "user_email": user_email,
            "comment": comment
        }

        demisto.debug(f"[SOCRadar V4.0] Adding comment to alarm: {alarm_id}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response

    def change_alarm_assignee(
        self,
        alarm_id: int,
        user_emails: List[str],
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Change alarm assignee(s)

        API Endpoint: POST /company/{company_id}/alarm/{alarm_id}/assignee
        Body: {
            "user_emails": ["test1@test.com", "test2@test.com"]
        }
        """
        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/alarm/{alarm_id}/assignee"

        body = {
            "user_emails": user_emails
        }

        demisto.debug(f"[SOCRadar V4.0] Changing assignee for alarm: {alarm_id}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response

    def add_or_remove_tag(
        self,
        alarm_id: int,
        tag: str,
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Add or remove a tag from an alarm

        API Endpoint: POST /company/{company_id}/alarm/tag
        Body: {
            "alarm_id": 123123123,
            "tag": "test"
        }
        """
        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/alarm/tag"

        body = {
            "alarm_id": alarm_id,
            "tag": tag
        }

        demisto.debug(f"[SOCRadar V4.0] Adding/removing tag for alarm: {alarm_id}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response

    def ask_analyst(
        self,
        alarm_id: int,
        comment: str,
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Request assistance from an analyst

        API Endpoint: POST /company/{company_id}/incidents/ask/analyst/v2
        Body: {
            "alarm_id": 12323,
            "comment": "Hi Team, I need your assistance..."
        }
        """
        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/incidents/ask/analyst/v2"

        body = {
            "alarm_id": alarm_id,
            "comment": comment
        }

        demisto.debug(f"[SOCRadar V4.0] Requesting analyst help for alarm: {alarm_id}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response

    def change_severity(
        self,
        alarm_id: int,
        severity: str,
        company_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Change alarm severity

        API Endpoint: POST /company/{company_id}/alarm/severity
        Body: {
            "alarm_id": 2312312312,
            "severity": "LOW"
        }
        """
        target_company_id = company_id if company_id is not None else self.company_id
        url_suffix = f"/company/{target_company_id}/alarm/severity"

        body = {
            "alarm_id": alarm_id,
            "severity": severity
        }

        demisto.debug(f"[SOCRadar V4.0] Changing severity for alarm: {alarm_id}")
        demisto.debug(f"[SOCRadar V4.0] Company ID: {target_company_id}")

        response = self._http_request(
            method="POST",
            url_suffix=url_suffix,
            json_data=body,
            headers=self._get_headers(),
        )

        return response


def test_module(client: Client) -> str:
    """Test API connectivity and authentication"""
    try:
        demisto.debug("[SOCRadar V4.0] Testing module - checking API connectivity")

        # Try to fetch 1 incident from the last 1 day
        response = client.search_incidents(
            start_date=(datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),
            end_date=datetime.now().strftime("%Y-%m-%d"),
            limit=1,
            page=1,
        )

        if response.get("is_success"):
            demisto.debug("[SOCRadar V4.0] Test successful")
            return "ok"
        else:
            error_msg = response.get("message", "Unknown error")
            demisto.error(f"[SOCRadar V4.0] Test failed: {error_msg}")
            return f"Test failed: {error_msg}"

    except Exception as e:
        error_msg = str(e)
        demisto.error(f"[SOCRadar V4.0] Test module failed: {error_msg}")
        if "401" in error_msg or "Unauthorized" in error_msg:
            return MESSAGES["AUTHORIZATION_ERROR"]
        elif "429" in error_msg:
            return MESSAGES["RATE_LIMIT_EXCEED_ERROR"]
        else:
            return f"Connection failed: {error_msg}"


def parse_alarm_date(date_str: Optional[str]) -> Optional[datetime]:
    """
    Parse alarm date from various formats

    Examples:
    - "2024-01-15T10:30:00.123456"
    - "2024-01-15T10:30:00"
    - "2024-01-15"
    """
    if not date_str:
        return None

    try:
        # Remove microseconds if present
        if "." in date_str:
            date_str = date_str.split(".")[0]

        # Try datetime with T separator
        if "T" in date_str:
            return datetime.strptime(date_str[:19], "%Y-%m-%dT%H:%M:%S")
        # Try date only
        else:
            return datetime.strptime(date_str[:10], "%Y-%m-%d")
    except Exception as e:
        demisto.debug(f"[SOCRadar V4.0] Date parsing error for '{date_str}': {str(e)}")
        return None


def get_alarm_id_from_incident(incident_id: Optional[str] = None) -> Optional[int]:
    """
    Get alarm_id from incident context

    The dbotMirrorId is stored as string alarm_id (e.g., "12345")
    This can be used in automation scripts to get alarm_id from incident

    Args:
        incident_id: XSOAR incident ID (optional)

    Returns:
        alarm_id as integer for SOCRadar API operations

    Example usage in automation:
        incident = demisto.incident()
        alarm_id = incident.get('dbotMirrorId')  # Returns "12345"
        # Use directly: client.change_alarm_status([int(alarm_id)], ...)
    """
    try:
        if incident_id:
            incident = demisto.executeCommand("getIncidents", {"id": incident_id})[0]
            if incident:
                alarm_id_str = incident.get("dbotMirrorId")
                if alarm_id_str:
                    return int(alarm_id_str)
        else:
            # Current incident context
            incident = demisto.incident()
            alarm_id_str = incident.get("dbotMirrorId")
            if alarm_id_str:
                return int(alarm_id_str)
    except Exception as e:
        demisto.debug(f"[SOCRadar V4.0] Error getting alarm_id from incident: {str(e)}")

    return None


def extract_content_fields(content: Any, max_depth: int = 2) -> Dict[str, str]:
    """
    Extract content fields dynamically from alarm content
    Content structure varies by alarm type, so we extract key-value pairs dynamically

    Args:
        content: Content object (can be dict, list, str, etc.)
        max_depth: Maximum depth for nested extraction

    Returns:
        Dict of flattened key-value pairs
    """
    result = {}

    if not content or max_depth <= 0:
        return result

    try:
        if isinstance(content, dict):
            for key, value in content.items():
                if value is None:
                    continue

                # For simple types, add directly
                if isinstance(value, (str, int, float, bool)):
                    result[key] = str(value)

                # For nested dicts, flatten with prefix
                elif isinstance(value, dict) and max_depth > 1:
                    nested = extract_content_fields(value, max_depth - 1)
                    for nested_key, nested_value in nested.items():
                        result[f"{key}_{nested_key}"] = nested_value

                # For lists, join if simple types
                elif isinstance(value, list):
                    simple_items = [str(item) for item in value if isinstance(item, (str, int, float, bool))]
                    if simple_items:
                        result[key] = ", ".join(simple_items[:5])  # Limit to first 5 items

        elif isinstance(content, list):
            # If content is a list, process each item
            for idx, item in enumerate(content[:3]):  # Limit to first 3 items
                if isinstance(item, dict):
                    nested = extract_content_fields(item, max_depth - 1)
                    for nested_key, nested_value in nested.items():
                        result[f"item{idx}_{nested_key}"] = nested_value

    except Exception as e:
        demisto.debug(f"[SOCRadar V4.0] Error extracting content fields: {str(e)}")

    return result


def alarm_to_incident(
    alarm: Dict[str, Any],
    include_content: bool = True,
    include_entities: bool = True,
    include_company_id: bool = False
) -> Dict[str, Any]:
    """
    Convert SOCRadar alarm to Demisto incident with configurable content extraction

    Args:
        alarm: Alarm data from API
        include_content: Whether to extract and include content fields in CustomFields
        include_entities: Whether to include detailed entity information in CustomFields
        include_company_id: Whether to include company ID in incident details and CustomFields

    IMPORTANT: The 'content' field structure varies by alarm type:
    - Impersonating Domain: has dns_information, whois_information, domain_status
    - Stolen Credentials: has credential_details, log_content_link, asset_match
    - Bad Reputation: may have different fields
    - Each alarm type has its own unique content structure

    We safely extract common fields and include full content in rawJSON.
    """

    # Extract basic alarm information with safe defaults
    alarm_id = alarm.get("alarm_id")
    alarm_risk_level = alarm.get("alarm_risk_level", "UNKNOWN")
    alarm_asset = alarm.get("alarm_asset", "N/A")
    alarm_status = alarm.get("status", "UNKNOWN")
    company_id = alarm.get("company_id", 0)

    # Safely get alarm type details
    alarm_type_details = alarm.get("alarm_type_details", {})
    if not isinstance(alarm_type_details, dict):
        alarm_type_details = {}

    alarm_main_type = alarm_type_details.get("alarm_main_type", "Unknown")
    alarm_sub_type = alarm_type_details.get("alarm_sub_type", "")
    alarm_type_id = alarm_type_details.get("alarm_type_id", "")

    # Safely parse date
    date_str = alarm.get("date")
    occurred_time = parse_alarm_date(date_str)

    # IMPORTANT: Ensure occurred is in proper ISO format with Z
    if occurred_time:
        occurred_iso = occurred_time.isoformat()
        if not occurred_iso.endswith('Z'):
            occurred_iso += "Z"
    else:
        occurred_iso = datetime.now().isoformat() + "Z"

    # Safely get tags
    tags = alarm.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags_str = ",".join(str(tag) for tag in tags) if tags else ""

    # Build incident name with Alarm ID for easy identification
    incident_name = f"SOCRadar Alarm #{alarm_id}: {alarm_main_type}"
    if alarm_sub_type:
        incident_name += f" - {alarm_sub_type}"
    incident_name += f" [{alarm_asset}]"

    # Safely get related entities for additional context
    related_entities = alarm.get("alarm_related_entities", [])
    if not isinstance(related_entities, list):
        related_entities = []

    # Extract key-value pairs from related entities
    entity_info = []
    entity_values = []
    for entity in related_entities:
        if isinstance(entity, dict):
            key = entity.get("key", "")
            value = entity.get("value", "")
            if key and value:
                entity_info.append(f"{key}: {value}")
                entity_values.append(str(value))

    # Get alarm_text for incident details - this is the main description users need to see
    alarm_text = alarm.get("alarm_text", "")

    # Build comprehensive details section
    details_parts = []

    # Add alarm ID prominently
    details_parts.append(f"🆔 Alarm ID: {alarm_id}")

    # Add company ID only if requested
    if include_company_id:
        details_parts.append(f"🏢 Company ID: {company_id}")

    details_parts.append(f"📊 Risk Level: {alarm_risk_level}")
    details_parts.append(f"🎯 Asset: {alarm_asset}")
    details_parts.append(f"📌 Status: {alarm_status}")

    if alarm_main_type:
        details_parts.append(f"🔍 Type: {alarm_main_type}")
    if alarm_sub_type:
        details_parts.append(f"   Sub-Type: {alarm_sub_type}")
    if alarm_type_id:
        details_parts.append(f"   Type ID: {alarm_type_id}")

    # Add related entities if available
    if entity_info:
        details_parts.append(f"\n🔗 Related Entities:")
        for info in entity_info:
            details_parts.append(f"  • {info}")

    # Add main alarm text - this is the key information for the user
    if alarm_text:
        details_parts.append(f"\n📝 Alarm Description:")
        details_parts.append(alarm_text)

    # Add tags if available
    if tags:
        details_parts.append(f"\n🏷️ Tags: {', '.join(str(tag) for tag in tags)}")

    # Combine all details
    full_details = "\n".join(details_parts)

    # Build CustomFields with all available data
    custom_fields = {
        "socradaralarmid": str(alarm_id) if alarm_id else "unknown",
        "socradarstatus": alarm_status,
        "socradarasset": alarm_asset,
        "socradaralarmtype": alarm_main_type,
        "socradaralarmsubtype": alarm_sub_type,
        "socradaralarmtypeid": str(alarm_type_id) if alarm_type_id else "",
        "socradartags": tags_str,
        "socradarrisklevel": alarm_risk_level,
        "socradaralarmtext": alarm_text[:1000] if alarm_text else "",  # Limit length
    }

    # Add company ID only if requested
    if include_company_id:
        custom_fields["socradarcompanyid"] = str(company_id)

    # Add related entities details if requested
    if include_entities and entity_values:
        custom_fields["socradarentities"] = ", ".join(entity_values[:10])  # Limit to 10

    # Extract and add content fields if requested
    if include_content:
        content = alarm.get("content")
        if content:
            content_fields = extract_content_fields(content, max_depth=2)
            # Add content fields with prefix
            for key, value in content_fields.items():
                # Sanitize key to be field-name safe
                safe_key = "socradarcontent" + key.replace(" ", "").replace("-", "")[:30]
                # Limit value length
                custom_fields[safe_key] = str(value)[:1000] if value else ""

    # Create incident with proper format
    incident = {
        "name": incident_name,
        "occurred": occurred_iso,  # Proper ISO format with Z
        "rawJSON": json.dumps(alarm),  # Full alarm data including variable content structure and company_id
        "severity": convert_to_demisto_severity(alarm_risk_level),
        "details": full_details,
        "dbotMirrorId": str(alarm_id) if alarm_id else None,  # Alarm ID as string for API operations
        "CustomFields": custom_fields,
    }

    company_info = f", Company: {company_id}" if include_company_id else ""
    demisto.debug(f"[SOCRadar V4.0] Created incident: Alarm #{alarm_id} - {alarm_main_type} (Risk: {alarm_risk_level}{company_info})")
    demisto.debug(f"[SOCRadar V4.0] Incident occurred time: {occurred_iso}")
    demisto.debug(f"[SOCRadar V4.0] Incident dbotMirrorId: {alarm_id}")

    return incident


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: Dict[str, Any],
    first_fetch_time: str,
    fetch_interval_minutes: int = 1,
    status: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    alarm_main_types: Optional[List[str]] = None,
    alarm_sub_types: Optional[List[str]] = None,
    alarm_type_ids: Optional[List[int]] = None,
    excluded_alarm_type_ids: Optional[List[int]] = None,
    include_content: bool = True,
    include_entities: bool = True,
    include_company_id: bool = False,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Fetch incidents from SOCRadar with REVERSE PAGINATION (last page to first page)

    Args:
        client: SOCRadar API client
        max_results: Maximum number of incidents to fetch
        last_run: Last run information from previous fetch
        first_fetch_time: Time range for first fetch (e.g., "30 days")
        fetch_interval_minutes: Time window for subsequent fetches in minutes
        status: List of status filters (OPEN, CLOSED, ON_HOLD) - multi-select
        severities: List of severity levels to filter
        alarm_main_types: List of main alarm types to filter
        alarm_sub_types: List of alarm subtypes to filter
        alarm_type_ids: List of alarm type IDs to include
        excluded_alarm_type_ids: List of alarm type IDs to exclude
        include_content: Whether to extract content fields to CustomFields
        include_entities: Whether to include detailed entity info in CustomFields
        include_company_id: Whether to include company ID in incidents (default: False)

    Strategy - REVERSE PAGINATION:
    1. First request (page 1) → Get total_pages count
    2. Start from LAST page (total_pages)
    3. Fetch pages in reverse: total_pages, total_pages-1, ..., 2, 1
    4. Send each page to XSOAR as we go
    5. Stop when we hit max_results or reach page 1
    """
    demisto.debug(f"[SOCRadar V4.0] ========================================")
    demisto.debug(f"[SOCRadar V4.0] Starting fetch_incidents with REVERSE PAGINATION")
    demisto.debug(f"[SOCRadar V4.0] max_results: {max_results}")
    demisto.debug(f"[SOCRadar V4.0] fetch_interval_minutes: {fetch_interval_minutes}")
    demisto.debug(f"[SOCRadar V4.0] status filter: {status}")
    demisto.debug(f"[SOCRadar V4.0] alarm_type_ids: {alarm_type_ids}")
    demisto.debug(f"[SOCRadar V4.0] excluded_alarm_type_ids: {excluded_alarm_type_ids}")
    demisto.debug(f"[SOCRadar V4.0] include_content: {include_content}")
    demisto.debug(f"[SOCRadar V4.0] include_entities: {include_entities}")

    # Get last fetch time
    last_fetch = last_run.get("last_fetch")
    last_alarm_ids = set(last_run.get("last_alarm_ids", []))

    demisto.debug(f"[SOCRadar V4.0] Last fetch: {last_fetch}")
    demisto.debug(f"[SOCRadar V4.0] Previously fetched alarm IDs: {len(last_alarm_ids)}")

    # Calculate time window
    current_time = datetime.now()

    if last_fetch:
        # Subsequent fetch: ALWAYS use fetch_interval from NOW
        # Start = NOW - interval (e.g., now - 1 minute)
        # This creates overlap, but ID deduplication prevents duplicates
        start_datetime = current_time - timedelta(minutes=fetch_interval_minutes)
        demisto.debug(f"[SOCRadar V4.0] Subsequent fetch: Using interval of {fetch_interval_minutes} minutes from NOW")
        demisto.debug(f"[SOCRadar V4.0] Overlap is intentional - ID deduplication will prevent duplicates")
    else:
        # First fetch: Use first_fetch_time
        start_datetime = arg_to_datetime(first_fetch_time, arg_name="first_fetch", required=True)
        demisto.debug(f"[SOCRadar V4.0] First fetch: Using first_fetch_time")

    # Convert to epoch time (seconds) for precise filtering
    # SOCRadar API accepts epoch time in start_date/end_date parameters
    start_date = int(start_datetime.timestamp())  # Epoch seconds
    end_date = int(current_time.timestamp())      # Epoch seconds

    demisto.debug(f"[SOCRadar V4.0] Time window (human): {start_datetime.isoformat()} to {current_time.isoformat()}")
    demisto.debug(f"[SOCRadar V4.0] Time window (epoch seconds): {start_date} to {end_date}")
    demisto.debug(f"[SOCRadar V4.0] Window duration: {(end_date - start_date) / 60:.2f} minutes")
    demisto.debug(f"[SOCRadar V4.0] Using EPOCH TIME for precise API filtering")
    demisto.debug(f"[SOCRadar V4.0] Will fetch using REVERSE PAGINATION (last page → first page)")

    # Collections
    all_incidents = []
    new_alarm_ids = set()
    latest_timestamp = start_datetime

    # Pagination settings
    per_page = 100  # API limit
    total_pages = None
    total_incidents_created = 0
    total_pages_fetched = 0

    try:
        # STEP 1: Get total pages count from first request
        demisto.debug(f"[SOCRadar V4.0] ========================================")
        demisto.debug(f"[SOCRadar V4.0] STEP 1: Getting total pages count...")

        initial_response = client.search_incidents(
            status=status,
            severities=severities,
            alarm_main_types=alarm_main_types,
            alarm_sub_types=alarm_sub_types,
            alarm_type_ids=alarm_type_ids,
            excluded_alarm_type_ids=excluded_alarm_type_ids,
            start_date=start_date,
            end_date=end_date,
            limit=per_page,
            page=1,
        )

        total_pages = initial_response.get("total_pages", 1)
        total_records = initial_response.get("total_records", 0)

        demisto.debug(f"[SOCRadar V4.0] Total available: {total_records} records across {total_pages} pages")
        demisto.debug(f"[SOCRadar V4.0] Will fetch from page {total_pages} down to page 1")

        if total_records == 0:
            demisto.debug(f"[SOCRadar V4.0] No alarms found in time window")
            return {
                "last_fetch": current_time.isoformat() + "Z",
                "last_alarm_ids": list(last_alarm_ids)[:1000]
            }, []

        # STEP 2: Start from LAST page and go backwards
        demisto.debug(f"[SOCRadar V4.0] ========================================")
        demisto.debug(f"[SOCRadar V4.0] STEP 2: Starting REVERSE PAGINATION from page {total_pages}")

        for current_page in range(total_pages, 0, -1):  # total_pages, total_pages-1, ..., 2, 1
            demisto.debug(f"[SOCRadar V4.0] Fetching page {current_page}/{total_pages} (reverse order)")

            # Fetch this page
            response = client.search_incidents(
                status=status,
                severities=severities,
                alarm_main_types=alarm_main_types,
                alarm_sub_types=alarm_sub_types,
                alarm_type_ids=alarm_type_ids,
                excluded_alarm_type_ids=excluded_alarm_type_ids,
                start_date=start_date,
                end_date=end_date,
                limit=per_page,
                page=current_page,
            )

            alarms = response.get("data", [])
            demisto.debug(f"[SOCRadar V4.0] Page {current_page}: Received {len(alarms)} alarms from API")

            total_pages_fetched += 1

            if not alarms:
                demisto.debug(f"[SOCRadar V4.0] No alarms on page {current_page}, continuing...")
                continue

            # Process THIS page's alarms
            page_incidents = []
            page_new = 0
            page_dup = 0

            for alarm in alarms:
                alarm_id = alarm.get("alarm_id")

                # Deduplication: Check both previous fetches AND current fetch
                if alarm_id in last_alarm_ids or alarm_id in new_alarm_ids:
                    page_dup += 1
                    continue

                # Track alarm ID
                new_alarm_ids.add(alarm_id)

                # Parse date for tracking latest timestamp
                alarm_date = parse_alarm_date(alarm.get("date"))
                if alarm_date and alarm_date > latest_timestamp:
                    latest_timestamp = alarm_date

                # Create incident (if under max_results)
                if total_incidents_created < max_results:
                    incident = alarm_to_incident(alarm, include_content, include_entities, include_company_id)
                    page_incidents.append(incident)
                    total_incidents_created += 1
                    page_new += 1

            demisto.debug(f"[SOCRadar V4.0] Page {current_page}: Created {page_new} NEW incidents, skipped {page_dup} duplicates")

            # Add this page's incidents to total
            all_incidents.extend(page_incidents)

            if total_incidents_created >= max_results:
                demisto.debug(f"[SOCRadar V4.0] Reached max_results ({max_results}), stopping pagination")
                break

        demisto.debug(f"[SOCRadar V4.0] ========================================")
        demisto.debug(f"[SOCRadar V4.0] FETCH SUMMARY")
        demisto.debug(f"[SOCRadar V4.0] ========================================")
        demisto.debug(f"[SOCRadar V4.0] Time window (epoch): {start_date} to {end_date}")
        demisto.debug(f"[SOCRadar V4.0] Time window (human): {start_datetime.isoformat()} to {current_time.isoformat()}")
        demisto.debug(f"[SOCRadar V4.0] Fetch interval: {fetch_interval_minutes} minutes")
        demisto.debug(f"[SOCRadar V4.0] Pages fetched: {total_pages_fetched}/{total_pages if total_pages else 'unknown'} (reverse order)")
        demisto.debug(f"[SOCRadar V4.0] Total alarms from API: {total_records}")
        demisto.debug(f"[SOCRadar V4.0] New alarms found: {len(new_alarm_ids)}")
        demisto.debug(f"[SOCRadar V4.0] Incidents created: {total_incidents_created} (max: {max_results})")
        demisto.debug(f"[SOCRadar V4.0] Status filter applied: {status}")
        demisto.debug(f"[SOCRadar V4.0] Alarm Type IDs filter: {alarm_type_ids}")
        demisto.debug(f"[SOCRadar V4.0] Excluded Alarm Type IDs: {excluded_alarm_type_ids}")
        demisto.debug(f"[SOCRadar V4.0] ========================================")

        # Log sample incident if available
        if all_incidents:
            sample = all_incidents[0]
            demisto.debug(f"[SOCRadar V4.0] Sample incident name: {sample.get('name')}")
            demisto.debug(f"[SOCRadar V4.0] Sample occurred: {sample.get('occurred')}")
            demisto.debug(f"[SOCRadar V4.0] Sample severity: {sample.get('severity')}")
            demisto.debug(f"[SOCRadar V4.0] Sample dbotMirrorId: {sample.get('dbotMirrorId')}")

        # Combine alarm IDs - keep NEWEST 1000 (new IDs first, then old IDs)
        combined_list = list(new_alarm_ids) + [aid for aid in last_alarm_ids if aid not in new_alarm_ids]
        combined_alarm_ids = combined_list[:1000]  # Keep first (newest) 1000

        # Update next run
        next_run = {
            "last_fetch": current_time.isoformat() + "Z",
            "last_alarm_ids": combined_alarm_ids
        }

        demisto.debug(f"[SOCRadar V4.0] Next fetch will use time window: last {fetch_interval_minutes} minutes")
        demisto.debug(f"[SOCRadar V4.0] Tracking {len(combined_alarm_ids)} alarm IDs")
        demisto.debug(f"[SOCRadar V4.0] Returning {len(all_incidents)} incidents to XSOAR")
        demisto.debug(f"[SOCRadar V4.0] ========================================")

        return next_run, all_incidents

    except Exception as e:
        demisto.error(f"[SOCRadar V4.0] ========================================")
        demisto.error(f"[SOCRadar V4.0] ERROR in fetch_incidents: {str(e)}")
        demisto.error(f"[SOCRadar V4.0] Traceback: {traceback.format_exc()}")
        demisto.error(f"[SOCRadar V4.0] ========================================")

        # Return what we have
        if all_incidents:
            combined_list = list(new_alarm_ids) + [aid for aid in last_alarm_ids if aid not in new_alarm_ids]
            combined_alarm_ids = combined_list[:1000]
            return {
                "last_fetch": current_time.isoformat() + "Z",
                "last_alarm_ids": combined_alarm_ids
            }, all_incidents

        # Safe fallback
        return {
            "last_fetch": last_fetch or datetime.now().isoformat() + "Z",
            "last_alarm_ids": list(last_alarm_ids)[:1000]
        }, []


def change_status_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Change status of alarms

    Can be used with:
    1. Explicit alarm_ids parameter: alarm_ids="123,456"
    2. From incident context: If called from incident, uses dbotMirrorId

    Example from incident automation:
        incident = demisto.incident()
        alarm_id = incident.get('dbotMirrorId')  # "12345"
        !socradar-change-alarm-status alarm_ids=${incident.dbotMirrorId} status_reason="RESOLVED"
    """
    alarm_ids_str = args.get("alarm_ids", "")
    status_reason = args.get("status_reason", "")
    comments = args.get("comments")
    company_id_str = args.get("company_id")

    if not alarm_ids_str or not status_reason:
        raise ValueError("alarm_ids and status_reason are required")

    # Parse alarm_ids - dbotMirrorId is stored as string alarm_id
    alarm_ids = [int(aid.strip()) for aid in alarm_ids_str.split(",")]
    company_id = int(company_id_str) if company_id_str else None

    demisto.debug(f"[SOCRadar V4.0] Changing status for alarm IDs (integers): {alarm_ids}")
    demisto.debug(f"[SOCRadar V4.0] Company ID (integer): {company_id or client.company_id}")

    response = client.change_alarm_status(alarm_ids, status_reason, comments, company_id)

    return CommandResults(
        readable_output=f"Status changed for {len(alarm_ids)} alarm(s)" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def mark_as_false_positive_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Mark alarm as false positive"""
    alarm_id = args.get("alarm_id")
    company_id_str = args.get("company_id")

    if not alarm_id:
        raise ValueError("alarm_id is required")

    company_id = int(company_id_str) if company_id_str else None

    response = client.change_alarm_status(
        [int(alarm_id)],
        "FALSE_POSITIVE",
        args.get("comments", "Marked as false positive"),
        company_id
    )

    return CommandResults(
        readable_output=f"Alarm {alarm_id} marked as false positive" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def mark_as_resolved_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Mark alarm as resolved"""
    alarm_id = args.get("alarm_id")
    company_id_str = args.get("company_id")

    if not alarm_id:
        raise ValueError("alarm_id is required")

    company_id = int(company_id_str) if company_id_str else None

    response = client.change_alarm_status(
        [int(alarm_id)],
        "RESOLVED",
        args.get("comments", "Marked as resolved"),
        company_id
    )

    return CommandResults(
        readable_output=f"Alarm {alarm_id} marked as resolved" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def add_comment_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Add comment to alarm"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    user_email = args.get("user_email", "")
    comment = args.get("comment", "")
    company_id_str = args.get("company_id")

    if not user_email or not comment:
        raise ValueError("user_email and comment are required")

    company_id = int(company_id_str) if company_id_str else None
    response = client.add_alarm_comment(alarm_id, user_email, comment, company_id)

    return CommandResults(
        readable_output=f"Comment added to alarm {alarm_id}" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def change_assignee_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Change alarm assignee(s)"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    user_emails_str = args.get("user_emails", "")
    company_id_str = args.get("company_id")

    if not user_emails_str:
        raise ValueError("user_emails is required")

    user_emails = [email.strip() for email in user_emails_str.split(",")]
    company_id = int(company_id_str) if company_id_str else None

    response = client.change_alarm_assignee(alarm_id, user_emails, company_id)

    return CommandResults(
        readable_output=f"Assignee(s) changed for alarm {alarm_id}" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def add_tag_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Add or remove tag from alarm"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    tag = args.get("tag", "")
    company_id_str = args.get("company_id")

    if not tag:
        raise ValueError("tag is required")

    company_id = int(company_id_str) if company_id_str else None
    response = client.add_or_remove_tag(alarm_id, tag, company_id)

    return CommandResults(
        readable_output=f"Tag operation completed for alarm {alarm_id}" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def ask_analyst_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Request assistance from analyst"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    comment = args.get("comment", "")
    company_id_str = args.get("company_id")

    if not comment:
        raise ValueError("comment is required")

    company_id = int(company_id_str) if company_id_str else None
    response = client.ask_analyst(alarm_id, comment, company_id)

    return CommandResults(
        readable_output=f"Analyst assistance requested for alarm {alarm_id}" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def change_severity_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Change alarm severity"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    severity = args.get("severity", "")
    company_id_str = args.get("company_id")

    if not severity:
        raise ValueError("severity is required")

    # Validate severity
    valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if severity.upper() not in valid_severities:
        raise ValueError(f"Invalid severity. Must be one of: {', '.join(valid_severities)}")

    company_id = int(company_id_str) if company_id_str else None
    response = client.change_severity(alarm_id, severity.upper(), company_id)

    return CommandResults(
        readable_output=f"Severity changed to {severity.upper()} for alarm {alarm_id}" +
                       (f" (Company ID: {company_id or client.company_id})" if company_id else ""),
        raw_response=response
    )


def test_fetch_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Test the fetch incidents functionality"""
    try:
        limit = arg_to_number(args.get("limit", 5)) or 5
        first_fetch = args.get("first_fetch", "3 days")

        demisto.debug(f"[SOCRadar V4.0] Testing fetch with limit={limit}, first_fetch='{first_fetch}'")

        # Parse first_fetch to get start date
        start_datetime = arg_to_datetime(first_fetch, arg_name="first_fetch", required=True)
        start_date = int(start_datetime.timestamp())  # Epoch seconds
        end_date = int(datetime.now().timestamp())    # Epoch seconds

        demisto.debug(f"[SOCRadar V4.0] Parsed date range: {start_datetime.isoformat()} to {datetime.now().isoformat()}")
        demisto.debug(f"[SOCRadar V4.0] Epoch time: {start_date} to {end_date}")

        # Fetch page 1 to get total count
        response = client.search_incidents(
            start_date=start_date,
            end_date=end_date,
            limit=100,
            page=1,
        )

        data = response.get("data", [])
        total_records = response.get("total_records", 0)
        total_pages = response.get("total_pages", 0)

        demisto.debug(f"[SOCRadar V4.0] Test fetch found {total_records} total records across {total_pages} pages")

        # Check if no incidents found
        if not data or len(data) == 0:
            message = f"⚠️ No incidents found in time window\n\n"
            message += f"Time range: {start_datetime.isoformat()} to {datetime.now().isoformat()}\n"
            message += f"Epoch time: {start_date} to {end_date}\n\n"
            message += "Possible reasons:\n"
            message += "- No alarms in this time period\n"
            message += "- Filters are too restrictive\n"
            message += "- Date range is too narrow\n\n"
            message += f"Total records in system: {total_records}"

            return CommandResults(
                readable_output=message,
                raw_response=response
            )

        # Build incident info with safe field access
        incidents_info = []
        for incident in data[:limit]:
            # Safely get alarm_type_details
            alarm_type_details = incident.get("alarm_type_details")
            if isinstance(alarm_type_details, dict):
                main_type = alarm_type_details.get("alarm_main_type", "Unknown")
                sub_type = alarm_type_details.get("alarm_sub_type", "")
            else:
                main_type = "Unknown"
                sub_type = ""

            alarm_type_display = main_type
            if sub_type:
                alarm_type_display += f" / {sub_type}"

            # Safely get related entities for additional info
            related_entities = incident.get("alarm_related_entities", [])
            entity_summary = ""
            if isinstance(related_entities, list) and related_entities:
                first_entity = related_entities[0]
                if isinstance(first_entity, dict):
                    entity_value = first_entity.get("value", "")
                    if entity_value:
                        entity_summary = f" | Entity: {entity_value[:30]}"

            # Build incident info
            incidents_info.append({
                "Alarm ID": incident.get("alarm_id", "N/A"),
                "Company ID": incident.get("company_id", "N/A"),
                "Risk Level": incident.get("alarm_risk_level", "UNKNOWN"),
                "Status": incident.get("status", "UNKNOWN"),
                "Asset": incident.get("alarm_asset", "N/A"),
                "Type": alarm_type_display,
                "Date": incident.get("date", "")[:19] if incident.get("date") else "N/A",
                "Extra": entity_summary
            })

        # Build success message
        message = f"✅ Found {len(data)} incident(s) on page 1!\n"
        message += f"📊 Total available: {total_records} records across {total_pages} pages\n"
        message += f"⏰ Time range: {start_datetime.isoformat()} to {datetime.now().isoformat()}\n"
        message += f"🔢 Epoch time: {start_date} to {end_date}\n"
        message += f"🔄 Will use REVERSE PAGINATION (page {total_pages} → page 1)\n\n"
        message += "Sample incidents:\n"
        for info in incidents_info:
            message += f"- [{info['Alarm ID']}] {info['Risk Level']} | {info['Status']} | {info['Asset']}\n"
            message += f"  Company: {info['Company ID']} | Type: {info['Type']}{info['Extra']}\n"

        # Show different content structures if available
        if data:
            first_alarm = data[0]
            content = first_alarm.get("content")
            if isinstance(content, dict):
                content_keys = list(content.keys())
                message += f"\n📋 Content structure example (keys): {', '.join(content_keys[:5])}"
                if len(content_keys) > 5:
                    message += f" ... and {len(content_keys) - 5} more"

        return CommandResults(
            readable_output=message,
            outputs_prefix="SOCRadar.TestFetch",
            outputs={
                "TotalCount": len(data),
                "TotalRecords": total_records,
                "TotalPages": total_pages,
                "SampleIncidents": incidents_info,
                "StartDate": start_datetime.isoformat(),
                "EndDate": datetime.now().isoformat(),
                "StartEpoch": start_date,
                "EndEpoch": end_date
            },
            raw_response=response
        )

    except Exception as e:
        error_msg = str(e)
        message = f"❌ Error testing fetch: {error_msg}\n\n"
        message += "Check:\n"
        message += "- API key validity\n"
        message += "- Network connectivity\n"
        message += "- Company ID correctness\n"
        message += f"- Date parsing (tried to parse: '{args.get('first_fetch', '3 days')}')\n\n"
        message += f"Full error:\n{traceback.format_exc()}"

        return CommandResults(
            readable_output=message,
            raw_response={"error": error_msg, "traceback": traceback.format_exc()}
        )


def main() -> None:
    """Main execution function"""
    params = demisto.params()
    api_key = params.get("apikey")
    company_id_str = params.get("company_id")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # Parse company_id as integer
    try:
        company_id = int(company_id_str)
    except (ValueError, TypeError):
        return_error(f"Invalid Company ID: '{company_id_str}'. Company ID must be a numeric value.")
        return

    demisto.debug(f"[SOCRadar V4.0] ========================================")
    demisto.debug(f"[SOCRadar V4.0] Starting command: {demisto.command()}")
    demisto.debug(f"[SOCRadar V4.0] Company ID: {company_id}")
    demisto.debug(f"[SOCRadar V4.0] ========================================")

    try:
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT,
            api_key=api_key,
            company_id=company_id,
            verify=verify_certificate,
            proxy=proxy,
        )

        command = demisto.command()

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-incidents":
            max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH)) or DEFAULT_MAX_FETCH
            max_fetch = min(max_fetch, 100000)  # Hard limit at 100k for safety
            fetch_interval_minutes = arg_to_number(params.get("fetch_interval_minutes", 1)) or 1

            # Get status filter (multi-select)
            status = argToList(params.get("status"))

            # Parse alarm_type_ids (comma-separated string to list of integers)
            alarm_type_ids_str = params.get("alarm_type_ids", "")
            alarm_type_ids = None
            if alarm_type_ids_str:
                try:
                    alarm_type_ids = [int(x.strip()) for x in alarm_type_ids_str.split(",") if x.strip()]
                except ValueError:
                    demisto.error(f"[SOCRadar V4.0] Invalid alarm_type_ids format: {alarm_type_ids_str}")

            # Parse excluded_alarm_type_ids (comma-separated string to list of integers)
            excluded_alarm_type_ids_str = params.get("excluded_alarm_type_ids", "")
            excluded_alarm_type_ids = None
            if excluded_alarm_type_ids_str:
                try:
                    excluded_alarm_type_ids = [int(x.strip()) for x in excluded_alarm_type_ids_str.split(",") if x.strip()]
                except ValueError:
                    demisto.error(f"[SOCRadar V4.0] Invalid excluded_alarm_type_ids format: {excluded_alarm_type_ids_str}")

            # Get content/entity inclusion flags
            include_content = params.get("include_content", True)
            include_entities = params.get("include_entities", True)
            include_company_id = params.get("include_company_id", False)

            demisto.debug(f"[SOCRadar V4.0] Fetch config - max_fetch: {max_fetch}, first_fetch: {params.get('first_fetch')}, fetch_interval: {fetch_interval_minutes} minutes")
            demisto.debug(f"[SOCRadar V4.0] Fetch config - status: {status}")
            demisto.debug(f"[SOCRadar V4.0] Fetch config - alarm_type_ids: {alarm_type_ids}, excluded_alarm_type_ids: {excluded_alarm_type_ids}")
            demisto.debug(f"[SOCRadar V4.0] Fetch config - include_content: {include_content}, include_entities: {include_entities}, include_company_id: {include_company_id}")

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_fetch,
                last_run=demisto.getLastRun(),
                first_fetch_time=params.get("first_fetch", "3 days"),
                fetch_interval_minutes=fetch_interval_minutes,
                status=status,
                severities=argToList(params.get("severities")),
                alarm_main_types=argToList(params.get("alarm_main_types")),
                alarm_sub_types=argToList(params.get("alarm_sub_types")),
                alarm_type_ids=alarm_type_ids,
                excluded_alarm_type_ids=excluded_alarm_type_ids,
                include_content=include_content,
                include_entities=include_entities,
                include_company_id=include_company_id,
            )

            demisto.debug(f"[SOCRadar V4.0] Setting last run to: {next_run}")
            demisto.debug(f"[SOCRadar V4.0] Returning {len(incidents)} incidents")

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "socradar-change-alarm-status":
            return_results(change_status_command(client, demisto.args()))
        elif command == "socradar-mark-false-positive":
            return_results(mark_as_false_positive_command(client, demisto.args()))
        elif command == "socradar-mark-resolved":
            return_results(mark_as_resolved_command(client, demisto.args()))
        elif command == "socradar-add-comment":
            return_results(add_comment_command(client, demisto.args()))
        elif command == "socradar-change-assignee":
            return_results(change_assignee_command(client, demisto.args()))
        elif command == "socradar-add-tag":
            return_results(add_tag_command(client, demisto.args()))
        elif command == "socradar-ask-analyst":
            return_results(ask_analyst_command(client, demisto.args()))
        elif command == "socradar-change-severity":
            return_results(change_severity_command(client, demisto.args()))
        elif command == "socradar-test-fetch":
            return_results(test_fetch_command(client, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"[SOCRadar V4.0] Error: {str(e)}")
        demisto.error(f"[SOCRadar V4.0] Traceback: {traceback.format_exc()}")
        return_error(f"Failed to execute {demisto.command()}.\nError: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
