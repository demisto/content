import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
try:
    from CommonServerUserPython import *  # noqa: F401
except Exception:
    pass

import traceback
import dateparser
from typing import Any, Union
from datetime import datetime

SOCRADAR_API_ENDPOINT = "https://platform.socradar.com/api"
SOCRADAR_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_INCIDENTS_TO_FETCH = 200  # Recommended limit for stability
MAX_INCIDENTS_PER_PAGE = 100  # API limit per page

STATUS_REASON_MAP = {
    "OPEN": 0,
    "INVESTIGATING": 2,
    "RESOLVED": 3,
    "PENDING_INFO": 4,
    "LEGAL_REVIEW": 6,
    "VENDOR_ASSESSMENT": 7,
    "FALSE_POSITIVE": 9,
    "DUPLICATE": 10,
    "PROCESSED_INTERNALLY": 11,
    "MITIGATED": 12,
    "NOT_APPLICABLE": 13,
}

MESSAGES = {
    "AUTHENTICATION_ERROR": "Authentication failed. Please verify your API Key.",
    "AUTHORIZATION_ERROR": "Access denied. Please verify your API Key has the correct permissions.",
    "NOT_FOUND_ERROR": "Resource not found. Please verify your Company ID and alarm IDs.",
    "SERVER_ERROR": "SOCRadar API server error. Please try again later.",
    "PROXY_ERROR": "Connection to SOCRadar API failed. Please check your proxy settings.",
    "CONNECTION_ERROR": "Failed to connect to SOCRadar API. Please check your network connection.",
}


class Client(BaseClient):
    """Client class to interact with SOCRadar API"""

    def __init__(self, base_url: str, api_key: str, company_id: str, verify: bool = True, proxy: bool = False, **kwargs):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)
        self.api_key = api_key
        self.company_id = company_id

    def _get_headers(self) -> dict[str, str]:
        """Get API request headers"""
        return {"API-Key": self.api_key}

    def search_incidents(
        self,
        status: str | list[str] | None = None,
        severities: str | list[str] | None = None,
        alarm_main_types: str | list[str] | None = None,
        alarm_sub_types: str | list[str] | None = None,
        alarm_type_ids: list[int] | None = None,
        excluded_alarm_type_ids: list[int] | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 20,
        page: int = 1,
        company_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Search incidents from SOCRadar API

        Args:
            status: Filter by status (OPEN, CLOSED, ON_HOLD)
            severities: List of severity levels to filter
            alarm_main_types: List of main alarm types to filter
            alarm_sub_types: List of alarm subtypes to filter
            alarm_type_ids: List of alarm type IDs to include
            excluded_alarm_type_ids: List of alarm type IDs to exclude
            start_date: Start date for filtering (YYYY-MM-DD)
            end_date: End date for filtering (YYYY-MM-DD)
            limit: Number of results per page (max 100)
            page: Page number for pagination

        API Response Structure:
        {
          "data": {
            "alarms": [...],
            "total_pages": 10,
            "total_records": 1000
          },
          "is_success": true,
          "message": "Success"
        }
        """
        params: dict[str, Any] = {"limit": min(limit, 100), "page": page, "include_total_records": "true"}

        # Send parameters as lists (API expects arrays)
        if status:
            params["status"] = status if isinstance(status, list) else [status]

        if severities:
            params["severities"] = severities if isinstance(severities, list) else [severities]

        if alarm_main_types:
            params["alarm_main_types"] = alarm_main_types if isinstance(alarm_main_types, list) else [alarm_main_types]

        if alarm_sub_types:
            params["alarm_sub_types"] = alarm_sub_types if isinstance(alarm_sub_types, list) else [alarm_sub_types]

        if alarm_type_ids:
            params["alarm_type_ids"] = alarm_type_ids

        if excluded_alarm_type_ids:
            params["excluded_alarm_type_ids"] = excluded_alarm_type_ids

        if start_date:
            params["start_date"] = start_date

        if end_date:
            params["end_date"] = end_date

        # Use provided company_id or fall back to default
        company_id_to_use = company_id or self.company_id
        url_suffix = f"/company/{company_id_to_use}/incidents/v4"

        demisto.debug(f"[SOCRadar] Requesting incidents from: {url_suffix}")
        demisto.debug(f"[SOCRadar] Request params: {params}")

        try:
            response = self._http_request(
                method="GET", url_suffix=url_suffix, params=params, headers=self._get_headers(), timeout=60, resp_type="json"
            )

            demisto.debug(f"[SOCRadar] Response type: {type(response)}")

            if isinstance(response, dict):
                demisto.debug(f"[SOCRadar] Response keys: {list(response.keys())}")

                # Check API success flag
                if not response.get("is_success", True):
                    error_msg = response.get("message", "Unknown error")
                    demisto.error(f"[SOCRadar] API Error: {error_msg}")
                    raise DemistoException(f"API Error: {error_msg}")

                # Get data object
                data_obj = response.get("data", {})

                # Extract alarms from data.alarms
                alarms = data_obj.get("alarms", [])
                total_pages = data_obj.get("total_pages", 1)
                total_records = data_obj.get("total_records", len(alarms))

                demisto.debug(f"[SOCRadar] Received {len(alarms)} alarms from page {page}")
                demisto.debug(f"[SOCRadar] Total records: {total_records}, Total pages: {total_pages}")

                # Log sample alarm structure
                if alarms and len(alarms) > 0:
                    sample = alarms[0]
                    demisto.debug(f"[SOCRadar] Sample alarm keys: {list(sample.keys())}")
                    demisto.debug(f"[SOCRadar] Sample alarm_id: {sample.get('alarm_id')}")
                    demisto.debug(f"[SOCRadar] Sample status: {sample.get('status')}")

                # Return normalized response
                return {
                    "is_success": response.get("is_success"),
                    "message": response.get("message", ""),
                    "data": alarms,
                    "total_pages": total_pages,
                    "total_records": total_records,
                    "current_page": page,
                }
            else:
                demisto.error(f"[SOCRadar] Unexpected response type: {type(response)}")
                raise DemistoException("Unexpected response format from API")

        except Exception as e:
            demisto.error(f"[SOCRadar] HTTP Request failed: {str(e)}")
            demisto.error(f"[SOCRadar] Traceback: {traceback.format_exc()}")
            raise

    def change_alarm_status(
        self, alarm_ids: list[int], status_reason: str, comments: str | None = None, company_id: str | None = None
    ) -> dict[str, Any]:
        """Change status of alarms"""
        # Case-insensitive status handling
        status_reason_upper = status_reason.upper()

        if status_reason_upper not in STATUS_REASON_MAP:
            raise ValueError(f"Invalid status reason: {status_reason}")

        # Use provided company_id or fall back to default
        company_id_to_use = company_id or self.company_id
        url_suffix = f"/company/{company_id_to_use}/alarms/status"

        json_data = {"alarm_ids": alarm_ids, "status_reason": STATUS_REASON_MAP[status_reason_upper]}

        if comments:
            json_data["comments"] = comments

        response = self._http_request(
            method="POST", url_suffix=url_suffix, json_data=json_data, headers=self._get_headers(), timeout=60
        )

        if not response.get("is_success"):
            raise DemistoException(f"API Error: {response.get('message')}")
        return response

    def add_alarm_comment(self, alarm_id: int, user_email: str, comment: str, company_id: str | None = None) -> dict[str, Any]:
        """Add comment to an alarm"""
        # Use provided company_id or fall back to default
        company_id_to_use = company_id or self.company_id
        url_suffix = f"/company/{company_id_to_use}/alarm/add/comment/v2"
        json_data = {"alarm_id": alarm_id, "user_email": user_email, "comment": comment}
        return self._http_request(
            method="POST", url_suffix=url_suffix, json_data=json_data, headers=self._get_headers(), timeout=60
        )

    def change_alarm_assignee(
        self,
        alarm_id: int,
        user_ids: list[int] | None = None,
        user_emails: list[str] | None = None,
        company_id: str | None = None,
    ) -> dict[str, Any]:
        """Change assignee of an alarm"""
        # Use provided company_id or fall back to default
        company_id_to_use = company_id or self.company_id
        url_suffix = f"/company/{company_id_to_use}/alarm/{alarm_id}/assignee"
        json_data: dict[str, Any] = {}

        if user_ids:
            json_data["user_ids"] = user_ids
        if user_emails:
            json_data["user_emails"] = user_emails

        return self._http_request(
            method="POST", url_suffix=url_suffix, json_data=json_data, headers=self._get_headers(), timeout=60
        )

    def add_remove_tag(self, alarm_id: int, tag: str, company_id: str | None = None) -> dict[str, Any]:
        """Add or remove a tag from an alarm"""
        # Use provided company_id or fall back to default
        company_id_to_use = company_id or self.company_id
        url_suffix = f"/company/{company_id_to_use}/alarm/{alarm_id}/tag/{tag}"
        return self._http_request(method="POST", url_suffix=url_suffix, headers=self._get_headers(), timeout=60)


def test_module(client: Client) -> str:
    """Test API connectivity and credentials"""
    try:
        demisto.debug("[SOCRadar] Running test module...")

        # Try to fetch 1 incident to verify API access
        response = client.search_incidents(limit=1, page=1)

        demisto.debug(f"[SOCRadar] Test response: {response}")

        if response.get("is_success"):
            demisto.debug("[SOCRadar] Test module successful")
            return "ok"
        else:
            error_msg = response.get("message", "Unknown error")
            demisto.error(f"[SOCRadar] Test module failed: {error_msg}")
            return f"Test failed: {error_msg}"

    except DemistoException as e:
        error_str = str(e)
        demisto.error(f"[SOCRadar] Test module error: {error_str}")

        if "401" in error_str or "Unauthorized" in error_str:
            return "Authorization Error: Invalid API Key"
        elif "403" in error_str or "Forbidden" in error_str:
            return "Authorization Error: Insufficient permissions"
        elif "404" in error_str:
            return "Invalid Company ID"
        else:
            return f"Connection Error: {error_str}"
    except Exception as e:
        demisto.error(f"[SOCRadar] Test module unexpected error: {str(e)}")
        return f"Unexpected error: {str(e)}"


def parse_alarm_date(date_str: str | None) -> datetime | None:
    """Parse alarm date with multiple format support"""
    if not date_str:
        return None

    try:
        # Try ISO format with microseconds
        if "." in date_str:
            # Handle microseconds
            date_str = date_str.split(".")[0] + "Z"
        # Remove 'Z' if present
        date_str = date_str.rstrip("Z")
        return datetime.fromisoformat(date_str)
    except (ValueError, AttributeError):
        # Fallback to dateparser
        return dateparser.parse(date_str, settings={"TIMEZONE": "UTC"})
    except Exception:
        return None


def alarm_to_incident(alarm: dict[str, Any]) -> dict[str, Any]:
    """
    Convert SOCRadar alarm to Demisto incident

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

    # Safely get alarm type details
    alarm_type_details = alarm.get("alarm_type_details", {})
    if not isinstance(alarm_type_details, dict):
        alarm_type_details = {}

    alarm_main_type = alarm_type_details.get("alarm_main_type", "Unknown")
    alarm_sub_type = alarm_type_details.get("alarm_sub_type", "")

    # Safely parse date
    date_str = alarm.get("date")
    occurred_time = parse_alarm_date(date_str)

    # Safely get tags
    tags = alarm.get("tags", [])
    if not isinstance(tags, list):
        tags = []
    tags_str = ",".join(str(tag) for tag in tags)

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
    for entity in related_entities:
        if isinstance(entity, dict):
            key = entity.get("key", "")
            value = entity.get("value", "")
            if key and value:
                entity_info.append(f"{key}: {value}")

    # Get alarm_text for incident details - this is the main description users need to see
    alarm_text = alarm.get("alarm_text", "")

    # Build comprehensive details section
    details_parts = []

    # Add alarm ID prominently
    details_parts.append(f"🆔 Alarm ID: {alarm_id}")
    details_parts.append(f"📊 Risk Level: {alarm_risk_level}")
    details_parts.append(f"🎯 Asset: {alarm_asset}")
    details_parts.append(f"📌 Status: {alarm_status}")

    if alarm_main_type:
        details_parts.append(f"🔍 Type: {alarm_main_type}")
    if alarm_sub_type:
        details_parts.append(f"   Sub-Type: {alarm_sub_type}")

    # Add related entities if available
    if entity_info:
        details_parts.append("\n🔗 Related Entities:")
        for info in entity_info:
            details_parts.append(f"  • {info}")

    # Add main alarm text - this is the key information for the user
    if alarm_text:
        details_parts.append("\n📝 Alarm Description:")
        details_parts.append(alarm_text)

    # Add tags if available
    if tags:
        details_parts.append(f"\n🏷️ Tags: {', '.join(str(tag) for tag in tags)}")

    # Combine all details
    full_details = "\n".join(details_parts)

    # Create incident with alarm_id as the dbotMirrorId for easy reference
    incident = {
        "name": incident_name,
        "occurred": occurred_time.isoformat() + "Z" if occurred_time else datetime.now().isoformat() + "Z",
        "severity": IncidentSeverity.MEDIUM,
        "rawJSON": json.dumps(alarm),
        "details": full_details,
        "dbotMirrorId": str(alarm_id),
        "CustomFields": {
            "socradaralarmid": str(alarm_id),
            "socradarstatus": alarm_status,
            "socradarasset": alarm_asset,
            "socradarrisklevel": alarm_risk_level,
            "socradartags": tags_str,
        },
    }

    demisto.debug(f"[SOCRadar] Created incident: Alarm #{alarm_id} - {alarm_main_type} (Risk: {alarm_risk_level})")

    return incident


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: dict[str, Any],
    first_fetch_time: str,
    fetch_interval_minutes: int = 1,
    status: str | list[str] | None = None,
    severities: str | list[str] | None = None,
    alarm_main_types: str | list[str] | None = None,
    alarm_sub_types: str | list[str] | None = None,
    alarm_type_ids: list[int] | None = None,
    excluded_alarm_type_ids: list[int] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Fetch incidents from SOCRadar with time-window based fetching

    Args:
        client: SOCRadar API client
        max_results: Maximum number of incidents to fetch
        last_run: Last run information
        first_fetch_time: Time to start first fetch from (e.g., "30 days")
        fetch_interval_minutes: Interval for subsequent fetches in minutes
        status: Status filter
        severities: Severity levels to filter
        alarm_main_types: Main alarm types to filter
        alarm_sub_types: List of alarm subtypes to filter
        alarm_type_ids: List of alarm type IDs to include
        excluded_alarm_type_ids: List of alarm type IDs to exclude

    Strategy:
    - First fetch: Use first_fetch_time (e.g., "30 days ago")
    - Subsequent fetches: Use last_fetch timestamp from previous run
    - Fetch ALL pages for the time window
    - Each page sent to XSOAR immediately (max 100 alarms per page)

    Example:
    First fetch (first_fetch_time = "30 days"):
      start_date: 30 days ago
      end_date: now
      Fetch ALL pages, each page → XSOAR

    Subsequent fetches (using last_fetch):
      start_date: last_fetch timestamp
      end_date: now
      If 500 new alarms → 5 pages → 5 separate sends to XSOAR
    """
    demisto.debug("[SOCRadar] Starting fetch_incidents")
    demisto.debug(f"[SOCRadar] max_results: {max_results}")
    demisto.debug(f"[SOCRadar] fetch_interval_minutes: {fetch_interval_minutes}")
    demisto.debug(f"[SOCRadar] alarm_type_ids: {alarm_type_ids}")
    demisto.debug(f"[SOCRadar] excluded_alarm_type_ids: {excluded_alarm_type_ids}")

    # Get last fetch time
    last_fetch = last_run.get("last_fetch")
    last_alarm_ids = set(last_run.get("last_alarm_ids", []))

    demisto.debug(f"[SOCRadar] Last fetch: {last_fetch}")
    demisto.debug(f"[SOCRadar] Previously fetched alarm IDs: {len(last_alarm_ids)}")

    # Calculate time window
    current_time = datetime.now()

    if last_fetch:
        # Subsequent fetch: Use last_fetch timestamp
        start_datetime = dateparser.parse(last_fetch)
        if not start_datetime:
            # Fallback to first_fetch_time if parsing fails
            start_datetime = arg_to_datetime(first_fetch_time, arg_name="first_fetch", required=True)
        demisto.debug("[SOCRadar] Subsequent fetch: Using last_fetch timestamp")
    else:
        # First fetch: Use first_fetch_time
        start_datetime = arg_to_datetime(first_fetch_time, arg_name="first_fetch", required=True)
        demisto.debug("[SOCRadar] First fetch: Using first_fetch_time")

    if not start_datetime:
        raise DemistoException("Failed to parse start datetime")

    start_date = start_datetime.strftime("%Y-%m-%d")
    end_date = current_time.strftime("%Y-%m-%d")

    demisto.debug(f"[SOCRadar] Time window: {start_date} to {end_date}")
    demisto.debug("[SOCRadar] Will fetch ALL pages for this time window")

    # Collections
    all_incidents = []
    new_alarm_ids = set()
    latest_timestamp = start_datetime

    # Pagination settings
    per_page = 100  # API limit
    current_page = 1
    total_pages = None
    total_incidents_created = 0
    total_pages_fetched = 0

    try:
        # Fetch ALL pages for this time window
        while True:
            demisto.debug(f"[SOCRadar] Fetching page {current_page}/{total_pages if total_pages else '?'}")

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
            total_records = response.get("total_records", 0)
            total_pages = response.get("total_pages", 0)

            demisto.debug(f"[SOCRadar] Page {current_page}: Received {len(alarms)} alarms")
            if current_page == 1:
                debug_msg = f"[SOCRadar] Total available in time window: {total_records} records across {total_pages} pages"
                demisto.debug(debug_msg)
                demisto.debug(f"[SOCRadar] Will fetch ALL {total_pages} pages")

            total_pages_fetched += 1

            if not alarms:
                demisto.debug(f"[SOCRadar] No alarms on page {current_page}")
                break

            # Process THIS page's alarms
            page_incidents = []
            page_new = 0
            page_dup = 0

            for alarm in alarms:
                try:
                    alarm_id = alarm.get("alarm_id")

                    if alarm_id in last_alarm_ids or alarm_id in new_alarm_ids:
                        page_dup += 1
                        continue

                    new_alarm_ids.add(alarm_id)

                    alarm_date = parse_alarm_date(alarm.get("date"))
                    if alarm_date and latest_timestamp and alarm_date > latest_timestamp:
                        latest_timestamp = alarm_date

                    if total_incidents_created < max_results:
                        incident = alarm_to_incident(alarm)
                        page_incidents.append(incident)
                        total_incidents_created += 1
                        page_new += 1

                except Exception as e:
                    demisto.error(f"[SOCRadar] Failed to process alarm {alarm.get('alarm_id')}: {str(e)}")
                    continue  # Skip this alarm and continue with others

            demisto.debug(f"[SOCRadar] Page {current_page}: Created {page_new} incidents, skipped {page_dup} duplicates")

            # Add this page's incidents to total
            # XSOAR will receive these incrementally
            all_incidents.extend(page_incidents)

            if total_incidents_created >= max_results:
                demisto.debug(f"[SOCRadar] Reached max_results ({max_results}), continuing to fetch pages for tracking")

            # Check if last page
            if current_page >= total_pages:
                demisto.debug(f"[SOCRadar] Reached last page ({current_page}/{total_pages})")
                break

            if len(alarms) < per_page:
                demisto.debug(f"[SOCRadar] Partial page ({len(alarms)} < {per_page}), probably last page")
                break

            # Next page
            current_page += 1

        demisto.debug("[SOCRadar] ========== FETCH SUMMARY ==========")
        demisto.debug(f"[SOCRadar] Time window: {start_date} to {end_date}")
        demisto.debug(f"[SOCRadar] Fetch interval: {fetch_interval_minutes} minutes")
        demisto.debug(f"[SOCRadar] Pages fetched: {total_pages_fetched}/{total_pages if total_pages else 'unknown'}")
        demisto.debug(f"[SOCRadar] Unique alarms found: {len(new_alarm_ids)} new + {len(last_alarm_ids)} previous")
        demisto.debug(f"[SOCRadar] Incidents created: {total_incidents_created} (max: {max_results})")
        demisto.debug(f"[SOCRadar] Alarm Type IDs filter: {alarm_type_ids}")
        demisto.debug(f"[SOCRadar] Excluded Alarm Type IDs: {excluded_alarm_type_ids}")
        demisto.debug("[SOCRadar] ====================================")

        # Combine alarm IDs - keep NEWEST 1000 (new IDs first, then old IDs)
        # Important: Use [:1000] not [-1000:] to keep the MOST RECENT alarms
        combined_list = list(new_alarm_ids) + [aid for aid in last_alarm_ids if aid not in new_alarm_ids]
        combined_alarm_ids = combined_list[:1000]  # Keep first (newest) 1000

        # Update next run
        if not latest_timestamp:
            latest_timestamp = start_datetime

        next_run = {"last_fetch": latest_timestamp.isoformat() + "Z", "last_alarm_ids": combined_alarm_ids}

        demisto.debug(f"[SOCRadar] Next fetch will use last_fetch timestamp: {latest_timestamp.isoformat()}")
        demisto.debug(f"[SOCRadar] Tracking {len(combined_alarm_ids)} alarm IDs")
        demisto.debug(f"[SOCRadar] Returning {len(all_incidents)} incidents to XSOAR")

        return next_run, all_incidents

    except Exception as e:
        demisto.error(f"[SOCRadar] Error in fetch_incidents: {str(e)}")
        demisto.error(f"[SOCRadar] Traceback: {traceback.format_exc()}")

        # Return what we have
        if all_incidents:
            combined_list = list(new_alarm_ids) + [aid for aid in last_alarm_ids if aid not in new_alarm_ids]
            combined_alarm_ids = combined_list[:1000]
            if not latest_timestamp:
                latest_timestamp = start_datetime
            return {"last_fetch": latest_timestamp.isoformat() + "Z", "last_alarm_ids": combined_alarm_ids}, all_incidents

        # Safe fallback
        fallback_time = last_fetch or datetime.now().isoformat() + "Z"
        return {"last_fetch": fallback_time, "last_alarm_ids": list(last_alarm_ids)[:1000]}, []


def change_status_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Change status of alarms"""
    alarm_ids_str = args.get("alarm_ids", "")
    status_reason = args.get("status_reason", "")
    comments = args.get("comments")
    company_id = args.get("company_id")  # Optional override

    if not alarm_ids_str or not status_reason:
        raise ValueError("alarm_ids and status_reason are required")

    alarm_ids = [int(aid.strip()) for aid in alarm_ids_str.split(",")]
    response = client.change_alarm_status(alarm_ids, status_reason, comments, company_id)

    return CommandResults(readable_output=f"Status changed for {len(alarm_ids)} alarm(s)", raw_response=response)


def mark_as_false_positive_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Mark alarm as false positive"""
    alarm_id = args.get("alarm_id")
    company_id = args.get("company_id")  # Optional override

    if not alarm_id:
        raise ValueError("alarm_id is required")

    response = client.change_alarm_status(
        [int(alarm_id)], "FALSE_POSITIVE", args.get("comments", "Marked as false positive"), company_id
    )

    return CommandResults(readable_output=f"Alarm {alarm_id} marked as false positive", raw_response=response)


def mark_as_resolved_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Mark alarm as resolved"""
    alarm_id = args.get("alarm_id")
    company_id = args.get("company_id")  # Optional override

    if not alarm_id:
        raise ValueError("alarm_id is required")

    response = client.change_alarm_status([int(alarm_id)], "RESOLVED", args.get("comments", "Marked as resolved"), company_id)

    return CommandResults(readable_output=f"Alarm {alarm_id} marked as resolved", raw_response=response)


def add_comment_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Add comment to alarm"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    user_email = args.get("user_email", "")
    comment = args.get("comment", "")
    company_id = args.get("company_id")  # Optional override

    if not alarm_id:
        raise ValueError("alarm_id is required")

    if not user_email or not comment:
        raise ValueError("user_email and comment are required")

    response = client.add_alarm_comment(alarm_id, user_email, comment, company_id)

    return CommandResults(readable_output=f"Comment added to alarm {alarm_id}", raw_response=response)


def change_assignee_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Change alarm assignee"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    user_emails = argToList(args.get("user_emails"))
    company_id = args.get("company_id")  # Optional override

    if not alarm_id:
        raise ValueError("alarm_id is required")

    if not user_emails:
        raise ValueError("user_emails is required")

    response = client.change_alarm_assignee(alarm_id, user_emails=user_emails, company_id=company_id)

    return CommandResults(readable_output=f"Assignee changed for alarm {alarm_id}", raw_response=response)


def add_tag_command(client: Client, args: dict[str, str]) -> CommandResults:
    """Add or remove tag from alarm"""
    alarm_id = arg_to_number(args.get("alarm_id"), "alarm_id", required=True)
    tag = args.get("tag", "")
    company_id = args.get("company_id")  # Optional override

    if not alarm_id:
        raise ValueError("alarm_id is required")

    if not tag:
        raise ValueError("tag is required")

    response = client.add_remove_tag(alarm_id, tag, company_id)

    return CommandResults(readable_output=f"Tag '{tag}' added/removed for alarm {alarm_id}", raw_response=response)


def test_fetch_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Test incident fetching with safe handling of variable content structures
    """
    limit = arg_to_number(args.get("limit", "5"), "limit") or 5
    company_id = args.get("company_id")  # Optional override

    try:
        # Parse first_fetch parameter
        first_fetch = args.get("first_fetch", "3 days")
        first_fetch_datetime = arg_to_datetime(first_fetch, arg_name="first_fetch", required=True)

        if not first_fetch_datetime:
            raise ValueError("Failed to parse first_fetch parameter")

        start_date = first_fetch_datetime.strftime("%Y-%m-%d")

        demisto.debug(f"[SOCRadar Test] Testing fetch from {start_date}")

        # Fetch incidents
        response = client.search_incidents(limit=limit, start_date=start_date, page=1, company_id=company_id)
        data = response.get("data", [])
        total_records = response.get("total_records", 0)
        total_pages = response.get("total_pages", 0)

        # No incidents found
        if not data:
            message = "❌ No incidents found. Possible reasons:\n"
            message += "- API Key or Company ID is incorrect\n"
            message += "- No incidents exist in this time range\n"
            message += "- Date range is too narrow\n\n"
            message += f"Tested with start_date: {start_date}\n"
            message += f"Total records in system: {total_records}"

            return CommandResults(readable_output=message, raw_response=response)

        # Build incident info with safe field access
        incidents_info = []
        for incident in data[:5]:
            # Safely get alarm type
            alarm_type_details = incident.get("alarm_type_details", {})
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
            if related_entities and isinstance(related_entities, list) and len(related_entities) > 0:
                first_entity = related_entities[0]
                if isinstance(first_entity, dict):
                    entity_value = first_entity.get("value", "")
                    if entity_value:
                        entity_summary = f" | Entity: {entity_value[:30]}"

            # Build incident info
            incidents_info.append(
                {
                    "Alarm ID": incident.get("alarm_id", "N/A"),
                    "Risk Level": incident.get("alarm_risk_level", "UNKNOWN"),
                    "Status": incident.get("status", "UNKNOWN"),
                    "Asset": incident.get("alarm_asset", "N/A"),
                    "Type": alarm_type_display,
                    "Date": incident.get("date", "")[:19] if incident.get("date") else "N/A",
                    "Extra": entity_summary,
                }
            )

        # Build success message
        message = f"✅ Found {len(data)} incident(s) on page 1 from {start_date}!\n"
        message += f"📊 Total available: {total_records} records across {total_pages} pages\n\n"
        message += "Sample incidents:\n"
        for info in incidents_info:
            message += f"- [{info['Alarm ID']}] {info['Risk Level']} | {info['Status']} | {info['Asset']}\n"
            message += f"  Type: {info['Type']}{info['Extra']}\n"

        # Show different content structures if available
        if data:
            first_alarm = data[0]
            content = first_alarm.get("content", {})
            if content and isinstance(content, dict):
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
                "StartDate": start_date,
            },
            raw_response=response,
        )

    except Exception as e:
        error_msg = str(e)
        message = f"❌ Error testing fetch: {error_msg}\n\n"
        message += "Please check:\n"
        message += "- API Key correctness\n"
        message += "- Network connectivity\n"
        message += "- Company ID correctness\n"
        message += f"- Date parsing (tried to parse: '{args.get('first_fetch', '3 days')}')\n\n"
        message += f"Full error:\n{traceback.format_exc()}"

        return CommandResults(readable_output=message, raw_response={"error": error_msg, "traceback": traceback.format_exc()})


def main() -> None:
    """Main execution function"""
    params = demisto.params()
    api_key = params.get("apikey")
    company_id = params.get("company_id")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    demisto.debug(f"[SOCRadar] Starting command: {demisto.command()}")
    demisto.debug(f"[SOCRadar] Company ID: {company_id}")

    try:
        client = Client(
            base_url=SOCRADAR_API_ENDPOINT, api_key=api_key, company_id=company_id, verify=verify_certificate, proxy=proxy
        )

        command = demisto.command()

        if command == "test-module":
            return_results(test_module(client))

        elif command == "fetch-incidents":
            max_fetch = arg_to_number(params.get("max_fetch", 200)) or 200
            max_fetch = min(max_fetch, MAX_INCIDENTS_TO_FETCH)
            fetch_interval_minutes = arg_to_number(params.get("fetch_interval_minutes", 1)) or 1

            # Parse alarm_type_ids (comma-separated string to list of integers)
            alarm_type_ids_str = params.get("alarm_type_ids", "")
            alarm_type_ids = None
            if alarm_type_ids_str:
                try:
                    alarm_type_ids = [int(x.strip()) for x in alarm_type_ids_str.split(",") if x.strip()]
                except ValueError:
                    demisto.error(f"[SOCRadar] Invalid alarm_type_ids format: {alarm_type_ids_str}")

            # Parse excluded_alarm_type_ids (comma-separated string to list of integers)
            excluded_alarm_type_ids_str = params.get("excluded_alarm_type_ids", "")
            excluded_alarm_type_ids = None
            if excluded_alarm_type_ids_str:
                try:
                    excluded_alarm_type_ids = [int(x.strip()) for x in excluded_alarm_type_ids_str.split(",") if x.strip()]
                except ValueError:
                    demisto.error(f"[SOCRadar] Invalid excluded_alarm_type_ids format: {excluded_alarm_type_ids_str}")

            fetch_config_msg = (
                f"[SOCRadar] Fetch config - max_fetch: {max_fetch}, "
                f"first_fetch: {params.get('first_fetch')}, "
                f"fetch_interval: {fetch_interval_minutes} minutes"
            )
            demisto.debug(fetch_config_msg)

            filter_config_msg = (
                f"[SOCRadar] Fetch config - alarm_type_ids: {alarm_type_ids}, "
                f"excluded_alarm_type_ids: {excluded_alarm_type_ids}"
            )
            demisto.debug(filter_config_msg)

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_fetch,
                last_run=demisto.getLastRun(),
                first_fetch_time=params.get("first_fetch", "3 days"),
                fetch_interval_minutes=fetch_interval_minutes,
                status=argToList(params.get("status")),
                severities=argToList(params.get("severities")),
                alarm_main_types=argToList(params.get("alarm_main_types")),
                alarm_sub_types=argToList(params.get("alarm_sub_types")),
                alarm_type_ids=alarm_type_ids,
                excluded_alarm_type_ids=excluded_alarm_type_ids,
            )

            demisto.debug(f"[SOCRadar] Setting last run to: {next_run}")
            demisto.debug(f"[SOCRadar] Returning {len(incidents)} incidents")

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
        elif command == "socradar-test-fetch":
            return_results(test_fetch_command(client, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        error_message = f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        demisto.error(traceback.format_exc())
        return_error(error_message)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
