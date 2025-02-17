from datetime import datetime, UTC
import json
from math import floor
from typing import Any
from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa: F401
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from datadog_api_client.v1.api.events_api import EventsApi
from datadog_api_client.v1.model.event_alert_type import EventAlertType
from datadog_api_client.v1.model.event_create_request import EventCreateRequest
from datadog_api_client.v1.model.event_priority import EventPriority
from datadog_api_client.v1.api.tags_api import TagsApi
from datadog_api_client.v1.model.host_tags import HostTags
from datadog_api_client.v1.api.metrics_api import MetricsApi
from datadog_api_client.v1.model.metric_metadata import MetricMetadata
from datadog_api_client.v2.api.incidents_api import IncidentsApi
from datadog_api_client.v2.model.incident_create_attributes import (
    IncidentCreateAttributes,
)
from datadog_api_client.v2.model.incident_create_data import IncidentCreateData
from datadog_api_client.v2.model.incident_create_request import IncidentCreateRequest
from datadog_api_client.v2.model.incident_field_attributes_single_value import (
    IncidentFieldAttributesSingleValue,
)
from datadog_api_client.v2.model.incident_field_attributes_single_value_type import (
    IncidentFieldAttributesSingleValueType,
)
from datadog_api_client.v2.model.incident_type import IncidentType
from datadog_api_client.v2.model.incident_notification_handle import (
    IncidentNotificationHandle,
)
from datadog_api_client.v2.model.incident_timeline_cell_create_attributes import (
    IncidentTimelineCellCreateAttributes,
)
from datadog_api_client.v2.model.incident_timeline_cell_markdown_content_type import (
    IncidentTimelineCellMarkdownContentType,
)
from datadog_api_client.v2.model.incident_timeline_cell_markdown_create_attributes_content import (
    IncidentTimelineCellMarkdownCreateAttributesContent,
)
from datadog_api_client.v2.model.incident_update_data import IncidentUpdateData
from datadog_api_client.v2.model.incident_update_request import IncidentUpdateRequest
from datadog_api_client.v2.model.incident_update_attributes import (
    IncidentUpdateAttributes,
)
from datadog_api_client.v2.model.incident_search_sort_order import (
    IncidentSearchSortOrder,
)
from dateparser import parse
from urllib3 import disable_warnings
from datadog_api_client.exceptions import ForbiddenException, UnauthorizedException
from datadog_api_client.v1.model.event_list_response import EventListResponse
from datadog_api_client.v1.model.event_response import EventResponse

# Disable insecure warnings
disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
UI_DATE_FORMAT = "%B %d, %Y %I:%M %p"
DEFAULT_OFFSET = 0
DEFAULT_PAGE_SIZE = 50
PAGE_NUMBER_ERROR_MSG = "Invalid Input Error: page number should be greater than zero."
PAGE_SIZE_ERROR_MSG = "Invalid Input Error: page size should be greater than zero."
DEFAULT_FROM_DATE = "-7days"
DEFAULT_TO_DATE = "now"
INTEGRATION_CONTEXT_NAME = "Datadog"
HOUR_SECONDS = 3600
NO_RESULTS_FROM_API_MSG = "API didn't return any results for given search parameters."
ERROR_MSG = "Something went wrong!\n"
DATE_ERROR_MSG = "Unable to parse date. Please check help section for right format."
URL_SEARCH_INCIDENTS = "https://api.datadoghq.com/api/v2/incidents/search"
AUTHENTICATION_ERROR_MSG = "Authentication Error: Invalid API Key. Make sure API Key and Server URL are correct."


# """ HELPER FUNCTIONS """


def get_paginated_results(results: list, offset: int, limit: int) -> list:
    """
    Results for pagination.
    Args:
        results: List of results.
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    Returns:
        Paginated results list.
    """
    return results[offset:offset + limit]


def table_header(
    sub_context: str, page: int | None, page_size: int | None
) -> str:
    """
    The header for table with pagination.
    Args:
        sub_context: Commands sub_context
        page: The page number.
        page_size: The number of requested results per page.
    Returns:
        Returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        return (
            f"{sub_context} List\nCurrent page size: {page_size}\n"
            f"Showing page {page} out of others that may exist"
        )

    return sub_context


def is_within_time(timestamp: int, time: int = 18) -> bool:
    """
    Check if a given Unix timestamp is within the time.

    Args:
        timestamp (int): A Unix timestamp(in seconds).
        time (int): Time in hours.

    Returns:
        bool: True if the given timestamp is within the time, False otherwise.
    """
    current_time = datetime.now()
    timestamp_time = datetime.fromtimestamp(timestamp)
    time_diff = current_time - timestamp_time
    time_diff_hours = time_diff.total_seconds() / HOUR_SECONDS
    return time_diff_hours <= time


def lookup_to_markdown(results: list[dict], title: str) -> str:
    """
    Convert a list of dictionaries to a Markdown table.

    Args:
        results (List[Dict]): A list of dictionaries representing the lookup results.
        title (str): The title of the Markdown table.

    Returns:
        str: A string containing the Markdown table.

    """
    headers = results[0] if results else {}
    return tableToMarkdown(
        title, results, headers=list(headers.keys()), removeNull=True
    )


def event_for_lookup(event: dict) -> dict:
    """
    Returns a dictionary with selected event information.

    Args:
        event (Dict): A dictionary representing an event.

    Returns:
        Dict: A dictionary containing the following keys.
    """
    return {
        "Title": event.get("title"),
        "Text": event.get("text"),
        "Date Happened": datetime.utcfromtimestamp(
            event.get("date_happened", 0)
        ).strftime(UI_DATE_FORMAT),
        "Id": event.get("id"),
        "Priority": event.get("priority"),
        "Source": event.get("source"),
        "Tags": ",".join(tag for tag in event.get("tags", []))
        if event.get("tags")
        else None,
        "Is Aggregate": event.get("is_aggregate"),
        "Host": event.get("host"),
        "Device Name": event.get("device_name"),
        "Alert Type": event.get("alert_type"),
        "Related Event ID": event.get("related_event_id"),
    }


def incident_for_lookup(incident: dict) -> dict:
    """
    Returns a dictionary with selected incident information.

    Args:
        incident (Dict): A dictionary representing an incident.

    Returns:`
        Dict: A dictionary containing the following keys.
    """
    return {
        "ID": str(incident.get("id")),
        "Title": str(incident.get("attributes", {}).get("title", "")),
        "Created": datetime.fromisoformat(
            incident.get("attributes", {}).get("created", "")
        ).strftime(UI_DATE_FORMAT)
        if incident.get("attributes", {}).get("created", "")
        else "",
        "Customer Impacted": str(
            incident.get("attributes", {}).get("customer_impacted", "")
        ),
        "Customer Impact Duration": str(
            incident.get("attributes", {}).get("customer_impact_duration", "")
        ),
        "Customer Impact Scope": str(
            incident.get("attributes", {}).get("customer_impact_scope", "")
        ),
        "Customer Impact Start": datetime.fromisoformat(
            incident.get("attributes", {}).get("customer_impact_start", "")
        ).strftime(UI_DATE_FORMAT)
        if incident.get("attributes", {}).get("customer_impact_start", "")
        else "",
        "Customer Impact End": datetime.fromisoformat(
            incident.get("attributes", {}).get("customer_impact_end", "")
        ).strftime(UI_DATE_FORMAT)
        if incident.get("attributes", {}).get("customer_impact_end", "")
        else "",
        "Detected": datetime.fromisoformat(
            incident.get("attributes", {}).get("detected", "")
        ).strftime(UI_DATE_FORMAT)
        if incident.get("attributes", {}).get("detected", "")
        else "",
        "Resolved": str(incident.get("attributes", {}).get("resolved", "")),
        "Time to Detect": str(incident.get("attributes", {}).get("time_to_detect", "")),
        "Time to Internal Response": str(
            incident.get("attributes", {}).get("time_to_internal_response", "")
        ),
        "Time to Repair": str(incident.get("attributes", {}).get("time_to_repair", "")),
        "Time to Resolve": str(
            incident.get("attributes", {}).get("time_to_resolve", "")
        ),
        "Severity": str(
            incident.get("attributes", {})
            .get("fields", {})
            .get("severity", {})
            .get("value", "")
        ),
        "State": str(
            incident.get("attributes", {})
            .get("fields", {})
            .get("state", {})
            .get("value", "")
        ),
        "Detection Method": str(
            incident.get("attributes", {})
            .get("fields", {})
            .get("detection_method", {})
            .get("value", "")
        ),
        "Root Cause": str(
            incident.get("attributes", {})
            .get("fields", {})
            .get("root_cause", {})
            .get("value", "")
        ),
        "Summary": str(
            incident.get("attributes", {})
            .get("fields", {})
            .get("summary", {})
            .get("value", "")
        ),
        "Notification Display Name": str(
            incident.get("attributes", {})
            .get("notification_handles")[0]
            .get("display_name")
        )
        if incident.get("attributes", {}).get("notification_handles")
        else None,
        "Notification Handle": str(
            incident.get("attributes", {}).get("notification_handles")[0].get("handle")
        )
        if incident.get("attributes", {}).get("notification_handles")
        else None,
    }


def pagination(
    limit: int | None, page: int | None, page_size: int | None
) -> tuple[int, int]:
    """
    Define pagination.
    Args:
        page: The page number.
        page_size: The number of requested results per page.
        limit: The number of requested results limit per page.
    Returns:
        limit (int): Records per page.
        offset (int): The number of records to be skipped.
    """
    if page and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    if page_size and limit:
        limit = page_size
    page = page - 1 if page else DEFAULT_OFFSET
    page_size = page_size or DEFAULT_PAGE_SIZE

    limit = limit or page_size or DEFAULT_PAGE_SIZE
    offset = page * page_size

    return limit, offset


def metric_command_results(
    results: Any, metric_name: str
) -> CommandResults | DemistoException:
    """
    Helper function that returns CommandResults with list of metric data for lookup table.

    Args:
        results: List of metric data.
        metric_name: The name of the metric.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
            outputs key field, and outputs data.
    """
    if results:
        results = results.to_dict()
        results["metric_name"] = metric_name
        lookup_data = {
            "Metric Name": metric_name,
            "Description": results.get("description"),
            "Integration": results.get("integration"),
            "Per Unit": results.get("per_unit"),
            "Short Name": results.get("short_name"),
            "StatusD Interval": results.get("statsd_interval"),
            "Type": results.get("type"),
            "Unit": results.get("unit"),
        }
        readable_output = lookup_to_markdown(
            [lookup_data], table_header("Metric Metadata Details", None, None)
        )
    else:
        readable_output = NO_RESULTS_FROM_API_MSG
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.MetricMetadata",
        outputs_key_field="description",
        outputs=results if results else [],
    )


def convert_datetime_to_str(data: dict) -> dict:
    """
    Converts any datetime objects found in the input dictionary to ISO-formatted strings.

    Args:
        data (Dict): The input dictionary to be converted.

    Returns:
        Dict: A new dictionary with the same structure as the input dictionary, but with datetime objects
        replaced by ISO-formatted strings.
    """
    for key, value in data.items():
        if isinstance(value, dict):
            convert_datetime_to_str(value)
        elif isinstance(value, datetime):
            data[key] = add_utc_offset(value.strftime("%Y-%m-%dT%H:%M:%S"))
    return data


def tags_context_and_readable_output(tags: HostTags) -> tuple:
    """
    Returns Context output and lookup data for Tags.

    Args:
        tags (Dict): The input tags dictionary.
    """
    return {"Tag": tags.get("tags"), "Hostname": tags.get("host")}, lookup_to_markdown(
        [{"Host Name": tags.get("host"), "Tag": tags.get("tags")}], "Host Tags Details"
    )


""" COMMAND FUNCTIONS """


def module_test(configuration: Configuration) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    with ApiClient(configuration) as api_client:
        # Testing api key
        try:
            api_instance = AuthenticationApi(api_client)
            api_instance.validate()
        except Exception:
            return AUTHENTICATION_ERROR_MSG
        # Testing application key
        try:
            events_api = EventsApi(api_client)
            start_time = parse("1 min ago", settings={"TIMEZONE": "UTC"})
            end_time = parse(DEFAULT_TO_DATE, settings={"TIMEZONE": "UTC"})
            events_api.list_events(
                start=int(start_time.timestamp() if start_time else 0),
                end=int(end_time.timestamp() if end_time else 0),
            )
        except Exception:
            return "Authentication Error: Invalid Application Key."
        return "ok"


def create_event_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Creates an event in Datadog.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (Dict[str, Any]): A dictionary of arguments for creating the event.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    priority = args.get("priority")
    alert_type = args.get("alert_type")
    if priority and priority not in EventPriority.allowed_values:
        return DemistoException("Priority not in allowed values.")
    if alert_type and alert_type not in EventAlertType.allowed_values:
        return DemistoException("Alert type not in allowed values.")
    date_happened = args.get("date_happened")

    if date_happened:
        date_happened_timestamp = parse(date_happened, settings={"TIMEZONE": "UTC"})
        if not is_within_time(
            int(date_happened_timestamp.timestamp() if date_happened_timestamp else 0)
        ):
            return CommandResults(
                readable_output="The time of the event cannot be older than 18 hours!\n"
            )
    date_happened = (
        parse(date_happened, settings={"TIMEZONE": "UTC"}) if date_happened else None
    )
    event_body = {
        "title": args.get("title"),
        "text": args.get("text"),
        "tags": args.get("tags", []).split(",") if args.get("tags") else None,
        "alert_type": EventAlertType(args.get("alert_type")),
        "priority": EventPriority(args.get("priority")),
        "aggregation_key": args.get("aggregation_key"),
        "related_event_id": int(args.get("related_event_id", 0))
        if args.get("related_event_id")
        else None,
        "host": args.get("host_name"),
        "device_name": args.get("device_name"),
        "date_happened": int(date_happened.timestamp()) if date_happened else None,
        "source_type_name": args.get("source_type_name"),
    }
    body = EventCreateRequest(
        **{key: value for key, value in event_body.items() if value is not None}  # type: ignore[arg-type]
    )

    with ApiClient(configuration) as api_client:
        api_instance = EventsApi(api_client)
        response = api_instance.create_event(body=body)
        results = response.to_dict()
        event_lookup_data = event_for_lookup(results.get("event"))
        readable_output = lookup_to_markdown([event_lookup_data], "Event Details")
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Event",
            outputs_key_field="id",
            outputs=results if response and response.status == "ok" else {},
        )


def get_events_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    List or get details of events from Datadog.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (Dict[str, Any]): The dictionary containing the arguments passed to the command.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
            outputs key field, and outputs data.
    """
    with ApiClient(configuration) as api_client:
        api_instance = EventsApi(api_client)

        if args.get("event_id"):
            event_response: EventResponse = api_instance.get_event(
                event_id=int(args["event_id"]),
            )
            data = event_response.get("event", {})
            if data:
                data = data.to_dict()
                event_results = [event_for_lookup(data)]
                readable_output = lookup_to_markdown(event_results, "Event Details")
            else:
                readable_output = "No event to present.\n"

        else:
            start_time = parse(
                args.get("start_date", DEFAULT_FROM_DATE), settings={"TIMEZONE": "UTC"}
            )
            end_time = parse(
                args.get("end_date", DEFAULT_TO_DATE), settings={"TIMEZONE": "UTC"}
            )
            page = arg_to_number(args.get("page"), arg_name="page")
            page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
            limit = arg_to_number(args.get("limit"), arg_name="limit")
            limit, offset = pagination(limit, page, page_size)
            datadog_page = floor(offset / 1000) if offset / 1000 > 1 else None
            body_dict = {
                "start": int(start_time.timestamp() if start_time else 0),
                "end": int(end_time.timestamp() if end_time else 0),
                "priority": args.get("priority"),
                "sources": args.get("sources"),
                "tags": args.get("tags"),
                "unaggregated": argToBoolean(args.get("unaggregated"))
                if args.get("unaggregated")
                else None,
                "exclude_aggregate": argToBoolean(args.get("exclude_aggregate"))
                if args.get("exclude_aggregate")
                else None,
                "page": datadog_page,
            }
            event_list_response: EventListResponse = api_instance.list_events(
                **{key: value for key, value in body_dict.items() if value is not None}  # type: ignore[arg-type]
            )
            results = event_list_response.get("events", [])
            resp = get_paginated_results(results, offset, limit)
            data = [event.to_dict() for event in resp]
            if data:
                events_list = [event_for_lookup(event) for event in data]
                readable_output = lookup_to_markdown(
                    events_list, table_header("Events List", page, page_size)
                )
            else:
                readable_output = NO_RESULTS_FROM_API_MSG
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Event",
            outputs_key_field="id",
            outputs=data,
        )


def get_tags_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Retrieve a list of tags, and paginate them according to the specified page, page size, and limit parameters.
    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (dict): A dictionary containing the command arguments, including:
            - page (int): The page number of the results to retrieve.
            - page_size (int): The number of results per page.
            - limit (int): The maximum number of results to return.
            - source (str): The source of the tags to retrieve.
    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get("limit"), arg_name="limit")
    limit, offset = pagination(limit, page, page_size)
    source = args.get("source")
    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = (
            tags_api.list_host_tags()
            if not source
            else tags_api.list_host_tags(source=source)
        )
        results = response.get("tags", {})
        if results:
            tags_list = [{"Tag": k, "Hostname": v} for k, v in results.items()]
            tags_list = get_paginated_results(tags_list, offset, limit)
            lookup_data = [
                {"Tag": tags["Tag"], "Host Name": tags["Hostname"]}
                for tags in tags_list
            ]
            readable_output = lookup_to_markdown(
                lookup_data, table_header("Tags List", page, page_size)
            )
        else:
            readable_output = NO_RESULTS_FROM_API_MSG
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=INTEGRATION_CONTEXT_NAME,
            outputs_key_field="Tag",
            outputs=tags_list if results else [],
        )


def get_host_tags_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
     Retrieves the tags for a given host name and optional source.

      Args:
        configuration (Configuration): The configuration object for Datadog.
        args (dict): A dictionary containing the command arguments, including:
            - host_name (str): The name of the host to retrieve tags for.
            - page (int): The page number of the results to retrieve.
            - page_size (int): The number of results per page.
            - limit (int): The maximum number of results to return.
            - source (str): The source of the tags to retrieve.
    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    host_name = args.get("host_name")
    source = args.get("source")
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get("limit"), arg_name="limit")
    limit, offset = pagination(limit, page, page_size)
    context_output: dict = {}
    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = (
            tags_api.get_host_tags(host_name=str(host_name))
            if not source
            else tags_api.get_host_tags(host_name=str(host_name), source=source)
        )
        tags = response.get("tags", [])
    if tags:
        host_tags_list = get_paginated_results(
            [{"Tags": tag} for tag in tags], offset, limit
        )
        host_tags = [obj.get("Tags") for obj in host_tags_list]
        context_output = {"Tag": host_tags, "Hostname": host_name}
        readable_output = lookup_to_markdown(
            host_tags_list, table_header("Host Tags List", page, page_size)
        )
    else:
        readable_output = NO_RESULTS_FROM_API_MSG

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=INTEGRATION_CONTEXT_NAME,
        outputs_key_field="Tag",
        outputs=context_output if tags else [],
    )


def add_tags_to_host_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
     This function adds tags to a specified host in Datadog.

     Args:
     configuration (Configuration): The configuration object for Datadog.
     args (Dict[str, Any]): A dictionary containing the following keys:
     - host_name (str): The name of the host to add tags to.
     - tags (str or List[str]): The tags to add to the host, separated by commas or provided as a list.

    Returns:
     CommandResults: The object containing the command results, including the readable output, outputs prefix,
      outputs key field, and outputs data.
    """
    host_name = args.get("host_name")
    tags = argToList(args.get("tags"), ",")

    body = HostTags(host=str(host_name), tags=tags)

    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = tags_api.create_host_tags(host_name=str(host_name), body=body)
        output_context, readable_output = tags_context_and_readable_output(response)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=INTEGRATION_CONTEXT_NAME,
        outputs_key_field="Tag",
        outputs=output_context if response and response.get("host") else [],
    )


def update_host_tags_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    This function updates the tags of a specified host in Datadog.

    Args:
     configuration (Configuration): The configuration object for Datadog.
     args (Dict[str, Any]): A dictionary containing the following keys:
    - host_name (str): The name of the host to update tags for.
    - tags (str or List[str]): The new tags to set for the host, separated by commas or provided as a list.

    Returns:
    CommandResults: The object containing the command results, including the readable output, outputs prefix,
     outputs key field, and outputs data.

    """
    host_name = args.get("host_name")
    tags = argToList(args.get("tags"), ",")

    body = HostTags(host=str(host_name), tags=tags)

    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = tags_api.update_host_tags(host_name=str(host_name), body=body)
        output_context, readable_output = tags_context_and_readable_output(response)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}",
        outputs_key_field="Tag",
        outputs=output_context if response and response.get("host") else [],
    )


def delete_host_tags_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Deletes all tags associated with the specified host name.

    Args:
     configuration (Configuration): The configuration object for Datadog.
     args: A dictionary of arguments for the command, containing:
        - host_name (str): The name of the host to delete tags from.

    Returns:
        A CommandResults object containing the following fields:
            - readable_output (str): A message indicating that the host tags were deleted successfully.
    """
    host_name = args.get("host_name")
    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        tags_api.delete_host_tags(host_name=str(host_name))
        readable_output = "### Host tags deleted successfully!\n"
    return CommandResults(readable_output=readable_output)


def active_metrics_list_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Get a list of active metrics from the API and return them in a paginated format.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args: A dictionary of arguments for the command, including:
            - from: A string representing a UTC timestamp for the start time of the metric data.
            - host_name: A string representing the hostname to filter metrics by.
            - tag_filter: A string representing a filter expression for metric tags.
            - page (int): The page number of the results to retrieve.
            - page_size (int): The number of results per page.
            - limit (int): The maximum number of results to return.

    Returns:
     CommandResults: The object containing the command results, including the readable output, outputs prefix,
      outputs key field, and outputs data.

    """
    from_timestamp: datetime | None = None
    from_arg: str | None = args.get("from")
    if from_arg:
        from_timestamp = parse(
            from_arg, settings={"TIMEZONE": "UTC"}
        )
    if not from_timestamp:
        return DemistoException(DATE_ERROR_MSG)
    search_params = {
        "_from": int(from_timestamp.timestamp()) if from_timestamp else None,
        "host": args.get("host_name"),
        "tag_filter": args.get("tag_filter"),
    }
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get("limit"), arg_name="limit")
    limit, offset = pagination(limit, page, page_size)
    context_output: dict = {}
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.list_active_metrics(
            **{key: value for key, value in search_params.items() if value}  # type: ignore
        )
        if response:
            results = response.to_dict()
            metrics_list = results.get("metrics")
            paginated_results = get_paginated_results(metrics_list, offset, limit)
            lookup_metric_list = {
                "From": datetime.utcfromtimestamp(
                    int(results.get("_from", 0))
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "Metric Name": paginated_results,
            }

            context_output = {
                "Metric.from": results.get("_from"),
                "Metric": paginated_results,
            }
            readable_output = lookup_to_markdown(
                [lookup_metric_list],
                table_header("Active Metric List", page, page_size),
            )
        else:
            readable_output = NO_RESULTS_FROM_API_MSG
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=INTEGRATION_CONTEXT_NAME,
            outputs_key_field="Metric",
            outputs=context_output if response else [],
        )


def metrics_search_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Search for metrics that match a given query and return them in a formatted table.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args: A dictionary of arguments for the command, including:
            - query: A string representing the query to search for.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.

    """
    query = args.get("query")
    context_output: dict = {}
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.list_metrics(
            q=str(query),
        )
        if response and response.results:
            results = response.to_dict()
            table_lookup_data = {"Metric Name": results.get("results").get("metrics")}
            context_output = {"metric_name": results.get("results").get("metrics")}
            readable_output = lookup_to_markdown(
                [table_lookup_data], table_header("Metrics Search List", None, None)
            )
        else:
            readable_output = NO_RESULTS_FROM_API_MSG
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Metric",
            outputs_key_field="Metric",
            outputs=context_output if response and response.results else [],
        )


def get_metric_metadata_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Get the metadata for a specific metric and return it in a formatted table.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args: A dictionary of arguments for the command, including:
            - metric_name: A string representing the name of the metric to retrieve metadata for.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    metric_name = str(args.get("metric_name"))
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.get_metric_metadata(
            metric_name=metric_name,
        )
        return metric_command_results(response, metric_name)


def update_metric_metadata_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Update the metadata of a metric with the specified parameters.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (Dict[str, Any]): A dictionary containing the arguments for the command.

            - metric_name (str): The name of the metric to be updated.
            - description (str, optional): The description of the metric.
            - per_unit (str, optional): The per-unit value of the metric.
            - short_name (str, optional): The short name of the metric.
            - statsd_interval (int, optional): The interval in seconds for sending data to StatsD.
            - type (str, optional): The type of the metric.
            - unit (str, optional): The unit of the metric.

     Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    metric_name = str(args.get("metric_name"))
    params = {
        "description": args.get("description"),
        "per_unit": args.get("per_unit"),
        "short_name": args.get("short_name"),
        "statsd_interval": int(args.get("statsd_interval", 0))
        if args.get("statsd_interval")
        else None,
        "type": args.get("type"),
        "unit": args.get("unit"),
    }

    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.update_metric_metadata(
            metric_name=metric_name,
            body=MetricMetadata(
                **{key: value for key, value in params.items() if value}  # type: ignore
            ),
        )
        return metric_command_results(response, metric_name)


def create_incident_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Creates an incident in Datadog.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (Dict[str, Any]): A dictionary of arguments for creating the incident.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    customer_impacted = False
    title = args.get("title")
    content = args.get("content")
    detection_method = args.get("detection_method")
    display_name = args.get("display_name")
    handle = args.get("handle")
    important = argToBoolean(args.get("important", False))
    root_cause = args.get("root_cause")
    severity = args.get("severity")
    state = args.get("state")
    summary = args.get("summary")
    body = IncidentCreateRequest(
        data=IncidentCreateData(
            type=IncidentType.INCIDENTS,
            attributes=IncidentCreateAttributes(
                title=str(title),
                customer_impacted=customer_impacted,
                fields={
                    "state": IncidentFieldAttributesSingleValue(
                        type=IncidentFieldAttributesSingleValueType.DROPDOWN,
                        value=state,
                    ),
                    "severity": IncidentFieldAttributesSingleValue(
                        type=IncidentFieldAttributesSingleValueType.DROPDOWN,
                        value=severity,
                    ),
                    "detection_method": IncidentFieldAttributesSingleValue(
                        type=IncidentFieldAttributesSingleValueType.DROPDOWN,
                        value=detection_method,
                    ),
                    "root_cause": IncidentFieldAttributesSingleValue(
                        type=IncidentFieldAttributesSingleValueType.TEXTBOX,
                        value=root_cause,
                    ),
                    "summary": IncidentFieldAttributesSingleValue(
                        type=IncidentFieldAttributesSingleValueType.TEXTBOX,
                        value=summary,
                    ),
                },
                notification_handles=[
                    IncidentNotificationHandle(display_name=display_name, handle=handle)  # type: ignore
                ],
                initial_cells=[
                    IncidentTimelineCellCreateAttributes(
                        cell_type=IncidentTimelineCellMarkdownContentType(
                            value="markdown"
                        ),
                        content=IncidentTimelineCellMarkdownCreateAttributesContent(
                            content=content
                        ),
                        important=important,
                    )
                ]
                if content
                else [],
            ),
        ),
    )
    configuration.unstable_operations["create_incident"] = True
    with ApiClient(configuration) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.create_incident(body=body)
        results = response.to_dict()
        formatted_data = convert_datetime_to_str(results.get("data"))
        if results.get("included"):
            formatted_data["included"] = results.get("included")
        incident_lookup_data = [incident_for_lookup(formatted_data)]
        readable_output = lookup_to_markdown(incident_lookup_data, "Incident Details")
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Incident",
            outputs_key_field="id",
            outputs=formatted_data if results else {},
        )


def update_incident_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Updates incident associated with the specified ID.

    Args:
     configuration (Configuration): The configuration object for Datadog.
     args: A dictionary of arguments for the command.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
         outputs key field, and outputs data.
    """
    if (
        args.get("customer_impact_start")
        or args.get("customer_impact_end")
        or args.get("customer_impact_scope")
    ):
        if args.get("customer_impact_scope") and not args.get("customer_impact_start"):
            return DemistoException("Customer Impact Start is required.")
        if not args.get("customer_impact_scope"):
            return DemistoException("Customer Impact Scope is required.")
    incident_id = args.get("incident_id")
    detection_method = args.get("detection_method")
    root_cause = args.get("root_cause")
    severity = args.get("severity")
    state = args.get("state")
    summary = args.get("summary")
    incident_attributes = {
        "title": args.get("title"),
        "customer_impacted": False,
        "detected": parse(str(args.get("detected")), settings={"TIMEZONE": "UTC"})
        if args.get("detected")
        else None,
        "customer_impact_scope": args.get("customer_impact_scope"),
        "customer_impact_start": parse(
            str(args.get("customer_impact_start")), settings={"TIMEZONE": "UTC"}
        )
        if args.get("customer_impact_start")
        else None,
        "customer_impact_end": parse(
            str(args.get("customer_impact_end")), settings={"TIMEZONE": "UTC"}
        )
        if args.get("customer_impact_end")
        else None,
    }
    incident_fields = {
        "state": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=state,
        )
        if state
        else None,
        "severity": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=severity,
        )
        if severity
        else None,
        "detection_method": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.DROPDOWN,
            value=detection_method,
        )
        if detection_method
        else None,
        "root_cause": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.TEXTBOX,
            value=root_cause,
        )
        if root_cause
        else None,
        "summary": IncidentFieldAttributesSingleValue(
            type=IncidentFieldAttributesSingleValueType.TEXTBOX,
            value=summary,
        )
        if summary
        else None,
    }
    body = IncidentUpdateRequest(
        data=IncidentUpdateData(
            id=str(incident_id),
            type=IncidentType.INCIDENTS,
            attributes=IncidentUpdateAttributes(
                **{  # type: ignore[arg-type]
                    key: value
                    for key, value in incident_attributes.items()
                    if value is not None
                },
                fields=dict(
                    **{key: value for key, value in incident_fields.items() if value},
                ),
            ),
        ),
    )

    configuration.unstable_operations["update_incident"] = True
    with ApiClient(configuration) as api_client:
        api_instance = IncidentsApi(api_client)
        response = api_instance.update_incident(incident_id=str(incident_id), body=body)
        results = response.to_dict()
        formatted_data = convert_datetime_to_str(results.get("data"))
        if results.get("included"):
            formatted_data["included"] = results.get("included")
        incident_lookup_data = [incident_for_lookup(formatted_data)]
        readable_output = lookup_to_markdown(incident_lookup_data, "Incident Details")
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Incident",
            outputs_key_field="id",
            outputs=formatted_data if results else {},
        )


def delete_incident_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    """
    Deletes incident with the specified ID.

    Args:
     configuration (Configuration): The configuration object for Datadog.
     args: A dictionary of arguments for the command, containing:
        - incident_id (str): The ID of the incident to delete.

    Returns:
        A CommandResults object containing the following fields:
            - readable_output (str): A message indicating that the incident was deleted successfully.
    """
    configuration.unstable_operations["delete_incident"] = True
    with ApiClient(configuration) as api_client:
        api_instance = IncidentsApi(api_client)
        api_instance.delete_incident(
            incident_id=str(args.get("incident_id")),
        )
        return CommandResults(readable_output="### Incident deleted successfully!\n")


def get_incident_command(
    configuration: Configuration, args: dict[str, Any]
) -> CommandResults | DemistoException:
    incident_id = args.get("incident_id")
    with ApiClient(configuration) as api_client:
        api_instance = IncidentsApi(api_client)
        if incident_id:
            configuration.unstable_operations["get_incident"] = True
            incident_response = api_instance.get_incident(
                incident_id=incident_id,
            )
            results = incident_response.to_dict()
            data = results.get("data", {})
            if data:
                data = convert_datetime_to_str(data)
                incident_lookup = incident_for_lookup(data)
                readable_output = lookup_to_markdown(
                    [incident_lookup], "Incident Details"
                )
            else:
                readable_output = "No incident to present.\n"
        else:
            sort = args.get("sort", "asc")
            sort_data = {"asc": "created", "desc": "-created"}
            page = arg_to_number(args.get("page"), arg_name="page")
            page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
            limit = arg_to_number(args.get("limit"), arg_name="limit")
            limit, offset = pagination(limit, page, page_size)
            query = incident_serach_query(args)
            configuration.unstable_operations["search_incidents"] = True
            incident_list_response = api_instance.search_incidents(
                query=query if query else "state:(active OR stable OR resolved)",
                sort=IncidentSearchSortOrder(sort_data[sort]),
                page_size=limit,
                page_offset=offset,
            )
            results = incident_list_response.to_dict()
            data = results.get("data", {}).get("attributes", {}).get("incidents", [])
            data = [convert_datetime_to_str(incident.get("data")) for incident in data]
            lookup_data = [incident_for_lookup(obj) for obj in data]
            readable_output = lookup_to_markdown(lookup_data, "Incidents List")
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Incident",
        outputs_key_field="id",
        outputs=data,
    )


def incident_serach_query(args: dict) -> str:
    query = ""
    if args.get("state"):
        query += f"state:{args.get('state')}"
    if args.get("severity"):
        query += (
            f" AND severity:{args.get('severity')}"
            if len(query)
            else f"severity:{args.get('severity')}"
        )
    if args.get("customer_impacted"):
        query += (
            f" AND customer_impacted:{args.get('customer_impacted', '').lower()}"
            if len(query)
            else f"customer_impacted:{args.get('customer_impacted', '').lower()}"
        )
    if args.get("detection_method"):
        query += (
            f" AND detection_method:{args.get('detection_method')}"
            if len(query)
            else f"detection_method:{args.get('detection_method')}"
        )
    if not query:
        query = "state:(active OR stable OR resolved)"
    return query


def query_timeseries_points_command(configuration: Configuration, args: dict[str, Any]):
    query = str(args.get("query"))
    from_time = parse(args.get("from", ""), settings={"TIMEZONE": "UTC"})
    to_time = parse(args.get("to", ""), settings={"TIMEZONE": "UTC"})
    if not from_time or not to_time:
        return DemistoException(DATE_ERROR_MSG)
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.query_metrics(
            _from=int(from_time.timestamp()) if from_time else 0,
            to=int(to_time.timestamp()) if to_time else 0,
            query=query + "{*}",
        )

        return [
            CommandResults(
                readable_output="### Query Timeseries Points \n",
                outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.TimeSeriesPoint",
                outputs=response.to_dict(),
            ),
            fileResult(
                filename="timeseries_query_points.json",
                data=str(response),
                file_type=EntryType.ENTRY_INFO_FILE,
            ),
        ]


def fetch_incidents(configuration: Configuration, params: dict):
    first_fetch_time = params.get("first_fetch", "3 days")
    fetch_limit = params.get("max_fetch", 50)
    first_fetch_time = dateparser.parse(f"-{first_fetch_time}")
    last_run = demisto.getLastRun()
    with ApiClient(configuration) as api_client:
        incidents = []
        api_instance = IncidentsApi(api_client)
        configuration.unstable_operations["search_incidents"] = True

        response = api_instance.search_incidents(
            query=incident_serach_query({}),
            page_size=int(fetch_limit) if int(fetch_limit) < 200 else 200,
            sort=IncidentSearchSortOrder("-created"),
        )
        results = response.to_dict()
        data = results.get("data", {}).get("attributes", {}).get("incidents", [])
        data = [convert_datetime_to_str(incident.get("data")) for incident in data]
        data_list = [
            incident
            for incident in data
            if (
                datetime.fromisoformat(incident["attributes"]["modified"])
                .replace(tzinfo=None)
                .timestamp()
                > datetime.fromisoformat(last_run.get("lastRun")).timestamp()
                if last_run.get("lastRun")
                else first_fetch_time.timestamp()
                if first_fetch_time
                else None
            )
        ]
        for obj in data_list:
            new_obj = obj["attributes"]
            new_obj["type"] = obj["type"]
            new_obj["detected"] = datetime.fromisoformat(
                obj["attributes"]["detected"]
            ).strftime(UI_DATE_FORMAT)
            new_obj["relationships"] = obj["relationships"]
            new_obj["id"] = obj["id"]
            new_obj["detection_method"] = obj["attributes"]["fields"][
                "detection_method"
            ]["value"]
            new_obj["root_cause"] = obj["attributes"]["fields"]["root_cause"]["value"]
            new_obj["summary"] = obj["attributes"]["fields"]["summary"]["value"]
            new_obj["notification_display_name"] = (
                obj["attributes"]["notification_handles"][0]["display_name"]
                if obj["attributes"]["notification_handles"]
                else None
            )
            new_obj["notification_handle"] = (
                obj["attributes"]["notification_handles"][0]["handle"]
                if obj["attributes"]["notification_handles"]
                else None
            )
            incident = {
                "name": obj["attributes"]["title"],
                "occurred": obj["attributes"]["modified"],
                "dbotMirrorId": obj["id"],
                "rawJSON": json.dumps({"incidents": new_obj}),
                "type": "Datadog Cloud SIEM",
            }
            incidents.append(incident)
        if data_list:
            demisto.setLastRun(
                {"lastRun": data_list[0].get("attributes", {}).get("modified", "")}
            )
    demisto.incidents(incidents)
    return "OK"


def add_utc_offset(dt_str: str):
    """
    Converts a datetime string in ISO format to the equivalent datetime object
    with a UTC offset, and returns the resulting datetime string in ISO format.

    Args:
        dt_str (str): A string representing a datetime in ISO format (YYYY-MM-DDTHH:MM:SS[.ffffff][+/-HH:MM])

    Returns:
        str: A string representing the input datetime with a UTC offset, in ISO format (YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00)
    """
    dt = datetime.fromisoformat(dt_str)
    dt_with_offset = dt.replace(tzinfo=UTC)
    return dt_with_offset.isoformat()


""" MAIN FUNCTION """


def main() -> None:
    command: str = demisto.command()
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    demisto.debug(f"Command being called is {command}")
    try:
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = params.get('api_key_creds', {}).get('password') or params.get("api_key")
        configuration.api_key["appKeyAuth"] = params.get('app_key_creds', {}).get('password') or params.get("app_key")
        configuration.server_variables["site"] = params.get("site")

        commands = {
            "datadog-event-create": create_event_command,
            "datadog-event-list": get_events_command,
            "datadog-tag-list": get_tags_command,
            "datadog-host-tag-create": add_tags_to_host_command,
            "datadog-host-tag-get": get_host_tags_command,
            "datadog-host-tag-update": update_host_tags_command,
            "datadog-host-tag-delete": delete_host_tags_command,
            "datadog-active-metric-list": active_metrics_list_command,
            "datadog-metric-search": metrics_search_command,
            "datadog-metric-metadata-get": get_metric_metadata_command,
            "datadog-metric-metadata-update": update_metric_metadata_command,
            "datadog-incident-create": create_incident_command,
            "datadog-incident-update": update_incident_command,
            "datadog-incident-delete": delete_incident_command,
            "datadog-incident-list": get_incident_command,
            "datadog-time-series-point-query": query_timeseries_points_command,
        }
        if command == "test-module":
            return_results(module_test(configuration))
        elif command == "fetch-incidents":
            return_results(fetch_incidents(configuration, params))
        elif command in commands:
            return_results(commands[command](configuration, args))
        else:
            raise NotImplementedError
    except (ForbiddenException, UnauthorizedException, Exception) as e:
        error = None
        if type(e) in (ForbiddenException, UnauthorizedException):
            error = AUTHENTICATION_ERROR_MSG
        return_error(error or f"Failed to execute {command} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
