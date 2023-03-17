from datetime import datetime
from math import floor
from typing import Any, Dict

from CommonServerPython import *  # noqa: F401 # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa: F401
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from datadog_api_client.v1.api.events_api import EventsApi
from datadog_api_client.v1.model.event import Event
from datadog_api_client.v1.model.event_alert_type import EventAlertType
from datadog_api_client.v1.model.event_create_request import EventCreateRequest
from datadog_api_client.v1.model.event_priority import EventPriority
from datadog_api_client.v1.api.tags_api import TagsApi
from datadog_api_client.v1.model.host_tags import HostTags
from datadog_api_client.v1.api.metrics_api import MetricsApi
from datadog_api_client.v1.model.metric_metadata import MetricMetadata
from dateparser import parse
from urllib3 import disable_warnings


# Disable insecure warnings
disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
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


# """ HELPER FUNCTIONS """


def get_paginated_results(results: List, offset: int, limit: int) -> List:
    return results[offset : offset + limit]


def table_header(
    sub_context: str, page: Optional[int], page_size: Optional[int]
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

    return f"{sub_context} List"


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


def lookup_to_markdown(results: List[Dict], title: str) -> str:
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


def event_for_lookup(event: Dict) -> Dict:
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
        "Date Happened": datetime.fromtimestamp(event.get("date_happened", 0)).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "Id": event.get("id"),
        "Priority": event.get("priority"),
        "Source": event.get("source"),
        "Tags": ",".join(tag for tag in event.get("tags", [])),
        "Is Aggregate": event.get("is_aggregate"),
        "Host": event.get("host"),
        "Device Name": event.get("device_name"),
        "Alert Type": event.get("alert_type"),
    }


def pagination(limit: Optional[int], page: Optional[int], page_size: Optional[int]):
    """
    Define pagination.
    Args:
        page: The page number.
        page_size: The number of requested results per page.
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


def metric_command_results(results):
    """
    Helper function that returns CommandResults with list of metric data for lookup table.

    Args:
        results: List of metric data.

    Returns:
        CommandResults: The object containing the command results, including the readable output, outputs prefix,
            outputs key field, and outputs data.
    """
    if results:
        results = results.to_dict()
        lookup_data = {
            "Description": results.get("description"),
            "Integration": results.get("integration"),
            "Per Unit": results.get("per_unit"),
            "Short Name": results.get("short_name"),
            "StatusD Interval": results.get("statsd_interval"),
            "Type": results.get("type"),
            "Unit": results.get("unit"),
        }
        readable_output = lookup_to_markdown(
            [lookup_data], table_header("Metric Metadata", None, None)
        )
    else:
        readable_output = NO_RESULTS_FROM_API_MSG
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Metric",
        outputs_key_field="description",
        outputs=results if results else [],
    )


""" COMMAND FUNCTIONS """


def test_module(configuration: Configuration) -> str:
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
            return "Authorization Error: Invalid API Key. Make sure API Key, Server URL is correctly set."
        # Testing application key
        try:
            api_instance = EventsApi(api_client)
            start_time = parse("1 min ago", settings={"TIMEZONE": "UTC"})
            end_time = parse(DEFAULT_TO_DATE, settings={"TIMEZONE": "UTC"})
            api_instance.list_events(
                start=int(start_time.timestamp() if start_time else 0),
                end=int(end_time.timestamp() if end_time else 0),
            )
        except Exception:
            return "Authorization Error: Invalid Application Key."
        return "ok"


def create_event_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
    """
    Creates an event in Datadog.

    Args:
        configuration (Configuration): The configuration object for Datadog.
        args (Dict[str, Any]): A dictionary of arguments for creating the event.

    Returns:
        CommandResults: A CommandResults object with the following properties:
        - "readable_output": A human-readable message indicating whether the event was created successfully.
        - "Event": A dictionary representing the created event.
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
        **{key: value for key, value in event_body.items() if value is not None}
    )

    with ApiClient(configuration) as api_client:
        api_instance = EventsApi(api_client)
        response = api_instance.create_event(body=body)
        readable_output = (
            "Event created successfully!"
            if response and response.status == "ok"
            else ERROR_MSG
        )
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Event",
            outputs_key_field="id",
            outputs=response.to_dict() if response and response.status == "ok" else {},
        )


def get_events_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
            response = api_instance.get_event(
                event_id=arg_to_number(args.get("event_id"), arg_name="event_id"),
            )
            data = response.get("event", {})
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
            response = api_instance.list_events(
                **{key: value for key, value in body_dict.items() if value is not None}
            )
            results: List[Event] = response.get("events", [])
            resp: List[Event] = get_paginated_results(results, offset, limit)
            data = [event.to_dict() for event in resp]
            if data:
                events_list = [event_for_lookup(event) for event in data]
                readable_output = lookup_to_markdown(
                    events_list, table_header("Events", page, page_size)
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
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
            tags_list = [{"Tag": k, "HostTag": v} for k, v in results.items()]
            tags_list = get_paginated_results(tags_list, offset, limit)
            # tags = [obj.get("Tag") for obj in tags_list]
            # context_output = {"Tag": tags}
            readable_output = lookup_to_markdown(
                tags_list, table_header("Tags", page, page_size)
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
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = (
            tags_api.get_host_tags(host_name=host_name)
            if not source
            else tags_api.get_host_tags(host_name=host_name, source=source)
        )
        tags = response.get("tags", [])
    if tags:
        host_tags_list = get_paginated_results(
            [{"Tags": tag} for tag in tags], offset, limit
        )
        host_tags = [obj.get("Tags") for obj in host_tags_list]
        context_output = {"Tag": host_tags, "HostTag": host_name}
        readable_output = lookup_to_markdown(
            host_tags_list, table_header("Host Tags", page, page_size)
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
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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

    body = HostTags(host=host_name, tags=tags)

    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = tags_api.create_host_tags(host_name=host_name, body=body)
    if response and response.get("host"):
        readable_output = "Tags added to host successfully!"
        output_context = {"Tag": response.get("tags"), "HostTag": response.get("host")}
    else:
        readable_output = ERROR_MSG

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=INTEGRATION_CONTEXT_NAME,
        outputs_key_field="Tag",
        outputs=output_context if response else [],
    )


def update_host_tags_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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

    body = HostTags(host=host_name, tags=tags)

    with ApiClient(configuration) as api_client:
        tags_api = TagsApi(api_client)
        response = tags_api.update_host_tags(host_name=host_name, body=body)

    if response and response.get("host"):
        output_context = {"Tag": response.get("tags"), "HostTag": response.get("host")}
        readable_output = "Tags updated to host successfully!"
    else:
        readable_output = ERROR_MSG

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}",
        outputs_key_field="Tag",
        outputs=output_context if response else [],
    )


def delete_host_tags_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
        tags_api.delete_host_tags(host_name=host_name)
        readable_output = "Host tags deleted successfully!"
    return CommandResults(readable_output=readable_output)


def active_metrics_list_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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

    from_arg: Optional[str] = args.get("from_date")
    if from_arg:
        from_timestamp: Optional[datetime] = parse(
            from_arg, settings={"TIMEZONE": "UTC"}
        )

    search_params = {
        "_from": int(from_timestamp.timestamp()) if from_timestamp else None,
        "host": args.get("host_name"),
        "tag_filter": args.get("tag_filter"),
    }
    page = arg_to_number(args.get("page"), arg_name="page")
    page_size = arg_to_number(args.get("page_size"), arg_name="page_size")
    limit = arg_to_number(args.get("limit"), arg_name="limit")
    limit, offset = pagination(limit, page, page_size)

    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.list_active_metrics(
            **{key: value for key, value in search_params.items() if value is not None}
        )
        if response:
            results = response.to_dict()
            metrics_list = results.get("metrics")
            paginated_results = get_paginated_results(metrics_list, offset, limit)
            lookup_metric_list = {
                "From": datetime.fromtimestamp(int(results.get("_from", 0))).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "Metrics": paginated_results,
            }

            context_output = {
                "Metric.from": results.get("_from"),
                "Metric": paginated_results,
            }
            readable_output = lookup_to_markdown(
                [lookup_metric_list], table_header("Metrics", page, page_size)
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
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.list_metrics(
            q=query,
        )
        if response and response.results:
            results = response.to_dict()
            context_output = {"Metric": results.get("results").get("metrics")}
            readable_output = lookup_to_markdown(
                [context_output], table_header("Metrics Search", None, None)
            )
        else:
            readable_output = NO_RESULTS_FROM_API_MSG
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=INTEGRATION_CONTEXT_NAME,
            outputs_key_field="Metric",
            outputs=context_output if response and response.results else [],
        )


def get_metric_metadata_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
    metric_name = args.get("metric_name")
    with ApiClient(configuration) as api_client:
        api_instance = MetricsApi(api_client)
        response = api_instance.get_metric_metadata(
            metric_name=metric_name,
        )
        return metric_command_results(response)


def update_metric_metadata_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
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
    metric_name = args.get("metric_name")
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
                **{key: value for key, value in params.items() if value is not None}
            ),
        )
        return metric_command_results(response)


""" MAIN FUNCTION """


def main() -> None:
    command: str = demisto.command()
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    demisto.debug(f"Command being called is {command}")
    try:
        configuration = Configuration()
        configuration.api_key["apiKeyAuth"] = params.get("api_key")
        configuration.api_key["appKeyAuth"] = params.get("app_key")
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
        }
        if command == "test-module":
            return_results(test_module(configuration))
        elif command in commands:
            return_results(commands[command](configuration, args))
        else:
            raise NotImplementedError
        # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
