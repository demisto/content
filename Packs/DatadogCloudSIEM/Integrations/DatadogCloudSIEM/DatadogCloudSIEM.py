from datetime import datetime
from math import floor
from typing import Any, Dict

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from datadog_api_client.v1.api.events_api import EventsApi
from datadog_api_client.v1.model.event import Event
from datadog_api_client.v1.model.event_alert_type import EventAlertType
from datadog_api_client.v1.model.event_create_request import EventCreateRequest
from datadog_api_client.v1.model.event_priority import EventPriority
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

# """ HELPER FUNCTIONS """


def get_command_title_string(
    sub_context: str, page: Optional[int], page_size: Optional[int]
) -> str:
    """
    Define command title
    Args:
        sub_context: Commands sub_context
        page: page_number
        page_size: page_size
    Returns:
        Returns the title for the readable output
    """
    if page and page_size and (page > 0 and page_size > 0):
        return (
            f"{sub_context} List\nCurrent page size: {page_size}\n"
            f"Showing page {page} out of others that may exist"
        )

    return f"{sub_context} List"


def is_within_18_hours(timestamp: int) -> bool:
    """
    Check if a given Unix timestamp is within the last 18 hours.

    Args:
        timestamp (int): A Unix timestamp.

    Returns:
        bool: True if the given timestamp is within the last 18 hours, False otherwise.
    """
    current_time = datetime.now()
    timestamp_time = datetime.fromtimestamp(timestamp)
    time_diff = current_time - timestamp_time
    time_diff_hours = time_diff.total_seconds() / 3600
    return time_diff_hours <= 18


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
    if page is not None and page <= 0:
        raise DemistoException(PAGE_NUMBER_ERROR_MSG)
    if page_size is not None and page_size <= 0:
        raise DemistoException(PAGE_SIZE_ERROR_MSG)

    page = page - 1 if page else DEFAULT_OFFSET
    page_size = page_size or DEFAULT_PAGE_SIZE
    # page_size = DEFAULT_PAGE_SIZE if page_size is None else page_size

    # limit = limit if limit else (page_size if page_size else DEFAULT_PAGE_SIZE)
    limit = limit or page_size or DEFAULT_PAGE_SIZE
    offset = page * page_size

    return limit, offset


""" COMMAND FUNCTIONS """


def test_module(configuration) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        with ApiClient(configuration) as api_client:
            api_instance = AuthenticationApi(api_client)
            api_instance.validate()

            # Testing application key

            api_instance = EventsApi(api_client)
            start_time = parse("1 min ago", settings={"TIMEZONE": "UTC"})
            end_time = parse(DEFAULT_TO_DATE, settings={"TIMEZONE": "UTC"})
            api_instance.list_events(
                start=int(start_time.timestamp() if start_time else 0),
                end=int(end_time.timestamp() if end_time else 0),
            )
            return "ok"
    except Exception:
        return "Authorization Error: Make sure API Key, Application Key, Server URL is correctly set."


def create_event_command(
    configuration: Configuration, args: Dict[str, Any]
) -> Union[CommandResults, DemistoException]:
    """
    Creates an event in the Datadog.

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
        if not is_within_18_hours(
            int(date_happened_timestamp.timestamp() if date_happened_timestamp else 0)
        ):
            return CommandResults(
                readable_output="The time of the event shall not be older than 18 hours!\n"
            )
    date_happened = parse(date_happened, settings={"TIMEZONE": "UTC"})
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
            else "Something went wrong!"
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
            resp: List[Event] = results[offset : offset + limit]
            data = [event.to_dict() for event in resp]
            if data:
                events_list = [event_for_lookup(event) for event in data]
                readable_output = lookup_to_markdown(
                    events_list, get_command_title_string("Events", page, page_size)
                )
            else:
                readable_output = "No Events to present.\n"
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_CONTEXT_NAME}.Event",
            outputs_key_field="id",
            outputs=data,
        )


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
