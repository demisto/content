import datetime as dt
from typing import TYPE_CHECKING, cast

import demistomock as demisto  # noqa: F401
from AWSApiModule import *
from CommonServerPython import *  # noqa: F401

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_securityhub import SecurityHubClient
    from mypy_boto3_securityhub.type_defs import AwsSecurityFindingTypeDef


VENDOR = "AWS"
PRODUCT = "Security Hub"
TIME_FIELD = "CreatedAt"
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DATETIME_FORMAT_NO_MS = "%Y-%m-%dT%H:%M:%SZ"  # Fallback format without milliseconds
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_RESULTS = 1000
API_MAX_PAGE_SIZE = 100  # The API only allows a maximum of 100 results per request. Using more raises an error.
RETRY_LIMIT_INCREMENT = 100  # How much to increase limit when AWS returns all events as duplicates
MAX_AWS_LIMIT = 10000  # Maximum limit to prevent excessive API calls


def parse_aws_timestamp(timestamp_str: str) -> dt.datetime:
    """
    Parse AWS timestamp with flexible format support.
    The AWS API returns timestamps in two formats:
    - With milliseconds: "2023-01-01T00:00:00.000Z"
    - Without milliseconds: "2023-01-01T00:00:00Z"

    Args:
        timestamp_str (str): Timestamp string from AWS API

    Returns:
        datetime: Parsed datetime object

    Raises:
        ValueError: If timestamp format is not supported
    """
    try:
        # Try parsing with milliseconds first
        return dt.datetime.strptime(timestamp_str, DATETIME_FORMAT)
    except ValueError:
        # Fallback to parsing without milliseconds
        return dt.datetime.strptime(timestamp_str, DATETIME_FORMAT_NO_MS)


def generate_last_run(events: list["AwsSecurityFindingTypeDef"], previous_last_run: dict | None = None) -> dict[str, Any]:
    """
    Generate the last run object using events data.

    Args:
        events (list[dict]): List of events to generate the last run object from.
        previous_last_run (dict | None, optional): Previous last run data for smart ignore list accumulation.

    Note:
        Since the time filters seem to be equal or greater than (which results in duplicate from the last run),
        we add findings that are equal to 'last_finding_update_time' and filter them out in the next fetch.
        Smart accumulation: If timestamp hasn't changed, accumulate ignore list instead of replacing it.

    Returns:
        dict: Last run object.
    """
    last_update_date = events[-1].get(TIME_FIELD)

    # Smart ignore list accumulation logic
    if previous_last_run and previous_last_run.get("last_update_date") == last_update_date:
        # Same timestamp - ACCUMULATE ignore list from previous run
        ignore_list: list[str] = previous_last_run.get("last_update_date_finding_ids", []).copy()
        demisto.debug(
            f"Same timestamp detected ({last_update_date}). Accumulating ignore list from {len(ignore_list)} existing IDs."
        )
    else:
        # New timestamp - START FRESH ignore list
        ignore_list = []
        if previous_last_run:
            demisto.debug(
                f"Timestamp changed from {previous_last_run.get('last_update_date')} to {last_update_date}. "
                f"Starting fresh ignore list."
            )

    # Since the "_time" key is added to each event, the event type changes from "AwsSecurityFindingTypeDef" to just dict
    events = cast(list[dict[str, Any]], events)
    for event in events:
        event["_time"] = event[TIME_FIELD]

        if event[TIME_FIELD] == last_update_date:
            ignore_list.append(event["Id"])

    demisto.debug(f"Generated ignore list with {len(ignore_list)} IDs for timestamp {last_update_date}")

    return {
        "last_update_date": last_update_date,
        "last_update_date_finding_ids": ignore_list,
    }


def get_events(
    client: "SecurityHubClient",
    start_time: dt.datetime | None = None,
    end_time: dt.datetime | None = None,
    id_ignore_list: list[str] | None = None,
    page_size: int = API_MAX_PAGE_SIZE,
    limit: int = 0,
    start_token: str | None = None,
) -> tuple[List["AwsSecurityFindingTypeDef"], str | None]:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        start_time (datetime | None, optional): Start time to fetch events from. Required if end_time is set.
        end_time (datetime | None, optional): Time to fetch events until. Defaults to current time.
        id_ignore_list (list[str] | None, optional): List of finding IDs to not include in the results.
            Defaults to None.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of results to fetch. Defaults to 0.
        start_token (str | None, optional): Token to use for pagination. Defaults to None.

    Returns:
        tuple: A 2-tuple containing:
            - Filtered events (list[AwsSecurityFindingTypeDef])
            - NextToken for continuation (str | None, None means no more events)
    """
    kwargs: dict = {"SortCriteria": [{"Field": TIME_FIELD, "SortOrder": "asc"}]}
    filters: dict = {}

    # Start from provided token if available
    if start_token:
        kwargs["NextToken"] = start_token

    if end_time and not start_time:
        raise ValueError("start_time must be set if end_time is used.")

    if start_time:
        filters[TIME_FIELD] = [
            {
                "Start": start_time.strftime(DATETIME_FORMAT),
                "End": end_time.strftime(DATETIME_FORMAT) if end_time else dt.datetime.now().strftime(DATETIME_FORMAT),
            }
        ]

    if id_ignore_list:
        id_ignore_set = set(id_ignore_list)
    else:
        id_ignore_set = set()

    if filters:
        # We send kwargs because passing Filters=None to get_findings() tries to use a None value for filters,
        # which raises an error.
        kwargs["Filters"] = filters

    # Collect all raw events first, then filter duplicates at the end
    all_raw_events: list[AwsSecurityFindingTypeDef] = []
    total_collected_count = 0
    pagination_iteration = 0

    demisto.debug(
        f"Starting get_events pagination with limit={limit}, page_size={page_size}, ignore_set_size={len(id_ignore_set)}"
    )

    while True:
        pagination_iteration += 1

        if limit and total_collected_count + page_size > limit:
            kwargs["MaxResults"] = limit - total_collected_count
        else:
            kwargs["MaxResults"] = page_size

        demisto.debug(f"Iteration {pagination_iteration}: Calling get_findings with kwargs: {kwargs}")
        response = client.get_findings(**kwargs)
        result = response.get("Findings", [])
        has_next_token = "NextToken" in response

        demisto.debug(
            f"Iteration {pagination_iteration}: AWS returned {len(result)} findings, NextToken present: {has_next_token}"
        )
        all_raw_events.extend(result)
        total_collected_count += len(result)

        demisto.debug(f"Iteration {pagination_iteration}: Total raw events collected so far: {len(all_raw_events)}")

        # Check if we should continue pagination
        should_continue = (
            has_next_token
            and (limit == 0 or total_collected_count < limit)
            and len(result) > 0  # Stop if AWS returns empty results
        )

        if should_continue:
            kwargs["NextToken"] = response["NextToken"]
            demisto.debug(
                f"Iteration {pagination_iteration}: Continuing pagination (limit={limit}, collected={total_collected_count})"
            )
        else:
            if not has_next_token:
                demisto.debug(f"Iteration {pagination_iteration}: No more pages available from AWS")
            elif limit > 0 and total_collected_count >= limit:
                demisto.debug(f"Iteration {pagination_iteration}: Reached limit ({total_collected_count}/{limit})")
            elif len(result) == 0:
                demisto.debug(f"Iteration {pagination_iteration}: AWS returned empty results, stopping pagination")
            break

    # Now filter duplicates from ALL collected events
    demisto.debug(f"Filtering duplicates from {len(all_raw_events)} total collected events")
    filtered_events = [event for event in all_raw_events if event["Id"] not in id_ignore_set]
    duplicates_filtered = len(all_raw_events) - len(filtered_events)

    demisto.debug(
        f"Pagination completed after {pagination_iteration} iterations. "
        f"Raw events: {len(all_raw_events)}, After deduplication: {len(filtered_events)} "
        f"({duplicates_filtered} duplicates filtered)"
    )

    # Return filtered events and the final NextToken
    final_next_token = response.get("NextToken")
    return (filtered_events, final_next_token)


def fetch_events(
    client: "SecurityHubClient",
    last_run: dict,
    first_fetch_time: dt.datetime | None,
    page_size: int = API_MAX_PAGE_SIZE,
    limit: int = 0,
) -> tuple[list["AwsSecurityFindingTypeDef"], dict, Exception | None]:
    """
    Fetch events from AWS Security Hub and send them to XSIAM.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        last_run (dict): Dict containing the last fetched event creation time.
        first_fetch_time (datetime | None, optional): In case of first fetch, fetch events from this datetime.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of events to fetch. Defaults to 0 (no limit).
    """
    demisto.debug(f"Fetching events with last_run: {last_run}")
    if last_run.get("last_update_date"):
        start_time = parse_aws_timestamp(last_run["last_update_date"])

    else:
        start_time = cast(dt.datetime, first_fetch_time)

    id_ignore_list: list = last_run.get("last_update_date_finding_ids", [])

    events: list[AwsSecurityFindingTypeDef] = []
    error = None
    current_limit = limit
    max_aws_limit = MAX_AWS_LIMIT

    # Fix end_time for all additional retries to keep NextToken valid
    end_time = dt.datetime.now()

    try:
        continuation_token = None
        while True:
            got_new_events = False

            filtered_events, continuation_token = get_events(
                client=client,
                start_time=start_time,
                end_time=end_time,
                id_ignore_list=id_ignore_list,
                page_size=page_size,
                limit=current_limit,
                start_token=continuation_token,
            )

            if filtered_events:  # If any events returned, they're new (already filtered)
                got_new_events = True
            events.extend(filtered_events)

            # If we got new events, we're done!
            if got_new_events:
                demisto.debug(f"Successfully fetched {len(events)} new events")
                break

            # No new events - should we increase the requested limit in order to exit the loop?
            if continuation_token and current_limit < max_aws_limit:
                # AWS has more events and we haven't hit the max API limit - continue from NextToken with a small amount
                current_limit = RETRY_LIMIT_INCREMENT
                demisto.info(
                    f"Infinite loop prevention: All events were duplicates but AWS has more events. "
                    f"Retrying with limit: {current_limit} (continuing from NextToken)"
                )
                continue

            # Can't or shouldn't retry - explain why and exit
            if not continuation_token:
                demisto.debug("All events were duplicates and AWS has no more events - reached end")
            else:
                demisto.debug(f"All events were duplicates but reached max limit ({max_aws_limit}) - stopping retries")
            break

    except Exception as e:
        demisto.error(f"Error while fetching events. Events fetched so far: {len(events)}. Error: {e}")
        error = e

    # --- Set next_run data ---
    if events:
        demisto.info(f"Fetched {len(events)} findings.")
        next_run = generate_last_run(events, last_run)
        demisto.info(f"Last run data updated to: {next_run}.")

    else:
        demisto.info("No new findings were found.")
        next_run = last_run

    return events, next_run, error


def get_events_command(
    client: "SecurityHubClient",
    should_push_events: bool,
    page_size: int,
    limit: int = 0,
    start_time: dt.datetime | None = None,
    end_time: dt.datetime | None = None,
) -> CommandResults:
    """
    Fetch events from AWS Security Hub.

    Args:
        client (SecurityHubClient): Boto3 client to use.
        should_push_events (bool): Whether to push events to XSIAM.
        page_size (int, optional): Number of results to fetch per request. Defaults to API_MAX_PAGE_SIZE.
        limit (int, optional): Maximum number of events to fetch. Defaults to 0 (no limit).
        start_time (dt.datetime, optional): Start time for filtering events. Defaults to None.
        end_time (dt.datetime, optional): End time for filtering events. Defaults to None.

    Returns:
        CommandResults: CommandResults object containing the events.
    """
    events, _ = get_events(client=client, page_size=page_size, limit=limit, start_time=start_time, end_time=end_time)

    if should_push_events:
        send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

    return CommandResults(
        readable_output=tableToMarkdown("AWS Security Hub Events", events, sort_headers=False),
    )


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    aws_role_arn = params.get("role_arn")
    aws_role_session_name = params.get("role_session_name")
    aws_default_region = params.get("default_region")
    aws_role_session_duration = params.get("role_session_duration")
    aws_access_key_id = demisto.get(params, "credentials.identifier")
    aws_secret_access_key = demisto.get(params, "credentials.password")
    verify_certificate = not params.get("insecure", True)
    timeout = params.get("timeout")
    retries = params.get("retries", 5)

    limit = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_RESULTS

    if limit <= 0:
        raise ValueError("Max fetch value cannot be lower than 1.")

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(
        arg=params.get("first_fetch", DEFAULT_FIRST_FETCH), arg_name="First fetch time", required=True
    )

    try:
        validate_params(
            aws_default_region=aws_default_region,
            aws_role_arn=aws_role_arn,
            aws_role_session_name=aws_role_session_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        aws_client = AWSClient(
            aws_default_region=aws_default_region,
            aws_role_arn=aws_role_arn,
            aws_role_session_name=aws_role_session_name,
            aws_role_session_duration=aws_role_session_duration,
            aws_role_policy=None,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            verify_certificate=verify_certificate,
            timeout=timeout,
            retries=retries,
        )

        client: SecurityHubClient = aws_client.aws_session(
            service="securityhub",
            region=aws_default_region,
            role_arn=aws_role_arn,
            role_session_name=aws_role_session_name,
            role_session_duration=aws_role_session_duration,
        )

        demisto.info(f'Executing "{command}" command...')

        if command == "test-module":
            get_events(client=client, limit=1)[0]  # Get events from tuple
            return_results("ok")

        elif command == "aws-securityhub-get-events":
            should_push_events = argToBoolean(args.get("should_push_events", False))
            page_size = arg_to_number(args.get("page_size", API_MAX_PAGE_SIZE))

            if page_size is None or page_size > 100:
                raise ValueError("Page size cannot be larger than 100 (not supported by the API).")

            limit = arg_to_number(args.get("limit")) or 1

            if limit is None or limit <= 0:
                raise ValueError("Max fetch value cannot be lower than 1.")

            # Parse optional start_time and end_time arguments
            start_time = arg_to_datetime(args.get("start_time")) if args.get("start_time") else None
            end_time = arg_to_datetime(args.get("end_time")) if args.get("end_time") else None

            return_results(
                get_events_command(
                    client=client,
                    should_push_events=should_push_events,
                    page_size=page_size,
                    limit=limit,
                    start_time=start_time,
                    end_time=end_time,
                )
            )

        elif command == "fetch-events":
            events, next_run, error = fetch_events(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                limit=limit,
            )

            send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(next_run)

            if error and events:
                raise Exception(
                    f"An error occurred while running fetch-events. "
                    f"The operation was partially successful, but failed midway.\n"
                    f"A total of {len(events)} events were successfully fetched "
                    f"before the error occurred."
                ) from error

            elif error:
                raise error

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
