import demistomock as demisto
from CommonServerPython import *


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
VENDOR = "gitlab"
PRODUCT = "gitlab"
DEFAULT_LIMIT = 500


""" HELPER FUNCTIONS """


def arg_to_strtime(value: Any) -> Optional[str]:
    if datetime_obj := arg_to_datetime(value):
        return datetime_obj.strftime(DATE_FORMAT)
    return None


def prepare_query_params(params: dict, last_run: dict = {}) -> str:
    """
    Parses the given inputs into GitLab Events API expected query params URL.
    """
    if next_url := last_run.get("next_url"):
        return next_url

    return f"pagination=keyset&created_after={arg_to_strtime(params.get('after'))}&per_page=100"


def reformat_details(audit_events: list, groups_and_projects_events: list) -> tuple[list, list]:
    for event in groups_and_projects_events:
        if "details" in event:
            for action in ["add", "change", "remove"]:
                if action in event["details"]:
                    event["details"]["action"] = f'{action}_{event["details"][action]}'
                    event["details"]["action_type"] = action
                    event["details"]["action_category"] = event["details"][action]
                    break

    for event in audit_events + groups_and_projects_events:
        event["_time"] = event["created_at"]

    return audit_events, groups_and_projects_events


""" CLIENT CLASS """


class Client(BaseClient):
    def get_events_request(self, query_params_url: str | None, url_suffix: str = "/audit_events") -> tuple:
        """
        Sends request to get events from GitLab.
        """
        response = self._http_request(method="GET", url_suffix=f"{url_suffix}?{query_params_url}", resp_type="response")

        events = response.json()
        next_url = (response.links or {}).get("next", {}).get("url")

        demisto.debug(f"Successfully got {len(events)} events.")
        return events, next_url

    def handle_pagination_first_batch(self, query_params_url: str | None, last_run: dict, url_suffix: str) -> tuple:
        """
        Makes the first events API call in the current fetch run.
        If `first_id` exists in the lastRun obj, finds it in the response and
        returns only the subsequent events (that weren't collected yet).
        """
        events, next_url = self.get_events_request(query_params_url, url_suffix)

        if last_run.get("first_id"):
            for idx, event in enumerate(events):
                if event.get("id") == last_run["first_id"]:
                    events = events[idx:]
                    break

            last_run.pop("first_id", None)  # removing to make sure it won't be used in future runs

        return events, next_url

    def fetch_events(
        self, query_params_url: str, last_run: dict, user_defined_params: dict, url_suffix: str = "/audit_events"
    ) -> List[dict]:
        """
        Aggregates events using cursor-based pagination, until one of the following occurs:
        1. Encounters an event that was already fetched in a previous run / reaches the end of the pagination.
           In both cases, clears the cursor from the lastRun obj, updates `last_id` to know where
           to stop in the next runs and returns the aggregated logs.

        2. Reaches the user-defined limit (parameter).
           In this case, stores the last used URL suffix and the id of the next event to collect (`first_id`)
           and returns the events that have been accumulated so far.

        3. Reaches a rate limit.
           In this case, stores the last URL suffix used in the lastRun obj
           and returns the events that have been accumulated so far.
        """
        aggregated_events: List[dict] = []

        user_defined_limit = arg_to_number(user_defined_params.get("limit")) or DEFAULT_LIMIT
        current_query_params_url: str | None = query_params_url

        try:
            events, next_url = self.handle_pagination_first_batch(current_query_params_url, last_run, url_suffix)
            while events:
                for event in events:
                    if event.get("id") == last_run.get("last_id"):
                        demisto.debug("Encountered an event that was already fetched - stopping.")
                        current_query_params_url = None
                        if aggregated_events:
                            last_run.update({"last_id": aggregated_events[0].get("id")})
                        break

                    if len(aggregated_events) == user_defined_limit:
                        demisto.debug(f"Reached the user-defined limit ({user_defined_limit}) - stopping.")
                        last_run["first_id"] = event.get("id")
                        break

                    aggregated_events.append(event)

                else:
                    # Finished iterating through all events in this batch
                    if next_url:
                        demisto.debug("Using the given next_url from the last API call to execute the next call.")
                        current_query_params_url = next_url.split("?", 1)[1]
                        events, next_url = self.get_events_request(current_query_params_url, url_suffix)
                        continue
                    else:
                        current_query_params_url = None

                demisto.debug("Finished iterating through all events in this fetch run for the current event type.")
                break

        except DemistoException as e:
            if not e.res or e.res.status_code != 429:
                raise e
            demisto.debug("Reached API rate limit, storing last used cursor.")

        if not last_run.get("last_id") and aggregated_events:
            last_run["last_id"] = aggregated_events[0].get("id")

        last_run["next_url"] = current_query_params_url
        return aggregated_events


""" COMMAND FUNCTIONS """


def test_module_command(client: Client, params: dict, events_types_ids: dict) -> str:
    """
    Tests connection to GitLab.
    Tests also given groups / projects ids that are exists.

    Args:
        client (Client): The client implementing the API to GitLab.
        params (dict): The configuration parameters.
        events_collection_management (dict): The event types ids collection.

    Returns:
        (str) 'ok' if success.
    """
    fetch_events_command(client, params, {}, events_types_ids)
    return "ok"


def get_events_command(client: Client, args: dict) -> tuple[list, CommandResults]:
    """
    Gets log events from GitLab.
    Args:
        client (Client): the client implementing the API to GitLab.
        args (dict): the command arguments.

    Returns:
        (list) the events retrieved from the API call.
        (CommandResults) the CommandResults object holding the collected events information.
    """
    query_params_url = prepare_query_params(args)
    events, _ = client.get_events_request(query_params_url)
    results = CommandResults(
        raw_response=events,
        readable_output=tableToMarkdown("GitLab Events", events, date_fields=["created_at"], removeNull=True),
    )
    return events, results


def fetch_events_command(client: Client, params: dict, last_run: dict, events_types_ids: dict) -> tuple[list, list, dict]:
    """
    Collects log events from GitLab using pagination.

    Args:
        client (Client): the client implementing the API to GitLab.
        params (dict): the instance configuration parameters.
        last_run (dict): the lastRun object, holding information from the previous run.
        events_types_ids (dict): The groups / projects Ids to fetch events for.

    Returns:
        (list) the audit events retrieved from the API call.
        (list) the groups and projects events retrieved from the API call.
        (dict) the updated lastRun object.
    """

    query_params_url = prepare_query_params(params, last_run.get("audit_events", {}))
    audit_events = client.fetch_events(query_params_url, last_run.get("audit_events", {}), params)
    demisto.debug(f"Aggregated audits events: {len(audit_events)}")

    group_and_project_events = []
    for event_type in ["groups", "projects"]:
        for obj_id in events_types_ids.get(f"{event_type}_ids", []):
            query_params_url = prepare_query_params(params, last_run.get(event_type, {}))
            events = client.fetch_events(
                query_params_url, last_run.get(event_type, {}), params, url_suffix=f"/{event_type}/{obj_id}/audit_events"
            )
            group_and_project_events.extend(events)

    demisto.debug(f"Aggregated group and project events: {len(group_and_project_events)}")
    return audit_events, group_and_project_events, last_run


""" MAIN FUNCTION """


def main() -> None:
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=f"{params['url']}/api/v4",
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            headers={"PRIVATE-TOKEN": params.get("api_key", {}).get("password")},
        )

        events_collection_management = {
            "groups_ids": argToList(params.get("group_ids", "")),
            "projects_ids": argToList(params.get("project_ids", "")),
        }

        if command == "test-module":
            return_results(test_module_command(client, params, events_collection_management))

        elif command == "gitlab-get-events":
            events, results = get_events_command(client, params)
            return_results(results)
            if argToBoolean(args.get("should_push_events", "false")):
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            if not last_run:
                last_run = {"groups": {}, "projects": {}, "audit_events": {}}
            audit_events, group_and_project_events, last_run = fetch_events_command(
                client, params, last_run, events_collection_management
            )
            audit_events, group_and_project_events = reformat_details(audit_events, group_and_project_events)

            send_events_to_xsiam(audit_events + group_and_project_events, vendor=VENDOR, product=PRODUCT)
            demisto.setLastRun(last_run)

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
