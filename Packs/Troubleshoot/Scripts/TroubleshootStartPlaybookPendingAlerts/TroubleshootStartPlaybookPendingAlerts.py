### GENERATED CODE ###: from GetIncidentsApiModule import *
# This code was inserted in place of an API module.
from CommonServerPython import *
from GetIncidentsApiModule import *
DEFAULT_LIMIT = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_TIME_FIELD = "created"
MAX_BULK_SIZE_ALLOWED = 10


def build_query_parameter(
    custom_query: str | None,
    incident_types: list[str],
    time_field: str,
    from_date: str | None,
    to_date: str | None,
    non_empty_fields: list[str],
) -> str:
    """Builds the query parameter string from given arguments.

    Args:
        custom_query (str | None): A custom query.
        incident_types (list[str] | None): Incident types to retrieve.
        time_field (str): The relevant time field to search by.
        from_date (str | None): The start date for the incidents query.
        to_date (str | None): The end date for the incidents query.
        non_empty_fields (list[str]): Required non-empty incident fields.

    Raises:
        Exception: If no query parts were added.

    Returns:
        str: The query string built from the given arguments.
    """
    query_parts = []
    if custom_query:
        query_parts.append(custom_query)
    if incident_types:
        types = [x if "*" in x else f'"{x}"' for x in incident_types]
        query_parts.append(f"type:({' '.join(types)})")
    if from_date and time_field:
        query_parts.append(f'{time_field}:>="{from_date}"')
    if to_date and time_field:
        query_parts.append(f'{time_field}:<"{to_date}"')
    if non_empty_fields:
        query_parts.append(" and ".join(f"{x}:*" for x in non_empty_fields))
    if not query_parts:
        raise DemistoException("Incidents query is empty - please fill at least one argument")
    return " and ".join(f"({x})" for x in query_parts)


def format_incident(inc: dict, fields_to_populate: list[str], include_context: bool) -> dict:
    """Flattens custom fields with incident data and filters by fields_to_populate

    Args:
        inc (dict): An incident.
        fields_to_populate (list[str]): List of fields to populate.
        include_context (bool): Whether or not to enrich the incident with its context data.

    Returns:
        dict: The formatted incident.
    """
    custom_fields = inc.pop('CustomFields', {})
    inc.update(custom_fields or {})
    if fields_to_populate:
        inc = {k: v for k, v in inc.items() if k.lower() in {val.lower() for val in fields_to_populate}}
        if any(f.lower() == "customfields" for f in fields_to_populate):
            inc["CustomFields"] = custom_fields
    if include_context:
        inc['context'] = execute_command("getContext", {"id": inc["id"]}, extract_contents=True)
    return inc


def get_incidents_with_pagination(
    query: str,
    from_date: str | None,
    to_date: str | None,
    fields_to_populate: list[str],
    include_context: bool,
    limit: int,
    page_size: int,
    sort: str,
) -> list[dict]:
    """Performs paginated getIncidents requests until limit is reached or no more results.
    Each incident in the response is formatted before returned.

    Args:
        query (str): The incidents query string.
        from_date (str | None): The fromdate argument for the incidents query.
        to_date (str | None): The todate argument for the incidents query.
        fields_to_populate (list[str]): The fields to populate for each incident.
        include_context (bool): Whether or not to enrich the returned incidents with their the context data.
        limit (int): Maximum number of incidents to return.
        page_size (int): Number of incidents to retrieve per page.
        sort (str): Sort order for incidents.

    Returns:
        list[dict]: The requested incidents.
    """
    incidents: list = []
    page = -1
    populate_fields = ",".join(f.split(".")[0] for f in fields_to_populate)
    demisto.debug(f"Running getIncidents with {query=}")
    while len(incidents) < limit:
        page += 1
        page_results = execute_command(
            "getIncidents",
            args={
                "query": query,
                "fromdate": from_date,
                "todate": to_date,
                "page": page,
                "populateFields": populate_fields,
                "size": page_size,
                "sort": sort,
            },
            extract_contents=True,
            fail_on_error=True,
        ).get('data') or []
        incidents += page_results
        if len(page_results) < page_size:
            break
    return [
        format_incident(inc, fields_to_populate, include_context)
        for inc in incidents[:limit]
    ]


def prepare_fields_list(fields_list: list[str] | None) -> list[str]:
    """Removes `incident.` prefix from the fields list and returns a list of unique values.

    Args:
        fields_list (list[str] | None): The current state of the fields list, as provided by the user.

    Returns:
        list[str]: The prepared fields list.
    """
    return list({
        field.removeprefix("incident.") for field in fields_list if field
    }) if fields_list else []


def get_incidents(
    custom_query: str | None = None,
    incident_types: list[str] | None = None,
    populate_fields: list[str] | None = None,
    non_empty_fields: list[str] | None = None,
    time_field: str = DEFAULT_TIME_FIELD,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    include_context: bool = False,
    limit: int = DEFAULT_LIMIT,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> list[dict]:
    """Performs a deeper formatting on the search arguments and runs paginated incidents search.

    Args:
        custom_query (str | None, optional): A custom query. Defaults to None.
        incident_types (list[str] | None, optional): Incident types to retrieve. Defaults to None.
        populate_fields (list[str] | None, optional): Incident fields to populate. Defaults to None.
        non_empty_fields (list[str] | None, optional): Required non-empty incident fields. Defaults to None.
        from_date (datetime | None, optional): The start date of the timeframe. Defaults to None.
        to_date (datetime | None, optional): The end date of the timeframe. Defaults to None.
        time_field (str, optional): The relevant time field to search by. Defaults to "created".
        include_context (bool, optional): Whether or not to enrich the returned incidents with their the context data.
            Defaults to False.
        limit (int, optional): The search limit. Defaults to 500.
        page_size (int, optional): Maximal page size. Defaults to 100.

    Returns:
        list[dict]: The requested incidents.
    """
    non_empty_fields = prepare_fields_list(non_empty_fields)

    if populate_fields := prepare_fields_list(populate_fields):
        populate_fields.extend(non_empty_fields + ["id"])
        populate_fields = list(set(populate_fields))

    query = build_query_parameter(
        custom_query,
        incident_types or [],
        time_field,
        from_date.isoformat() if from_date and time_field != "created" else None,
        to_date.isoformat() if to_date and time_field != "created" else None,
        non_empty_fields,
    )

    return get_incidents_with_pagination(
        query,
        from_date.astimezone().isoformat() if from_date and time_field == "created" else None,
        to_date.astimezone().isoformat() if to_date and time_field == "created" else None,
        populate_fields,
        include_context,
        limit,
        page_size=min(limit, page_size),
        sort=f"{time_field}.desc",
    )


def get_incidents_by_query(args: dict) -> list[dict]:
    """Performs an initial parsing of args and calls the get_incidents method.

    Args:
        args (dict): the GetIncidentsByQuery arguments.

    Returns:
        list[dict]: The requested incidents.
    """
    query = args.get("query")
    incident_types = argToList(args.get("incidentTypes"), transform=str.strip)
    populate_fields = args.get("populateFields")
    if populate_fields is not None:
        populate_fields = populate_fields.replace("|", ",")
        populate_fields = argToList(populate_fields, transform=str.strip)
    non_empty_fields = argToList(args.get("NonEmptyFields"), transform=str.strip)
    time_field = args.get("timeField") or DEFAULT_TIME_FIELD
    from_date = arg_to_datetime(args.get("fromDate"))
    to_date = arg_to_datetime(args.get("toDate"))
    include_context = False
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    page_size = arg_to_number(args.get("pageSize")) or DEFAULT_PAGE_SIZE

    return get_incidents(
        query,
        incident_types,
        populate_fields,
        non_empty_fields,
        time_field,
        from_date,
        to_date,
        include_context,
        limit,
        page_size,
    )

### END GENERATED CODE ###

def handle_results(command_results: dict, playbook_id: str, alert_ids: list) -> str:
    """Extract the relevent info from the result dict

    Args:
        command_results (dict): The results from the API call.
        playbook_id (str): The playbook id for info.
        alert_ids (list): A list of alert Ids for info.

    Returns:
        str: Texts indicating the operation status, either success or the error log.
    """
    if not command_results:
        return "No results found for this query"

    try:
        result_dict = command_results[0]['Contents']['response']
        if not result_dict:
            return f"Alerts {alert_ids} set successfully with playbook {playbook_id}"

        ids_with_issues = [result_dict.keys()]
        ids_without_issues = [set(alert_ids) - set(ids_with_issues)]
        ids_issue_message = [result_dict.values()]
        if ids_without_issues:
            return "\n".join(ids_issue_message) + f"\nAlerts {ids_without_issues} set successfully with playbook {playbook_id}"

        return "\n".join(ids_issue_message)
    except:
        return f"Unsupported response: {command_results[0]}"

def open_inv_and_set_playbook_on_alerts(playbook_id: str, alert_ids: list, sleep_time: int) -> str:
    """
    uses set_playbook_on_alerts, but reopen the investigation first, and reclose it at the end
    """
    opened = [demisto.executeCommand("core-api-post", {"uri":"/investigation/:id/reopen", "body":{"id":alert, "version":-1}}) for alert in alert_ids]
    command_results = set_playbook_on_alerts(playbook_id=playbook_id, alert_ids=alert_ids)
    safe_sleep(sleep_time)
    closed = [demisto.executeCommand("closeInvestigation", {"id":alert, "closeReason": "Resolved - Auto Resolve"}) for alert in alert_ids]
    return command_results


def set_playbook_on_alerts(playbook_id: str, alert_ids: list) -> str:
    """Using an API call, create a new investigation Playbook with a given playbook ID and alerts ID

    Args:
        playbook_id (str): The playbook id to set.
        alert_ids (list): A list of alert Ids. limited to 10 at a time.

    Returns:
        dict: The command results.
    """
    command_results = demisto.executeCommand("core-api-post", {"uri":"/xsoar/inv-playbook/new", "body":{"playbookId":playbook_id, "alertIds":alert_ids, "version":-1}} )
    return handle_results(command_results, playbook_id, alert_ids)


def loop_on_alerts(incidents: list[dict], playbook_id: str, limit: int, sleep_time: int, reopen_closed_inv: bool) -> str:
    """Loop alerts and run set_playbook_on_alerts by batch limit

    Args:
        incidents (list of dict): The incidents found.
        playbook_id (str): The playbook id to set.
        limit (int): Max alerts to set in this run, regardless of how many were found.

    Returns:
        str: Texts indicating the operation status, either success or the error log.
    """
    if len(incidents) == 0:
        return "Couldn't find any alerts"

    alert_inv_status = {
        "close": [],
        "open": []
    }

    for inc in incidents[:limit]:
        if inc["closeReason"] != "":
            alert_inv_status["close"].append(inc["id"])
        else:
            alert_inv_status["open"].append(inc["id"])

    alert_closed_bulks = [alert_inv_status["close"][i:i+MAX_BULK_SIZE_ALLOWED] for i in range(0, len(alert_inv_status["close"]), MAX_BULK_SIZE_ALLOWED)]
    alert_open_bulks = [alert_inv_status["open"][i:i+MAX_BULK_SIZE_ALLOWED] for i in range(0, len(alert_inv_status["open"]), MAX_BULK_SIZE_ALLOWED)]

    message_response = []
    if alert_closed_bulks and reopen_closed_inv:
        message_response += [open_inv_and_set_playbook_on_alerts(playbook_id=playbook_id, alert_ids=bulk, sleep_time=sleep_time) for bulk in alert_closed_bulks]
    if alert_open_bulks:
        message_response += [set_playbook_on_alerts(playbook_id=playbook_id, alert_ids=bulk) for bulk in alert_open_bulks]
    return '\n'.join(message_response)


def split_by_playbooks(incidents: list[dict], limit: int, sleep_time: int, reopen_closed_inv: bool) -> str:
    # playbook_map = {playbook_id : [list of dicts of alerts on this id]}
    playbook_map = {}
    could_not_find_attached = ""
    for inc in incidents[:limit]:
        playbook_id = inc["playbookId"]
        if playbook_id:
            if playbook_id in playbook_map:
                playbook_map[playbook_id].append(inc)
            else:
                playbook_map[playbook_id] = [inc]
        else:
            could_not_find_attached += inc["id"] + ", "
    if could_not_find_attached:
        print(f"Could not find an attached playbook for the following alerts id: {could_not_find_attached}")

    message_response = ""
    for map_playbook_id, map_incidents in playbook_map.items():
        message_response += loop_on_alerts(map_incidents, map_playbook_id, limit, sleep_time, reopen_closed_inv) + "\n"
    return message_response


def main():
    try:
        args = demisto.args()
        incidents = get_incidents_by_query(args)
        playbook_id = args.get("playbook_id") # check if there is a way to pass playbook_name instead of id
        limit = int(args.get("limit"))
        sleep_time = int(args.get("sleep_time"))
        reopen_closed_inv = argToBoolean(args.get("reopen_closed_inv"))
        if not playbook_id:
            # we will try to rerun each alert's assigned playbook
            results = split_by_playbooks(incidents, limit, sleep_time, reopen_closed_inv)
        else:
            results = loop_on_alerts(incidents, playbook_id, limit, sleep_time, reopen_closed_inv)
        return_results(results)
    except Exception as e:
        return_error(str(e))


if __name__ in ["builtins", "__main__"]:
    main()
