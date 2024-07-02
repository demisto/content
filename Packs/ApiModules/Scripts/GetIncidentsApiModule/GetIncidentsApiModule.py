from CommonServerPython import *

DEFAULT_LIMIT = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_TIME_FIELD = "created"


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
    include_context = argToBoolean(args.get("includeContext") or False)
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
