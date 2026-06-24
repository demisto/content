import json

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


WAR_ROOM_ENTRY_URL = "/xsoar/entry"
CREATE_INVESTIGATION_ID_URL = "/xsoar/investigation"
WEBAPP_GET_DATA_URL = "/api/webapp/get_data"
CASES_TABLE = "CASE_MANAGER_TABLE"
ALERTS_VIEW_TABLE = "ALERTS_VIEW_TABLE"
MAX_ASSETS = 20

FILTER_FIELD: dict[str, str] = {
    "case": "CASE_ID",
    "issue": "internal_id",
}
TABLE_NAME: dict[str, str] = {
    "case": CASES_TABLE,
    "issue": ALERTS_VIEW_TABLE,
}


def build_webapp_request_data(table_name: str, filter_field: str, asset_ids: list[str]) -> dict:
    """Build the request body for ``/api/webapp/get_data`` that matches any of *asset_ids*.

    Uses an ``OR`` of ``EQ`` clauses so that all IDs are checked in a single
    API call.  This mirrors the filter structure used by the Cortex webapp UI.

    Args:
        table_name: The webapp table to query (e.g. ``CASES_TABLE``).
        filter_field: The field name to filter on (e.g. ``'CASE_ID'``).
        asset_ids: One or more values to match.

    Returns:
        A dict ready to be JSON-serialised and sent to the webapp endpoint.

    """
    or_clauses = [{"SEARCH_FIELD": filter_field, "SEARCH_TYPE": "EQ", "SEARCH_VALUE": asset_id} for asset_id in asset_ids]
    filter_dict = {"AND": [{"OR": or_clauses}]}
    return {
        "type": "grid",
        "table_name": table_name,
        "filter_data": {
            "sort": [],
            "paging": {"from": 0, "to": len(asset_ids)},
            "filter": filter_dict,
        },
        "jsons": [],
        "onDemandFields": [],
    }


def get_existing_ids_batch(asset_type: str, asset_ids: list[str]) -> set[str]:
    """Return the subset of *asset_ids* that actually exist in the platform.

    Makes exactly **one** API call regardless of how many IDs are requested.

    Args:
        asset_type: Either ``'case'`` or ``'issue'``.
        asset_ids: The IDs to look up.

    Returns:
        A :class:`set` of IDs (as strings) that were found.  Missing IDs are
        simply absent from the returned set.

    """
    if not asset_ids:
        return set()

    table_name = TABLE_NAME[asset_type]
    filter_field = FILTER_FIELD[asset_type]

    request_data = build_webapp_request_data(table_name, filter_field, asset_ids)
    demisto.debug(f"Batch-checking {asset_type} IDs {asset_ids!r}: {request_data}")

    raw = demisto._apiCall(
        method="POST",
        path=WEBAPP_GET_DATA_URL,
        data=json.dumps(request_data),
        headers={"Content-Type": "application/json"},
    )
    try:
        response = json.loads(raw["data"])
    except (json.JSONDecodeError, TypeError, KeyError):
        demisto.debug(f"get_existing_ids_batch: failed to parse response. Raw: {raw!r}")
        return set()

    rows = response.get("reply", {}).get("DATA", [])
    return {str(row[filter_field]) for row in rows}


def post_war_room_entry(investigation_id: str, content: str) -> dict:
    """Create a war room investigation context and post an entry to it.

    Args:
        investigation_id: The investigation ID string (e.g. ``'123'`` or ``'INCIDENT-456'``).
        content: The text content of the entry to create.

    Returns:
        The raw response dict from the war room entry POST request.

    """
    demisto._apiCall(
        method="POST",
        path=f"{CREATE_INVESTIGATION_ID_URL}/{investigation_id}",
        data=None,
        headers={"Content-Type": "application/json"},
    )
    return demisto._apiCall(
        method="POST",
        path=WAR_ROOM_ENTRY_URL,
        data=json.dumps({"investigationId": investigation_id, "data": content}),
        headers={"Content-Type": "application/json"},
    )


def create_war_room_entry(issue_ids: list[str], case_ids: list[str], content: str) -> CommandResults:
    """Create a war room entry for the given assets (Cases and/or Issues).

    Validates all issue IDs in a single API call and all case IDs in another
    single API call, then determines which IDs are missing before posting
    entries only for the ones that exist.

    Args:
        issue_ids: A list of issue IDs (may be empty).
        case_ids: A list of case IDs (may be empty).
        content: The text content of the entry to create.

    Returns:
        CommandResults with the entry ID(s) on success, or an error result
        if no IDs were provided, a target asset does not exist or more than
        20 issues and cases were provided (combined).

    """
    if not issue_ids and not case_ids:
        return CommandResults(
            outputs_prefix="CortexCreateWarRoomEntry",
            outputs={"result": [], "errors": ["At least one of 'issue_id' or 'case_id' must be provided."]},
        )

    total = len(issue_ids) + len(case_ids)
    if total > MAX_ASSETS:
        return CommandResults(
            outputs_prefix="CortexCreateWarRoomEntry",
            outputs={
                "result": [],
                "errors": [
                    f"Too many assets provided ({total}). A maximum of {MAX_ASSETS} issues and cases combined is allowed."
                ],
            },
        )

    existing_issues = get_existing_ids_batch("issue", issue_ids)
    existing_cases = get_existing_ids_batch("case", case_ids)

    errors: list[str] = []
    entry_ids: list[str] = []

    assets = [
        ("Issue", issue_ids, existing_issues, lambda asset_id: asset_id),
        ("Case", case_ids, existing_cases, lambda asset_id: f"INCIDENT-{asset_id}"),
    ]

    for label, ids, existing, to_investigation_id in assets:
        for asset_id in ids:
            if asset_id in existing:
                response = post_war_room_entry(to_investigation_id(asset_id), content)
                raw_data = response.get("data")
                if raw_data:
                    try:
                        if entry_id := json.loads(raw_data).get("id"):
                            entry_ids.append(entry_id)
                    except (json.JSONDecodeError, TypeError):
                        demisto.debug(
                            f"post_war_room_entry: failed to parse entry ID from response for {label} {asset_id!r}. "
                            f"Raw: {response!r}"
                        )
            else:
                errors.append(f"{label} with ID '{asset_id}' was not found. Please verify the {label.lower()} ID and try again.")

    return CommandResults(
        outputs_prefix="CortexCreateWarRoomEntry",
        outputs={"result": entry_ids, "errors": errors},
    )


def main():  # pragma: no cover
    """Executes create_war_room_entry script with the given arguments."""
    try:
        args = demisto.args()
        issue_ids = argToList(args.get("issue_ids", ""))
        case_ids = argToList(args.get("case_ids", ""))
        raw_content = args.get("content", "")
        content = raw_content if isinstance(raw_content, str) else json.dumps(raw_content)

        result = create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content=content)
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute CortexCreateWarRoomEntry. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
