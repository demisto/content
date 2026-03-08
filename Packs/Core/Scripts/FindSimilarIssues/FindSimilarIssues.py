import demistomock as demisto
import pandas as pd
from CommonServerPython import *
from SimilarObjectApiModule import *  # noqa: E402
from CommonServerUserPython import *

TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
INCIDENT_ALIAS = "issue"
TAG_INCIDENT = "issues"
TAG_SCRIPT_INDICATORS = "similarIncidents"  # Keeps similarIncidents as it comes from the indicator script


def update_args(args):
    """
    Rename issue-based argument keys to incident-based equivalents,
    keeping all other keys unchanged.
    Args:
        args (dict): dictionary of argument names and values.
    Returns:
        dict: new dictionary with renamed keys.
    """
    name_mapping = {
        "issue_id": "incidentId",
        "min_similarity": "minimunIncidentSimilarity",
        "max_issues_to_display": "maxIncidentsToDisplay",
        "max_issues_in_indicators_for_white_list": "maxIncidentsInIndicatorsForWhiteList",
        "filter_equal_fields": "fieldExactMatch",
        "text_similarity_fields": "similarTextField",
        "json_similarity_fields": "similarJsonField",
        "discrete_match_fields": "similarCategoricalField",
        "fields_to_display": "fieldsToDisplay",
        "from_date": "fromDate",
        "to_date": "toDate",
        "aggregate_issues_different_date": "aggreagateIncidentsDifferentDate",
        "include_indicators_similarity": "includeIndicatorsSimilarity",
        "min_number_of_indicators": "minNumberOfIndicators",
        "indicators_types": "indicatorsTypes",
        "show_current_issue": "showCurrentIncident",
    }

    # Rename keys if found in mapping, otherwise keep them as-is
    new_args = {name_mapping.get(k, k): v for k, v in args.items()}
    demisto.debug(f"Changed args for calling the script to: {new_args}")
    return new_args


def replace_fields(args: dict, replacements: dict) -> dict:
    """
    Replaces field names in certain args according to a replacements mapping.
    Handles both comma-separated strings and lists.

    :param args: dictionary of arguments
    :param replacements: dictionary of replacements
    :return: updated args dict
    """
    fields_to_check = ["text_similarity_fields", "filter_equal_fields", "discrete_match_fields"]

    for key in fields_to_check:
        value = args.get(key)
        if not value:
            continue

        # Handle both list and string values
        if isinstance(value, str):
            fields = [f.strip() for f in value.split(",")]
        elif isinstance(value, list):
            fields = [str(f).strip() for f in value]
        else:
            continue

        updated_fields = []
        for f in fields:
            if key == "filter_equal_fields" and (f == "status" or f == "assignee"):
                updated_fields.append(f)
            else:
                updated_fields.append(replacements.get(f, f))

        args[key] = ",".join(updated_fields)

    return args


def get_issue_by_id(issue_id: str | None, from_date: str | None, to_date: str | None):
    """
    Get issue according to issue id using core-get-issues
    :param issue_id:
    :param from_date: from_date
    :param to_date: to_date
    :return: Get issue according to issue id
    """
    demisto.debug(
        f"Calling core-get-issues for {issue_id=} between {from_date=} and {to_date=}"
    )
    args = remove_empty_elements({
        "issue_id": issue_id,
        "start_time": from_date,
        "end_time": to_date,
        "time_frame": "custom"
    })

    res = demisto.executeCommand(
        "core-get-issues",
        args
    )
    if is_error(res):
        return_error(get_error(res))

    issues_res = []
    if res and isinstance(res, list):
        for entry in res:
            if isinstance(entry, dict) and (contents := entry.get("Contents")):
                if isinstance(contents, dict) and (alerts := contents.get("alerts")):
                    issues_res = alerts if alerts is not None else []
                    break

    return issues_res[0].get("alert_fields") if issues_res else None


def get_all_issues_for_time_window_and_exact_match(
    exact_match_fields: set[str],
    issue: dict,
    from_date: str | None,
    to_date: str | None,
    limit: int,
    replacements: dict,
    custom_filter: dict | None = None,
):
    """
    Get issues for a time window and exact match for some fields using core-get-issues
    :param exact_match_fields: Set of field for exact match
    :param issue: json representing the current issue
    :param from_date: from_date
    :param to_date: to_date
    :param limit: limit of how many issues we want to query
    :param replacements: dictionary of replacements for field mapping
    :param custom_filter: dictionary of additional filters
    :return:
    """
    msg = ""
    base_args = {
        "start_time": from_date,
        "end_time": to_date,
        "time_frame": "custom",
    }

    if custom_filter:
        base_args["custom_filter"] = custom_filter

    for exact_match_field in exact_match_fields:
        # The field in the 'issue' dict might be the mapped name (e.g., resolution_status)
        # while the argument for core-get-issues might be the original name (e.g., status).
        mapped_field = replacements.get(exact_match_field, exact_match_field)
        if mapped_field in issue:
            base_args[exact_match_field] = issue[mapped_field]
        elif exact_match_field in issue:
            base_args[exact_match_field] = issue[exact_match_field]
        else:
            msg += f"{MESSAGE_NO_FIELD % exact_match_field} \n"

    demisto.debug(f"Base args sent to core-get-issues to filter by: {base_args}")
    all_issues: list[dict] = []
    page_size = 50
    current_issue_id = str(issue.get("internal_id"))

    # Prepare batch commands
    commands = []
    for offset in range(0, limit, page_size):
        current_batch_limit = min(limit, offset + page_size)
        args = {**base_args, "offset": offset, "limit": current_batch_limit}
        commands.append({"core-get-issues": args})

    demisto.debug(f"Calling core-get-issues in batch with {len(commands)} commands.")
    batch_results = demisto.executeCommandBatch(commands)

    for results_list in batch_results:
        for res in results_list:
            if is_error(res):
                return_error(get_error(res))

            batch_issues = []
            if res and isinstance(res, dict) and (contents := res.get("Contents")):
                if isinstance(contents, dict) and (alerts := contents.get("alerts")):
                    batch_issues = alerts if alerts is not None else []

            if not batch_issues:
                continue

            # Filter out the current issue and extract alert_fields
            filtered_batch = [
                i.get("alert_fields") for i in batch_issues
                if str(i.get("alert_fields", {}).get("internal_id")) != current_issue_id
            ]

            all_issues.extend(filtered_batch)

            # If we got fewer results than requested in a batch, it might indicate we reached the end
            if len(batch_issues) < page_size:
                break

    demisto.debug(f"Total issues fetched: {len(all_issues)}")
    if not all_issues:
        msg += f"{MESSAGE_NO_INCIDENT_FETCHED} \n"
        return None, msg
    
    if len(all_issues) == limit:
        all_issues.pop()
    
    return all_issues, msg


def load_current_issue(issue_id: str | None, from_date: str | None, to_date: str | None):
    """
    Load current issue if issue_id given or load current issue investigated
    :param issue_id: issue_id
    :param from_date: from_date
    :param to_date: to_date
    :return:
    """
    issue = get_issue_by_id(issue_id, from_date, to_date)
    if not issue:
        return None, issue_id
    return issue, issue_id


def return_outputs_summary(
    confidence: float, number_issue_fetched: int, number_issues_found: int, fields_used: list[str], global_msg: str
) -> None:
    """
    Return entry for summary of the automation - Give information about the automation run
    :param confidence: confidence level given by the user
    :param number_issue_fetched: number of issue fetched from the instance
    :param number_issues_found: number of similar issue found
    :param fields_used: Fields used to find similarity
    :param global_msg: informative message
    :return:
    """
    summary = {
        "Confidence": str(confidence),
        f"Number of {INCIDENT_ALIAS}s fetched with exact match ": number_issue_fetched,
        f"Number of similar {INCIDENT_ALIAS}s found ": number_issues_found,
        "Valid fields used for similarity": ", ".join(fields_used),
    }
    return_outputs(readable_output=global_msg + tableToMarkdown("Summary", summary))


def return_outputs_similar_issues(
    show_actual_issue: str | bool | None,
    current_issue: pd.DataFrame,
    similar_issues: pd.DataFrame,
    context: dict,
    tag: str | None = None,
):
    """
    Return entry and context for similar issues
    :param show_actual_issue: Boolean if showing the current issue
    :param current_issue: current issue
    :param similar_issues: DataFrame of the similar issues
    :param context: context for the entry
    :param tag: tag for the entry
    :return: None
    """
    colums_to_display = similar_issues.columns.tolist()
    colums_to_display = [x for x in FIRST_COLUMNS_INCIDENTS_DISPLAY if x in similar_issues.columns] + [
        x for x in colums_to_display if (x not in FIRST_COLUMNS_INCIDENTS_DISPLAY and x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY)
    ]

    first_col = [x for x in colums_to_display if x in current_issue.columns]
    col_current_issue_to_display = first_col + [
        x for x in current_issue.columns if (x not in first_col and x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY)
    ]

    rename_map = {"internal_id": "issue_id"}
    similar_issues = similar_issues.rename(columns=rename_map)
    current_issue = current_issue.rename(columns=rename_map)

    colums_to_display = [rename_map.get(x, x) for x in colums_to_display]
    col_current_issue_to_display = [rename_map.get(x, x) for x in col_current_issue_to_display]

    similar_issues = similar_issues.rename(lambda x: str(x).replace("_", " ").title(), axis="columns")
    current_issue = current_issue.rename(lambda x: str(x).replace("_", " ").title(), axis="columns")

    colums_to_display = [str(x).replace("_", " ").title() for x in colums_to_display]
    col_current_issue_to_display = [str(x).replace("_", " ").title() for x in col_current_issue_to_display]

    similar_issues = similar_issues.replace(np.nan, "", regex=True)
    current_issue = current_issue.replace(np.nan, "", regex=True)

    similar_issues_json = similar_issues.to_dict(orient="records")
    issue_json = current_issue.to_dict(orient="records")

    if str(show_actual_issue) == "True":
        return_outputs(
            readable_output=tableToMarkdown(
                f"Current {INCIDENT_ALIAS.capitalize()}", issue_json, col_current_issue_to_display
            )
        )
    readable_output = tableToMarkdown(f"Similar {INCIDENT_ALIAS.capitalize()}s", similar_issues_json, colums_to_display)
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats["json"],
        "Contents": similar_issues_json,
        "EntryContext": {"SimilarIssues": context},
    }
    if tag is not None:
        return_entry["Tags"] = [f"SimilarIssues_{tag}"]
    demisto.results(return_entry)


def return_outputs_error(error_msg):
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": error_msg,
        "ContentsFormat": formats["json"],
        "Contents": None,
        "EntryContext": None,
        "Tags": ["Error.id"],
    }
    demisto.results(return_entry)


def return_outputs_similar_issues_empty():
    """
    Return entry and context for similar issues if no similar issues were found
    :return:
    """
    return_outputs(
        readable_output=f"### Similar {INCIDENT_ALIAS.capitalize()}\nNo Similar {INCIDENT_ALIAS}s were found.",
        outputs={"SimilarIssues": create_context_for_issues()},
    )


def create_context_for_issues(similar_issues=pd.DataFrame()):
    """
    Return context from dataframe of issue
    :param similar_issues: DataFrame of issues with indicators
    :return: context
    """
    df = similar_issues.copy()

    rename_map = {
        SIMILARITY_COLUNM_NAME: "similarityIssue",
        "id": "id",
        "name": "name",
        "details": "details",
        "Identical indicators": "identicalIndicators",
        SIMILARITY_COLUNM_NAME_INDICATOR: "similarityIndicators"
    }

    df = df.rename(columns=rename_map)
    df = df.replace(np.nan, "", regex=True)

    if len(df) == 0:
        context = {"isSimilarIssueFound": False}
    else:
        context = {
            "executionSummary": "Execution completed successfully.",
            "similarIssue": (df.to_dict(orient="records")),
            "isSimilarIssueFound": True
        }
    return context


def main():
    args = demisto.args()

    # Apply mappings from SearchSimilarIssues
    replacements = {
        "status": "resolution_status",
        "assignee": "assigned_to_pretty",
        "type": "issue_type",
        "category": "issue_category",
        "name": "issue_name",
        "description": "issue_description",
        "id": "issue_id",
        "domain": "issue_domain",
        "source": "issue_source"
    }
    args = replace_fields(args, replacements)
    args = update_args(args)

    custom_filter = args.get("custom_filter")
    exact_match_fields = set(argToList(args.get("fieldExactMatch")))
    similar_text_field = set(argToList(args.get("similarTextField")))
    similar_categorical_field = set(argToList(args.get("similarCategoricalField")))
    similar_json_field = set(argToList(args.get("similarJsonField")))

    if not (similar_text_field | similar_categorical_field | similar_json_field):
        raise DemistoException("Please provide at least one of the following args: text_similarity_fields, discrete_match_fields, json_similarity_fields.")

    display_fields = {"internal_id", "issue_name", "issue_description"} | set(argToList(args.get("fieldsToDisplay")))

    # Ensure internal_id is always present in display fields for processing
    display_fields.add("internal_id")

    from_date = arg_to_datetime(args.get("fromDate"))
    to_date = arg_to_datetime(args.get("toDate"))

    from_date_str = str(date_to_timestamp(from_date, TIME_FORMAT)) if from_date else None
    to_date_str = str(date_to_timestamp(to_date, TIME_FORMAT)) if to_date else None
    show_distance = args.get("showIncidentSimilarityForAllFields")
    confidence = float(args.get("minimunIncidentSimilarity") or 0.2)
    max_issues = int(args.get("maxIncidentsToDisplay") or 100)
    aggregate = args.get("aggreagateIncidentsDifferentDate") or "False"
    limit = int(args.get("limit") or 1500) + 1
    show_actual_issue = args.get("showCurrentIncident")
    issue_id = args.get("incidentId")
    include_indicators_similarity = args.get("includeIndicatorsSimilarity") or "False"

    global_msg = ""

    issue, issue_id = load_current_issue(issue_id, from_date_str, to_date_str)
    if not issue:
        return_outputs_error(error_msg=f"{MESSAGE_NO_CURRENT_INCIDENT % issue_id} \n")
        return None, global_msg

    # load the related issues
    issues_res = get_all_issues_for_time_window_and_exact_match(
        exact_match_fields, issue, from_date_str, to_date_str, limit, replacements, custom_filter
    )
    if issues_res:
        issues, msg = issues_res
    else:
        issues, msg = None, ""
    global_msg += f"{msg} \n"

    if issues:
        demisto.debug(f"Found {len(issues)} {INCIDENT_ALIAS}s for {issue_id=}")
    else:
        demisto.debug(f"No {INCIDENT_ALIAS}s found for {issue_id=}")
        return_outputs_summary(confidence, 0, 0, [], global_msg)
        return_outputs_similar_issues_empty()
        return None, global_msg
    number_issue_fetched = len(issues)

    issues_df = pd.DataFrame(issues)
    issues_df.index = issues_df.internal_id

    issues_df = fill_nested_fields(issues_df, issues, list(similar_text_field), list(similar_categorical_field))

    # Find given fields that does not exist in the issue
    # We filter out fields that were used for exact match but not for similarity
    # because they might not exist as columns in the returned dataframe (mapped fields).
    fields_to_check_existence = [f for f in (similar_text_field | similar_json_field | similar_categorical_field)]
    global_msg, incorrect_fields = find_incorrect_fields(fields_to_check_existence, issues_df, global_msg)

    # remove fields that does not exist in the issues
    display_fields, similar_text_field, similar_json_field, similar_categorical_field = [
        list(set(f) - set(incorrect_fields)) for f in [display_fields, similar_text_field, similar_json_field, similar_categorical_field]
    ]

    # Dumps all dict in the current issue
    issue_df = dumps_json_field_in_incident(deepcopy(issue))
    issue_df = fill_nested_fields(issue_df, issue, list(similar_text_field), list(similar_categorical_field))

    # Model prediction
    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(
        issue_df, issues_df, list(similar_text_field), list(similar_categorical_field), list(display_fields), list(similar_json_field)
    )
    try:
        similar_issues, fields_used = model.predict()
    except DemistoException as e:
        global_msg += f"{MESSAGE_NO_FIELDS_USED.format(str(e))} \n"
        return_outputs_summary(confidence, number_issue_fetched, 0, [], global_msg)
        return_outputs_similar_issues_empty()
        return None, global_msg

    if isinstance(similar_issues, pd.Series):
        similar_issues = similar_issues.to_frame().T

    similar_issues = prepare_incidents_for_display(
        similar_issues,
        confidence,
        argToBoolean(show_distance or "False"),
        max_issues,
        fields_used,
        str(aggregate),
        argToBoolean(include_indicators_similarity)
    )

    # Filter issue to investigate
    issue_filter = prepare_current_incident(
        issue_df, list(display_fields), list(similar_text_field), list(similar_json_field), list(similar_categorical_field), list(exact_match_fields)
    )

    # Return summary outputs of the automation
    number_issues_found = len(similar_issues)
    return_outputs_summary(confidence, number_issue_fetched, number_issues_found, fields_used, global_msg)

    # Create context and outputs
    context = create_context_for_issues(similar_issues)
    return_outputs_similar_issues(show_actual_issue, issue_filter, similar_issues, context, TAG_INCIDENT)
    return similar_issues, global_msg


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
