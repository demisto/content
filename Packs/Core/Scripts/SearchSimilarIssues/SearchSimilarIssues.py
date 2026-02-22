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
        "use_all_fields": "useAllFields",
        "from_date": "fromDate",
        "to_date": "toDate",
        "aggregate_issues_different_date": "aggreagateIncidentsDifferentDate",
        "include_indicators_similarity": "includeIndicatorsSimilarity",
        "min_number_of_indicators": "minNumberOfIndicators",
        "indicators_types": "indicatorsTypes",
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
    :param replacements: dictionary of replacements, e.g. {"status": "status.progress", "domain": "alert_domain"}
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

        updated_fields = [replacements.get(f, f) for f in fields]
        args[key] = ",".join(updated_fields)

    return args


def get_issue_by_id(issue_id: str, from_date: str | None, to_date: str | None):
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

    contents_1 = res[0].get("Contents", {}) if res else None
    contents_2 = res[1].get("Contents", {}) if res else None
    if isinstance(contents_1, dict):
        issues_res = contents_1.get("alerts", {})
    elif isinstance(contents_2, dict):
        issues_res = contents_2.get("alerts", {})
        
    if isinstance(issues_res, list) and len(issues_res) > 0:
        issue = issues_res[0].get("alert_fields")
    # issues = contents if isinstance(contents, list) else []
    
    return issue


def get_all_issues_for_time_window_and_exact_match(
    exact_match_fields: list[str],
    issue: dict,
    from_date: str,
    to_date: str,
    query_sup: str,
    limit: int,
):
    """
    Get issues for a time window and exact match for some fields using core-get-issues
    :param exact_match_fields: List of field for exact match
    :param issue: json representing the current issue
    :param from_date: from_date
    :param to_date: to_date
    :param query_sup: additional query
    :param limit: limit of how many issues we want to query
    :return:
    """
    msg = ""
    args = {
        "start_time": from_date,
        "end_time": to_date,
        "time_frame": "custom",
        "limit": limit,
    }

    for exact_match_field in exact_match_fields:
        if exact_match_field not in issue:
            msg += f"{MESSAGE_NO_FIELD % exact_match_field} \n"
        else:
            args[exact_match_field] = issue[exact_match_field]

    demisto.debug(f"Calling core-get-issues with {args=}")
    res = demisto.executeCommand("core-get-issues", args)
    if is_error(res):
        return_error(get_error(res))

    contents_1 = res[0].get("Contents", {}) if res else None
    contents_2 = res[1].get("Contents", {}) if res else None
    if isinstance(contents_1, dict):
        issues = contents_1.get("alerts", {})
    else:
        issues = contents_2.get("alerts", {})
    
    # Filter out the current issue
    issues = [i.get("alert_fields") for i in issues if str(i.get("internal_id")) != str(issue.get("internal_id"))]
    if len(issues) == 0:
        msg += f"{MESSAGE_NO_INCIDENT_FETCHED} \n"
        return None, msg
    if len(issues) >= limit:
        msg += f"{MESSAGE_WARNING_TRUNCATED % (str(len(issues)), str(limit))} \n"
        return issues, msg
    return issues, msg


def load_current_issue(issue_id: str | None, from_date: str | None, to_date: str | None):
    """
    Load current issue if issue_id given or load current issue investigated
    :param issue_id: issue_id
    :param from_date: from_date
    :param to_date: to_date
    :return:
    """
    # seems that the if part returned with different fields from the core-get-issues.
    # if not issue_id:
    #     # In XSIAM/Platform, issues are often in the context
    #     incidents = demisto.incidents()
    #     print(incidents)
    #     if not incidents:
    #         return None, None
    #     issue_id = incidents[0].get("id")
    #     if not issue_id:
    #         return None, None
    #     issue = get_issue_by_id(issue_id, from_date or "", to_date or "")
    #     if not issue:
    #         return None, issue_id
    # else:
    issue = get_issue_by_id(issue_id, from_date, to_date)
    if not issue:
        return None, issue_id
    return issue, issue_id


def get_similar_issues_by_indicators(args: dict):
    """
    Use DBotFindSimilarIncidentsByIndicators automation and return similar issues from the automation
    :param args: argument for DBotFindSimilarIncidentsByIndicators automation
    :return:  return similar issues from the automation
    """
    demisto.debug("Executing DBotFindSimilarIncidentsByIndicators")
    # Note: The underlying script might still be named DBotFindSimilarIncidentsByIndicators
    res = demisto.executeCommand("DBotFindSimilarIncidentsByIndicators", args)
    if is_error(res):
        return_error(get_error(res))
    res = get_data_from_indicators_automation(res, TAG_SCRIPT_INDICATORS)
    return res


def get_data_from_indicators_automation(res, TAG_SCRIPT_INDICATORS_VALUE):
    if res is not None:
        for entry in res:
            if entry and entry.get("Tags") and TAG_SCRIPT_INDICATORS_VALUE in entry.get("Tags"):
                return entry["Contents"]
    return None


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
    display_df = similar_issues.copy()

    rename_map = {
        SIMILARITY_COLUNM_NAME: "Similarity Issue",
        "id": "Issue ID",
        "created": "Created",
        "name": "Name"
    }

    colums_to_display = display_df.columns.tolist()
    colums_to_display = [x for x in colums_to_display if x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY]

    display_df = display_df.rename(columns=rename_map)
    colums_to_display = [rename_map.get(x, x) for x in colums_to_display if rename_map.get(x, x)]

    display_df = display_df.rename(str.title, axis="columns")
    colums_to_display = [str(x).title() for x in colums_to_display]

    current_issue_display = current_issue.copy()
    current_issue_display = current_issue_display.rename(columns=rename_map)
    current_issue_display = current_issue_display.rename(str.title, axis="columns")

    col_current_issue_to_display = current_issue_display.columns.tolist()
    col_current_issue_to_display = [x for x in col_current_issue_to_display if x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY]
    col_current_issue_to_display = [str(x).title() for x in col_current_issue_to_display]

    display_df = display_df.replace(np.nan, "", regex=True)
    current_issue_display = current_issue_display.replace(np.nan, "", regex=True)

    similar_issues_json = display_df.to_dict(orient="records")
    issue_json = current_issue_display.to_dict(orient="records")

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


def enriched_with_indicators_similarity(full_args_indicators_script: dict, similar_issues: pd.DataFrame):
    """
    Take DataFrame of similar_issues and args for indicators script and add information about indicators
    to similar_issues
    :param full_args_indicators_script: args for indicators script
    :param similar_issues: DataFrame of issues
    :return: similar_issues enriched with indicators data
    """
    indicators_similarity_json = get_similar_issues_by_indicators(full_args_indicators_script)
    indicators_similarity_df = pd.DataFrame(indicators_similarity_json)
    if indicators_similarity_df.empty:
        indicators_similarity_df = pd.DataFrame(columns=[SIMILARITY_COLUNM_NAME_INDICATOR, "Identical indicators", "id"])
    keep_columns = [x for x in KEEP_COLUMNS_INDICATORS if x not in similar_issues]
    indicators_similarity_df.index = indicators_similarity_df.id
    similar_issues.loc[:, keep_columns] = indicators_similarity_df[keep_columns]
    values = {SIMILARITY_COLUNM_NAME_INDICATOR: 0, "Identical indicators": ""}
    similar_issues = similar_issues.fillna(value=values)
    return similar_issues


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
        "created": "created",
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
    replacements = {"status": "status.progress", "type": "alert_type", "category": "categoryname", "url": "alerturl", "name": "issue_name"}
    args = replace_fields(args, replacements)
    args = update_args(args)

    exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field = get_field_args(args)

    display_fields = list(set(["id", "created", "name", "details"] + argToList(args.get("fieldsToDisplay"))))

    from_date = date_to_timestamp(arg_to_datetime(args.get("fromDate"), TIME_FORMAT))
    to_date = date_to_timestamp(arg_to_datetime(args.get("toDate"), TIME_FORMAT))
    show_distance = args.get("showIncidentSimilarityForAllFields")
    confidence = float(args.get("minimunIncidentSimilarity") or 0.2)
    max_issues = int(args.get("maxIncidentsToDisplay") or 100)
    query = args.get("query") or ""
    aggregate = args.get("aggreagateIncidentsDifferentDate") or "False"
    limit = int(args.get("limit") or 1500)
    show_actual_issue = args.get("showCurrentIncident")
    issue_id = args.get("incidentId")
    include_indicators_similarity = args.get("includeIndicatorsSimilarity") or "False"

    global_msg = ""

    populate_fields = (
        similar_text_field + similar_json_field + similar_categorical_field + exact_match_fields + display_fields + ["id"]
    )
    # populate_high_level_fields = keep_high_level_field(populate_fields)

    issue, issue_id = load_current_issue(issue_id, from_date, to_date)
    if not issue:
        return_outputs_error(error_msg=f"{MESSAGE_NO_CURRENT_INCIDENT % issue_id} \n")
        return None, global_msg

    # load the related issues
    issues, msg = get_all_issues_for_time_window_and_exact_match(
        exact_match_fields, issue, from_date, to_date, query, limit
    )
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

    issues_df = fill_nested_fields(issues_df, issues, similar_text_field, similar_categorical_field)

    # Find given fields that does not exist in the issue
    global_msg, incorrect_fields = find_incorrect_fields(populate_fields, issues_df, global_msg)

    # remove fields that does not exist in the issues
    display_fields, similar_text_field, similar_json_field, similar_categorical_field = remove_fields_not_in_incident(
        display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields=incorrect_fields
    )

    # Dumps all dict in the current issue
    issue_df = dumps_json_field_in_incident(deepcopy(issue))
    issue_df = fill_nested_fields(issue_df, issue, similar_text_field, similar_categorical_field)

    # Model prediction
    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(
        issue_df, issues_df, similar_text_field, similar_categorical_field, display_fields, similar_json_field
    )
    try:
        similar_issues, fields_used = model.predict()
    except DemistoException as e:
        global_msg += f"{MESSAGE_NO_FIELDS_USED.format(str(e))} \n"
        return_outputs_summary(confidence, number_issue_fetched, 0, [], global_msg)
        return_outputs_similar_issues_empty()
        return None, global_msg

    # Get similarity based on indicators
    if include_indicators_similarity == "True":
        args_defined_by_user = {key: args.get(key) for key in KEYS_ARGS_INDICATORS}
        full_args_indicators_script = {**CONST_PARAMETERS_INDICATORS_SCRIPT, **args_defined_by_user}
        similar_issues = enriched_with_indicators_similarity(full_args_indicators_script, similar_issues)

    if isinstance(similar_issues, pd.Series):
        similar_issues = similar_issues.to_frame().T

    similar_issues = prepare_incidents_for_display(
        similar_issues, confidence, str(show_distance or "False"), max_issues, fields_used, str(aggregate), str(include_indicators_similarity)
    )

    # Filter issue to investigate
    issue_filter = prepare_current_incident(
        issue_df, display_fields, similar_text_field, similar_json_field, similar_categorical_field, exact_match_fields
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
