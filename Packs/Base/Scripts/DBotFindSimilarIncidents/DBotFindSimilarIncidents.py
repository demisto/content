import demistomock as demisto
import pandas as pd
from CommonServerPython import *
from GetIncidentsApiModule import *  # noqa: E402
from SimilarObjectApiModule import *  # noqa: E402

from CommonServerUserPython import *


def get_incident_by_id(incident_id: str, populate_fields: list[str], from_date: str, to_date: str):
    """
    Get incident acording to incident id
    :param incident_id:
    :param populate_fields:
    :param from_date: from_date
    :param to_date: to_date
    :return: Get incident acording to incident id
    """
    populate_fields_value = " , ".join(populate_fields)
    demisto.debug(
        f"Calling get_incidents_by_query for {incident_id=} between {from_date=} and {to_date=},{populate_fields_value=}"
    )
    incidents = get_incidents_by_query(
        {
            "query": f"id:({incident_id})",
            "populateFields": populate_fields_value,
            "fromDate": from_date,
            "toDate": to_date,
        }
    )
    return incidents[0] if incidents else None


def get_all_incidents_for_time_window_and_exact_match(
    exact_match_fields: list[str],
    populate_fields: list[str],
    incident: dict,
    from_date: str,
    to_date: str,
    query_sup: str,
    limit: int,
):
    """
    Get incidents for a time window and exact match for somes fields
    :param exact_match_fields: List of field for exact match
    :param populate_fields: List of field to populate
    :param incident: json representing the current incident
    :param from_date: from_date
    :param to_date: to_date
    :param query_sup: additional query
    :param limit: limit of how many incidents we want to query
    :return:
    """
    msg = ""
    exact_match_fields_list = []
    for exact_match_field in exact_match_fields:
        if exact_match_field not in incident:
            msg += f"{MESSAGE_NO_FIELD % exact_match_field} \n"
        else:
            exact_match_fields_list.append(f'{exact_match_field}: "{incident[exact_match_field]}"')
    query = " AND ".join(exact_match_fields_list)
    query += f" AND -id:{incident['id']} "
    if query_sup:
        query += f" {query_sup}"

    populate_fields_value = " , ".join(populate_fields)
    demisto.debug(f"Calling get_incidents_by_query between {from_date=} and {to_date=},{limit=}, {populate_fields_value=}")

    incidents = get_incidents_by_query(
        {"query": query, "populateFields": populate_fields_value, "fromDate": from_date, "toDate": to_date, "limit": limit}
    )
    if len(incidents) == 0:
        msg += f"{MESSAGE_NO_INCIDENT_FETCHED} \n"
        return None, msg
    if len(incidents) == limit:
        msg += f"{MESSAGE_WARNING_TRUNCATED % (str(len(incidents)), str(limit))} \n"
        return incidents, msg
    return incidents, msg


def load_current_incident(incident_id: str, populate_fields: list[str], from_date: str, to_date: str):
    """
    Load current incident if incident_id given or load current incident investigated
    :param incident_id: incident_id
    :param populate_fields: populate_fields
    :param from_date: from_date
    :param to_date: to_date
    :return:
    """
    if not incident_id:
        incident = demisto.incidents()[0]
        cf = incident.pop("CustomFields", {}) or {}
        incident.update(cf)
        incident = {k: v for k, v in incident.items() if k in populate_fields}
        incident_id = incident["id"]
    else:
        incident = get_incident_by_id(incident_id, populate_fields, from_date, to_date)
        if not incident:
            return None, incident_id
    return incident, incident_id


def get_similar_incidents_by_indicators(args: dict):
    """
    Use DBotFindSimilarIncidentsByIndicators automation and return similars incident from the automation
    :param args: argument for DBotFindSimilarIncidentsByIndicators automation
    :return:  return similars incident from the automation
    """
    demisto.debug("Executing DBotFindSimilarIncidentsByIndicators")
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
    confidence: float, number_incident_fetched: int, number_incidents_found: int, fields_used: list[str], global_msg: str
) -> None:
    """
    Return entry for summary of the automation - Give information about the automation run
    :param confidence: confidence level given by the user
    :param number_incident_fetched: number of incident fetched from the instance
    :param number_incidents_found: number of similar incident found
    :param fields_used: Fields used to find similarity
    :param global_msg: informative message
    :return:
    """
    summary = {
        "Confidence": str(confidence),
        f"Number of {INCIDENT_ALIAS}s fetched with exact match ": number_incident_fetched,
        f"Number of similar {INCIDENT_ALIAS}s found ": number_incidents_found,
        "Valid fields used for similarity": ", ".join(fields_used),
    }
    return_outputs(readable_output=global_msg + tableToMarkdown("Summary", summary))


def return_outputs_similar_incidents(
    show_actual_incident: bool,
    current_incident: pd.DataFrame,
    similar_incidents: pd.DataFrame,
    context: dict,
    tag: str | None = None,
):
    """
    Return entry and context for similar incidents
    :param show_actual_incident: Boolean if showing the current incident
    :param current_incident: current incident
    :param similar_incidents: DataFrame of the similar incidents
    :param colums_to_display: List of columns we want to show in the tableToMarkdown
    :param context: context for the entry
    :param tag: tag for the entry
    :return: None
    """
    # Columns to show for outputs
    colums_to_display = similar_incidents.columns.tolist()
    colums_to_display = [x for x in FIRST_COLUMNS_INCIDENTS_DISPLAY if x in similar_incidents.columns] + [
        x for x in colums_to_display if (x not in FIRST_COLUMNS_INCIDENTS_DISPLAY and x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY)
    ]

    first_col = [x for x in colums_to_display if x in current_incident.columns]
    col_current_incident_to_display = first_col + [
        x for x in current_incident.columns if (x not in first_col and x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY)
    ]

    similar_incidents = similar_incidents.rename(str.title, axis="columns")
    current_incident = current_incident.rename(str.title, axis="columns")

    colums_to_display = [x.title() for x in colums_to_display]
    col_current_incident_to_display = [x.title() for x in col_current_incident_to_display]

    similar_incidents = similar_incidents.replace(np.nan, "", regex=True)
    current_incident = current_incident.replace(np.nan, "", regex=True)

    similar_incidents_json = similar_incidents.to_dict(orient="records")
    incident_json = current_incident.to_dict(orient="records")

    if show_actual_incident == "True":
        return_outputs(
            readable_output=tableToMarkdown(
                f"Current {INCIDENT_ALIAS.capitalize()}", incident_json, col_current_incident_to_display
            )
        )
    readable_output = tableToMarkdown(f"Similar {INCIDENT_ALIAS.capitalize()}s", similar_incidents_json, colums_to_display)
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats["json"],
        "Contents": similar_incidents_json,
        "EntryContext": {"DBotFindSimilarIncidents": context},
    }
    if tag is not None:
        return_entry["Tags"] = [f"SimilarIncidents_{tag}"]
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


def return_outputs_similar_incidents_empty():
    """
    Return entry and context for similar incidents if no similar incidents were found
    :return:
    """
    return_outputs(
        readable_output=f"### Similar {INCIDENT_ALIAS.capitalize()}\nNo Similar {INCIDENT_ALIAS}s were found.",
        outputs={"DBotFindSimilarIncidents": create_context_for_incidents()},
    )


def enriched_with_indicators_similarity(full_args_indicators_script: dict, similar_incidents: pd.DataFrame):
    """
    Take DataFrame of similar_incidents and args for indicators script and add information about indicators
    to similar_incidents
    :param full_args_indicators_script: args for indicators script
    :param similar_incidents: DataFrame of incidents
    :return: similar_incidents enriched with indicators data
    """
    indicators_similarity_json = get_similar_incidents_by_indicators(full_args_indicators_script)
    indicators_similarity_df = pd.DataFrame(indicators_similarity_json)
    if indicators_similarity_df.empty:
        indicators_similarity_df = pd.DataFrame(columns=[SIMILARITY_COLUNM_NAME_INDICATOR, "Identical indicators", "id"])
    keep_columns = [x for x in KEEP_COLUMNS_INDICATORS if x not in similar_incidents]
    indicators_similarity_df.index = indicators_similarity_df.id
    similar_incidents.loc[:, keep_columns] = indicators_similarity_df[keep_columns]
    values = {SIMILARITY_COLUNM_NAME_INDICATOR: 0, "Identical indicators": ""}
    similar_incidents = similar_incidents.fillna(value=values)
    return similar_incidents


def main():
    args = demisto.args()
    exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field = get_field_args(args)

    display_fields = list(set(["id", "created", "name"] + argToList(args.get("fieldsToDisplay"))))

    from_date = args.get("fromDate")
    to_date = args.get("toDate")
    show_distance = args.get("showIncidentSimilarityForAllFields")
    confidence = float(args.get("minimunIncidentSimilarity"))
    max_incidents = int(args.get("maxIncidentsToDisplay"))
    query = args.get("query")
    aggregate = args.get("aggreagateIncidentsDifferentDate")
    limit = int(args["limit"])
    show_actual_incident = args.get("showCurrentIncident")
    incident_id = args.get("incidentId")
    include_indicators_similarity = args.get("includeIndicatorsSimilarity")

    global_msg = ""

    populate_fields = (
        similar_text_field + similar_json_field + similar_categorical_field + exact_match_fields + display_fields + ["id"]
    )
    populate_high_level_fields = keep_high_level_field(populate_fields)

    incident, incident_id = load_current_incident(incident_id, populate_high_level_fields, from_date, to_date)
    if not incident:
        return_outputs_error(error_msg=f"{MESSAGE_NO_CURRENT_INCIDENT % incident_id} \n")
        return None, global_msg

    # load the related incidents
    populate_fields.remove("id")
    incidents, msg = get_all_incidents_for_time_window_and_exact_match(
        exact_match_fields, populate_high_level_fields, incident, from_date, to_date, query, limit
    )
    print(incidents)
    global_msg += f"{msg} \n"

    if incidents:
        demisto.debug(f"Found {len(incidents)} {INCIDENT_ALIAS}s for {incident_id=}")
    else:
        demisto.debug(f"No {INCIDENT_ALIAS}s found for {incident_id=}")
        return_outputs_summary(confidence, 0, 0, [], global_msg)
        return_outputs_similar_incidents_empty()
        return None, global_msg
    number_incident_fetched = len(incidents)

    incidents_df = pd.DataFrame(incidents)
    incidents_df.index = incidents_df.id

    incidents_df = fill_nested_fields(incidents_df, incidents, similar_text_field, similar_categorical_field)

    # Find given fields that does not exist in the incident
    global_msg, incorrect_fields = find_incorrect_fields(populate_fields, incidents_df, global_msg)

    # remove fields that does not exist in the incidents
    display_fields, similar_text_field, similar_json_field, similar_categorical_field = remove_fields_not_in_incident(
        display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields=incorrect_fields
    )

    # Dumps all dict in the current incident
    incident_df = dumps_json_field_in_incident(deepcopy(incident))
    incident_df = fill_nested_fields(incident_df, incident, similar_text_field, similar_categorical_field)

    # Model prediction
    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(
        incident_df, incidents_df, similar_text_field, similar_categorical_field, display_fields, similar_json_field
    )
    try:
        similar_incidents, fields_used = model.predict()
    except DemistoException as e:
        global_msg += f"{MESSAGE_NO_FIELDS_USED.format(str(e))} \n"
        return_outputs_summary(confidence, number_incident_fetched, 0, [], global_msg)
        return_outputs_similar_incidents_empty()
        return None, global_msg

    # Get similarity based on indicators
    if include_indicators_similarity == "True":
        args_defined_by_user = {key: args.get(key) for key in KEYS_ARGS_INDICATORS}
        full_args_indicators_script = {**CONST_PARAMETERS_INDICATORS_SCRIPT, **args_defined_by_user}
        similar_incidents = enriched_with_indicators_similarity(full_args_indicators_script, similar_incidents)

    similar_incidents = prepare_incidents_for_display(
        similar_incidents, confidence, show_distance, max_incidents, fields_used, aggregate, include_indicators_similarity
    )

    # Filter incident to investigate
    incident_filter = prepare_current_incident(
        incident_df, display_fields, similar_text_field, similar_json_field, similar_categorical_field, exact_match_fields
    )

    # Return summary outputs of the automation
    number_incidents_found = len(similar_incidents)
    return_outputs_summary(confidence, number_incident_fetched, number_incidents_found, fields_used, global_msg)

    # Create context and outputs
    context = create_context_for_incidents(similar_incidents)
    return_outputs_similar_incidents(show_actual_incident, incident_filter, similar_incidents, context, TAG_INCIDENT)
    return similar_incidents, global_msg


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
