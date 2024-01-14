import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
import numpy as np
from collections import Counter
import re
import math

STATUS_DICT = {
    0: "Pending",
    1: "Active",
    2: "Closed",
    3: "Archive",
}

ROUND_SCORING = 2
PLAYGROUND_PATTERN = "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"
FIRST_COLUMNS_INCIDENTS_DISPLAY = ["incident ID", "created", "name"]
FIELDS_TO_EXCLUDE_FROM_DISPLAY = ["id"]
INCIDENT_FIELDS_TO_USE = ["indicators"]
FIELD_INDICATOR_TYPE = "indicator_type"


def flatten_list(my_list: list[list]) -> list:
    """
    Flatten a list of list
    :param l: list of list
    :return: list
    """
    return [item for sublist in my_list for item in sublist]


class FrequencyIndicators(BaseEstimator, TransformerMixin):
    """
    FrequencyIndicators class for indicator frequencies computation
    """

    def __init__(self, incident_field, normalize_function, current_incident):
        self.incident_field = incident_field
        self.normalize_function = normalize_function
        self.frequency = {}
        if self.normalize_function:
            current_incident = current_incident[self.incident_field].apply(self.normalize_function)
        else:
            current_incident = current_incident[self.incident_field]
        self.vocabulary = current_incident.iloc[0].split(" ")

    def fit(self, x):
        if self.normalize_function:
            x = x[self.incident_field].apply(self.normalize_function)
        else:
            x = x[self.incident_field]
        size = len(x) + 1
        frequencies = Counter(flatten_list([t.split(" ") for t in x.values]))
        frequencies.update(Counter(self.vocabulary))
        self.frequency = {k: math.log(1 + size / v) for k, v in frequencies.items()}
        return self

    def transform(self, x):
        if self.normalize_function:
            x = x[self.incident_field].apply(self.normalize_function)
        else:
            x = x[self.incident_field]
        return x.apply(self.compute_term_score)

    def compute_term_score(self, indicators_values_string: str) -> float:
        x = indicators_values_string.split(" ")
        return sum([1 * self.frequency[word] for word in self.vocabulary if word in x]) / sum(
            [self.frequency[word] for word in self.vocabulary])


TRANSFORMATION = {
    "frequency_indicators": {
        "transformer": FrequencyIndicators,
        "normalize": None,
        "scoring_function": lambda x: x
    },
}


class Transformer:
    def __init__(self, p_transformer_type, incident_field, p_incidents_df, p_current_incident, p_params):
        """
        :param p_transformer_type: One of the key value of TRANSFORMATION dict
        :param incident_field: incident field used in this transformation
        :param p_incidents_df: DataFrame of incident (should contains one columns which same name than incident_field)
        :param p_current_incident: DataFrame of the current incident
        :param p_params: Dictionary of all the transformation - TRANSFORMATION
        """
        self.transformer_type = p_transformer_type
        self.incident_field = incident_field
        self.current_incident = p_current_incident
        self.incidents_df = p_incidents_df
        self.params = p_params

    def fit_transform(self):
        transformation = self.params[self.transformer_type]
        transformer = transformation["transformer"](self.incident_field, transformation["normalize"],
                                                    self.current_incident)
        X_vect = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.current_incident)
        return X_vect, incident_vect

    def get_score(self):
        scoring_function = self.params[self.transformer_type]["scoring_function"]
        X_vect, _ = self.fit_transform()
        distance = scoring_function(X_vect)
        self.incidents_df[f"similarity {self.incident_field}"] = np.round(distance, ROUND_SCORING)
        return self.incidents_df


class Model:
    def __init__(
        self,
        p_incident_to_match: pd.DataFrame,
        p_incidents_df: pd.DataFrame,
    ) -> None:
        """
        :param p_transformation: Dict with the transformers parameters - TRANSFORMATION
        :param p_incident_to_match: Dataframe with one incident
        :param p_incidents_df: Dataframe with all the incidents
        :param p_fields_indicators_transformation: list of incident fields that for the transformer "indicators"
        """
        self.transformation = TRANSFORMATION
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.fields_for_frequencyIndicators = INCIDENT_FIELDS_TO_USE

    def predict(self):
        self.remove_empty_field()
        self.get_score()
        self.prepare_for_display()
        return self.incidents_df

    def remove_empty_field(self):
        remove_list = [
            field for field in self.fields_for_frequencyIndicators
            if any([
                field not in self.incident_to_match.columns,
                not self.incident_to_match[field].values[0],
                not isinstance(self.incident_to_match[field].values[0], str),
                self.incident_to_match[field].values[0] == "None",
                self.incident_to_match[field].values[0] == "N/A",
            ])
        ]
        self.fields_for_frequencyIndicators = [
            x for x in self.fields_for_frequencyIndicators
            if x not in remove_list
        ]

    def get_score(self):
        for field in self.fields_for_frequencyIndicators:
            t = Transformer("frequency_indicators", field, self.incidents_df, self.incident_to_match,
                            self.transformation)
            t.get_score()

    def prepare_for_display(self):
        vocabulary = self.incident_to_match["indicators"].iloc[0].split(" ")
        self.incidents_df["Identical indicators"] = self.incidents_df["indicators"].apply(
            lambda x: ",".join([id for id in x.split(" ") if id in vocabulary]))


def get_indicators_of_actual_incident(
        incident_id: str,
        indicator_types: list[str],
        min_nb_of_indicators: int,
        max_indicators_for_white_list: int,
) -> dict[str, dict]:
    """ Returns a map between IDs of indicators in the actual incident to their data
    :param incident_id: ID of current incident
    :param indicators_types: list of indicators type accepted
    :param min_nb_of_indicators: Min number of indicators in the current incident
    :param max_indicators_for_white_list: Max incidents in indicators for white list
    :return: a map from indicator ids of the actual incident to their data
    """
    indicators = execute_command("findIndicators", {"query": f"investigationIDs:{incident_id}"}, fail_on_error=True)
    if not indicators:
        return {}
    indicators = [i for i in indicators if len(i.get("investigationIDs") or []) <= max_indicators_for_white_list]
    if indicator_types:
        indicators = [x for x in indicators if x[FIELD_INDICATOR_TYPE].lower() in indicator_types]
    if len(indicators) < min_nb_of_indicators:
        return {}
    return {ind["id"]: ind for ind in indicators}


def get_related_incidents(
    indicators: dict[str, dict],
    query: str,
    from_date: str | None,
) -> list[str]:
    """ Given indicators data including their related incidents,
    filters their related incidents by query and date and returns a list of the incident IDs.
    Return incident ids from a list of indicators
    :param indicators: List of indicators
    :return: [*incidents_ids]
    """
    incident_ids = flatten_list([i.get("investigationIDs") or [] for i in indicators.values()])
    incident_ids = list({x for x in incident_ids if not re.match(PLAYGROUND_PATTERN, x)})
    if not (query or from_date) or not incident_ids:
        return incident_ids
    res = execute_command(
        "GetIncidentsByQuery",
        args={
            "query": f"{query + ' AND ' if query else ''}incident.id:({' '.join(incident_ids)})",
            "populateFields": "id",
            "fromDate": from_date,
        },
        fail_on_error=True,
    )
    return [incident["id"] for incident in json.loads(res)]


def get_mutual_indicators(
    incident_ids: list[str],
    indicators_of_actual_incident: dict[str, dict],
) -> list[dict]:
    if not incident_ids or not indicators_of_actual_incident:
        return []

    return execute_command(
        "GetIndicatorsByQuery",
        args={
            "query": f"id:({' '.join(indicators_of_actual_incident)}) investigationIDs:({' '.join(incident_ids)})",
            "limit": "150",
            "populateFields": "id,indicator_type,investigationIDs,score,value"
        },
        fail_on_error=True,
    )


def get_mutual_indicators_df(
    indicators: list[dict],
    incident_ids: list[str],
) -> pd.DataFrame:
    indicators_df = pd.DataFrame(indicators)
    if not indicators_df.empty:
        indicators_df["Involved Incidents Count"] = indicators_df["investigationIDs"].apply(
            lambda inv_ids: sum(id_ in incident_ids for id_ in inv_ids),
        )
        indicators_df["Id"] = indicators_df["id"].apply(lambda x: f"[{x}](#/indicator/{x})")
        indicators_df = indicators_df.sort_values(["score", "Involved Incidents Count"], ascending=False)
        indicators_df["Reputation"] = indicators_df["score"].apply(scoreToReputation)  # pylint: disable=E1137
        indicators_df = indicators_df.rename({"value": "Value", "indicator_type": "Type"}, axis=1)
    return indicators_df


def mutual_indicators_results(mutual_indicators: list[dict], incident_ids: list[str]):
    indicators_df = get_mutual_indicators_df(mutual_indicators, incident_ids)
    readable_output = tableToMarkdown(
        "Mutual Indicators",
        indicators_df.to_dict(orient="records"),
        headers=["Id", "Value", "Type", "Reputation", "Involved Incidents Count"],
    )
    indicators_df = indicators_df.rename({"Value": "value"}, axis=1)
    return CommandResults(
        outputs=indicators_df[["id", "value"]].to_dict(orient="records"),
        outputs_prefix="MutualIndicators.indicators",
        readable_output=readable_output,
    )


def create_actual_incident_df(indicators_of_actual_incident: dict[str, dict]) -> pd.DataFrame:
    return pd.DataFrame(
        data=[" ".join(indicators_of_actual_incident.keys())],
        columns=["indicators"],
    )


def create_related_incidents_df(
    indicators: list[dict],
    incident_ids: list[str],
    actual_incident_id: str,
) -> dict[str, list]:
    """
    :param indicators: list of dict representing indicators
    :param incident_ids: list of incident ids
    :return: dict of {incident id : list of indicators ids related to this incident)
    """
    incidents_to_indicators = {
        inc_id: [
            indicator["id"] for indicator in indicators
            if inc_id in (indicator.get("investigationIDs") or [])
        ]
        for inc_id in incident_ids
    }
    return pd.DataFrame.from_dict(
        data={
            k: " ".join(v) for k, v in incidents_to_indicators.items()
            if k != actual_incident_id
        },
        orient="index",
        columns=["indicators"],
    )


def enrich_incidents(
    similar_incidents: pd.DataFrame,
    fields_to_display: list,
) -> pd.DataFrame:
    """
    Enriched incidents with data
    :param df: Incidents dataFrame
    :param fields_to_display: Fields selected for enrichement
    :param from_date: from_date
    :return: Incidents dataFrame enriched
    """
    if similar_incidents.empty:
        return similar_incidents
    incident_ids = similar_incidents.id.tolist() if "id" in similar_incidents.columns else similar_incidents.index
    res = execute_command(
        "GetIncidentsByQuery",
        args={
            "query": f"incident.id:({' '.join(incident_ids)})",
            "populateFields": ",".join(fields_to_display),
        },
        fail_on_error=True,
    )
    incidents: dict[str, dict] = {incident["id"]: incident for incident in json.loads(res)}
    if "created" in fields_to_display:
        similar_incidents["created"] = [
            dateparser.parse(incidents[inc_id]["created"]).strftime("%Y-%m-%d")  # type: ignore
            for inc_id in incident_ids
        ]
    if "status" in fields_to_display:
        similar_incidents["status"] = [
            STATUS_DICT.get(incidents[inc_id]["status"]) or " "
            for inc_id in incident_ids
        ]

    for field in fields_to_display:
        if field not in ["created", "status"]:
            similar_incidents[field] = [incidents[inc_id][field] or "" for inc_id in incident_ids]
    return similar_incidents


def replace_indicator_ids_with_values(
    inc_ids: str,
    indicators_data: dict[str, dict],
) -> str:
    return "\n".join([
        indicators_data.get(x, {}).get("value") or " "
        for x in inc_ids.split(" ")
    ])


def get_similar_incidents(
    model: Model,
    indicators_data: dict[str, dict],
    threshold: float,
    max_incidents_to_display: int,
    fields_to_display: list[str],
) -> pd.DataFrame:
    """
    Clean and organize dataframe before displaying
    :param model: the model used for prediction of similar incidents
    :param indicators_data: Dict of indicators
    :param threshold: threshold for similarity score
    :param max_incidents_to_display:  Max number of incidents we want to display
    :param fields_to_display: Fields selected for enrichement
    :return: Clean DataFrame of incident
    """
    similar_incidents: pd.DataFrame = model.predict()
    similar_incidents = similar_incidents.reset_index().rename(columns={"index": "id"})
    similar_incidents["incident ID"] = similar_incidents["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    similar_incidents["Identical indicators"] = similar_incidents["Identical indicators"].apply(
        lambda inc_ids: replace_indicator_ids_with_values(inc_ids, indicators_data)
    )
    similar_incidents = similar_incidents[["incident ID", "id", "Identical indicators", "similarity indicators"]]
    similar_incidents = similar_incidents[similar_incidents["similarity indicators"] > threshold]
    similar_incidents = similar_incidents.sort_values(["similarity indicators"], ascending=False)
    similar_incidents = similar_incidents.head(max_incidents_to_display)
    return enrich_incidents(similar_incidents, fields_to_display)


def similar_incidents_results(similar_incidents: pd.DataFrame, tag: Optional[str] = None):
    outputs = similar_incidents.to_dict(orient="records")
    additional_headers = [
        x for x in similar_incidents.columns.tolist()
        if x not in FIRST_COLUMNS_INCIDENTS_DISPLAY + FIELDS_TO_EXCLUDE_FROM_DISPLAY
    ]
    return CommandResults(
        outputs={"similarIncident": outputs},
        outputs_prefix="DBotFindSimilarIncidentsByIndicators",
        raw_response=outputs,
        readable_output=tableToMarkdown(
            "Similar incidents",
            outputs,
            headers=FIRST_COLUMNS_INCIDENTS_DISPLAY + additional_headers,
            headerTransform=str.title,
        ),
        tags=[tag] if tag else None,  # type: ignore
    )


def actual_incident_results(
    incident_df: pd.DataFrame,
    incident_id: str,
    fields_incident_to_display: list[str],
) -> CommandResults:
    """
    Display current incident
    :param incident_df: DataFrame of incident
    :param incident_id: incident ID
    :param fields_incident_to_display: fields to display
    :return: CommandResults
    """
    incident_df["id"] = [incident_id]
    incident_df = enrich_incidents(incident_df, fields_incident_to_display)
    incident_df["Incident ID"] = incident_df["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    additional_headers = [
        x for x in incident_df.columns.tolist()
        if x not in FIRST_COLUMNS_INCIDENTS_DISPLAY + ["id", "indicators"]
    ]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Actual Incident",
            incident_df.to_dict(orient="records"),
            headers=FIRST_COLUMNS_INCIDENTS_DISPLAY + additional_headers,
            headerTransform=str.title,
        ),
    )


def format_actual_incident_data(
    actual_incident_df: pd.DataFrame,
    indicators_data: dict[str, dict],
):
    actual_incident_df["Indicators"] = actual_incident_df["indicators"].apply(
        lambda inc_ids: replace_indicator_ids_with_values(inc_ids, indicators_data)
    )
    return actual_incident_df


def find_similar_incidents_by_indicators(incident_id: str, args: dict) -> list[CommandResults]:
    # get_indicators_of_actual_incident() args
    indicators_types = argToList(args.get("indicatorsTypes"), transform=str.lower)
    min_nb_of_indicators = int(args["minNumberOfIndicators"])
    max_indicators_for_white_list = int(args["maxIncidentsInIndicatorsForWhiteList"])

    # get_related_incidents() args
    query = args.get("query") or ""
    from_date = args.get("fromDate")

    # get_similar_incidents() args
    similarity_threshold = float(args["threshold"])
    max_incidents_to_display = int(args["maxIncidentsToDisplay"])

    # outputs formatting args
    show_actual_incident = argToBoolean(args.get("showActualIncident"))
    fields_to_display = list(set(argToList(args["fieldsIncidentToDisplay"])) | {"created", "name"})

    command_results_list: list[CommandResults] = []

    indicators_of_actual_incident = get_indicators_of_actual_incident(
        incident_id,
        indicators_types,
        min_nb_of_indicators,
        max_indicators_for_white_list,
    )

    incident_ids = get_related_incidents(indicators_of_actual_incident, query, from_date)
    mutual_indicators = get_mutual_indicators(incident_ids, indicators_of_actual_incident)

    actual_incident_df = create_actual_incident_df(indicators_of_actual_incident)
    related_incidents_df = create_related_incidents_df(mutual_indicators, incident_ids, incident_id)

    similar_incidents = get_similar_incidents(
        Model(actual_incident_df, related_incidents_df),
        indicators_of_actual_incident,
        similarity_threshold,
        max_incidents_to_display,
        fields_to_display,
    )

    if show_actual_incident and not similar_incidents.empty:
        actual_incident_data = format_actual_incident_data(actual_incident_df, indicators_of_actual_incident)
        command_results_list.append(
            actual_incident_results(
                actual_incident_data,
                incident_id,
                fields_to_display,
            )
        )
    command_results_list.extend([
        mutual_indicators_results(mutual_indicators, incident_ids),
        similar_incidents_results(similar_incidents),
    ])
    return command_results_list


def main():
    try:
        args = demisto.args()
        incident_id = args.get("incidentId") or demisto.incidents()[0]["id"]
        return_results(find_similar_incidents_by_indicators(incident_id, args))
    except Exception as e:
        return_error(f"Failed to execute DBotFindSimilarIncidentsByIndicators. Error: {e}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
