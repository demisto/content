import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
import numpy as np
from collections import Counter
import re
import math

from GetIncidentsApiModule import *  # noqa: E402

SEARCH_INDICATORS_LIMIT = 10000
SEARCH_INDICATORS_PAGE_SIZE = 500

ROUND_SCORING = 2
PLAYGROUND_PATTERN = "[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}"

# Mutual indicators fields/columns
INDICATOR_ID_FIELD = "id"
VALUE_FIELD = "value"
VALUE_FIELD_FOR_COMPATIBILITY = "name"  # value field can't be used in demisto.searchIndicators on v6.9.0
SCORE_FIELD = "score"
INVESTIGATION_IDS_FIELD = "investigationIDs"
INDICATOR_TYPE_FIELD = "indicator_type"
INDICATOR_LINK_COLUMN = "indicatorID"
TYPE_COLUMN = "type"
REPUTATION_COLUMN = "Reputation"
INVOLVED_INCIDENTS_COUNT_COLUMN = "involvedIncidentsCount"

INDICATOR_FIELDS_TO_POPULATE_FROM_QUERY = [
    INDICATOR_ID_FIELD, INDICATOR_TYPE_FIELD, INVESTIGATION_IDS_FIELD, SCORE_FIELD, VALUE_FIELD_FOR_COMPATIBILITY
]
MUTUAL_INDICATORS_HEADERS = [
    INDICATOR_LINK_COLUMN, VALUE_FIELD, TYPE_COLUMN, REPUTATION_COLUMN, INVOLVED_INCIDENTS_COUNT_COLUMN
]

# Similar incidents fields/columns
INCIDENT_ID_FIELD = "id"
CREATED_FIELD = "created"
NAME_FIELD = "name"
STATUS_FIELD = "status"
INCIDENT_LINK_COLUMN = "incident ID"
INDICATORS_COLUMN = "indicators"
SIMILARITY_SCORE_COLUMN = "similarity indicators"
IDENTICAL_INDICATORS_COLUMN = "Identical indicators"

FIRST_COLUMNS_INCIDENTS_DISPLAY = [INCIDENT_LINK_COLUMN, CREATED_FIELD, NAME_FIELD]
FIELDS_TO_EXCLUDE_FROM_DISPLAY = [INCIDENT_ID_FIELD]

STATUS_DICT = {
    0: "Pending",
    1: "Active",
    2: "Closed",
    3: "Archive",
}
INDICATOR_LINK_FORMAT = "[{0}](#/indicator/{0})"
INCIDENT_LINK_FORMAT = "[{0}](#/Details/{0})"
DATE_FORMAT = "%Y-%m-%d"


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

    def __init__(self, incident_field: str, actual_incident: pd.DataFrame) -> None:
        self.column_name = incident_field
        self.frequency: dict = {}
        self.vocabulary = actual_incident[self.column_name].iloc[0].split(" ")

    def fit(self, x: pd.DataFrame) -> 'FrequencyIndicators':
        x = x[self.column_name]
        size = len(x) + 1
        frequencies = Counter(flatten_list([t.split(" ") for t in x.values]))
        frequencies.update(Counter(self.vocabulary))
        self.frequency = {k: math.log(1 + size / v) for k, v in frequencies.items()}
        return self

    def transform(self, x: pd.DataFrame) -> pd.DataFrame:
        return x[self.column_name].apply(self.compute_term_score)

    def compute_term_score(self, indicators_values_string: str) -> float:
        x = indicators_values_string.split(" ")
        return sum([1 * self.frequency[word] for word in self.vocabulary if word in x]) / sum(
            [self.frequency[word] for word in self.vocabulary])


class FrequencyIndicatorsTransformer:
    def __init__(self, incidents_df: pd.DataFrame, actual_incident: pd.DataFrame):
        """
        :param incidents_df: DataFrame of related incidents
        :param actual_incident: DataFrame of the actual incident
        """
        self.incidents_df = incidents_df
        self.actual_incident = actual_incident
        self.transformed_column = INDICATORS_COLUMN
        self.scoring_function = lambda x: x

    def fit_transform(self):
        transformer = FrequencyIndicators(
            self.transformed_column,
            self.actual_incident,
        )
        x_vector = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.actual_incident)
        return x_vector, incident_vect

    def get_score(self):
        x_vector, _ = self.fit_transform()
        distance = self.scoring_function(x_vector)
        self.incidents_df[SIMILARITY_SCORE_COLUMN] = np.round(distance, ROUND_SCORING)
        return self.incidents_df


class Model:
    def __init__(
        self,
        incident_to_match: pd.DataFrame,
        incidents_df: pd.DataFrame,
        similarity_threshold: float,
        max_incidents: int,
    ) -> None:
        """
        :param incident_to_match: Dataframe with one incident
        :param incidents_df: Dataframe with all the incidents
        :param similarity_threshold: The similarity threshold
        :param max_incidents: Maximum number of incidents to return
        """
        self.incident_to_match = incident_to_match
        self.incidents_df = incidents_df
        self.threshold = similarity_threshold
        self.max_incidents = max_incidents

    def predict(self) -> pd.DataFrame:
        self.get_score()
        self.filter_results()
        self.prepare_for_display()
        return self.incidents_df

    def get_score(self) -> None:
        t = FrequencyIndicatorsTransformer(
            self.incidents_df,
            self.incident_to_match,
        )
        t.get_score()

    def filter_results(self) -> None:
        self.incidents_df = self.incidents_df[self.incidents_df[SIMILARITY_SCORE_COLUMN] > self.threshold]
        self.incidents_df = self.incidents_df.sort_values([SIMILARITY_SCORE_COLUMN], ascending=False)
        self.incidents_df = self.incidents_df.head(self.max_incidents)

    def prepare_for_display(self) -> None:
        vocabulary = self.incident_to_match[INDICATORS_COLUMN].iloc[0].split(" ")
        self.incidents_df[IDENTICAL_INDICATORS_COLUMN] = self.incidents_df[INDICATORS_COLUMN].apply(
            lambda x: ",".join([id for id in x.split(" ") if id in vocabulary])
        )


def search_indicators(
    query: str,
    fields_to_populate: list | None = None,
    limit: int = SEARCH_INDICATORS_LIMIT,
    page_size: int = SEARCH_INDICATORS_PAGE_SIZE,
) -> list:
    demisto.debug(f"Searching indicators with {query=}")
    search_indicators = IndicatorsSearcher(
        query=query,
        limit=limit,
        size=page_size,
        filter_fields=",".join(fields_to_populate) if fields_to_populate else None
    )
    return flatten_list([ioc_res.get('iocs') or [] for ioc_res in search_indicators])


def get_indicators_of_actual_incident(
    incident_id: str,
    indicator_types: list[str],
    min_number_of_indicators: int,
    max_incidents_per_indicator: int,
) -> dict[str, dict]:
    """ Given an incident ID, returns a map between IDs of its related indicators and their data

    :param incident_id: ID of actual incident
    :param indicators_types: list of indicators type accepted
    :param min_number_of_indicators: Min number of indicators in the actual incident
    :param max_incidents_per_indicator: Max incidents in indicators for white list
    :return: a map from indicator ids of the actual incident to their data
    """
    indicators = search_indicators(query=f"investigationIDs:({incident_id})")
    if not indicators:
        return {}
    indicators = [i for i in indicators if len(i.get("investigationIDs") or []) <= max_incidents_per_indicator]
    if indicator_types:
        indicators = [x for x in indicators if x[INDICATOR_TYPE_FIELD].lower() in indicator_types]
    if len(indicators) < min_number_of_indicators:
        return {}

    indicators_data = {ind[INDICATOR_ID_FIELD]: ind for ind in indicators}
    demisto.debug(
        f"Found {len(indicators_data)} indicators for incident {incident_id}: {list(indicators_data.keys())}"
    )
    return indicators_data


def get_related_incidents(
    indicators: dict[str, dict],
    query: str,
    from_date: str | None,
) -> list[str]:
    """ Given indicators data including their related incidents,
    filters their related incidents by query and date and returns a list of the incident IDs.

    :param indicators: List of indicators
    :param query: A query to filter the related incidents by
    :param from_date: A created date to filter the related incidents by
    :return: The list of the related incident IDs
    """
    incident_ids = flatten_list([i.get("investigationIDs") or [] for i in indicators.values()])
    incident_ids = list({x for x in incident_ids if not re.match(PLAYGROUND_PATTERN, x)})
    if not (query or from_date) or not incident_ids:
        demisto.debug(f"Found {len(incident_ids)} related incidents: {incident_ids}")
        return incident_ids

    args = {
        "query": f"{query + ' AND ' if query else ''}incident.id:({' '.join(incident_ids)})",
        "populateFields": INCIDENT_ID_FIELD,
        "fromDate": from_date,
    }
    demisto.debug(f"Executing GetIncidentsByQuery with {args=}")
    incidents = get_incidents_by_query(args)
    incident_ids = [incident[INCIDENT_ID_FIELD] for incident in incidents]
    demisto.debug(f"Found {len(incident_ids)} related incidents: {incident_ids}")
    return incident_ids


def get_indicators_of_related_incidents(
    incident_ids: list[str],
    max_incidents_per_indicator: int,
) -> list[dict]:
    if not incident_ids:
        demisto.debug("No mutual indicators were found.")
        return []
    indicators = search_indicators(
        query=f"investigationIDs:({' '.join(incident_ids)})",
        fields_to_populate=INDICATOR_FIELDS_TO_POPULATE_FROM_QUERY,
    )
    indicators = [i for i in indicators if len(i.get("investigationIDs") or []) <= max_incidents_per_indicator]
    indicators_ids = [ind[INDICATOR_ID_FIELD] for ind in indicators]
    demisto.debug(f"Found {len(indicators_ids)} related indicators: {indicators_ids}")
    return indicators


def get_mutual_indicators(
    related_indicators: list[dict],
    indicators_of_actual_incident: dict[str, dict],
) -> list[dict]:
    mutual_indicators = [
        ind for ind in related_indicators if ind[INDICATOR_ID_FIELD] in indicators_of_actual_incident
    ]
    mutual_indicators_ids = [ind[INDICATOR_ID_FIELD] for ind in mutual_indicators]
    demisto.debug(f"Found {len(mutual_indicators_ids)} mutual indicators: {mutual_indicators_ids}")
    return mutual_indicators


def get_mutual_indicators_df(
    indicators: list[dict],
    incident_ids: list[str],
) -> pd.DataFrame:
    indicators_df = pd.DataFrame(indicators)
    if not indicators_df.empty:
        indicators_df[INVOLVED_INCIDENTS_COUNT_COLUMN] = indicators_df[INVESTIGATION_IDS_FIELD].apply(
            lambda inv_ids: sum(id_ in incident_ids for id_ in inv_ids),
        )
        indicators_df[INDICATOR_LINK_COLUMN] = indicators_df[INDICATOR_ID_FIELD].apply(
            lambda x: INDICATOR_LINK_FORMAT.format(x)
        )
        indicators_df = indicators_df.sort_values(
            [SCORE_FIELD, INVOLVED_INCIDENTS_COUNT_COLUMN],
            ascending=False,
        )
        indicators_df[REPUTATION_COLUMN] = indicators_df[SCORE_FIELD].apply(scoreToReputation)  # pylint: disable=E1137
        indicators_df = indicators_df.rename({INDICATOR_TYPE_FIELD: TYPE_COLUMN}, axis=1)
        indicators_df = indicators_df.rename({VALUE_FIELD_FOR_COMPATIBILITY: VALUE_FIELD}, axis=1)
    return indicators_df


def mutual_indicators_results(mutual_indicators: list[dict], incident_ids: list[str]):
    indicators_df = get_mutual_indicators_df(mutual_indicators, incident_ids)
    outputs = [] if indicators_df.empty else indicators_df[[INDICATOR_ID_FIELD, VALUE_FIELD]].to_dict(orient="records")
    readable_output = tableToMarkdown(
        "Mutual Indicators",
        indicators_df.to_dict(orient="records"),
        headers=MUTUAL_INDICATORS_HEADERS,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        outputs=outputs,
        outputs_prefix="MutualIndicators.indicators",
        readable_output=readable_output,
    )


def create_actual_incident_df(indicators_of_actual_incident: dict[str, dict]) -> pd.DataFrame:
    return pd.DataFrame(
        data=[" ".join(indicators_of_actual_incident.keys())],
        columns=[INDICATORS_COLUMN],
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
            indicator[INDICATOR_ID_FIELD] for indicator in indicators
            if inc_id in (indicator.get(INVESTIGATION_IDS_FIELD) or [])
        ]
        for inc_id in incident_ids
    }
    return pd.DataFrame.from_dict(
        data={
            k: " ".join(v) for k, v in incidents_to_indicators.items()
            if k != actual_incident_id
        },
        orient="index",
        columns=[INDICATORS_COLUMN],
    )


def enrich_incidents(
    incidents: pd.DataFrame,
    fields_to_display: list,
) -> pd.DataFrame:
    """
    Enriches a DataFrame of incidents with the given fields to display.

    :param similar_incidents: Incidents dataFrame
    :param fields_to_display: Fields selected for enrichement
    :return: Incidents dataFrame enriched
    """
    if incidents.empty:
        return incidents

    incident_ids = incidents.id.tolist() if INCIDENT_ID_FIELD in incidents.columns else incidents.index

    args = {
        "query": f"incident.id:({' '.join(incident_ids)})",
        "populateFields": ",".join(fields_to_display),
    }
    demisto.debug(f"Executing GetIncidentsByQuery with {args=}")
    res = get_incidents_by_query(args)
    incidents_map: dict[str, dict] = {incident[INCIDENT_ID_FIELD]: incident for incident in res}
    if CREATED_FIELD in fields_to_display:
        incidents[CREATED_FIELD] = [
            dateparser.parse(incidents_map[inc_id][CREATED_FIELD]).strftime(DATE_FORMAT)  # type: ignore
            for inc_id in incident_ids
        ]
    if STATUS_FIELD in fields_to_display:
        incidents[STATUS_FIELD] = [
            STATUS_DICT.get(incidents_map[inc_id][STATUS_FIELD]) or " "
            for inc_id in incident_ids
        ]

    for field in fields_to_display:
        if field not in [CREATED_FIELD, STATUS_FIELD]:
            incidents[field] = [incidents_map[inc_id].get(field) or "" for inc_id in incident_ids]
    return incidents


def replace_indicator_ids_with_values(
    inc_ids: str,
    indicators_data: dict[str, dict],
) -> str:
    return "\n".join([
        indicators_data.get(x, {}).get(VALUE_FIELD_FOR_COMPATIBILITY) or " "
        for x in inc_ids.split(" ")
    ])


def format_similar_incidents(
    similar_incidents: pd.DataFrame,
    indicators_data: dict[str, dict],
    fields_to_display: list[str],
) -> pd.DataFrame:
    """ Formats the similar incidents DataFrame.

    :param indicators_data: a mapping between IDs and the mutual indicators data
    :param fields_to_display: Fields selected for enrichement
    :return: a formatted, enriched DataFrame of the similar incidents.
    """
    if similar_incidents.empty:
        demisto.debug("No similar incidents found.")
        return similar_incidents

    # format and enrich DataFrame
    similar_incidents = similar_incidents.reset_index().rename(columns={"index": INCIDENT_ID_FIELD})
    similar_incidents[INCIDENT_LINK_COLUMN] = similar_incidents[INCIDENT_ID_FIELD].apply(
        lambda _id: INCIDENT_LINK_FORMAT.format(_id)
    )
    similar_incidents[IDENTICAL_INDICATORS_COLUMN] = similar_incidents[IDENTICAL_INDICATORS_COLUMN].apply(
        lambda inc_ids: replace_indicator_ids_with_values(inc_ids, indicators_data)
    )
    similar_incidents = similar_incidents[
        [INCIDENT_LINK_COLUMN, INCIDENT_ID_FIELD, IDENTICAL_INDICATORS_COLUMN, SIMILARITY_SCORE_COLUMN]
    ]
    return enrich_incidents(similar_incidents, fields_to_display)


def similar_incidents_results(
    similar_incidents: pd.DataFrame,
    indicators_of_actual_incident: dict,
    fields_to_display: list,
):
    similar_incidents = format_similar_incidents(similar_incidents, indicators_of_actual_incident, fields_to_display)
    outputs = similar_incidents.to_dict(orient="records")
    additional_headers = [
        x for x in similar_incidents.columns.tolist()
        if x not in FIRST_COLUMNS_INCIDENTS_DISPLAY + FIELDS_TO_EXCLUDE_FROM_DISPLAY
    ]
    return CommandResults(
        outputs={"similarIncident": outputs, "isSimilarIncidentFound": len(outputs) > 0},
        outputs_prefix="DBotFindSimilarIncidentsByIndicators",
        raw_response=outputs,
        readable_output=tableToMarkdown(
            "Similar Incidents",
            outputs,
            headers=FIRST_COLUMNS_INCIDENTS_DISPLAY + additional_headers,
            headerTransform=str.title,
        ),
        tags=["similarIncidents"],  # type: ignore
    )


def actual_incident_results(
    incident_df: pd.DataFrame,
    incident_id: str,
    indicators_data: dict,
    fields_to_display: list[str],
) -> CommandResults:
    """
    Formats the given DataFrame, and returns a CommandResults object of the actual incident data
    :param incident_df: a DataFrame of actual incident
    :param incident_id: the incident ID
    :param indicators_data: indicators data of the actual incident
    :param fields_to_display: A list of fields to display
    :return: a CommandResults obj
    """
    incident_df[INCIDENT_ID_FIELD] = [incident_id]
    incident_df[INCIDENT_LINK_COLUMN] = incident_df[INCIDENT_ID_FIELD].apply(
        lambda _id: INCIDENT_LINK_FORMAT.format(_id)
    )
    incident_df[INDICATORS_COLUMN] = incident_df[INDICATORS_COLUMN].apply(
        lambda inc_ids: replace_indicator_ids_with_values(inc_ids, indicators_data)
    )
    incident_df = enrich_incidents(incident_df, fields_to_display)
    additional_headers = [
        x for x in incident_df.columns.tolist()
        if x not in FIRST_COLUMNS_INCIDENTS_DISPLAY + FIELDS_TO_EXCLUDE_FROM_DISPLAY
    ]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Actual Incident",
            incident_df.to_dict(orient="records"),
            headers=FIRST_COLUMNS_INCIDENTS_DISPLAY + additional_headers,
            headerTransform=pascalToSpace,
        ),
    )


def find_similar_incidents_by_indicators(incident_id: str, args: dict) -> list[CommandResults]:
    # get_indicators_of_actual_incident() args
    indicators_types = argToList(args.get("indicatorsTypes"), transform=str.lower)
    min_number_of_indicators = int(args["minNumberOfIndicators"])
    max_incidents_per_indicator = int(args["maxIncidentsInIndicatorsForWhiteList"])

    # get_related_incidents() args
    query = args.get("query") or ""
    from_date = args.get("fromDate")

    # get_similar_incidents() args
    similarity_threshold = float(args["threshold"])
    max_incidents_to_display = int(args["maxIncidentsToDisplay"])

    # outputs formatting args
    show_actual_incident = argToBoolean(args.get("showActualIncident"))
    fields_to_display = list(set(argToList(args["fieldsIncidentToDisplay"])) | {CREATED_FIELD, NAME_FIELD})

    command_results_list: list[CommandResults] = []

    indicators_of_actual_incident = get_indicators_of_actual_incident(
        incident_id,
        indicators_types,
        min_number_of_indicators,
        max_incidents_per_indicator,
    )

    incident_ids = get_related_incidents(indicators_of_actual_incident, query, from_date)
    related_indicators = get_indicators_of_related_incidents(incident_ids, max_incidents_per_indicator)
    mutual_indicators = get_mutual_indicators(related_indicators, indicators_of_actual_incident)
    actual_incident_df = create_actual_incident_df(indicators_of_actual_incident)
    related_incidents_df = create_related_incidents_df(related_indicators, incident_ids, incident_id)

    similar_incidents = Model(
        actual_incident_df,
        related_incidents_df,
        similarity_threshold,
        max_incidents_to_display,
    ).predict()

    if show_actual_incident:
        command_results_list.append(
            actual_incident_results(actual_incident_df, incident_id, indicators_of_actual_incident, fields_to_display)
        )
    command_results_list.extend([
        mutual_indicators_results(mutual_indicators, incident_ids),
        similar_incidents_results(similar_incidents, indicators_of_actual_incident, fields_to_display),
    ])
    return command_results_list


def main():  # pragma: no cover
    try:
        args = demisto.args()
        incident_id = args.get("incidentId") or demisto.incidents()[0]["id"]
        return_results(find_similar_incidents_by_indicators(incident_id, args))
    except Exception as e:
        return_error(f"Failed to execute DBotFindSimilarIncidentsByIndicators. Error: {e}")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
