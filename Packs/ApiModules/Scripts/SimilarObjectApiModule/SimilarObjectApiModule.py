import json
import re
import warnings
from copy import deepcopy
from types import UnionType
from typing import Any

import demistomock as demisto
import numpy as np
import pandas as pd
from CommonServerPython import *
from scipy.spatial.distance import cdist
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

from CommonServerUserPython import *

warnings.simplefilter("ignore")
warnings.filterwarnings("ignore", category=UserWarning)


INCIDENT_ALIAS = "alert" if (is_xsiam() or is_platform()) else "incident"

FIELD_SKIP_REASON_DOESNT_EXIST = f"The '{{field}}' field does not exist in {INCIDENT_ALIAS}"
FIELD_SKIP_REASON_FALSY_VALUE = f"The '{{field}}' field has a falsy value in current {INCIDENT_ALIAS}: '{{val}}'"
FIELD_SKIP_REASON_INVALID_TYPE = "Expected type of the '{field}' field is: {valid}, actual type is: {type}"
FIELD_SKIP_REASON_TOO_SHORT = f"Value of the '{{field}}' field in {INCIDENT_ALIAS}: '{{val}}' has length of {{len}}"
FIELD_SKIP_REASON_LIST_OF_FALSY_VALS = (
    f"Value of '{{field}}' field in {INCIDENT_ALIAS}: '{{val}}' is a list with only falsy values"
)
MESSAGE_NO_FIELDS_USED = "- No field are used to find similarity. Reasons:\n{}"

MESSAGE_NO_INCIDENT_FETCHED = f"- 0 {INCIDENT_ALIAS}s fetched with these exact match for the given dates."

MESSAGE_WARNING_TRUNCATED = (
    f"- {INCIDENT_ALIAS.capitalize()} fetched have been truncated to "
    "%s"
    f", please either add {INCIDENT_ALIAS} fields in "
    "fieldExactMatch, enlarge the time period or increase the limit argument "
    "to more than %s."
)

MESSAGE_NO_CURRENT_INCIDENT = (
    f"- {INCIDENT_ALIAS.capitalize()} %s does not exist within the given time range. "
    f"Please check incidentId value or that you are running the command within an {INCIDENT_ALIAS}."
)
MESSAGE_NO_FIELD = f"- %s field(s) does not exist in the current {INCIDENT_ALIAS}."
MESSAGE_INCORRECT_FIELD = f"- %s field(s) don't/doesn't exist within the fetched {INCIDENT_ALIAS}s."

SIMILARITY_COLUNM_NAME = f"similarity {INCIDENT_ALIAS}"
SIMILARITY_COLUNM_NAME_INDICATOR = "similarity indicators"
IDENTICAL_INDICATOR = "Identical indicators"
ORDER_SCORE_WITH_INDICATORS = [SIMILARITY_COLUNM_NAME, SIMILARITY_COLUNM_NAME_INDICATOR]
ORDER_SCORE_NO_INDICATORS = [SIMILARITY_COLUNM_NAME]
COLUMN_ID = f"{INCIDENT_ALIAS} ID"
FIRST_COLUMNS_INCIDENTS_DISPLAY = [
    COLUMN_ID,
    "created",
    "name",
    SIMILARITY_COLUNM_NAME,
    SIMILARITY_COLUNM_NAME_INDICATOR,
    IDENTICAL_INDICATOR,
]
REMOVE_COLUMNS_INCIDENTS_DISPLAY = ["id", "Id"]
FIELDS_NO_AGGREGATION = ["id", "created", COLUMN_ID]
COLUMN_TIME = "created"
TAG_INCIDENT = "incidents"
TAG_SCRIPT_INDICATORS = "similarIncidents"
KEEP_COLUMNS_INDICATORS = ["Identical indicators", "similarity indicators"]

PREFIXES_TO_REMOVE = ["incident.", "alert.", "issue."]
CONST_PARAMETERS_INDICATORS_SCRIPT = {
    "threshold": "0",
    "showActualIncident": "False",
    "debug": "False",
    "maxIncidentsToDisplay": "3000",
}
KEYS_ARGS_INDICATORS = ["indicatorsTypes", "maxIncidentsInIndicatorsForWhiteList", "minNumberOfIndicators", "incidentId"]

REGEX_DATE_PATTERN = [
    re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})Z"),
    re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*"),
]
REGEX_IP = re.compile(r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])")
REPLACE_COMMAND_LINE = {
    "=": " = ",
    "\\": "/",
    "[": "",
    "]": "",
    '"': "",
    "'": "",
}


def get_field_args(args) -> tuple:
    use_all_field = argToBoolean(args.get("useAllFields") or "False")
    exact_match_fields = [] if use_all_field else extract_fields_from_args(args.get("fieldExactMatch"))
    similar_text_field = [] if use_all_field else extract_fields_from_args(args.get("similarTextField"))
    similar_categorical_field = [] if use_all_field else extract_fields_from_args(args.get("similarCategoricalField"))
    similar_json_field = ["CustomFields"] if use_all_field else extract_fields_from_args(args.get("similarJsonField"))

    demisto.debug(f"{exact_match_fields=}\n{similar_text_field=}\n{similar_categorical_field=}\n{similar_json_field=}")
    return exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field


def keep_high_level_field(incidents_field: list[str]) -> list[str]:
    """
    Return list of fields if they are in the first level of the argument - xdralert.commandline will return xdralert
    :param incidents_field: list of incident fields
    :return: Return list of fields
    """
    return [x.split(".")[0] if "." in x else x for x in incidents_field]


def extract_values(data: dict | list, path: str, values_to_exclude: list) -> list:
    """Recursively extracts values from nested object by path (dot notation).

    For example: extract_values(
        data={"A": [
            {"B": 1, "C": 0},
            {"B": 2},
            {"B": None},
            {"B": "N/A"},
        ]},
        path="A.B",
        values_to_exclude=[None, "N/A"],
    ) == [1, 2]

    Args:
        data (dict | list): The object to extract values from.
        path (str): The path (dot notation) to the values to extract.
        values_to_exclude (list): A list of values to exclude from result.

    Returns:
        list: The extracted values.
    """

    def recurse(obj: Any, keys: list[str]):
        if not keys:
            result = obj if isinstance(obj, list) else [obj]
            return [val for val in result if val not in values_to_exclude]
        if isinstance(obj, dict):
            if keys[0] in obj:
                return recurse(obj[keys[0]], keys[1:])
        elif isinstance(obj, list):
            return [result for item in obj for result in recurse(item, keys)]
        return []

    return recurse(data, path.split("."))


def preprocess_incidents_field(incidents_field: str, prefix_to_remove: list[str]) -> str:
    """
    Remove prefixe from incident fields
    :param incidents_field: field
    :param prefix_to_remove: prefix_to_remove
    :return: field without prefix
    """
    incidents_field = incidents_field.strip()
    for prefix in prefix_to_remove:
        if incidents_field.startswith(prefix):
            incidents_field = incidents_field[len(prefix) :]
    return incidents_field


def check_list_of_dict(obj) -> bool:  # type: ignore
    """
    If object is list of dict
    :param obj: any object
    :return: boolean if object is list of dict
    """
    return bool(obj) and all(isinstance(elem, dict) for elem in obj)  # type: ignore


def remove_duplicates(seq: list[str]) -> list[str]:
    seen = set()  # type: ignore
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


def recursive_filter(item: list[dict] | dict, regex_patterns: list, *fieldsToRemove):
    """

    :param item: Dict of list of Dict
    :param regex_patterns: List of regex pattern to remove from the dict
    :param fieldsToRemove: values to remove from the object
    :return: Dict or List of Dict without unwanted values or regex pattern
    """
    if isinstance(item, list):
        return [recursive_filter(entry, regex_patterns, *fieldsToRemove) for entry in item if entry not in fieldsToRemove]
    if isinstance(item, dict):
        result = {}
        for key, value in item.items():
            value = recursive_filter(value, regex_patterns, *fieldsToRemove)
            if key not in fieldsToRemove and value not in fieldsToRemove and (not match_one_regex(value, regex_patterns)):
                result[key] = value
        return result
    return item


def match_one_regex(string: str, patterns) -> bool:  # type: ignore
    """
    If string matches one or more from patterns
    :param string: string
    :param patterns: List of regex pattern
    :return:
    """
    if not isinstance(string, str):
        return False
    if len(patterns) == 0:
        return False
    if len(patterns) == 1:
        return bool(patterns[0].match(string))
    else:
        return match_one_regex(string, patterns[1:]) or bool(patterns[0].match(string))


def normalize_json(obj) -> str:  # type: ignore
    """
    Normalize json from removing unwantd regex pattern or stop word
    :param obj:Dumps of a json or dict
    :return:
    """
    if isinstance(obj, float) or not obj:
        return " "
    if isinstance(obj, str):
        obj = json.loads(obj)
    if check_list_of_dict(obj):
        obj = dict(enumerate(obj))
    if not isinstance(obj, dict):
        return " "
    my_dict = recursive_filter(obj, REGEX_DATE_PATTERN, "None", "N/A", None, "")
    my_string = json.dumps(my_dict)
    pattern = re.compile(r"([^\s\w]|_)+")
    my_string = pattern.sub(" ", my_string)
    my_string = my_string.lower()
    return my_string


def normalize_command_line(command: str) -> str:
    """
    Normalize command line
    :param command: command line
    :return: Normalized command line
    """

    if command and isinstance(command, list):
        command = " ".join(set(command))
    if command and isinstance(command, str):
        my_string = command.lower()
        my_string = "".join([REPLACE_COMMAND_LINE.get(c, c) for c in my_string])
        my_string = REGEX_IP.sub("IP", my_string)
        my_string = my_string.strip()
        return my_string
    else:
        return ""


def fill_nested_fields(incidents_df: pd.DataFrame, incidents: dict | list, *list_of_field_list: list[str]) -> pd.DataFrame:
    for field_type in list_of_field_list:
        for field in field_type:
            if "." in field:
                value_list = extract_values(incidents, field, values_to_exclude=["None", None, "N/A"])
                incidents_df[field] = " ".join(value_list)
    return incidents_df


def normalize_identity(my_string: str) -> str:
    """
    Return identity if string
    :param my_string: string
    :return: my_string
    """
    if my_string and isinstance(my_string, str):
        return my_string
    else:
        return ""


def euclidian_similarity_capped(x: np.ndarray, y: np.ndarray) -> np.ndarray:
    """
    Return max between 1 and euclidian distance between X and y
    :param x: np.array n*m
    :param y: np.array 1*m
    :return: np.array of ditance 1*n
    """
    return np.maximum(1 - cdist(x, y)[:, 0], 0)


def identity(X, y):  # type: ignore
    """
    Return np.nan if value is different and 1 if value is the same
    :param X: np.array
    :param y: np.array
    :return; np.array
    """
    z = (X.to_numpy() == y.to_numpy()).astype(float)
    z[z == 0] = np.nan
    return z


class Tfidf(BaseEstimator, TransformerMixin):
    """
    TFIDF transformer
    """

    def __init__(self, incident_field: str, tfidf_params: dict, normalize_function, current_incident):
        """
        :param incident_field: incident on which we want to use the transformer
        :param tfidf_params: parameters of TFIDF
        :param normalize_function: Normalize function to apply on each sample of the corpus before the vectorization
        :param current_incident: current incident
        """
        self.incident_field = incident_field
        self.params = tfidf_params
        self.normalize_function = normalize_function
        if self.normalize_function:
            current_incident = current_incident[self.incident_field].apply(self.normalize_function)
        self.vocabulary = TfidfVectorizer(**self.params, use_idf=False).fit(current_incident).vocabulary_
        self.vec = TfidfVectorizer(**self.params, vocabulary=self.vocabulary)

    def fit(self, x):
        """
        Fit TFIDF transformer
        :param x: incident on which we want to fit the transfomer
        :return: self
        """
        if self.normalize_function:
            x = x[self.incident_field].apply(self.normalize_function)
        self.vec.fit(x)
        return self

    def transform(self, x):
        """
        Transform x with the trained vectorizer
        :param x: DataFrame or np.array
        :return:
        """
        if self.normalize_function:
            x = x[self.incident_field].apply(self.normalize_function)
        else:
            x = x[self.incident_field]
        return self.vec.transform(x).toarray()


class Identity(BaseEstimator, TransformerMixin):
    """
    Identity transformer for Categorical field
    """

    def __init__(self, feature_names, identity_params, normalize_function, x=None):
        self.feature_names = feature_names
        self.normalize_function = normalize_function
        self.identity_params = identity_params

    def fit(self, x, y=None):
        return self

    def transform(self, x, y=None):
        if self.normalize_function:
            return x[self.feature_names].apply(self.normalize_function)
        else:
            return x[self.feature_names]


TRANSFORMATION = {
    "commandline": {
        "transformer": Tfidf,
        "normalize": normalize_command_line,
        "params": {"analyzer": "char", "max_features": 2000, "ngram_range": (2, 5)},
        "scoring_function": euclidian_similarity_capped,
    },
    "potentialMatch": {"transformer": Identity, "normalize": None, "params": {}, "scoring_function": identity},
    "json": {
        "transformer": Tfidf,
        "normalize": normalize_json,
        "params": {"analyzer": "char", "max_features": 10000, "ngram_range": (2, 5)},
        "scoring_function": euclidian_similarity_capped,
    },
}


class Transformer:
    """
    Class for Transformer
    """

    def __init__(self, p_transformer_type, field, p_incidents_df, p_incident_to_match, p_params):
        """
        :param p_transformer_type: One of the key value of TRANSFORMATION dict
        :param field: incident field used in this transformation
        :param p_incidents_df: DataFrame of incident (should contains one columns which same name than incident_field)
        :param p_incident_to_match: DataFrame of the current incident
        :param p_params: Dictionary of all the transformation - TRANSFORMATION
        """
        self.transformer_type = p_transformer_type
        self.field = field
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.params = p_params

    def fit_transform(self):
        """
        Fit self.incident_to_match and transform self.incidents_df and self.incident_to_match
        :return:
        """
        transformation = self.params[self.transformer_type]
        transformer = transformation["transformer"](
            self.field, transformation["params"], transformation["normalize"], self.incident_to_match
        )
        demisto.debug(f"Running fit_transform for field {self.field} with transformer {type(transformer)}")
        x_vect = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.incident_to_match)

        return x_vect, incident_vect

    def get_score(self):
        """
        :return: Add one columns 'similarity %s' % self.field to self.incidents_df Dataframe with the score
        """
        scoring_function = self.params[self.transformer_type]["scoring_function"]
        X_vect, incident_vect = self.fit_transform()
        demisto.debug(f"Calculating similarity of field {self.field} with function {scoring_function.__name__}")
        dist = scoring_function(X_vect, incident_vect)
        self.incidents_df[f"similarity {self.field}"] = np.round(dist, 2)
        return self.incidents_df


class Model:
    def __init__(self, p_transformation):
        """
        :param p_transformation: Dict with the transformers parameters - TRANSFORMATION
        """
        self.transformation = p_transformation

    def init_prediction(
        self,
        p_incident_to_match,
        p_incidents_df,
        p_field_for_command_line=[],
        p_field_for_potential_exact_match=[],
        p_field_for_display_fields_incidents=[],
        p_field_for_json=[],
    ):
        """

        :param p_incident_to_match: Dataframe with one incident
        :param p_incidents_df: Dataframe with all the incidents
        :param p_field_for_command_line: list of incident fields that for the transformer 'command_line'
        :param p_field_for_potential_exact_match: list of incident fields that for the transformer 'potential_exact_match'
        :param p_field_for_display_fields_incidents: list of incident fields that for the transformer 'display_fields_incidents'
        :param p_field_for_json: list of incident fields that for the transformer 'json'
        :return:
        """
        self.incident_to_match: pd.DataFrame = p_incident_to_match
        self.incidents_df: pd.DataFrame = p_incidents_df
        self.field_for_command_line = p_field_for_command_line
        self.field_for_potential_exact_match = p_field_for_potential_exact_match
        self.field_for_display_fields_incidents = p_field_for_display_fields_incidents
        self.field_for_json = p_field_for_json

    def predict(self):
        should_proceed, all_skip_reasons = self.remove_empty_or_short_fields()
        if not should_proceed:
            raise DemistoException("\n".join(all_skip_reasons) or "  * No fields were provided for similarity calculation")
        self.get_score()
        self.compute_final_score()
        return (
            self.prepare_for_display(),
            self.field_for_command_line + self.field_for_potential_exact_match + self.field_for_json,
        )

    def remove_empty_or_short_fields(self) -> tuple[bool, list[str]]:
        """
        Remove field where value is empty or is shorter than 2 characters or unusable or does not exist in the incident.
        :return: whether should proceed with calculation, and a list of reasons for skipped fields
        """
        all_skip_reasons = []

        def find_skip_reason(field: str, valid_types: type | UnionType | None) -> str | None:
            skip_reason = None
            # returns a reason to drop field if exists, or None if no such
            if field not in self.incident_to_match.columns:
                skip_reason = FIELD_SKIP_REASON_DOESNT_EXIST.format(field=field)
            else:
                val = self.incident_to_match[field].values[0]
                if not val or val in ["None", "N/A"]:
                    skip_reason = FIELD_SKIP_REASON_FALSY_VALUE.format(field=field, val=val)
                elif valid_types and not isinstance(val, valid_types):
                    skip_reason = FIELD_SKIP_REASON_INVALID_TYPE.format(field=field, valid=valid_types, type=type(val))
                elif len(val) < 2:
                    skip_reason = FIELD_SKIP_REASON_TOO_SHORT.format(field=field, val=val, len=len(val))
                elif isinstance(val, list) and all(not x for x in val):
                    skip_reason = FIELD_SKIP_REASON_LIST_OF_FALSY_VALS.format(field=field, val=val)

            if skip_reason:
                demisto.debug(f"Skipping - {skip_reason}")
            else:
                demisto.debug(f"Including {field=} in similarity calculation (value in incident is: {val})")
            return skip_reason

        def filter_fields(
            fields_list: list[str],
            valid_types: type | UnionType | None = None,
        ) -> tuple[list[str], list[str]]:
            fields_to_use = []
            skip_reasons = []
            for field in fields_list:
                if skip_reason := find_skip_reason(field, valid_types):
                    skip_reasons.append(f"  - {skip_reason}")
                else:
                    fields_to_use.append(field)
            return fields_to_use, skip_reasons

        self.field_for_command_line, skip_reasons = filter_fields(self.field_for_command_line, valid_types=str | list)
        all_skip_reasons.extend(skip_reasons)

        self.field_for_potential_exact_match, skip_reasons = filter_fields(self.field_for_potential_exact_match, valid_types=str)
        all_skip_reasons.extend(skip_reasons)

        self.field_for_json, skip_reasons = filter_fields(self.field_for_json)
        all_skip_reasons.extend(skip_reasons)

        should_proceed = len(self.field_for_command_line + self.field_for_potential_exact_match + self.field_for_json) != 0

        return should_proceed, all_skip_reasons

    def get_score(self):
        """
        Apply transformation for each field in possible transformer
        :return:
        """
        for field in self.field_for_command_line:
            t = Transformer("commandline", field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()
        for field in self.field_for_potential_exact_match:
            t = Transformer("potentialMatch", field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()
        for field in self.field_for_json:
            t = Transformer("json", field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()

    def compute_final_score(self):
        """
        Compute final score based on average of similarity score for each field transformed
        :return:
        """
        col = self.incidents_df.loc[:, [f"similarity {field}" for field in self.field_for_command_line + self.field_for_json + self.field_for_potential_exact_match]]
        self.incidents_df[SIMILARITY_COLUNM_NAME] = np.round(col.mean(axis=1), 2)

    def prepare_for_display(self):
        self.compute_final_score()
        display_fields = remove_duplicates(
            self.field_for_display_fields_incidents
            + self.field_for_command_line
            + self.field_for_potential_exact_match
            + [
                f"similarity {field}"
                for field in self.field_for_command_line + self.field_for_json + self.field_for_potential_exact_match
            ]
        )
        df_sorted = self.incidents_df[display_fields + [SIMILARITY_COLUNM_NAME]]
        return df_sorted


def return_clean_date(timestamp: str) -> str:
    """
    Return YYYY-MM-DD
    :param timestamp: str of the date
    :return: Return YYYY-MM-DD
    """
    if timestamp and len(timestamp) > 10:
        return timestamp[:10]
    else:
        return ""


def prepare_incidents_for_display(
    similar_incidents: pd.DataFrame,
    confidence: float,
    show_distance: bool,
    max_incidents: int,
    fields_used: list[str],
    aggregate: str,
    include_indicators_similarity: bool,
) -> pd.DataFrame:
    """
    Organize data
    :param similar_incidents: DataFrame of incident
    :param confidence: threshold for similarity score
    :param show_distance: If wants to show distance for each of the field
    :param max_incidents: max incidents in the results
    :param fields_used: field used to compute final score
    :param aggregate: if aggragate the data that are identical according to the field - False if used indicators
    :param include_indicators_similarity: if include_indicators_similarity
    :return: Clean Dataframe
    """
    if "id" in similar_incidents.columns.tolist():
        similar_incidents[COLUMN_ID] = similar_incidents["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    if COLUMN_TIME in similar_incidents.columns:
        similar_incidents[COLUMN_TIME] = similar_incidents[COLUMN_TIME].apply(lambda x: return_clean_date(x))
    if aggregate == "True":
        agg_fields = [x for x in similar_incidents.columns if x not in FIELDS_NO_AGGREGATION]
        similar_incidents = similar_incidents.groupby(agg_fields, as_index=False, dropna=False).agg(
            {
                COLUMN_TIME: lambda x: f"{min(filter(None, x))} -> {max(filter(None, x))}" if len(x) > 1 else x,
                "id": lambda x: " , ".join(x),
                COLUMN_ID: lambda x: " , ".join(x),
            }
        )

    if confidence:
        similar_incidents = similar_incidents[similar_incidents[SIMILARITY_COLUNM_NAME] >= confidence]
    if show_distance == "False":
        col_to_remove = [f"similarity {field}" for field in fields_used]
        similar_incidents = similar_incidents.drop(col_to_remove, axis=1)
    if include_indicators_similarity == "True":
        similar_incidents = similar_incidents.sort_values(by=ORDER_SCORE_WITH_INDICATORS, ascending=False)
    else:
        similar_incidents = similar_incidents.sort_values(by=ORDER_SCORE_NO_INDICATORS, ascending=False)

    return similar_incidents.head(max_incidents)


def extract_fields_from_args(arg: str) -> list[str]:
    fields_list = [preprocess_incidents_field(x.strip(), PREFIXES_TO_REMOVE) for x in argToList(arg) if x]
    return list(dict.fromkeys(fields_list))


def remove_fields_not_in_incident(*args, incorrect_fields):
    """
    Return list without field in incorrect_fields
    :param args: *List of fields
    :param incorrect_fields: fields that we don't want
    :return:
    """
    return [[x for x in field_type if x not in incorrect_fields] for field_type in args]


def dumps_json_field_in_incident(incident: dict):
    """
    Dumps value that are dict in for incident values
    :param incident: json representing the incident
    :return:
    """
    for field in incident:
        if isinstance(incident[field], dict):
            incident[field] = json.dumps(incident[field])
    incident_df = pd.DataFrame.from_dict(incident, orient="index").T
    return incident_df


def create_context_for_incidents(similar_incidents=pd.DataFrame()):
    """
    Return context from dataframe of incident
    :param similar_incidents: DataFrame of incidents with indicators
    :return: context
    """
    similar_incidents = similar_incidents.replace(np.nan, "", regex=True)
    if len(similar_incidents) == 0:
        context = {"similarIncidentList": {}, "isSimilarIncidentFound": False}
    else:
        context = {"similarIncident": (similar_incidents.to_dict(orient="records")), "isSimilarIncidentFound": True}
    return context


def find_incorrect_fields(populate_fields: list[str], incidents_df: pd.DataFrame, global_msg: str):
    """
    Check Field that appear in populate_fields but are not in the incidents_df and return message
    :param populate_fields: List of fields
    :param incidents_df: DataFrame of the incidents with fields in columns
    :param global_msg: global_msg
    :return: global_msg, incorrect_fields
    """
    incorrect_fields = [i for i in populate_fields if i not in incidents_df.columns.tolist()]
    if incorrect_fields:
        global_msg += "%s \n" % MESSAGE_INCORRECT_FIELD % " , ".join(incorrect_fields)  # noqa: UP031
    return global_msg, incorrect_fields


def prepare_current_incident(
    incident_df: pd.DataFrame,
    display_fields: list[str],
    similar_text_field: list[str],
    similar_json_field: list[str],
    similar_categorical_field: list[str],
    exact_match_fields: list[str],
) -> pd.DataFrame:
    """
    Prepare current incident for visualization
    :param incident_df: incident_df
    :param display_fields: display_fields
    :param similar_text_field: similar_text_field
    :param similar_json_field: similar_json_field
    :param similar_categorical_field: similar_categorical_field
    :param exact_match_fields: exact_match_fields
    :return:
    """

    incident_filter = incident_df.copy()[
        [
            x
            for x in display_fields + similar_text_field + similar_categorical_field + exact_match_fields
            if x in incident_df.columns
        ]
    ]
    if COLUMN_TIME in incident_filter.columns.tolist():
        incident_filter[COLUMN_TIME] = incident_filter[COLUMN_TIME].apply(lambda x: return_clean_date(x))
    if "id" in incident_filter.columns.tolist():
        incident_filter[COLUMN_ID] = incident_filter["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    return incident_filter
