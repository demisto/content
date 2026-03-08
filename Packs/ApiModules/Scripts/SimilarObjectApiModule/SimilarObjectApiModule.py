import json
import re
import warnings
from copy import deepcopy
from types import UnionType
from typing import Any

import demistomock as demisto
import numpy as np
import pandas as pd
from GetIncidentsApiModule import *
from CommonServerPython import *
from scipy.spatial.distance import cdist
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer

from CommonServerUserPython import *

warnings.simplefilter("ignore")
warnings.filterwarnings("ignore", category=UserWarning)


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
    def __init__(self, p_transformation, incident_alias="incident"):
        """
        :param p_transformation: Dict with the transformers parameters - TRANSFORMATION
        """
        self.transformation = p_transformation
        self.incident_alias = incident_alias

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
                skip_reason = f"The '{field}' field does not exist in {self.incident_alias}"
            else:
                val = self.incident_to_match[field].values[0]
                if not val or val in ["None", "N/A"]:
                    skip_reason = f"The '{field}' field has a falsy value in current {self.incident_alias}: '{val}'"
                elif valid_types and not isinstance(val, valid_types):
                    skip_reason = f"Expected type of the '{field}' field is: {valid_types}, actual type is: {type(val)}"
                elif len(val) < 2:
                    skip_reason = f"Value of the '{field}' field in {self.incident_alias}: '{val}' has length of {len(val)}"
                elif isinstance(val, list) and all(not x for x in val):
                    skip_reason = f"Value of '{field}' field in {self.incident_alias}: '{val}' is a list with only falsy values"

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
        self.incidents_df[f"similarity {self.incident_alias}"] = np.round(col.mean(axis=1), 2)

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
        df_sorted = self.incidents_df[display_fields + [f"similarity {self.incident_alias}"]]
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
    incident_alias: str = "incident",
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
        similar_incidents[f"{incident_alias} ID"] = similar_incidents["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    if "created" in similar_incidents.columns:
        similar_incidents["created"] = similar_incidents["created"].apply(lambda x: return_clean_date(x))
    if aggregate == "True":
        agg_fields = [x for x in similar_incidents.columns if x not in ["id", "created", f"{incident_alias} ID"]]
        similar_incidents = similar_incidents.groupby(agg_fields, as_index=False, dropna=False).agg(
            {
                "created": lambda x: f"{min(filter(None, x))} -> {max(filter(None, x))}" if len(x) > 1 else x,
                "id": lambda x: " , ".join(x),
                f"{incident_alias} ID": lambda x: " , ".join(x),
            }
        )

    if confidence:
        similar_incidents = similar_incidents[similar_incidents[f"similarity {incident_alias}"] >= confidence]
    if not show_distance:
        col_to_remove = [f"similarity {field}" for field in fields_used]
        similar_incidents = similar_incidents.drop(col_to_remove, axis=1)
    if include_indicators_similarity == "True":
        similar_incidents = similar_incidents.sort_values(by=[f"similarity {incident_alias}", "similarity indicators"], ascending=False)
    else:
        similar_incidents = similar_incidents.sort_values(by=[f"similarity {incident_alias}"], ascending=False)

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


def find_incorrect_fields(populate_fields: list[str], incidents_df: pd.DataFrame, global_msg: str,
    incident_alias: str = "incident"):
    """
    Check Field that appear in populate_fields but are not in the incidents_df and return message
    :param populate_fields: List of fields
    :param incidents_df: DataFrame of the incidents with fields in columns
    :param global_msg: global_msg
    :return: global_msg, incorrect_fields
    """
    incorrect_fields = [i for i in populate_fields if i not in incidents_df.columns.tolist()]
    if incorrect_fields:
        global_msg += "%s \n" % f"- {', '.join(incorrect_fields)} field(s) don't/doesn't exist within the fetched {incident_alias}s."  # noqa: UP031
    return global_msg, incorrect_fields


def prepare_current_incident(
    incident_df: pd.DataFrame,
    display_fields: list[str],
    similar_text_field: list[str],
    similar_json_field: list[str],
    similar_categorical_field: list[str],
    exact_match_fields: list[str],
    incident_alias: str = "incident",
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
    if "created" in incident_filter.columns.tolist():
        incident_filter["created"] = incident_filter["created"].apply(lambda x: return_clean_date(x))
    if "id" in incident_filter.columns.tolist():
        incident_filter[f"{incident_alias} ID"] = incident_filter["id"].apply(lambda _id: f"[{_id}](#/Details/{_id})")
    return incident_filter


class BaseSimilarObjectFinder:
    def __init__(self, args: dict):
        self.args = args
        self.global_msg = ""
        self.incident_alias = "incident"
        self.tag_incident = "incidents"
        self.id_field = "id"
        self.time_format = "%Y-%m-%dT%H:%M:%S"

    def preprocess_args(self):
        pass

    def get_fields(self):
        use_all_field = argToBoolean(self.args.get("useAllFields") or "False")
        exact_match_fields = [] if use_all_field else extract_fields_from_args(self.args.get("fieldExactMatch"))
        similar_text_field = [] if use_all_field else extract_fields_from_args(self.args.get("similarTextField"))
        similar_categorical_field = [] if use_all_field else extract_fields_from_args(self.args.get("similarCategoricalField"))
        similar_json_field = ["CustomFields"] if use_all_field else extract_fields_from_args(self.args.get("similarJsonField"))
        
        if not (similar_text_field or similar_categorical_field or similar_json_field):
            raise DemistoException("Please provide at least one of the following args: text_similarity_fields, discrete_match_fields, json_similarity_fields.")
            
        return exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field

    def get_display_fields(self):
        return list(set([self.id_field, "created", "name"] + argToList(self.args.get("fieldsToDisplay"))))

    def get_dates(self):
        return self.args.get("fromDate"), self.args.get("toDate")

    def load_current_incident(self, incident_id, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, from_date, to_date):
        raise NotImplementedError

    def get_all_incidents(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, incident, from_date, to_date, limit):
        raise NotImplementedError

    def get_fields_to_check_existence(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields):
        raise NotImplementedError

    def remove_incorrect_fields(self, display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields):
        return remove_fields_not_in_incident(
            display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields=incorrect_fields
        )

    def enrich_with_indicators(self, similar_incidents, include_indicators_similarity):
        return similar_incidents

    def return_outputs_error(self, error_msg):
        return_entry = {
            "Type": entryTypes["note"],
            "HumanReadable": error_msg,
            "ContentsFormat": formats["json"],
            "Contents": None,
            "EntryContext": None,
            "Tags": ["Error.id"],
        }
        demisto.results(return_entry)

    def return_outputs_summary(self, confidence: float, number_incident_fetched: int, number_incidents_found: int, fields_used: list[str]):
        summary = {
            "Confidence": str(confidence),
            f"Number of {self.incident_alias}s fetched with exact match ": number_incident_fetched,
            f"Number of similar {self.incident_alias}s found ": number_incidents_found,
            "Valid fields used for similarity": ", ".join(fields_used),
        }
        return_outputs(readable_output=self.global_msg + tableToMarkdown("Summary", summary))

    def return_outputs_similar_incidents_empty(self):
        return_outputs(
            readable_output=f"### Similar {self.incident_alias.capitalize()}\nNo Similar {self.incident_alias}s were found.",
            outputs={self.get_context_key(): self.create_context(pd.DataFrame())},
        )

    def get_context_key(self):
        return "DBotFindSimilarIncidents"

    def create_context(self, similar_incidents):
        similar_incidents = similar_incidents.replace(np.nan, "", regex=True)
        if len(similar_incidents) == 0:
            context = {"similarIncidentList": {}, "isSimilarIncidentFound": False}
        else:
            context = {"similarIncident": (similar_incidents.to_dict(orient="records")), "isSimilarIncidentFound": True}
        return context

    def return_outputs_similar_incidents(self, show_actual_incident, current_incident, similar_incidents, context):
        first_columns = [
            f"{self.incident_alias} ID",
            "created",
            "name",
            f"similarity {self.incident_alias}",
            "similarity indicators",
            "Identical indicators",
        ]
        remove_columns = ["id", "Id"]
        
        colums_to_display = similar_incidents.columns.tolist()
        colums_to_display = [x for x in first_columns if x in similar_incidents.columns] + [
            x for x in colums_to_display if (x not in first_columns and x not in remove_columns)
        ]

        first_col = [x for x in colums_to_display if x in current_incident.columns]
        col_current_incident_to_display = first_col + [
            x for x in current_incident.columns if (x not in first_col and x not in remove_columns)
        ]

        similar_incidents = similar_incidents.rename(str.title, axis="columns")
        current_incident = current_incident.rename(str.title, axis="columns")

        colums_to_display = [x.title() for x in colums_to_display]
        col_current_incident_to_display = [x.title() for x in col_current_incident_to_display]

        similar_incidents = similar_incidents.replace(np.nan, "", regex=True)
        current_incident = current_incident.replace(np.nan, "", regex=True)

        similar_incidents_json = similar_incidents.to_dict(orient="records")
        incident_json = current_incident.to_dict(orient="records")

        if str(show_actual_incident) == "True":
            return_outputs(
                readable_output=tableToMarkdown(
                    f"Current {self.incident_alias.capitalize()}", incident_json, col_current_incident_to_display
                )
            )
        readable_output = tableToMarkdown(f"Similar {self.incident_alias.capitalize()}s", similar_incidents_json, colums_to_display)
        return_entry = {
            "Type": entryTypes["note"],
            "HumanReadable": readable_output,
            "ContentsFormat": formats["json"],
            "Contents": similar_incidents_json,
            "EntryContext": {self.get_context_key(): context},
        }
        if self.tag_incident is not None:
            return_entry["Tags"] = [f"SimilarIncidents_{self.tag_incident}"]
        demisto.results(return_entry)

    def run(self):
        self.preprocess_args()
        
        exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field = self.get_fields()
        
        display_fields = self.get_display_fields()
        
        from_date, to_date = self.get_dates()
        
        show_distance = self.args.get("showIncidentSimilarityForAllFields")
        confidence = float(self.args.get("minimunIncidentSimilarity") or 0.2)
        max_incidents = int(self.args.get("maxIncidentsToDisplay") or 100)
        aggregate = self.args.get("aggreagateIncidentsDifferentDate") or "False"
        limit = int(self.args.get("limit") or 1500)
        if self.incident_alias == "issue":
            limit += 1
        show_actual_incident = self.args.get("showCurrentIncident")
        incident_id = self.args.get("incidentId")
        include_indicators_similarity = self.args.get("includeIndicatorsSimilarity") or "False"
        
        incident, incident_id = self.load_current_incident(
            incident_id, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, from_date, to_date
        )
        
        if not incident:
            self.return_outputs_error(error_msg=f"- {self.incident_alias.capitalize()} {incident_id} does not exist within the given time range. Please check incidentId value or that you are running the command within an {self.incident_alias}. \n")
            return None, self.global_msg
            
        incidents, msg = self.get_all_incidents(
            exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, incident, from_date, to_date, limit
        )
        self.global_msg += f"{msg} \n"
        
        if incidents:
            demisto.debug(f"Found {len(incidents)} {self.incident_alias}s for {incident_id=}")
        else:
            demisto.debug(f"No {self.incident_alias}s found for {incident_id=}")
            self.return_outputs_summary(confidence, 0, 0, [])
            self.return_outputs_similar_incidents_empty()
            return None, self.global_msg
            
        number_incident_fetched = len(incidents)
        
        incidents_df = pd.DataFrame(incidents)
        incidents_df.index = incidents_df[self.id_field]
        
        incidents_df = fill_nested_fields(incidents_df, incidents, list(similar_text_field), list(similar_categorical_field))
        
        fields_to_check_existence = self.get_fields_to_check_existence(
            exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields
        )
        
        self.global_msg, incorrect_fields = find_incorrect_fields(fields_to_check_existence, incidents_df, self.global_msg, self.incident_alias)
        
        display_fields, similar_text_field, similar_json_field, similar_categorical_field = self.remove_incorrect_fields(
            display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields
        )
        
        incident_df = dumps_json_field_in_incident(deepcopy(incident))
        incident_df = fill_nested_fields(incident_df, incident, list(similar_text_field), list(similar_categorical_field))
        
        model = Model(p_transformation=TRANSFORMATION, incident_alias=self.incident_alias)
        model.init_prediction(
            incident_df, incidents_df, list(similar_text_field), list(similar_categorical_field), list(display_fields), list(similar_json_field)
        )
        
        try:
            similar_incidents, fields_used = model.predict()
        except DemistoException as e:
            self.global_msg += f"- No field are used to find similarity. Reasons:\n{str(e)} \n"
            self.return_outputs_summary(confidence, number_incident_fetched, 0, [])
            self.return_outputs_similar_incidents_empty()
            return None, self.global_msg
            
        if isinstance(similar_incidents, pd.Series):
            similar_incidents = similar_incidents.to_frame().T
            
        similar_incidents = self.enrich_with_indicators(similar_incidents, include_indicators_similarity)
        
        similar_incidents = prepare_incidents_for_display(
            similar_incidents,
            confidence,
            argToBoolean(show_distance or "False"),
            max_incidents,
            fields_used,
            str(aggregate),
            argToBoolean(include_indicators_similarity),
            self.incident_alias
        )
        
        incident_filter = prepare_current_incident(
            incident_df, list(display_fields), list(similar_text_field), list(similar_json_field), list(similar_categorical_field), list(exact_match_fields), self.incident_alias
        )
        
        number_incidents_found = len(similar_incidents)
        self.return_outputs_summary(confidence, number_incident_fetched, number_incidents_found, fields_used)
        
        context = self.create_context(similar_incidents)
        self.return_outputs_similar_incidents(show_actual_incident, incident_filter, similar_incidents, context)
        
        return similar_incidents, self.global_msg


class SimilarIncidentFinder(BaseSimilarObjectFinder):
    def __init__(self, args: dict):
        super().__init__(args)
        self.incident_alias = "alert" if (is_xsiam() or is_platform()) else "incident"
        self.tag_incident = "incidents"
        self.id_field = "id"

    def get_fields_to_check_existence(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields):
        populate_fields = (
            list(similar_text_field) + list(similar_json_field) + list(similar_categorical_field) + list(exact_match_fields) + list(display_fields) + ["id"]
        )
        return populate_fields

    def load_current_incident(self, incident_id, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, from_date, to_date):
        populate_fields = (
            list(similar_text_field) + list(similar_json_field) + list(similar_categorical_field) + list(exact_match_fields) + list(display_fields) + ["id"]
        )
        populate_high_level_fields = keep_high_level_field(populate_fields)
        
        if not incident_id:
            incident = demisto.incidents()[0]
            cf = incident.pop("CustomFields", {}) or {}
            incident.update(cf)
            incident = {k: v for k, v in incident.items() if k in populate_high_level_fields}
            incident_id = incident["id"]
        else:
            populate_fields_value = " , ".join(populate_high_level_fields)
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
            incident = incidents[0] if incidents else None
            if not incident:
                return None, incident_id
        return incident, incident_id

    def get_all_incidents(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, incident, from_date, to_date, limit):
        populate_fields = (
            list(similar_text_field) + list(similar_json_field) + list(similar_categorical_field) + list(exact_match_fields) + list(display_fields) + ["id"]
        )
        populate_high_level_fields = keep_high_level_field(populate_fields)
        if "id" in populate_high_level_fields:
            populate_high_level_fields.remove("id")
            
        msg = ""
        exact_match_fields_list = []
        for exact_match_field in exact_match_fields:
            if exact_match_field not in incident:
                msg += f"- {exact_match_field} field(s) does not exist in the current {self.incident_alias}. \n"
            else:
                exact_match_fields_list.append(f'{exact_match_field}: "{incident[exact_match_field]}"')
        query = " AND ".join(exact_match_fields_list)
        query += f" AND -id:{incident['id']} "
        query_sup = self.args.get("query")
        if query_sup:
            query += f" {query_sup}"

        populate_fields_value = " , ".join(populate_high_level_fields)
        demisto.debug(f"Calling get_incidents_by_query between {from_date=} and {to_date=},{limit=}, {populate_fields_value=}")

        incidents = get_incidents_by_query(
            {"query": query, "populateFields": populate_fields_value, "fromDate": from_date, "toDate": to_date, "limit": limit}
        )
        if len(incidents) == 0:
            msg += f"- 0 {self.incident_alias}s fetched with these exact match for the given dates. \n"
            return None, msg
        if len(incidents) == limit:
            msg += f"- {self.incident_alias.capitalize()} fetched have been truncated to {len(incidents)}, please either add {self.incident_alias} fields in fieldExactMatch, enlarge the time period or increase the limit argument to more than {limit}. \n"
            return incidents, msg
        return incidents, msg

    def enrich_with_indicators(self, similar_incidents, include_indicators_similarity):
        if include_indicators_similarity == "True":
            args_defined_by_user = {key: self.args.get(key) for key in KEYS_ARGS_INDICATORS}
            full_args_indicators_script = {**CONST_PARAMETERS_INDICATORS_SCRIPT, **args_defined_by_user}
            
            demisto.debug("Executing DBotFindSimilarIncidentsByIndicators")
            res = demisto.executeCommand("DBotFindSimilarIncidentsByIndicators", full_args_indicators_script)
            if is_error(res):
                return_error(get_error(res))
                
            indicators_similarity_json = None
            if res is not None:
                for entry in res:
                    if entry and entry.get("Tags") and "similarIncidents" in entry.get("Tags"):
                        indicators_similarity_json = entry["Contents"]
                        break
                        
            indicators_similarity_df = pd.DataFrame(indicators_similarity_json)
            if indicators_similarity_df.empty:
                indicators_similarity_df = pd.DataFrame(columns=["similarity indicators", "Identical indicators", "id"])
            keep_columns = [x for x in ["Identical indicators", "similarity indicators"] if x not in similar_incidents]
            indicators_similarity_df.index = indicators_similarity_df.id
            similar_incidents.loc[:, keep_columns] = indicators_similarity_df[keep_columns]
            values = {"similarity indicators": 0, "Identical indicators": ""}
            similar_incidents = similar_incidents.fillna(value=values)
        return similar_incidents


class SimilarIssueFinder(BaseSimilarObjectFinder):
    def __init__(self, args: dict):
        super().__init__(args)
        self.incident_alias = "issue"
        self.tag_incident = "issues"
        self.id_field = "internal_id"
        self.replacements = {
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

    def preprocess_args(self):
        fields_to_check = ["text_similarity_fields", "filter_equal_fields", "discrete_match_fields"]

        for key in fields_to_check:
            value = self.args.get(key)
            if not value:
                continue

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
                    updated_fields.append(self.replacements.get(f, f))

            self.args[key] = ",".join(updated_fields)

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
            "show_issue_fields_similarity": "showIncidentSimilarityForAllFields"
        }

        new_args = {name_mapping.get(k, k): v for k, v in self.args.items()}
        demisto.debug(f"Changed args for calling the script to: {new_args}")
        self.args = new_args

    def get_display_fields(self):
        display_fields = {"internal_id", "issue_name", "issue_description"} | set(argToList(self.args.get("fieldsToDisplay")))
        display_fields.add("internal_id")
        return list(display_fields)

    def get_dates(self):
        from_date = arg_to_datetime(self.args.get("fromDate"))
        to_date = arg_to_datetime(self.args.get("toDate"))

        from_date_str = str(date_to_timestamp(from_date, self.time_format)) if from_date else None
        to_date_str = str(date_to_timestamp(to_date, self.time_format)) if to_date else None
        return from_date_str, to_date_str

    def get_fields_to_check_existence(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields):
        return [f for f in (set(similar_text_field) | set(similar_json_field) | set(similar_categorical_field))]

    def remove_incorrect_fields(self, display_fields, similar_text_field, similar_json_field, similar_categorical_field, incorrect_fields):
        return [
            list(set(f) - set(incorrect_fields)) for f in [display_fields, similar_text_field, similar_json_field, similar_categorical_field]
        ]

    def load_current_incident(self, incident_id, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, from_date, to_date):
        demisto.debug(
            f"Calling core-get-issues for {incident_id=} between {from_date=} and {to_date=}"
        )
        args = remove_empty_elements({
            "issue_id": incident_id,
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

        issue = issues_res[0].get("alert_fields") if issues_res else None
        if not issue:
            return None, incident_id
        return issue, incident_id

    def get_all_incidents(self, exact_match_fields, similar_text_field, similar_categorical_field, similar_json_field, display_fields, incident, from_date, to_date, limit):
        msg = ""
        base_args = {
            "start_time": from_date,
            "end_time": to_date,
            "time_frame": "custom",
        }

        custom_filter = self.args.get("custom_filter")
        if custom_filter:
            base_args["custom_filter"] = custom_filter

        for exact_match_field in exact_match_fields:
            mapped_field = self.replacements.get(exact_match_field, exact_match_field)
            if mapped_field in incident:
                base_args[exact_match_field] = incident[mapped_field]
            elif exact_match_field in incident:
                base_args[exact_match_field] = incident[exact_match_field]
            else:
                msg += f"- {exact_match_field} field(s) does not exist in the current {self.incident_alias}. \n"

        demisto.debug(f"Base args sent to core-get-issues to filter by: {base_args}")
        all_issues: list[dict] = []
        page_size = 50
        current_issue_id = str(incident.get("internal_id"))

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

                filtered_batch = [
                    i.get("alert_fields") for i in batch_issues
                    if str(i.get("alert_fields", {}).get("internal_id")) != current_issue_id
                ]

                all_issues.extend(filtered_batch)

                if len(batch_issues) < page_size:
                    break

        demisto.debug(f"Total issues fetched: {len(all_issues)}")
        if not all_issues:
            msg += f"- 0 {self.incident_alias}s fetched with these exact match for the given dates. \n"
            return None, msg
        
        if len(all_issues) == limit:
            all_issues.pop()
        
        return all_issues, msg

    def get_context_key(self):
        return "SimilarIssues"

    def create_context(self, similar_incidents):
        df = similar_incidents.copy()

        rename_map = {
            f"similarity {self.incident_alias}": "similarityIssue",
            "id": "id",
            "name": "name",
            "details": "details",
            "Identical indicators": "identicalIndicators",
            "similarity indicators": "similarityIndicators"
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

    def return_outputs_similar_incidents(self, show_actual_incident, current_incident, similar_incidents, context):
        first_columns = [
            f"{self.incident_alias} ID",
            "created",
            "name",
            f"similarity {self.incident_alias}",
            "similarity indicators",
            "Identical indicators",
        ]
        remove_columns = ["id", "Id"]
        
        colums_to_display = similar_incidents.columns.tolist()
        colums_to_display = [x for x in first_columns if x in similar_incidents.columns] + [
            x for x in colums_to_display if (x not in first_columns and x not in remove_columns)
        ]

        first_col = [x for x in colums_to_display if x in current_incident.columns]
        col_current_incident_to_display = first_col + [
            x for x in current_incident.columns if (x not in first_col and x not in remove_columns)
        ]

        rename_map = {"internal_id": "issue_id"}
        similar_incidents = similar_incidents.rename(columns=rename_map)
        current_incident = current_incident.rename(columns=rename_map)

        colums_to_display = [rename_map.get(x, x) for x in colums_to_display]
        col_current_incident_to_display = [rename_map.get(x, x) for x in col_current_incident_to_display]

        similar_incidents = similar_incidents.rename(lambda x: str(x).replace("_", " ").title(), axis="columns")
        current_incident = current_incident.rename(lambda x: str(x).replace("_", " ").title(), axis="columns")

        colums_to_display = [str(x).replace("_", " ").title() for x in colums_to_display]
        col_current_incident_to_display = [str(x).replace("_", " ").title() for x in col_current_incident_to_display]

        similar_incidents = similar_incidents.replace(np.nan, "", regex=True)
        current_incident = current_incident.replace(np.nan, "", regex=True)

        similar_incidents_json = similar_incidents.to_dict(orient="records")
        incident_json = current_incident.to_dict(orient="records")

        if str(show_actual_incident) == "True":
            return_outputs(
                readable_output=tableToMarkdown(
                    f"Current {self.incident_alias.capitalize()}", incident_json, col_current_incident_to_display
                )
            )
        readable_output = tableToMarkdown(f"Similar {self.incident_alias.capitalize()}s", similar_incidents_json, colums_to_display)
        return_entry = {
            "Type": entryTypes["note"],
            "HumanReadable": readable_output,
            "ContentsFormat": formats["json"],
            "Contents": similar_incidents_json,
            "EntryContext": {self.get_context_key(): context},
        }
        if self.tag_incident is not None:
            return_entry["Tags"] = [f"SimilarIssues_{self.tag_incident}"]
        demisto.results(return_entry)
