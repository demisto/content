import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import warnings
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.base import BaseEstimator, TransformerMixin
import json
import pandas as pd
from scipy.spatial.distance import cdist

warnings.simplefilter("ignore")

MESSAGE_NO_FIELDS_USED = "- No field are used to find similarity. Possible reasons: 1) No field selected  " \
                         " 2) Selected field are empty for this incident  3) Fields are misspelled"

MESSAGE_NO_INCIDENT_FETCHED = "- 0 incidents fetched with these exact match for the given dates."

MESSAGE_WARNING_TRUNCATED = "- Incidents fetched have been truncated to %s, please either add incident fields in " \
                            "fieldExactMatch, enlarge the time period or increase the limit argument " \
                            "to more than %s."

MESSAGE_NO_CURRENT_INCIDENT = "- Incident %s does not exist within the given time range. " \
                              "Please check incidentId value or that you are running the command within an incident."
MESSAGE_NO_FIELD = "- %s field(s) does not exist in the current incident."
MESSAGE_INCORRECT_FIELD = "- %s field(s) don't/doesn't exist within the fetched incidents."

SIMILARITY_COLUNM_NAME = 'similarity incident'
SIMILARITY_COLUNM_NAME_INDICATOR = 'similarity indicators'
IDENTICAL_INDICATOR = 'Identical indicators'
ORDER_SCORE_WITH_INDICATORS = [SIMILARITY_COLUNM_NAME, SIMILARITY_COLUNM_NAME_INDICATOR]
ORDER_SCORE_NO_INDICATORS = [SIMILARITY_COLUNM_NAME]
COLUMN_ID = 'incident ID'
FIRST_COLUMNS_INCIDENTS_DISPLAY = [COLUMN_ID, 'created', 'name', SIMILARITY_COLUNM_NAME,
                                   SIMILARITY_COLUNM_NAME_INDICATOR,
                                   IDENTICAL_INDICATOR]
REMOVE_COLUMNS_INCIDENTS_DISPLAY = ['id', 'Id']
FIELDS_NO_AGGREGATION = ['id', 'created', COLUMN_ID]
COLUMN_TIME = 'created'
TAG_INCIDENT = 'incidents'
TAG_SCRIPT_INDICATORS = "similarIncidents"
KEEP_COLUMNS_INDICATORS = ['Identical indicators', 'similarity indicators']

PREFIXES_TO_REMOVE = ['incident.']
CONST_PARAMETERS_INDICATORS_SCRIPT = {'threshold': '0',
                                      'showActualIncident': 'False',
                                      'debug': 'False',
                                      'maxIncidentsToDisplay': '3000'
                                      }
KEYS_ARGS_INDICATORS = ['indicatorsTypes', 'maxIncidentsInIndicatorsForWhiteList', 'minNumberOfIndicators',
                        'incidentId']

REGEX_DATE_PATTERN = [re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})Z"),
                      re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*")]
REGEX_IP = re.compile(
    r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
REPLACE_COMMAND_LINE = {"=": " = ", "\\": "/", "[": "", "]": "", '"': "", "'": "", }


def keep_high_level_field(incidents_field: List[str]) -> List[str]:
    """
    Return list of fields if they are in the first level of the argument - xdralert.commandline will return xdralert
    :param incidents_field: list of incident fields
    :return: Return list of fields
    """
    return [x.split('.')[0] if '.' in x else x for x in incidents_field]


def wrapped_list(obj: List) -> List:
    """
    Wrapped object into a list if not list
    :param obj:
    :return:
    """
    if not isinstance(obj, list):
        return [obj]
    return obj


def preprocess_incidents_field(incidents_field: str, prefix_to_remove: List[str]) -> str:
    """
    Remove prefixe from incident fields
    :param incidents_field: field
    :param prefix_to_remove: prefix_to_remove
    :return: field without prefix
    """
    incidents_field = incidents_field.strip()
    for prefix in prefix_to_remove:
        if incidents_field.startswith(prefix):
            incidents_field = incidents_field[len(prefix):]
    return incidents_field


def check_list_of_dict(obj) -> bool:  # type: ignore
    """
    If object is list of dict
    :param obj: any object
    :return: boolean if object is list of dict
    """
    return bool(obj) and all(isinstance(elem, dict) for elem in obj)  # type: ignore


def remove_duplicates(seq: List[str]) -> List[str]:
    seen = set()  # type: ignore
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]


def recursive_filter(item: Union[List[Dict], Dict], regex_patterns: List, *fieldsToRemove):
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
        obj = {k: v for k, v in enumerate(obj)}
    if not isinstance(obj, dict):
        return " "
    my_dict = recursive_filter(obj, REGEX_DATE_PATTERN, "None", "N/A", None, "")
    my_string = json.dumps(my_dict)
    pattern = re.compile(r'([^\s\w]|_)+')
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
        command = ' '.join(set(command))
    if command and isinstance(command, str):
        my_string = command.lower()
        my_string = "".join([REPLACE_COMMAND_LINE.get(c, c) for c in my_string])
        my_string = REGEX_IP.sub('IP', my_string)
        my_string = my_string.strip()
        return my_string
    else:
        return ''


def fill_nested_fields(incidents_df: pd.DataFrame, incidents: pd.DataFrame, *list_of_field_list: List[str]) -> \
        pd.DataFrame:
    for field_type in list_of_field_list:
        for field in field_type:
            if '.' in field:
                if isinstance(incidents, list):
                    value_list = [wrapped_list(demisto.dt(incident, field)) for incident in incidents]
                    value_list = [' '.join(set(list(filter(lambda x: x not in ['None', None, 'N/A'], x)))) for x in
                                  value_list]
                else:
                    value_list = wrapped_list(demisto.dt(incidents, field))
                    value_list = ' '.join(  # type: ignore
                        set(list(filter(lambda x: x not in ['None', None, 'N/A'], value_list))))  # type: ignore
                incidents_df[field] = value_list
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
        return ''


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
    'commandline': {'transformer': Tfidf,
                    'normalize': normalize_command_line,
                    'params': {'analyzer': 'char', 'max_features': 2000, 'ngram_range': (2, 5)},
                    'scoring_function': euclidian_similarity_capped
                    },
    'potentialMatch': {'transformer': Identity,
                       'normalize': None,
                       'params': {},
                       'scoring_function': identity
                       },
    'json': {'transformer': Tfidf,
             'normalize': normalize_json,
             'params': {'analyzer': 'char', 'max_features': 10000, 'ngram_range': (2, 5)},
             'scoring_function': euclidian_similarity_capped
             }
}


class Transformer():
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
        transformer = transformation['transformer'](self.field, transformation['params'], transformation['normalize'],
                                                    self.incident_to_match)
        x_vect = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.incident_to_match)

        return x_vect, incident_vect

    def get_score(self):
        """
        :return: Add one columns 'similarity %s' % self.field to self.incidents_df Dataframe with the score
        """
        scoring_function = self.params[self.transformer_type]['scoring_function']
        X_vect, incident_vect = self.fit_transform()
        dist = scoring_function(X_vect, incident_vect)
        self.incidents_df['similarity %s' % self.field] = np.round(dist, 2)
        return self.incidents_df


class Model:
    def __init__(self, p_transformation):
        """
        :param p_transformation: Dict with the transformers parameters - TRANSFORMATION
        """
        self.transformation = p_transformation

    def init_prediction(self, p_incident_to_match, p_incidents_df, p_field_for_command_line=[],
                        p_field_for_potential_exact_match=[], p_field_for_display_fields_incidents=[],
                        p_field_for_json=[]):
        """

        :param p_incident_to_match: Dataframe with one incident
        :param p_incidents_df: Dataframe with all the incidents
        :param p_field_for_command_line: list of incident fields that for the transformer 'command_line'
        :param p_field_for_potential_exact_match: list of incident fields that for the transformer 'potential_exact_match'
        :param p_field_for_display_fields_incidents: list of incident fields that for the transformer 'display_fields_incidents'
        :param p_field_for_json: list of incident fields that for the transformer 'json'
        :return:
        """
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.field_for_command_line = p_field_for_command_line
        self.field_for_potential_exact_match = p_field_for_potential_exact_match
        self.field_for_display_fields_incidents = p_field_for_display_fields_incidents
        self.field_for_json = p_field_for_json

    def predict(self):
        self.remove_empty_field()
        self.get_score()
        self.compute_final_score()
        return self.prepare_for_display(), self.field_for_command_line + self.field_for_potential_exact_match + \
            self.field_for_json

    def remove_empty_field(self):
        """
        Remove field where value if empty or unusable or does not exist in the incident...
        :return:
        """
        remove_list = []
        for field in self.field_for_command_line:
            if field not in self.incident_to_match.columns \
                    or not self.incident_to_match[field].values[0] \
                    or (not isinstance(self.incident_to_match[field].values[0], str) and not isinstance(
                    self.incident_to_match[field].values[0], list)) \
                    or self.incident_to_match[field].values[0] == 'None' \
                    or self.incident_to_match[field].values[0] == 'N/A':
                remove_list.append(field)
        self.field_for_command_line = [x for x in self.field_for_command_line if x not in remove_list]

        remove_list = []
        for field in self.field_for_potential_exact_match:
            if field not in self.incident_to_match.columns or not self.incident_to_match[field].values[
                0] or not isinstance(self.incident_to_match[field].values[0], str) or \
                    self.incident_to_match[field].values[0] == 'None' or self.incident_to_match[field].values[
                    0] == 'N/A':
                remove_list.append(field)
        self.field_for_potential_exact_match = [x for x in self.field_for_potential_exact_match if x not in remove_list]

        remove_list = []
        for field in self.field_for_json:
            if field not in self.incident_to_match.columns or not self.incident_to_match[field].values[
                0] or self.incident_to_match[field].values[0] == 'None' or self.incident_to_match[field].values[
                    0] == 'N/A' or all(not x for x in self.incident_to_match[field].values[0]):
                remove_list.append(field)
        self.field_for_json = [x for x in self.field_for_json if x not in remove_list]

    def get_score(self):
        """
        Apply transformation for each field in possible transformer
        :return:
        """
        for field in self.field_for_command_line:
            t = Transformer('commandline', field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()
        for field in self.field_for_potential_exact_match:
            t = Transformer('potentialMatch', field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()
        for field in self.field_for_json:
            t = Transformer('json', field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()

    def compute_final_score(self):
        """
        Compute final score based on average of similarity score for each field transformed
        :return:
        """
        col = self.incidents_df.loc[:, ['similarity %s' % field for field in self.field_for_command_line
                                        + self.field_for_json]]
        self.incidents_df[SIMILARITY_COLUNM_NAME] = np.round(col.mean(axis=1), 2)

    def prepare_for_display(self):
        self.compute_final_score()
        display_fields = remove_duplicates(
            self.field_for_display_fields_incidents + self.field_for_command_line
            + self.field_for_potential_exact_match + [
                'similarity %s' % field for field in
                self.field_for_command_line + self.field_for_json + self.field_for_potential_exact_match])
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


def prepare_incidents_for_display(similar_incidents: pd.DataFrame, confidence: float, show_distance: bool, max_incidents: int,
                                  fields_used: List[str],
                                  aggregate: str, include_indicators_similarity: bool) -> pd.DataFrame:
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
    if 'id' in similar_incidents.columns.tolist():
        similar_incidents[COLUMN_ID] = similar_incidents['id'].apply(lambda _id: "[%s](#/Details/%s)" % (_id, _id))
    if COLUMN_TIME in similar_incidents.columns:
        similar_incidents[COLUMN_TIME] = similar_incidents[COLUMN_TIME].apply(lambda x: return_clean_date(x))
    if aggregate == 'True':
        agg_fields = [x for x in similar_incidents.columns if x not in FIELDS_NO_AGGREGATION]
        similar_incidents = similar_incidents.groupby(agg_fields, as_index=False, dropna=False).agg(
            {
                COLUMN_TIME: lambda x: "%s -> %s" % (min(filter(None, x)), max(filter(None, x))) if len(x) > 1 else x,
                'id': lambda x: ' , '.join(x),
                COLUMN_ID: lambda x: ' , '.join(x),
            }
        )

    if confidence:
        similar_incidents = similar_incidents[similar_incidents[SIMILARITY_COLUNM_NAME] >= confidence]
    if show_distance == 'False':
        col_to_remove = ['similarity %s' % field for field in fields_used]
        similar_incidents.drop(col_to_remove, axis=1, inplace=True)
    if include_indicators_similarity == "True":
        similar_incidents = similar_incidents.sort_values(by=ORDER_SCORE_WITH_INDICATORS, ascending=False)
    else:
        similar_incidents = similar_incidents.sort_values(by=ORDER_SCORE_NO_INDICATORS, ascending=False)

    return similar_incidents.head(max_incidents)


def get_incident_by_id(incident_id: str, populate_fields: List[str], from_date: str, to_date: str):
    """
    Get incident acording to incident id
    :param incident_id:
    :param populate_fields:
    :param from_date: from_date
    :param to_date: to_date
    :return: Get incident acording to incident id
    """
    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': "id:(%s)" % incident_id,
        'populateFields': ' , '.join(populate_fields),
        'fromDate': from_date,
        'toDate': to_date,
    })
    if is_error(res):
        return_error(res)
    if not json.loads(res[0]['Contents']):
        return None
    else:
        incident = json.loads(res[0]['Contents'])
        return incident[0]


def get_all_incidents_for_time_window_and_exact_match(exact_match_fields: List[str], populate_fields: List[str],
                                                      incident: Dict, from_date: str, to_date: str,
                                                      query_sup: str, limit: int):
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
        if exact_match_field not in incident.keys():
            msg += "%s \n" % MESSAGE_NO_FIELD % exact_match_field
        else:
            exact_match_fields_list.append('%s: "%s"' % (exact_match_field, incident[exact_match_field]))
    query = " AND ".join(exact_match_fields_list)
    query += " AND -id:%s " % incident['id']
    if query_sup:
        query += " %s" % query_sup

    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': query,
        'populateFields': ' , '.join(populate_fields),
        'fromDate': from_date,
        'toDate': to_date,
        'limit': limit
    })
    if is_error(res):
        return_error(res)
    incidents = json.loads(res[0]['Contents'])
    if len(incidents) == 0:
        msg += "%s \n" % MESSAGE_NO_INCIDENT_FETCHED
        return None, msg
    if len(incidents) == limit:
        msg += "%s \n" % MESSAGE_WARNING_TRUNCATED % (str(len(incidents)), str(limit))
        return incidents, msg
    return incidents, msg


def extract_fields_from_args(arg: List[str]) -> List[str]:
    fields_list = [preprocess_incidents_field(x.strip(), PREFIXES_TO_REMOVE) for x in arg if x]
    return list(dict.fromkeys(fields_list))


def get_args():  # type: ignore
    """
    Gets argument of this automation
    :return: Argument of this automation
    """
    use_all_field = demisto.args().get('useAllFields')
    if use_all_field == 'True':
        similar_text_field = []
        similar_json_field = ['CustomFields']
        similar_categorical_field = []
        exact_match_fields = ['type']
    else:
        similar_text_field = demisto.args().get('similarTextField', '').split(',')
        similar_text_field = extract_fields_from_args(similar_text_field)

        similar_categorical_field = demisto.args().get('similarCategoricalField', '').split(',')
        similar_categorical_field = extract_fields_from_args(similar_categorical_field)

        similar_json_field = demisto.args().get('similarJsonField', '').split(',')
        similar_json_field = extract_fields_from_args(similar_json_field)

        exact_match_fields = demisto.args().get('fieldExactMatch', '').split(',')
        exact_match_fields = extract_fields_from_args(exact_match_fields)

    display_fields = demisto.args().get('fieldsToDisplay', '').split(',')
    display_fields = [x.strip() for x in display_fields if x]
    display_fields = list(set(['id', 'created', 'name'] + display_fields))
    display_fields = list(dict.fromkeys(display_fields))

    from_date = demisto.args().get('fromDate')
    to_date = demisto.args().get('toDate')
    show_similarity = demisto.args().get('showIncidentSimilarityForAllFields')
    confidence = float(demisto.args().get('minimunIncidentSimilarity'))
    max_incidents = int(demisto.args().get('maxIncidentsToDisplay'))
    query = demisto.args().get('query')
    aggregate = demisto.args().get('aggreagateIncidentsDifferentDate')
    limit = int(demisto.args()['limit'])
    show_actual_incident = demisto.args().get('showCurrentIncident')
    incident_id = demisto.args().get('incidentId')
    include_indicators_similarity = demisto.args().get('includeIndicatorsSimilarity')

    return similar_text_field, similar_json_field, similar_categorical_field, exact_match_fields, display_fields, \
        from_date, to_date, show_similarity, confidence, max_incidents, query, aggregate, limit, \
        show_actual_incident, incident_id, include_indicators_similarity


def load_current_incident(incident_id: str, populate_fields: List[str], from_date: str, to_date: str):
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
        cf = incident.pop('CustomFields', {}) or {}
        incident.update(cf)
        incident = {k: v for k, v in incident.items() if k in populate_fields}
        incident_id = incident['id']
    else:
        incident = get_incident_by_id(incident_id, populate_fields, from_date, to_date)
        if not incident:
            return None, incident_id
    return incident, incident_id


def remove_fields_not_in_incident(*args, incorrect_fields):
    """
    Return list without field in incorrect_fields
    :param args: *List of fields
    :param incorrect_fields: fields that we don't want
    :return:
    """
    return [[x for x in field_type if x not in incorrect_fields] for field_type in args]


def get_similar_incidents_by_indicators(args: Dict):
    """
    Use DBotFindSimilarIncidentsByIndicators automation and return similars incident from the automation
    :param args: argument for DBotFindSimilarIncidentsByIndicators automation
    :return:  return similars incident from the automation
    """
    res = demisto.executeCommand('DBotFindSimilarIncidentsByIndicators', args)
    if is_error(res):
        return_error(get_error(res))
    res = get_data_from_indicators_automation(res, TAG_SCRIPT_INDICATORS)
    return res


def get_data_from_indicators_automation(res, TAG_SCRIPT_INDICATORS_VALUE):
    for entry in res:
        if entry and entry.get('Tags') and TAG_SCRIPT_INDICATORS_VALUE in entry.get('Tags'):
            return entry['Contents']
    return None


def dumps_json_field_in_incident(incident: Dict):
    """
    Dumps value that are dict in for incident values
    :param incident: json representing the incident
    :return:
    """
    for field in incident.keys():
        if isinstance(incident[field], dict):
            incident[field] = json.dumps(incident[field])
    incident_df = pd.DataFrame.from_dict(incident, orient='index').T
    return incident_df


def return_outputs_summary(confidence: float, number_incident_fetched: int, number_incidents_found: int,
                           fields_used: List[str], global_msg: str) -> None:
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
        'Confidence': str(confidence),
        'Number of incidents fetched with exact match ': number_incident_fetched,
        'Number of similar incidents found ': number_incidents_found,
        'Valid fields used for similarity': ', '.join(fields_used),
    }
    return_outputs(readable_output=global_msg + tableToMarkdown("Summary", summary))


def create_context_for_incidents(similar_incidents=pd.DataFrame()):
    """
    Return context from dataframe of incident
    :param similar_incidents: DataFrame of incidents with indicators
    :return: context
    """
    similar_incidents = similar_incidents.replace(np.nan, '', regex=True)
    if len(similar_incidents) == 0:
        context = {
            'similarIncidentList': {},
            'isSimilarIncidentFound': False
        }
    else:
        context = {
            'similarIncident': (similar_incidents.to_dict(orient='records')),
            'isSimilarIncidentFound': True
        }
    return context


def return_outputs_similar_incidents(show_actual_incident: bool, current_incident: pd.DataFrame,
                                     similar_incidents: pd.DataFrame, context: Dict,
                                     tag: Union[str, None] = None):
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
    colums_to_display = [x for x in FIRST_COLUMNS_INCIDENTS_DISPLAY if x in similar_incidents.columns] + \
                        [x for x in colums_to_display if (x not in FIRST_COLUMNS_INCIDENTS_DISPLAY and x not in
                                                          REMOVE_COLUMNS_INCIDENTS_DISPLAY)]

    first_col = [x for x in colums_to_display if x in current_incident.columns]
    col_current_incident_to_display = first_col + [x for x in current_incident.columns if
                                                   (x not in first_col and x not in REMOVE_COLUMNS_INCIDENTS_DISPLAY)]

    similar_incidents = similar_incidents.rename(str.title, axis='columns')
    current_incident = current_incident.rename(str.title, axis='columns')

    colums_to_display = [x.title() for x in colums_to_display]
    col_current_incident_to_display = [x.title() for x in col_current_incident_to_display]

    similar_incidents = similar_incidents.replace(np.nan, '', regex=True)
    current_incident = current_incident.replace(np.nan, '', regex=True)

    similar_incidents_json = similar_incidents.to_dict(orient='records')
    incident_json = current_incident.to_dict(orient='records')

    if show_actual_incident == 'True':
        return_outputs(
            readable_output=tableToMarkdown("Current Incident", incident_json, col_current_incident_to_display))
    readable_output = tableToMarkdown("Similar incidents", similar_incidents_json, colums_to_display)
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats['json'],
        "Contents": similar_incidents_json,
        "EntryContext": {'DBotFindSimilarIncidents': context},
    }
    if tag is not None:
        return_entry["Tags"] = ['SimilarIncidents_{}'.format(tag)]
    demisto.results(return_entry)


def find_incorrect_fields(populate_fields: List[str], incidents_df: pd.DataFrame, global_msg: str):
    """
    Check Field that appear in populate_fields but are not in the incidents_df and return message
    :param populate_fields: List of fields
    :param incidents_df: DataFrame of the incidents with fields in columns
    :param global_msg: global_msg
    :return: global_msg, incorrect_fields
    """
    incorrect_fields = [i for i in populate_fields if i not in incidents_df.columns.tolist()]
    if incorrect_fields:
        global_msg += "%s \n" % MESSAGE_INCORRECT_FIELD % ' , '.join(
            incorrect_fields)
    return global_msg, incorrect_fields


def return_outputs_error(error_msg):
    return_entry = {"Type": entryTypes["note"],
                    "HumanReadable": error_msg,
                    "ContentsFormat": formats['json'],
                    "Contents": None,
                    "EntryContext": None,
                    "Tags": ['Error.id']
                    }
    demisto.results(return_entry)


def return_outputs_similar_incidents_empty():
    """
    Return entry and context for similar incidents if no similar incidents were found
    :return:
    """
    hr = '### Similar Incident' + '\n'
    hr += 'No Similar incident were found.'
    return_outputs(readable_output=hr,
                   outputs={'DBotFindSimilarIncidents': create_context_for_incidents()})


def enriched_with_indicators_similarity(full_args_indicators_script: Dict, similar_incidents: pd.DataFrame):
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
        indicators_similarity_df = pd.DataFrame(
            columns=[SIMILARITY_COLUNM_NAME_INDICATOR, 'Identical indicators', 'id'])
    keep_columns = [x for x in KEEP_COLUMNS_INDICATORS if x not in similar_incidents]
    indicators_similarity_df.index = indicators_similarity_df.id
    similar_incidents = similar_incidents.join(indicators_similarity_df[keep_columns])
    values = {SIMILARITY_COLUNM_NAME_INDICATOR: 0, 'Identical indicators': ""}
    similar_incidents = similar_incidents.fillna(value=values)
    return similar_incidents


def prepare_current_incident(incident_df: pd.DataFrame, display_fields: List[str], similar_text_field: List[str],
                             similar_json_field: List[str], similar_categorical_field: List[str],
                             exact_match_fields: List[str]) -> pd.DataFrame:
    """
    Prepare current incident for vizualisation
    :param incident_df: incident_df
    :param display_fields: display_fields
    :param similar_text_field: similar_text_field
    :param similar_json_field: similar_json_field
    :param similar_categorical_field: similar_categorical_field
    :param exact_match_fields: exact_match_fields
    :return:
    """
    incident_filter = incident_df[[x for x in
                                   display_fields + similar_text_field + similar_categorical_field
                                   + exact_match_fields if x in incident_df.columns]]
    if COLUMN_TIME in incident_filter.columns.tolist():
        incident_filter[COLUMN_TIME] = incident_filter[COLUMN_TIME].apply(lambda x: return_clean_date(x))
    if 'id' in incident_filter.columns.tolist():
        incident_filter[COLUMN_ID] = incident_filter['id'].apply(lambda _id: "[%s](#/Details/%s)" % (_id, _id))
    return incident_filter


def main():
    similar_text_field, similar_json_field, similar_categorical_field, exact_match_fields, display_fields, from_date, \
        to_date, show_distance, confidence, max_incidents, query, aggregate, limit, show_actual_incident, \
        incident_id, include_indicators_similarity = get_args()

    global_msg = ""

    populate_fields = similar_text_field + similar_json_field + similar_categorical_field + exact_match_fields \
        + display_fields + ['id']
    populate_high_level_fields = keep_high_level_field(populate_fields)

    incident, incident_id = load_current_incident(incident_id, populate_high_level_fields, from_date, to_date)
    if not incident:
        return_outputs_error(error_msg="%s \n" % MESSAGE_NO_CURRENT_INCIDENT % incident_id)
        return None, global_msg

    # load the related incidents
    populate_fields.remove('id')
    incidents, msg = get_all_incidents_for_time_window_and_exact_match(exact_match_fields, populate_high_level_fields,
                                                                       incident,
                                                                       from_date, to_date, query, limit)
    global_msg += "%s \n" % msg

    if not incidents:
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
    display_fields, similar_text_field, similar_json_field, similar_categorical_field = \
        remove_fields_not_in_incident(display_fields, similar_text_field, similar_json_field, similar_categorical_field,
                                      incorrect_fields=incorrect_fields)

    # Dumps all dict in the current incident
    incident_df = dumps_json_field_in_incident(incident)
    incident_df = fill_nested_fields(incident_df, incident, similar_text_field, similar_categorical_field)

    # Model prediction
    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(incident_df, incidents_df, similar_text_field,
                          similar_categorical_field, display_fields, similar_json_field)
    similar_incidents, fields_used = model.predict()

    if len(fields_used) == 0:
        global_msg += "%s \n" % MESSAGE_NO_FIELDS_USED
        return_outputs_summary(confidence, number_incident_fetched, 0, fields_used, global_msg)
        return_outputs_similar_incidents_empty()
        return None, global_msg

    # Get similarity based on indicators
    if include_indicators_similarity == "True":
        args_defined_by_user = {key: demisto.args().get(key) for key in KEYS_ARGS_INDICATORS}
        full_args_indicators_script = {**CONST_PARAMETERS_INDICATORS_SCRIPT, **args_defined_by_user}
        similar_incidents = enriched_with_indicators_similarity(full_args_indicators_script, similar_incidents)

    similar_incidents = prepare_incidents_for_display(similar_incidents, confidence, show_distance, max_incidents,
                                                      fields_used, aggregate, include_indicators_similarity)

    # Filter incident to investigate
    incident_filter = prepare_current_incident(incident_df, display_fields, similar_text_field, similar_json_field,
                                               similar_categorical_field, exact_match_fields)

    # Return summary outputs of the automation
    number_incidents_found = len(similar_incidents)
    return_outputs_summary(confidence, number_incident_fetched, number_incidents_found, fields_used, global_msg)

    # Create context and outputs
    context = create_context_for_incidents(similar_incidents)
    return_outputs_similar_incidents(show_actual_incident, incident_filter, similar_incidents, context, TAG_INCIDENT)
    return similar_incidents, global_msg


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
