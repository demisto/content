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
COMMON_FIELDS = ['id', 'created', 'name']
PLAYGROUND_PATTERN = '[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}'


def normalize(x: List[str]) -> str:
    """
    Normalize function for indicators
    :param x:  list of indicators
    :return:
    """
    return ' '.join(x)


def identity_score(x):
    """
    Identity function
    :param x: object
    :return:
    """
    return x


def flatten(my_list: List[List]) -> List:
    """
    Flatten a list of list
    :param l: list of list
    :return: list
    """
    return [item for sublist in my_list for item in sublist]


class Tfidf(BaseEstimator, TransformerMixin):
    """
    TFIDF class for indicator
    """

    def __init__(self, feature_names, normalize_function, x):
        self.feature_names = feature_names
        self.normalize_function = normalize_function
        self.frequency = {}
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        self.vocabulary = x.iloc[0].split(' ')

    def fit(self, x):
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        size = len(x) + 1
        frequencies = Counter(flatten([t.split(' ') for t in x.values]))
        frequencies.update(Counter(self.vocabulary))
        self.frequency = {k: math.log(1 + size / v) for k, v in frequencies.items()}
        return self

    def transform(self, x):
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        return x.apply(self.compute_term_score)

    def compute_term_score(self, x):
        x = x.split(' ')
        return sum([1 * self.frequency[word] for word in self.vocabulary if word in x]) / sum(
            [self.frequency[word] for word in self.vocabulary])


TRANSFORMATION = {
    'indicators': {'transformer': Tfidf,
                   'normalize': None,
                   'params': {'analyzer': 'word', 'max_features': 200, 'token_pattern': '.'},
                   'scoring_function': identity_score
                   }
}


class Transformer():
    def __init__(self, p_transformer_type, field, p_incidents_df, p_incident_to_match, p_params):
        self.transformer_type = p_transformer_type
        self.field = field
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.params = p_params

    def fit_transform(self):
        transformation = self.params[self.transformer_type]
        transformer = transformation['transformer'](self.field, transformation['normalize'],
                                                    self.incident_to_match)
        X_vect = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.incident_to_match)
        return X_vect, incident_vect

    def get_score(self):
        scoring_function = self.params[self.transformer_type]['scoring_function']
        X_vect, incident_vect = self.fit_transform()
        distance = scoring_function(X_vect)
        self.incidents_df['similarity %s' % self.field] = np.round(distance, ROUND_SCORING)
        return self.incidents_df


class Model:
    def __init__(self, p_transformation):
        self.transformation = p_transformation

    def init_prediction(self, p_incident_to_match, p_incidents_df, p_indicators=[]):
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.indicators = p_indicators

    def predict(self):
        self.remove_empty_field()
        self.get_score()
        self.display()
        return self.incidents_df

    def remove_empty_field(self):
        remove_list = []
        for field in self.indicators:
            if field not in self.incident_to_match.columns or not self.incident_to_match[field].values[
                0] or not isinstance(self.incident_to_match[field].values[0], str) or \
                    self.incident_to_match[field].values[0] == 'None' or \
                    self.incident_to_match[field].values[0] == 'N/A':
                remove_list.append(field)
        self.indicators = [x for x in self.indicators if x not in remove_list]

    def get_score(self):
        for field in self.indicators:
            t = Transformer('indicators', field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()

    def display(self):
        vocabulary = self.incident_to_match['indicators'].iloc[0].split(' ')
        self.incidents_df['Identical indicators'] = self.incidents_df['indicators'].apply(
            lambda x: ','.join([id for id in x.split(' ') if id in vocabulary]))


def get_all_indicators_for_incident(incident_id: str) -> List[Dict]:
    """
    Get indicators for one incident
    :param incident_id: incident id
    :return:
    """
    query = 'incident.id:%s' % incident_id
    res = demisto.executeCommand("findIndicators", {'query': query})
    if is_error(res):
        get_error(res)
    if not res[0]['Contents']:
        return_error("No indicators found for this incident")
    indicators = res[0]['Contents']
    return indicators


def get_number_of_invs_for_indicators(indicator: Dict) -> int:
    """
    :param indicator: list of dict representing indicators
    :return: lenght of investigation ids for this indicator
    """
    invs = indicator.get('investigationIDs') or []
    return len(invs)


def get_indicators_from_incident_ids(ids: List[str]) -> List[Dict]:
    """
    Get indicators for list of incidents ids
    :param ids: List of incident ids
    :return: List of indicators for each id
    """
    ids_string = []
    for id_ in ids:
        ids_string.append('incident.id: "%s"' % id_)
    query = " OR ".join(ids_string)
    res = demisto.executeCommand('findIndicators', {
        'query': query
    })
    if is_error(res):
        get_error(res)
    if not res[0]['Contents']:
        return_error("No indicators found for the related incidents")
    indicators = res[0]['Contents']
    return indicators


def match_indicators_incident(indicators: List[Dict], incident_ids: List[str]) -> Dict[str, List]:
    """
    :param indicators: list of dict representing indicators
    :param incident_ids: list of incident ids
    :return: dict of {incident id : list of indicators ids related to this incident)
    """
    d = {k: [] for k in incident_ids}  # type: Dict[str, List]
    for indicator in indicators:
        inv_ids = indicator.get('investigationIDs', None)
        if inv_ids:
            for inv_id in inv_ids:
                if inv_id in d.keys():
                    d[inv_id] = d[inv_id] + [indicator['id']]
    return d


def enriched_incidents(df, fields_incident_to_display):
    """
    Enriched incidents with data
    :param df: Incidents dataFrame
    :param fields_incident_to_display: Fields selected for enrichement
    :return: Incidents dataFrame enriched
    """
    if 'id' in df.columns:
        ids = df.id.tolist()
    else:
        ids = df.index
    ids_string = []
    for id_ in ids:
        ids_string.append('id: "%s"' % id_)
    query = " OR ".join(ids_string)
    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': query,
        'populateFields': ' , '.join(fields_incident_to_display)
    })
    if is_error(res):
        return_error(res)
    if not json.loads(res[0]['Contents']):
        return df
    else:
        incidents = json.loads(res[0]['Contents'])
        for field in fields_incident_to_display:
            if field == 'created':
                df[field] = [x.get(field)[:10] for x in incidents]
            elif field == 'status':
                df[field] = [STATUS_DICT.get(x.get(field)) if x.get(field) in STATUS_DICT else ' ' for x in incidents]
            else:
                df[field] = [x.get(field) for x in incidents]
        return df


def return_outputs_custom(readable_output, outputs=None):
    return_entry = {
        "Type": entryTypes["note"],
        "HumanReadable": readable_output,
        "ContentsFormat": formats['json'],
        "Contents": outputs,
        "EntryContext": outputs,
    }
    demisto.results(return_entry)


def return_no_mututal_indicators_found_entry():
    hr = '### Mutual Indicators' + '\n'
    hr += 'No mutual indicators were found.'
    return_outputs_custom(hr, add_context_key(create_context_for_indicators()))


def create_context_for_indicators(indicators_df=None):
    if indicators_df is None:
        indicators_context = []
    else:
        indicators_df.rename({'Value': 'value'}, axis=1, inplace=True)
        indicators_df = indicators_df[['id', 'value']]
        indicators_context = indicators_df.to_dict(orient='records')
    return {'indicators': indicators_context}


def add_context_key(entry_context):
    new_context = {}
    for k, v in entry_context.items():
        new_context['{}.{}'.format('MutualIndicators', k)] = v
    return new_context


def return_indicator_entry(incident_ids, indicators_types, indicators_list):
    indicators_query = 'investigationIDs:({})'.format(' '.join('"{}"'.format(id_) for id_ in incident_ids))
    fields = ['id', 'indicator_type', 'investigationIDs', 'relatedIncCount', 'score', 'value']
    indicators_args = {'query': indicators_query, 'limit': '150', 'populateFields': ','.join(fields)}
    res = demisto.executeCommand('GetIndicatorsByQuery', args=indicators_args)
    if is_error(res):
        return_error(res)
    indicators = res[0]['Contents']
    indicators_df = pd.DataFrame(data=indicators)
    if len(indicators_df) == 0:
        return_no_mututal_indicators_found_entry()
        return indicators_df
    indicators_df = indicators_df[indicators_df['relatedIncCount'] < 150]
    indicators_df['Involved Incidents Count'] = \
        indicators_df['investigationIDs'].apply(lambda x: sum(id_ in incident_ids for id_ in x))
    indicators_df = indicators_df[indicators_df['Involved Incidents Count'] > 1]
    if indicators_types:
        indicators_df = indicators_df[indicators_df.indicator_type.isin(indicators_types)]
    indicators_df = indicators_df[indicators_df.id.isin([x.get('id') for x in indicators_list])]
    if len(indicators_df) == 0:
        return_no_mututal_indicators_found_entry()
        return indicators_df
    indicators_df['Id'] = indicators_df['id'].apply(lambda x: "[%s](#/indicator/%s)" % (x, x))
    indicators_df = indicators_df.sort_values(['score', 'Involved Incidents Count'], ascending=False)
    indicators_df['Reputation'] = indicators_df['score'].apply(scoreToReputation)
    indicators_df.rename({'value': 'Value', 'indicator_type': 'Type'}, axis=1, inplace=True)
    indicators_headers = ['Id', 'Value', 'Type', 'Reputation', 'Involved Incidents Count']
    hr = tableToMarkdown('Mutual Indicators', indicators_df.to_dict(orient='records'),
                         headers=indicators_headers)
    return_outputs_custom(hr, add_context_key(create_context_for_indicators(indicators_df)))
    return indicators_df


def get_indicators_map(indicators: List[Dict]) -> Dict[str, Dict]:
    """
    :param indicators: list of dict representing indicators
    :return: Dictionary {id of indicators: indicators}
    """
    return {ind['id']: ind for ind in indicators}


def join(my_list: List) -> str:
    return ' '.join(my_list)


def display(similar_incidents: pd.DataFrame, indicators_map: Dict[str, Dict], aggregate: bool, threshold: float,
            max_incidents_to_display: int) \
        -> pd.DataFrame:
    """
    Clean and organize dataframe before displaying
    :param similar_incidents: DataFrame of incident
    :param indicators_map: Dict of indicators
    :param aggregate:  boolean if we want to aggregate (disabled for now)
    :param threshold: threshold for similarity score
    :param max_incidents_to_display:  Max number of incidents we want to display
    :return: Clean DataFrame of incident
    """
    similar_incidents = similar_incidents.reset_index().rename(columns={'index': 'id'})
    similar_incidents['ID'] = similar_incidents['id'].apply(lambda _id: "[%s](#/Details/%s)" % (_id, _id))
    similar_incidents['Identical indicators'] = similar_incidents['Identical indicators'].apply(
        lambda _ids: '\n'.join(
            [indicators_map.get(x).get('value') if indicators_map.get(x) else ' ' for x in  # type: ignore
             _ids.split(',')]))  # type: ignore
    similar_incidents = similar_incidents[['ID', 'id', 'Identical indicators', 'similarity indicators']]
    similar_incidents = similar_incidents[similar_incidents['similarity indicators'] > threshold]
    similar_incidents.sort_values(['similarity indicators'], inplace=True, ascending=False)
    return similar_incidents.head(max_incidents_to_display)


def return_no_similar_incident_found_entry():
    hr = '### No Similar indicators' + '\n'
    hr += 'No Similar indicators were found.'
    return_outputs(readable_output=hr, outputs={'DBotFindSimilarIncidentsByIndicators': create_context_for_incidents()})


def create_context_for_incidents(similar_incidents=pd.DataFrame()):
    """
    Return context from dataframe of incident
    :param similar_incidents: DataFrame of incidents with indicators
    :return: context
    """
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


def display_actual_incident(incident_df: pd.DataFrame, incident_id: str, fields_incident_to_display: List[str]) -> None:
    """
    Display current incident
    :param incident_df: DataFrame of incident
    :param incident_id: incident ID
    :param fields_incident_to_display: fields to display
    :return: None
    """
    incident_df['id'] = [incident_id]
    incident_df = enriched_incidents(incident_df, fields_incident_to_display)
    incident_json = incident_df.to_dict(orient='records')
    col_incident = incident_df.columns.tolist()
    col_incident = COMMON_FIELDS + [x for x in col_incident if
                                    x not in ['id', 'created', 'name', 'indicators']]
    return_outputs(readable_output=tableToMarkdown("Actual Incident", incident_json,
                                                   col_incident))


def load_indicators_for_current_incident(incident_id: str, indicators_types: List[str], limit_nb_of_indicators: int,
                                         max_indicators: int, debug: bool):
    """
    Take
    :param incident_id: ID of current incident
    :param indicators_types: list of indicators type accepted
    :param limit_nb_of_indicators: Min number of indicators in the current incident
    :param max_indicators: Max incidents in indicators for white list
    :param debug: Boolean if want to print additional comment
    :return: return [*indicators] and dictionnary {key: indicators} and if early_stop
    """
    indicators = get_all_indicators_for_incident(incident_id)
    indicators_map = get_indicators_map(indicators)
    indicators = list(filter(lambda x: get_number_of_invs_for_indicators(x) < max_indicators, indicators))
    if indicators_types:
        indicators = [x for x in indicators if x.get('indicator_type') in indicators_types]
    if len(indicators) < limit_nb_of_indicators:
        return_no_mututal_indicators_found_entry()
        return_no_similar_incident_found_entry()
        return [], {}, True
    if debug == 'True':
        demisto.results("Indicators found for the incident")
        demisto.results(json.dumps([x.get('id') for x in indicators]))
    return indicators, indicators_map, False


def get_incidents_ids_related_to_indicators(indicators):
    """
    Return incident ids from a list of indicators
    :param indicators: List of indicators
    :return: [*incidents_ids]
    """
    incident_ids = [indicator.get('investigationIDs', None) for indicator in indicators if
                    indicator.get('investigationIDs', None)]
    incident_ids = flatten(incident_ids)
    p = re.compile(PLAYGROUND_PATTERN)
    incident_ids = [x for x in incident_ids if not p.match(x)]
    if not incident_ids:
        return_no_mututal_indicators_found_entry()
        return_no_similar_incident_found_entry()
        return [], True
    return incident_ids, False


def get_related_incidents_with_indicators(incident_ids: List[str], indicators_types: List[str],
                                          incident_id: str) -> pd.DataFrame:
    """
    Create dataframe of incident with indicators from incidents ids list
    :param incident_ids: List if incident id
    :param indicators_types: List of indicators type
    :param incident_id: current incident (in order to remove it)
    :return: dataframe of incident with indicators
    """
    indicators_related = get_indicators_from_incident_ids(incident_ids)
    if indicators_types:
        indicators_related = [x for x in indicators_related if x.get('indicator_type') in indicators_types]
        if not indicators_related:
            return_no_similar_incident_found_entry()
            return pd.DataFrame(), True
    incidents_with_indicators = match_indicators_incident(indicators_related, incident_ids)
    incidents_with_indicators_join = {k: join(v) for k, v in incidents_with_indicators.items()}
    incidents_with_indicators_join.pop(incident_id, None)
    if not bool(incidents_with_indicators_join):
        return_no_similar_incident_found_entry()
        return pd.DataFrame(), True
    incidents_df = pd.DataFrame.from_dict(incidents_with_indicators_join, orient='index')
    incidents_df.columns = ['indicators']
    return incidents_df, False


def main():
    max_indicators = int(demisto.args()['maxIncidentsInIndicatorsForWhiteList'])
    aggregate = demisto.args().get('aggregateIncidents')
    limit_nb_of_indicators = int(demisto.args()['minNumberOfIndicators'])
    threshold = float(demisto.args()['threshold'])
    indicators_types = demisto.args().get('indicatorsTypes')
    if indicators_types:
        indicators_types = indicators_types.split(',')
        indicators_types = [x.strip() for x in indicators_types if x]
    show_actual_incident = demisto.args().get('showActualIncident')
    debug = demisto.args().get('debug')
    max_incidents_to_display = int(demisto.args()['maxIncidentsToDisplay'])
    fields_incident_to_display = demisto.args()['fieldsIncidentToDisplay'].split(',')
    fields_incident_to_display = [x.strip() for x in fields_incident_to_display if x]
    fields_incident_to_display = list(set(['created', 'name'] + fields_incident_to_display))

    # load the Dcurrent incident
    incident_id = demisto.args().get('incidentId')
    if not incident_id:
        incident = demisto.incidents()[0]
        incident_id = incident['id']

    # load the related indicators to the incidents
    indicators, indicators_map, early_exit = load_indicators_for_current_incident(incident_id, indicators_types,
                                                                                  limit_nb_of_indicators,
                                                                                  max_indicators, debug)
    if early_exit:
        return

    # Get the Investigation IDs related to the indicators if the incidents
    incident_ids, early_exit = get_incidents_ids_related_to_indicators(indicators)
    if early_exit:
        return

    # Return Mutual indicators
    _ = return_indicator_entry(incident_ids, indicators_types, indicators)

    # Get related incidents with indicators
    incidents_df, early_exit = get_related_incidents_with_indicators(incident_ids, indicators_types, incident_id)
    if early_exit:
        return

    # Current incident
    indicators_for_incident = [' '.join(set([x.get('id') for x in indicators]))]  # type: ignore
    current_incident_df = pd.DataFrame(indicators_for_incident, columns=['indicators'])

    if debug == 'True':
        incidents_df_debug = incidents_df.reset_index()
        return_outputs(
            readable_output=tableToMarkdown("Incident dataframe debug", incidents_df_debug.to_dict(orient='records'),
                                            list(incidents_df_debug.columns)))

    # Prediction
    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(current_incident_df, incidents_df, ['indicators'])
    similar_incidents = model.predict()

    if debug == "True":
        similar_incidents_debug = similar_incidents.reset_index()
        return_outputs(
            readable_output=tableToMarkdown("After model predict", similar_incidents_debug.to_dict(orient='records'),
                                            list(similar_incidents_debug.columns)))

    # Display and enriched incidents data
    current_incident_df['Indicators'] = current_incident_df['indicators'].apply(
        lambda _ids: '\n'.join(
            [indicators_map.get(x).get('value') if indicators_map.get(x) else ' ' for x in  # type: ignore
             _ids.split(' ')]))  # type: ignore
    similar_incidents = display(similar_incidents, indicators_map, aggregate, threshold, max_incidents_to_display)
    similar_incidents = enriched_incidents(similar_incidents, fields_incident_to_display)

    incident_found_bool = (len(similar_incidents) > 0)

    # Outputs
    similar_incidents_json = similar_incidents.to_dict(orient='records')
    col = similar_incidents.columns.tolist()
    col = ['ID', 'created', 'name'] + [x for x in col if x not in ['ID', 'created', 'name', 'id']]

    if show_actual_incident == 'True':
        display_actual_incident(current_incident_df, incident_id, fields_incident_to_display)

    if incident_found_bool:
        context = create_context_for_incidents(similar_incidents)
        return_outputs(readable_output=tableToMarkdown("Similar incidents", similar_incidents_json, col),
                       outputs={'DBotFindSimilarIncidentsByIndicators': context})
    else:
        return_no_similar_incident_found_entry()

    return similar_incidents_json


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
