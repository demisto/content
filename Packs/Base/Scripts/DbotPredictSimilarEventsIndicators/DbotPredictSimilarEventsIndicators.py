import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd
import numpy as np
from collections import Counter
import re


def normalize(l):
    return ' '.join(l)


def identity_score(X, y):
    return X


def flatten(l):
    return [item for sublist in l for item in sublist]


class Tfidf(BaseEstimator, TransformerMixin):
    def __init__(self, feature_names, tfidf_params, normalize_function, x):
        self.feature_names = feature_names
        self.params = tfidf_params
        self.normalize_function = normalize_function
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        self.vocabulary = x.iloc[0].split(' ')

    def fit(self, x, y=None):
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        self.frequency = Counter(flatten([t.split(' ') for t in x.values]))
        self.frequency.update(Counter(self.vocabulary))
        return self

    def transform(self, x, y=None):
        if self.normalize_function:
            x = x[self.feature_names].apply(self.normalize_function)
        else:
            x = x[self.feature_names]
        return x.apply(self.compute_term_score)

    def compute_term_score(self, x):
        x = x.split(' ')
        return sum([1 * (1 / self.frequency[word]) for word in self.vocabulary if word in x]) / \
               sum([(1 / self.frequency[word]) for word in self.vocabulary])


TRANSFORMATION = {
    'indicators': {'transformer': Tfidf,
                   'normalize': None,
                   'params': {'analyzer': 'word', 'max_features': 200, 'token_pattern': '.'},  # [\d\D]*
                   'scoring': {'scoring_function': identity_score, 'min': 0.5}
                   }
}


class Transformer():
    def __init__(self, p_type, field, p_incidents_df, p_incident_to_match, p_params):
        self.type = p_type
        self.field = field
        self.incident_to_match = p_incident_to_match
        self.incidents_df = p_incidents_df
        self.params = p_params

    def fit_transform(self):
        transformation = self.params[self.type]
        transformer = transformation['transformer'](self.field, transformation['params'], transformation['normalize'],
                                                    self.incident_to_match)
        X_vect = transformer.fit_transform(self.incidents_df)
        incident_vect = transformer.transform(self.incident_to_match)

        return X_vect, incident_vect

    def get_score(self):
        scoring_function = self.params[self.type]['scoring']['scoring_function']
        X_vect, incident_vect = self.fit_transform()
        dist = scoring_function(X_vect, incident_vect)
        self.incidents_df['similarity %s' % self.field] = np.round(dist, 2)
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
            if not field in self.incident_to_match.columns or not self.incident_to_match[field].values[
                0] or not isinstance(self.incident_to_match[field].values[0], str) or \
                    self.incident_to_match[field].values[0] == 'None' or self.incident_to_match[field].values[
                0] == 'N/A':
                remove_list.append(field)
        self.indicators = [x for x in self.indicators if x not in remove_list]

    def get_score(self):
        for field in self.indicators:
            t = Transformer('indicators', field, self.incidents_df, self.incident_to_match, self.transformation)
            t.get_score()

    def display(self):
        # self.incidents_df.sort_values(['similarity indicators'], inplace=True, ascending=False)
        vocabulary = self.incident_to_match['indicators'].iloc[0].split(' ')
        self.incidents_df['Identical indicators'] = self.incidents_df['indicators'].apply(
            lambda x: ','.join([id for id in x.split(' ') if id in vocabulary]))


def get_all_indicators_for_incident(incident_id):
    query = 'incident.id:%s' % incident_id
    res = demisto.executeCommand("findIndicators", {'query': query})
    if is_error(res):
        get_error(res)
    if not res[0]['Contents']:
        return_error("No indicators found for this incident")
    indicators = res[0]['Contents']
    return indicators


def get_number_of_invs_for_indicators(indicator):
    invs = indicator.get('investigationIDs') or []
    return len(invs)


def get_indicators_from_incident_ids(ids, incident_id):
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


def match_indicators_incident(indicators, incident_ids):
    d = {k: [] for k in incident_ids}
    for indicator in indicators:
        inv_ids = indicator.get('investigationIDs', None)
        if inv_ids:
            for inv_id in inv_ids:
                if inv_id in d.keys():
                    d[inv_id] = d[inv_id] + [indicator['id']]
    return d


def get_indicators_map(indicators):
    return {ind['id']: ind for ind in indicators}


def join(l):
    return ' '.join(l)


def get_prediction_for_incident():
    max_indicators = int(demisto.args()['maxIncidentsInIndicatorsForWhiteList'])
    aggregate = demisto.args().get('aggreagateIncidents')
    limit_nb_of_indicators = int(demisto.args()['minNumberOfIndicators'])
    threshold = float(demisto.args()['threshold'])
    indicatorsTypes = demisto.args()['indicatorsTypes'].split(',')
    indicatorsTypes = [x.strip() for x in indicatorsTypes if x]

    # load the Dcurrent incident
    incident_id = demisto.args().get('incidentId')
    if not incident_id:
        incident = demisto.incidents()[0]
        incident_id = incident['id']

    # load the related indicators to the incident
    indicators = get_all_indicators_for_incident(incident_id)
    indicators_map = get_indicators_map(indicators)
    indicators = list(filter(lambda x: get_number_of_invs_for_indicators(x) < max_indicators, indicators))
    indicators = [x for x in indicators if x.get('indicator_type') in indicatorsTypes]
    if len(indicators) < limit_nb_of_indicators:
        return_error("Number of indicators found is less then minNumberOfIndicators")

    # Get the Investigation IDs related to the indicators if the incidents
    incident_ids = [indicator.get('investigationIDs', None) for indicator in indicators if
                    indicator.get('investigationIDs', None)]
    incident_ids = flatten(incident_ids)
    p = re.compile('[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}')
    incident_ids = [x for x in incident_ids if not p.match(x)]

    # Get indicators related to those investigations ids
    indicators_related = get_indicators_from_incident_ids(incident_ids, incident_id)
    indicators_related = [x for x in indicators_related if x.get('indicator_type') in indicatorsTypes]
    incidents_with_indicators = match_indicators_incident(indicators_related, incident_ids)
    incidents_with_indicators_join = {k: join(v) for k, v in incidents_with_indicators.items()}
    incidents_with_indicators_join.pop(incident_id, None)
    if not bool(incidents_with_indicators_join):
        return_error("No related incidents found")

    incidents_df = pd.DataFrame.from_dict(incidents_with_indicators_join, orient='index')
    incidents_df.columns = ['indicators']

    indicators_for_incident = [' '.join(set([x.get('id') for x in indicators]))]
    incident_df = pd.DataFrame(indicators_for_incident, columns=['indicators'])

    model = Model(p_transformation=TRANSFORMATION)
    model.init_prediction(incident_df, incidents_df, ['indicators'])
    similar_incidents = model.predict()

    similar_incidents = similar_incidents.reset_index().rename(columns={'index': 'id'})
    similar_incidents['id'] = similar_incidents['id'].apply(lambda _id: "[%s](#/Details/%s)" % (_id, _id))
    similar_incidents['Identical indicators'] = similar_incidents['Identical indicators'].apply(
        lambda _ids: ' '.join([indicators_map.get(x).get('value') for x in _ids.split(',')]))
    similar_incidents = similar_incidents[['id', 'Identical indicators', 'similarity indicators']]
    if aggregate == 'True':
        agg_fields = [x for x in similar_incidents.columns if x not in ['id']]  #
        similar_incidents = similar_incidents.groupby(agg_fields, as_index=False, dropna=False).agg(
            {
                'id': lambda x: ' , '.join(x)}
        )
    similar_incidents = similar_incidents[similar_incidents['similarity indicators'] > threshold]
    similar_incidents.sort_values(['similarity indicators'], inplace=True, ascending=False)
    similar_incidents_json = similar_incidents.to_dict(orient='records')
    return_outputs(readable_output=tableToMarkdown("Similar incidents", similar_incidents_json,
                                                   ['id', 'Identical indicators', 'similarity indicators']))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    get_prediction_for_incident()
