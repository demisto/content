import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn import cluster
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
import hdbscan
#from MulticoreTSNE import MulticoreTSNE as TSNE


MESSAGE_NO_INCIDENT_FETCHED = "- 0 incidents fetched with these exact match for the given dates."
MESSAGE_WARNING_TRUNCATED = "- Incidents fetched have been truncated to %s, please either add incident fields in " \
                            "fieldExactMatch, enlarge the time period or increase the limit argument " \
                            "to more than %s."

PREFIXES_TO_REMOVE = ['incident.']
REGEX_DATE_PATTERN = [re.compile("^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})Z"),
                      re.compile("(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*")]

HDBSCAN_PARAMS = {
    'algorithm': 'best',
    'n_jobs': -1,
    'prediction_data': True
}


class Clustering(object):
    """
    Class to build a clustering model.
    """

    def __init__(self, params, model_name='hdbscan'):
        """
        Instiantiate class object for clustering
        """

        self.model_name = model_name
        self.model_glo = None
        self.path_file = None
        self.model = None

        # Data
        self.raw_data = None
        self.data = None
        self.label = None

        # Results
        self.clusters = {}
        self.number_clusters = None
        self.results = None

        # control
        self.TSNE_ = False
        self.centers = {}

        self.create_model(parameters=params)

    def __repr__(self):
        return f'Clustering: model:{self.model_name}, number cluster:{self.number_clusters}'

    @classmethod
    def hdbscan(cls, params):
        return cls(params, 'hdbscan')

    @classmethod
    def kmeans(cls, params):
        return cls(params, 'KMeans')

    @classmethod
    def dbscan(cls, params):
        return cls(params, 'DBSCAN')

    def create_model(self, parameters={}):
        """ Create a new model.
        This function takes in parameter a dictionnary.
        The keys of this dictionnary should comply with the Scikit Learn
        naming.
        """
        if self.model_name == "DBSCAN":
            self.model = cluster.DBSCAN()
        elif self.model_name == "KMeans":
            self.model = cluster.KMeans()
        elif self.model_name == "hdbscan":
            self.model_glo = hdbscan
            self.model = self.model_glo.HDBSCAN()

        for key, value in parameters.items():
            setattr(self.model, key, value)
        return

    def get_data(self, X, y):
        """
        Load X and y
        :type value: DataFrame with SHA1 as index and features as colums

        """
        self.raw_data = X.join(y, how='right')
        self.data = X
        self.label = y

    def fit(self, X):
        """
        Fit the model with the self.data set.
        The self.data set should be a numpy.array
        """
        if hasattr(self.model, 'fit_predict'):
            self.results = self.model.fit_predict(X)
        else:
            self.model.fit(X)
            if hasattr(self.model, 'labels_'):
                self.results = self.model.labels_.astype(np.int)
            else:
                self.results = self.model.predict(X)
        self.number_clusters = len(set(self.results[self.results >= 0]))
        return

    # def reduce_dimension(self, dimension=2):
    #     if not self.TSNE_:
    #         tsne = TSNE(n_jobs=32, n_components=dimension)  # TSNE(n_components=2, learning_rate=1000, verbose=2)
    #         self.data_2d = tsne.fit_transform(self.data)
    #         self.TSNE_ = True

    def compute_centers(self):
        for cluster in range(self.number_clusters):
            center = np.mean(self.data_2d[np.where(self.model.labels_ == cluster)], axis=0)
            self.centers[cluster] = center


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


def extract_fields_from_args(arg: List[str]) -> List[str]:
    fields_list = [preprocess_incidents_field(x.strip(), PREFIXES_TO_REMOVE) for x in arg if x]
    return list(dict.fromkeys(fields_list))


def get_args():  # type: ignore
    """
    Gets argument of this automation
    :return: Argument of this automation
    """
    fields_for_clustering = demisto.args().get('fieldsForClustering', '').split(',')
    fields_for_clustering = extract_fields_from_args(fields_for_clustering)

    field_for_cluster_name = demisto.args().get('fieldForClusterName', '').split(',')
    field_for_cluster_name = extract_fields_from_args(field_for_cluster_name)

    from_date = demisto.args().get('fromDate')
    to_date = demisto.args().get('toDate')
    limit = int(demisto.args()['limit'])
    query = demisto.args().get('query')
    incident_type = demisto.args().get('incidentType')

    max_number_of_cluster = int(demisto.args().get('maxNumberOfCluster'))
    min_number_of_incident_in_cluster = int(demisto.args().get('minNumberofIncidentinCluster'))
    model_name = demisto.args().get('modelName')
    store_model = demisto.args().get('storeModel')

    return fields_for_clustering, field_for_cluster_name, from_date, to_date, limit, query, incident_type, \
           max_number_of_cluster, min_number_of_incident_in_cluster, model_name, store_model


def get_all_incidents_for_time_window_and_type(populate_fields, from_date, to_date, query_sup, limit, type):
    msg = ""
    if query_sup:
        query = " %s" % query_sup
    else:
        query = ""
    res = demisto.executeCommand('GetIncidentsByQuery', {
        'query': query,
        'populateFields': ' , '.join(populate_fields),
        'fromDate': from_date,
        'toDate': to_date,
        'limit': limit,
        'type': type
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


def check_list_of_dict(obj) -> bool:  # type: ignore
    """
    If object is list of dict
    :param obj: any object
    :return: boolean if object is list of dict
    """
    return bool(obj) and all(isinstance(elem, dict) for elem in obj)  # type: ignore


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
    pattern = re.compile('([^\s\w]|_)+')
    my_string = pattern.sub(" ", my_string)
    my_string = my_string.lower()
    return my_string


class Tfidf(BaseEstimator, TransformerMixin):
    """
    TFIDF transformer
    """

    def __init__(self,normalize_function):
        """
        :param model_params: parameters of TFIDF
        :param normalize_function: Normalize function to apply on each sample of the corpus before the vectorization
        """
        self.normalize_function = normalize_function
        self.vec = TfidfVectorizer({'analyzer': 'char', 'max_features': 2000, 'ngram_range': (2, 5)})

    def fit(self, x):
        """
        Fit TFIDF transformer
        :param x: incident on which we want to fit the transfomer
        :return: self
        """
        if self.normalize_function:
            x = x.apply(self.normalize_function)
        self.vec.fit(x)
        return self

    def transform(self, x):
        """
        Transform x with the trained vectorizer
        :param x: DataFrame or np.array
        :return:
        """
        if self.normalize_function:
            x = x.apply(self.normalize_function)
        else:
            x = x
        return self.vec.transform(x).toarray()

def main():
    global_msg = ""

    # Get argument of the automation
    fields_for_clustering, field_for_cluster_name, from_date, to_date, limit, query, incident_type, \
    max_number_of_cluster, min_number_of_incident_in_cluster, model_name, store_model = get_args()

    # Get all the incidents from query, date and field similarity and field family
    populate_fields = fields_for_clustering + field_for_cluster_name
    incidents, msg = get_all_incidents_for_time_window_and_type(populate_fields, from_date, to_date, query, limit, type)
    global_msg += "%s \n" % msg

    if not incidents:
        pass

    incidents_df = pd.DataFrame(incidents)
    incidents_df.index = incidents_df.id

    X = incidents_df[fields_for_clustering]
    labels = incidents_df[field_for_cluster_name]

    ## Model

    # transformers
    tfidf_params = {'analyzer': 'char', 'max_features': 2000, 'ngram_range': (2, 5)}
    tfidf_pipe = Pipeline(steps=[
        ('tfidf', Tfidf(normalize_function=normalize_json))
    ])

    # preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('tfidf', tfidf_pipe, fields_for_clustering),
        ])

    # pipeline
    HDBSCAN_PARAMS.update({'min_cluster_size': min_number_of_incident_in_cluster,
                           'min_samples': min_number_of_incident_in_cluster})
    model = Pipeline(steps=[('preprocessor', preprocessor),
                            ('clustering', Clustering(HDBSCAN_PARAMS))
                            ])

    # Vectorize the data
    df_vectorized = model.fit(incidents_df)

    # Cluster the data

    # Postprocess the clusters

    # Outputs
    # json of clustering (demo)
    # model
