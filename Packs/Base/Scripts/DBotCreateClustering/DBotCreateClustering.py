import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import pandas as pd
import numpy as np
import collections
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn import cluster
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn import metrics
import hdbscan
#from MulticoreTSNE import MulticoreTSNE as TSNE


MESSAGE_NO_INCIDENT_FETCHED = "- 0 incidents fetched with these exact match for the given dates."
MESSAGE_WARNING_TRUNCATED = "- Incidents fetched have been truncated to %s, please either add incident fields in " \
                            "fieldExactMatch, enlarge the time period or increase the limit argument " \
                            "to more than %s."

PREFIXES_TO_REMOVE = ['incident.']
REGEX_DATE_PATTERN = [re.compile("^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})Z"),
                      re.compile("(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*")]
REPLACE_COMMAND_LINE = {"=": " = ", "\\": "/", "[": "", "]": "", '"': "", "'": "", }


HDBSCAN_PARAMS = {
    'algorithm': 'best',
    'n_jobs': -1,
    'prediction_data': True
}


class PostProcessing(object):
   """
   Class to analyze the clustering
   """

   def __init__(self, model, threshold):
       """
       Instiantiate class object for visualization
       :param clustering: Object Clustering
       """
       self.model = model
       self.clustering = model.named_steps['clustering']
       self.threshold = threshold
       self.stats = {}
       self.silhouette = None
       self.statistics()
       self.compute_dist()

   def statistics(self):
       """
       Compute statistics of the clusters
       """
       plot_silhouette = self.com_silhouette()
       self.stats['General'] = {}
       self.stats['General']['Nb sample'] = self.clustering.raw_data.shape[0]
       self.stats['General']['Nb cluster'] = self.clustering.number_clusters
       self.stats['General']['min_samples'] = self.clustering.model.min_samples
       self.stats['General']['min_cluster_size'] = self.clustering.model.min_cluster_size
       for number_cluster in range(0, self.clustering.number_clusters):
           self.stats[number_cluster] = {}
           self.stats[number_cluster]['number_samples'] = sum(self.clustering.model.labels_ == number_cluster)
           ind = np.where(self.clustering.model.labels_ == number_cluster)[0]
           selected_data = [x for x in self.clustering.raw_data.iloc[ind].label]
           #flat_list = [item for sublist in selected_data for item in sublist]
           counter = collections.Counter(selected_data)
           total = sum(dict(counter).values(), 0.0)
           dist = {k : v * 100 / total for k, v in counter.items()}
           dist = dict((k, v) for k, v in dist.items() if v >= 1)
           self.stats[number_cluster]['distribution sample'] = dist


   def com_silhouette(self):
       """
       Compute the silhouette for the trained model.
       """
       plot_silhouette = []
       print("Silhouette Coefficient:")
       self.silhouette = metrics.silhouette_samples(self.clustering.data, self.clustering.results, metric='euclidean')
       print(np.mean(self.silhouette))
       for number_cluster in range(-1, self.clustering.number_clusters):
           plot_silhouette.append(
               np.mean([self.silhouette[i] for i in range(len(self.silhouette)) if self.clustering.results[i] == number_cluster])
           )
       return plot_silhouette


   def compute_dist(self):
        """
        :param cluster: the number of the chosen cluster
        :param threshols: the threshold used to select the family(ies)
        :return:
        """
        dist_total={}
        for cluster in range(0, self.clustering.number_clusters):
            chosen = {k: v for k, v in self.stats[cluster]['distribution sample'].items() if v >= self.threshold*100}
            total = sum(dict(chosen).values(), 0.0)
            dist = {k: v * 100 / total for k, v in chosen.items()}
            dist_total[cluster] = dist
        self.clus_names = dist_total

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
        :type value: DataFrame with SHA1 as index and features as columns

        """
        X = pd.DataFrame(X, index= y.index)
        self.raw_data = pd.DataFrame(X).join(y, how='right')
        self.data = X
        self.label = y

    def fit(self, X, y=None):
        """
        Fit the model with the self.data set.
        The self.data set should be a numpy.array
        """
        self.get_data(X, y)
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

    min_homogeneity_cluster = float(demisto.args().get('minHomogeneityCluster'))

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
           max_number_of_cluster, min_number_of_incident_in_cluster, model_name, store_model, min_homogeneity_cluster


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


def normalize_global(obj):
    if isinstance(obj, str):
        return normalize_command_line(obj)
    else:
        return normalize_json(obj)

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

def normalize_command_line(command: str) -> str:
    """
    Normalize command line
    :param command: command line
    :return: Normalized command line
    """
    if command and isinstance(command, str):
        my_string = command.lower()
        my_string = "".join([REPLACE_COMMAND_LINE.get(c, c) for c in my_string])
        my_string = my_string.strip()
        return my_string
    else:
        return ''


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
        self.vec = TfidfVectorizer(**{'analyzer': 'char', 'max_features': 2000, 'ngram_range': (2, 5)})

    def fit(self, x, y=None):
        """
        Fit TFIDF transformer
        :param x: incident on which we want to fit the transfomer
        :return: self
        """
        feature_name = x.columns[0]
        if self.normalize_function:
            x = x[feature_name].apply(self.normalize_function)
        self.vec.fit(x)
        return self

    def transform(self, x):
        """
        Transform x with the trained vectorizer
        :param x: DataFrame or np.array
        :return:
        """
        feature_name = x.columns[0]
        if self.normalize_function:
            x = x[feature_name].apply(self.normalize_function)
        else:
            x = x[feature_name]
        return self.vec.transform(x).toarray()


def is_clustering_valid(clustering_model):
    n_labels = len(set(clustering_model.model.labels_))
    n_samples = len(clustering_model.raw_data)
    if not 1 < n_labels < n_samples:
        return False
    return True


def main():
    global_msg = ""

    # Get argument of the automation
    fields_for_clustering, field_for_cluster_name, from_date, to_date, limit, query, incident_type, \
    max_number_of_cluster, min_number_of_incident_in_cluster, model_name, store_model,\
    min_homogeneity_cluster = get_args()

    # Get all the incidents from query, date and field similarity and field family
    populate_fields = fields_for_clustering + field_for_cluster_name
    incidents, msg = get_all_incidents_for_time_window_and_type(populate_fields, from_date, to_date, query, limit, type)
    global_msg += "%s \n" % msg

    if not incidents:
        pass

    incidents_df = pd.DataFrame(incidents)
    incidents_df.index = incidents_df.id

    X = incidents_df[fields_for_clustering]
    labels = incidents_df[field_for_cluster_name].rename(columns={field_for_cluster_name[0]: 'label'})

    ## Model
    # transformers
    tfidf_params = {'analyzer': 'char', 'max_features': 2000, 'ngram_range': (2,5)}

    tfidf_pipe = Pipeline(steps=[
        ('tfidf', Tfidf(normalize_function=normalize_global))
    ])


    #create transformer list

    # preprocessor
    #transformers_list = create_transformers_list(fields_for_clustering)
    transformers_list = [('tfidf', tfidf_pipe, ['commandline']) for field in fields_for_clustering]
    preprocessor = ColumnTransformer(
        transformers=transformers_list)




    # preprocessor = ColumnTransformer(
    #     transformers=[
    #         ('tfidf', tfidf_pipe_text, ['commandline']),
    #     ])

    # pipeline
    HDBSCAN_PARAMS.update({'min_cluster_size': min_number_of_incident_in_cluster,
                           'min_samples': min_number_of_incident_in_cluster})
    model = Pipeline(steps=[('preprocessor', preprocessor),
                            ('clustering', Clustering(HDBSCAN_PARAMS))
                            ])

    model.fit(incidents_df, labels)
    if not is_clustering_valid(model.named_steps['clustering']):
        a=1
        #write actions if clustering not valid
    #model.named_steps['clustering'].reduce_dimension()
    #model.named_steps['clustering'].compute_centers()
    p = PostProcessing(model, min_homogeneity_cluster)



