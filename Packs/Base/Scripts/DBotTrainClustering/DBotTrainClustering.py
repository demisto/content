import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import pandas as pd
import numpy as np
import collections
import dill as pickle
import builtins
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn import cluster
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.manifold import TSNE
import hdbscan
from datetime import datetime
from typing import Type, Tuple, Dict, List, Union
import math

GENERAL_MESSAGE_RESULTS = "#### - We succeeded to group **%s incidents into %s groups**.\n #### - The grouping was based on " \
                          "the **%s** field(s).\n #### - Each group name is based on the majority value of the **%s** field in " \
                          "the group.\n #### - For %s incidents, we didn’t find any matching.\n" \
                          " #### - Model was trained on **%s**.\n"

MESSAGE_NO_INCIDENT_FETCHED = "- 0 incidents fetched with these exact match for the given dates."
MESSAGE_WARNING_TRUNCATED = "- Incidents fetched have been truncated to %s. please either enlarge the time period " \
                            "or increase the limit argument to more than %s."
MESSAGE_CLUSTERING_NOT_VALID = "Clustering cannot be created with this dataset"
MESSAGE_INCORRECT_FIELD = "- %s field(s) don't/doesn't exist within the fetched incidents."
MESSAGE_INVALID_FIELD = "- %s field(s) has/have too many missing values and won't be used in the model."
MESSAGE_NO_FIELD_NAME_OR_CLUSTERING = "- Empty or incorrect fieldsForClustering " \
                                      "for training OR fieldForClusterName is incorrect."

PREFIXES_TO_REMOVE = ['incident.']
REGEX_DATE_PATTERN = [re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})Z"),  # guardrails-disable-line
                      re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2}).*")]  # guardrails-disable-line
REPLACE_COMMAND_LINE = {"=": " = ", "\\": "/", "[": "", "]": "", '"': "", "'": "", }
TFIDF_PARAMS = {'max_features': 500, 'ngram_range': (2, 4)}

HDBSCAN_PARAMS = {
    'algorithm': 'best',
    'n_jobs': -1,
    'prediction_data': True
}
FAMILY_COLUMN_NAME = 'label'
UNKNOWN_MODEL_TYPE = 'UNKNOWN_MODEL_TYPE'
MESSAGE_ERROR_MESSAGE = 'Model cannot be loaded'
CLUSTERING_STEP_PIPELINE = 'clustering'
PREPROCESSOR_STEP_PIPELINE = 'preprocessor'

PALETTE_COLOR = ['0048BA', '#B0BF1A	', '#7CB9E8	', '#B284BE	', '#E52B50', '#FFBF00', '#665D1E', '#8DB600',
                 '#D0FF14']


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
        self.model = None

        # Data
        self.raw_data = None  # type: Union[Dict, None]
        self.data = None
        self.label = None

        # Results
        self.clusters = {}
        self.number_clusters = None
        self.results = None

        # control
        self.TSNE_ = False
        self.centers = {}
        self.centers_2d = {}

        self.create_model(parameters=params)

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

    def get_data(self, X: np.ndarray, y: pd.DataFrame):
        """
        Load vector of feature X and label y
        :param X: vector of feature - np.ndarray
        :param y: vector of label - pd.DataFrame
        :return:
        """
        X = pd.DataFrame(X, index=y.index)
        self.raw_data = pd.DataFrame(X).join(y, how='right')
        self.data = X
        self.label = y

    def fit(self, X: np.ndarray, y: pd.DataFrame = None):
        """
        Fit the model with the self.data set.
        The self.data set should be a numpy.array
        :param X: vector of feature - np.ndarray
        :param y: vector of label - pd.DataFrame
        :return:
        """
        self.get_data(X, y)
        if hasattr(self.model, 'fit_predict'):
            self.results = self.model.fit_predict(X)  # type: ignore
        else:
            self.model.fit(X)  # type: ignore
            if hasattr(self.model, 'labels_'):
                self.results = self.model.labels_.astype(np.int)  # type: ignore
            else:
                self.results = self.model.predict(X)  # type: ignore
        self.number_clusters = len(set(self.results[self.results >= 0]))
        return

    def reduce_dimension(self, dimension=2):
        """
        Use TSNE technique to reduce dimension
        :param dimension:
        :return:
        """
        if not self.TSNE_:
            tsne = TSNE(n_jobs=-1, n_components=dimension, learning_rate=1000)
            self.data_2d = tsne.fit_transform(pd.DataFrame(self.centers).T)
            for coordinates, center in zip(self.data_2d, pd.DataFrame(self.centers).T.index):
                self.centers_2d[center] = coordinates
            self.TSNE_ = True

    def compute_centers(self):
        """
        Compute center for each cluster
        :return: None
        """
        for cluster_ in range(self.number_clusters):  # type: ignore
            center = np.mean(self.data[self.model.labels_ == cluster_], axis=0)  # type: ignore
            if center.isnull().values.any():  # type: ignore
                self.centers[cluster_] = center.fillna(0)  # type: ignore
            else:
                self.centers[cluster_] = center


class PostProcessing(object):
    """
    Class to analyze the clustering
    """

    def __init__(self, clustering: Type[Clustering], threshold: float, generic_cluster_name: bool):
        """
        Instantiate class object for visualization
        :param clustering: Object Clustering
        :param threshold: Threshold for the cluster homogeneity
        :param generic_cluster_name: Boolean if cluster don't have name and needs generic naming
        :return: Instantiate class object for visualization
        """
        self.clustering = clustering  # type: Type[Clustering]
        self.threshold = threshold  # type: float
        self.generic_cluster_name = generic_cluster_name
        self.stats = {}  # type: ignore
        self.statistics()
        self.compute_dist()
        self.date_training = datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        self.summary = None  # type: ignore
        self.global_msg = None  # type: ignore
        self.json = None  # type: ignore

    def statistics(self):
        """
        Compute statistics of the clusters
        """
        # plot_silhouette = self.com_silhouette()
        self.stats['General'] = {}
        self.stats['General']['Nb sample'] = self.clustering.raw_data.shape[0]  # type: ignore
        self.stats['General']['Nb cluster'] = self.clustering.number_clusters
        self.stats['General']['min_samples'] = self.clustering.model.min_samples  # type: ignore
        self.stats['General']['min_cluster_size'] = self.clustering.model.min_cluster_size  # type: ignore
        for number_cluster in range(-1, self.clustering.number_clusters):  # type: ignore
            self.stats[number_cluster] = {}
            self.stats[number_cluster]['number_samples'] = sum(
                self.clustering.model.labels_ == number_cluster)  # type: ignore
            ind = np.where(self.clustering.model.labels_ == number_cluster)[0]  # type: ignore
            selected_data = [x for x in self.clustering.raw_data.iloc[ind][FAMILY_COLUMN_NAME]]  # type: ignore
            counter = collections.Counter(selected_data)
            total = sum(dict(counter).values(), 0.0)
            dist = {k: v * 100 / total for k, v in counter.items()}
            dist = dict((k, v) for k, v in dist.items() if v >= 1)
            self.stats[number_cluster]['distribution sample'] = dist

    def compute_dist(self):
        """
        Compute distribution of sample per cluster (depending of the naming and threshold)
        """
        dist_total = {}  # type: Dict
        duplicate_family = {}  # type: ignore
        if not self.generic_cluster_name:
            for cluster_number in range(-1, self.clustering.number_clusters):  # type: ignore
                chosen = {k: v for k, v in self.stats[cluster_number]['distribution sample'].items() if
                          v >= self.threshold * 100}
                if not chosen and cluster_number != -1:
                    continue
                total = sum(dict(chosen).values(), 0.0)
                dist = {k: v * 100 / total for k, v in chosen.items()}
                dist_total[cluster_number] = {}
                dist_total[cluster_number]['number_samples'] = sum(
                    self.clustering.raw_data[  # type: ignore
                        self.clustering.model.labels_ == cluster_number].label.isin(  # type: ignore
                        list(chosen.keys())))  # type: ignore
                dist_total[cluster_number]['distribution'] = dist
                cluster_name = ' , '.join([x for x in chosen.keys()])[:15]
                if cluster_name in duplicate_family.keys():
                    new_cluster_name = '%s_%s' % (cluster_name, str(duplicate_family[cluster_name]))
                    duplicate_family[cluster_name] += 1
                else:
                    new_cluster_name = cluster_name
                    duplicate_family[cluster_name] = 0
                dist_total[cluster_number]['clusterName'] = new_cluster_name
        else:
            for cluster_number in range(-1, self.clustering.number_clusters):  # type: ignore
                chosen = self.stats[cluster_number]['distribution sample']
                total = sum(dict(chosen).values(), 0.0)
                dist = {k: v * 100 / total for k, v in chosen.items()}
                dist_total[cluster_number] = {}
                dist_total[cluster_number]['distribution'] = dist
                dist_total[cluster_number]['number_samples'] = self.stats[cluster_number]['number_samples']
                dist_total[cluster_number]['clusterName'] = 'Cluster %s' % str(cluster_number)
        self.stats['number_of_clusterized_sample_after_selection'] = sum(dist_total[cluster_number]['number_samples']
                                                                         for cluster_number in dist_total.keys())
        self.selected_clusters = dist_total


def extract_fields_from_args(arg: List[str]) -> List[str]:
    """
    Extract field from field with prefixe (like incident.commandline)
    :param arg: List of field
    :return: List of field without prefix
    """
    fields_list = [preprocess_incidents_field(x.strip(), PREFIXES_TO_REMOVE) for x in arg if x]
    return list(dict.fromkeys(fields_list))


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


def get_args():  # type: ignore
    """
    Gets argument of this automation
    :return: Argument of this automation
    """
    fields_for_clustering = demisto.args().get('fieldsForClustering', '').split(',')
    fields_for_clustering = extract_fields_from_args(fields_for_clustering)

    field_for_cluster_name = demisto.args().get('fieldForClusterName', '').split(',')
    field_for_cluster_name = extract_fields_from_args(field_for_cluster_name)

    display_fields = demisto.args().get('fieldsToDisplay', '').split(',')
    display_fields = extract_fields_from_args(display_fields)
    display_fields = list(set(['id', 'created', 'name'] + display_fields))

    number_feature_per_field = int(demisto.args().get('numberOfFeaturesPerField'))
    analyzer = demisto.args().get('analyzer')

    min_homogeneity_cluster = float(demisto.args().get('minHomogeneityCluster'))

    from_date = demisto.args().get('fromDate')
    to_date = demisto.args().get('toDate')
    limit = int(demisto.args().get('limit'))
    query = demisto.args().get('query')
    incident_type = demisto.args().get('type')
    max_percentage_of_missing_value = float(demisto.args().get('maxRatioOfMissingValue'))

    min_number_of_incident_in_cluster = int(demisto.args().get('minNumberofIncidentPerCluster'))
    model_name = demisto.args().get('modelName')
    store_model = demisto.args().get('storeModel', 'False') == 'True'
    model_override = demisto.args().get('overrideExistingModel', 'False') == 'True'
    debug = demisto.args().get('debug', 'False') == 'True'
    force_retrain = demisto.args().get('forceRetrain', 'False') == 'True'
    model_expiration = float(demisto.args().get('modelExpiration'))
    model_hidden = demisto.args().get('model_hidden', 'False') == 'True'

    return fields_for_clustering, field_for_cluster_name, display_fields, from_date, to_date, limit, query, \
        incident_type, min_number_of_incident_in_cluster, model_name, store_model, min_homogeneity_cluster, \
        model_override, max_percentage_of_missing_value, debug, force_retrain, model_expiration, model_hidden, \
        number_feature_per_field, analyzer


def get_all_incidents_for_time_window_and_type(populate_fields: List[str], from_date: str, to_date: str,
                                               query_sup: str, limit: int, incident_type: str):  # type: ignore
    """
    Get incidents with given parameters and return list of incidents
    :param populate_fields: List of field to populate
    :param from_date: from_date
    :param to_date: to_date
    :param query_sup: additional criteria for the query
    :param limit: maximum number of incident to fetch
    :param incident_type: type of incident to fetch
    :return: list of incident
    """
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
        'limit': str(limit),
        'incidentTypes': incident_type
    })
    if is_error(res):
        return_error(res)
    incidents = json.loads(res[0]['Contents'])
    if len(incidents) == 0:
        msg += "%s \n" % MESSAGE_NO_INCIDENT_FETCHED
        return None, msg  # type: ignore
    if len(incidents) == limit:
        msg += "%s \n" % MESSAGE_WARNING_TRUNCATED % (str(len(incidents)), str(limit))
        return incidents, msg  # type: ignore
    return incidents, msg  # type: ignore


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


def recursive_filter(item, regex_patterns: List, *fieldsToRemove):  # type: ignore
    """

    :param item: Dict of list of Dict
    :param regex_patterns: List of regex pattern to remove from the dict
    :param fieldsToRemove: values to remove from the object
    :return: Dict or List of Dict without unwanted values or regex pattern
    """
    if isinstance(item, list):
        return [recursive_filter(entry, regex_patterns, *fieldsToRemove) for entry in item if
                entry not in fieldsToRemove]
    if isinstance(item, dict):
        result = {}
        for key, value in item.items():
            value = recursive_filter(value, regex_patterns, *fieldsToRemove)
            if key not in fieldsToRemove and value not in fieldsToRemove and (
                    not match_one_regex(value, regex_patterns)):
                result[key] = value
        return result
    return item


def normalize_global(obj):
    if isinstance(obj, float) or not obj:
        return " "
    if check_list_of_dict(obj):
        obj = {k: v for k, v in enumerate(obj)}  # type: ignore
        return normalize_json(obj)
    if isinstance(obj, dict):
        return normalize_json(obj)
    if isinstance(obj, str) or isinstance(obj, list):
        return normalize_command_line(obj)


def normalize_json(obj) -> str:  # type: ignore
    """
    Normalize json from removing unwanted regex pattern or stop word
    :param obj:Dumps of a json or dict
    :return:
    """
    my_dict = recursive_filter(obj, REGEX_DATE_PATTERN, "None", "N/A", None, "")
    extracted_values = [x if isinstance(x, str) else str(x) for x in json_extract(my_dict)]
    my_string = ' '.join(extracted_values)  # json.dumps(my_dict)
    pattern = re.compile(r'([^\s\w]|_)+')  # guardrails-disable-line
    my_string = pattern.sub(" ", my_string)
    my_string = my_string.lower()
    return my_string


def json_extract(obj):
    """Recursively fetch values from nested JSON."""
    arr = []  # type: ignore

    def extract(obj, arr):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr)
                else:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr)
        return arr

    values = extract(obj, arr)
    return values


def normalize_command_line(command) -> str:
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
        my_string = my_string.strip()
        return my_string
    else:
        return ''


class Tfidf(BaseEstimator, TransformerMixin):
    """
    TFIDF transformer
    """

    def __init__(self, normalize_function):
        """
        :param model_params: parameters of TFIDF
        :param normalize_function: Normalize function to apply on each sample of the corpus before the vectorization
        """
        self.normalize_function = normalize_function
        self.vec = TfidfVectorizer(**TFIDF_PARAMS)

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


def store_model_in_demisto(model: Type[PostProcessing], model_name: str, model_override: bool,
                           model_hidden: bool) -> None:
    model_data = base64.b64encode(pickle.dumps(model)).decode('utf-8')  # guardrails-disable-line
    res = demisto.executeCommand('createMLModel', {'modelData': model_data,
                                                   'modelName': model_name,
                                                   'modelOverride': model_override,
                                                   'modelHidden': model_hidden,
                                                   'modelExtraInfo': {
                                                       'modelSummaryMarkdown': model.summary_description}  # type:ignore
                                                   })
    if is_error(res):
        return_error(get_error(res))


def is_clustering_valid(clustering_model: Type[Clustering]) -> bool:
    """
    Criteria to decide if clustering is valid or not (like not enough clusters)
    :param clustering_model: Clustering model
    :return: Boolean
    """
    n_labels = len(set(clustering_model.model.labels_))  # type: ignore
    n_samples = len(clustering_model.raw_data)  # type: ignore
    if not 1 < n_labels < n_samples:
        return False
    return True


def create_clusters_json(model_processed: Type[PostProcessing], incidents_df: pd.DataFrame, type: str,
                         display_fields: List[str], fields_for_clustering: List[str]) -> str:
    """

    :param model_processed: Postprocessing
    :param incidents_df: incidents_df
    :param type: type of incident
    :return: json with information on the clusters
    """
    clustering = model_processed.clustering
    data = {}  # type: ignore
    data['data'] = []
    fields_for_clustering_remove_display = [x for x in fields_for_clustering if x not in display_fields]
    for cluster_number, coordinates in clustering.centers_2d.items():
        if cluster_number not in model_processed.selected_clusters.keys():
            continue
        d = {'x': float(coordinates[0]),
             'y': float(coordinates[1]),
             'name': model_processed.selected_clusters[cluster_number]['clusterName'],
             'dataType': 'incident',
             'color': PALETTE_COLOR[divmod(cluster_number, len(PALETTE_COLOR))[1]],
             'pivot': "clusterId:" + str(cluster_number),
             'incidents_ids': [x for x in incidents_df[  # type: ignore
                 clustering.model.labels_ == cluster_number].id.values.tolist()],  # type: ignore
             'incidents': incidents_df[clustering.model.labels_ == cluster_number]  # type: ignore
             [display_fields + fields_for_clustering_remove_display].to_json(  # type: ignore
                 orient='records'),  # type: ignore
             'query': 'type:%s' % type,  # type: ignore
             'data': [int(model_processed.stats[cluster_number]['number_samples'])]}
        data['data'].append(d)
    d_outliers = {
        'incidents_ids': [x for x in incidents_df[  # type: ignore
            clustering.model.labels_ == -1].id.values.tolist()],  # type: ignore
        'incidents': incidents_df[clustering.model.labels_ == -1][display_fields].to_json(  # type: ignore
            orient='records'),  # type: ignore
    }
    data['outliers'] = d_outliers
    ranges = calculate_range(data)
    data['range'] = ranges[0]
    data['rangeX'] = ranges[1]
    data['rangeY'] = ranges[2]
    pretty_json = json.dumps(data, indent=4, sort_keys=True)
    return pretty_json


def find_incorrect_field(populate_fields: List[str], incidents_df: pd.DataFrame, global_msg: str):
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


def remove_fields_not_in_incident(*args, incorrect_fields: List[str]) -> List[str]:
    """
    Return list without field in incorrect_fields
    :param args: *List of fields
    :param incorrect_fields: fields that we don't want
    :return:
    """
    return [[x for x in field_type if x not in incorrect_fields] for field_type in args]  # type: ignore


def get_results(model_processed: Type[PostProcessing]):
    number_of_sample = model_processed.stats["General"]["Nb sample"]
    number_clusters_selected = len(model_processed.selected_clusters) - 1
    number_of_outliers = number_of_sample - model_processed.stats['number_of_clusterized_sample_after_selection']
    return number_of_sample, number_clusters_selected, number_of_outliers


def create_summary(model_processed: Type[PostProcessing], fields_for_clustering: List[str],
                   field_for_cluster_name: List[str]) -> dict:
    """
    Create json with summary of the training
    :param model_processed: Postprocessing
    :return: JSON with information about the training
    """
    clustering = model_processed.clustering
    number_of_sample = model_processed.stats["General"]["Nb sample"]
    nb_clusterized_after_selection = model_processed.stats['number_of_clusterized_sample_after_selection']
    nb_clusters = model_processed.stats["General"]["Nb cluster"]
    number_clusters_selected = len(model_processed.selected_clusters) - 1  # type: ignore
    number_of_clusterized = sum(clustering.model.labels_ != -1)  # type: ignore
    percentage_clusters_selected = round(100 * number_clusters_selected / nb_clusters, 0)
    percentage_selected_samples = round(100 * (nb_clusterized_after_selection / number_of_sample), 0)
    percentage_clusterized_samples = round(100 * (number_of_clusterized / number_of_sample), 0)
    summary = {
        'Total number of samples ': str(number_of_sample),
        'Percentage of clusterized samples after selection (after Phase 1 and Phase 2)': "%s  (%s/%s)"
                                                                                         % (
                                                                                             str(percentage_selected_samples),
                                                                                             str(nb_clusterized_after_selection),
                                                                                             str(number_of_sample)),
        'Percentage of clusterized samples (after Phase 1)': "%s  (%s/%s)" %
                                                             (str(percentage_clusterized_samples),
                                                              str(number_of_clusterized),
                                                              str(number_of_sample)),
        'Percentage of cluster selected (Number of high quality groups/Total number of groups)':
            "%s  (%s/%s)" %
            (str(percentage_clusters_selected),
             str(number_clusters_selected),
             str(nb_clusters)),
        'Fields used for training': ' , '.join(fields_for_clustering),
        'Fields used for cluster name': field_for_cluster_name[0] if field_for_cluster_name else "",
        'Training time': str(model_processed.date_training)
    }
    return summary


def return_entry_clustering(output_clustering: Dict, tag: str = None) -> None:
    """
    Create and return entry with the JSON containing the clusters
    :param output_clustering: json with the cluster
    :param tag: tag
    :return: Return entry to demisto
    """
    return_entry = {
        "Type": entryTypes["note"],
        "ContentsFormat": formats['json'],
        "Contents": output_clustering,
        "EntryContext": {'DBotTrainClustering': output_clustering},
    }
    if tag is not None:
        return_entry["Tags"] = ['Clustering_{}'.format(tag)]
    demisto.results(return_entry)


def wrapped_list(obj: List) -> List:
    """
    Wrapped object into a list if not list
    :param obj:
    :return:
    """
    if not isinstance(obj, list):
        return [obj]
    return obj


def fill_nested_fields(incidents_df: pd.DataFrame, incidents: List, *list_of_field_list: List[str],
                       keep_unique_value=False) -> \
        pd.DataFrame:
    """
    Handle nested fields by concatening values for each sub list of the field
    :param incidents_df: DataFrame of incidents
    :param incidents: List of incident
    :param list_of_field_list: field which can be nested. Can be also no nested field and will remain the same
    :return: DataFrame with nested field columns updated
    """
    for field_type in list_of_field_list:
        for field in field_type:
            if '.' in field:
                if isinstance(incidents, list):
                    value_list = [wrapped_list(demisto.dt(incident, field)) for incident in incidents]
                    if not keep_unique_value:
                        value_list = [' '.join(  # type: ignore
                            set(
                                list(
                                    filter(lambda x: x not in ['None', None, 'N/A'], x)
                                )
                            )
                        )
                            for x in value_list]
                    else:
                        value_list = [most_frequent(list(filter(lambda x: x not in ['None', None, 'N/A'], x)))
                                      for x in value_list]
                else:
                    value_list = wrapped_list(demisto.dt(incidents, field))
                    value_list = ' '.join(  # type: ignore
                        set(list(filter(lambda x: x not in ['None', None, 'N/A'], value_list))))  # type: ignore
                incidents_df[field] = value_list
    return incidents_df


def most_frequent(list_: List):
    """
    Return most frequent element of a list if not empty elase return empty string
    :param l: list with element
    :return: item in list with most occurrence
    """
    if not list_:
        return ""
    else:
        return max(set(list_), key=list_.count)


def remove_not_valid_field(fields_for_clustering: List[str], incidents_df: pd.DataFrame, global_msg: str,
                           max_ratio_of_missing_value: float) -> Tuple[List[str], str]:
    """
    Remove fields that are not valid (like too small number of sample)
    :param fields_for_clustering: List of field to use for the clustering
    :param incidents_df: DataFrame of incidents
    :param global_msg: global_msg
    :param max_ratio_of_missing_value: max ratio of missing values we accept
    :return: List of valid fields, message
    """
    missing_values_percentage = incidents_df[fields_for_clustering].applymap(lambda x: x == '').sum(axis=0) / len(
        incidents_df)
    mask = missing_values_percentage < max_ratio_of_missing_value
    valid_field = mask[mask].index.tolist()
    invalid_field = mask[~mask].index.tolist()
    if invalid_field:
        global_msg += "%s \n" % MESSAGE_INVALID_FIELD % ' , '.join(invalid_field)
    return valid_field, global_msg


def get_model_data(model_name):
    """
    Return model in base 64 and message about the load of the model
    :param model_name: model_name
    :return:
    """
    res_model = demisto.executeCommand("getMLModel", {"modelName": model_name})[0]
    if not is_error(res_model):
        model_data = res_model['Contents']['modelData']
        try:
            model_type = res_model['Contents']['model']["type"]["type"]
            return model_data, model_type
        except Exception:
            return model_data, UNKNOWN_MODEL_TYPE
    else:
        return None, MESSAGE_ERROR_MESSAGE


def is_model_needs_retrain(force_retrain: bool, model_expiration: float, model_name: str):
    """
    Return boolean if the model needs to be retrain based on the expiration of the model and force_retrain atgument
    :param force_retrain: boolean if the user cho to retrain the model in any case
    :param model_expiration: period in hour after which you want to retrain the model
    :param model_name: model_name
    :return: PostProcessing model, boolean if needs to be retrained
    """
    if force_retrain:
        return None, True
    model_data, model_type = get_model_data(model_name)
    if not model_data:
        return None, True
    else:
        model = load_model64(model_data)
        model_training_time = pd.to_datetime(model.date_training)
        return model, model_training_time < datetime.now() - timedelta(hours=model_expiration)


def load_model64(model_base64: str):
    """
    Load model from base64 model
    :param model_base64: string base64 model
    :return: PostProcessing model
    """
    try:
        model = pickle.loads(base64.b64decode(model_base64))  # guardrails-disable-line
        return model
    except pickle.UnpicklingError:
        return_error("Model exist but cannot be loaded")


def prepare_data_for_training(generic_cluster_name, incidents_df, field_for_cluster_name):
    """

    :param generic_cluster_name: if using generic name or field name given by the user in argument
    :param incidents_df: dataframe of incidents
    :param field_for_cluster_name: field for cluster name given by the user
    :return: labels
    """
    if generic_cluster_name:
        incidents_df[FAMILY_COLUMN_NAME] = ""
        labels = incidents_df[FAMILY_COLUMN_NAME]
    else:
        labels = incidents_df[field_for_cluster_name].rename(columns={field_for_cluster_name[0]: FAMILY_COLUMN_NAME})
    return labels


def transform_names_if_list(incidents_df, field_for_cluster_name):
    """
    Check if field_for_cluster_name value are type list and keep the maximun value if this is the case
    :param incidents_df: Dataframe of incidents
    :param field_for_cluster_name: List with one field that correspong to the name of the cluster
    :return: Dataframe of incidents with modification on field_for_cluster_name columns
    """
    if field_for_cluster_name and field_for_cluster_name[0] in incidents_df.columns:
        incidents_df[field_for_cluster_name[0]] = incidents_df[field_for_cluster_name[0]].apply(
            lambda x: most_frequent(x) if isinstance(x, list) else x)
    return incidents_df


def keep_high_level_field(incidents_field: List[str]) -> List[str]:
    """
    Return list of fields if they are in the first level of the argument - xdralert.commandline will return xdralert
    :param incidents_field: list of incident fields
    :return: Return list of fields
    """
    return [x.split('.')[0] if '.' in x else x for x in incidents_field]


def calculate_range(data):
    all_data_size = list(map(lambda x: x['data'][0], data['data']))
    all_x = list(map(lambda x: x['x'], data['data']))
    all_y = list(map(lambda x: x['y'], data['data']))
    max_size = max(all_data_size)
    min_size = min(all_data_size)
    min_range = max(30, min_size)
    max_range = min_range + max(300, max_size - min_size)
    return [min_range, max_range], [int(math.ceil(min(all_x))), int(math.ceil(max(all_x)))], \
           [int(math.ceil(min(all_y))), int(math.ceil(max(all_y)))]


def main():
    builtins.Clustering = Clustering  # type: ignore
    builtins.PostProcessing = PostProcessing  # type: ignore
    builtins.Tfidf = Tfidf  # type: ignore

    global_msg = ""
    generic_cluster_name = False

    # Get argument of the automation
    fields_for_clustering, field_for_cluster_name, display_fields, from_date, to_date, limit, query, incident_type, \
        min_number_of_incident_in_cluster, model_name, store_model, min_homogeneity_cluster, model_override, \
        max_percentage_of_missing_value, debug, force_retrain, model_expiration, model_hidden, \
        number_feature_per_field, analyzer = get_args()

    HDBSCAN_PARAMS.update({'min_cluster_size': min_number_of_incident_in_cluster,
                           'min_samples': min_number_of_incident_in_cluster})

    TFIDF_PARAMS.update({'max_features': number_feature_per_field})
    TFIDF_PARAMS.update({'analyzer': analyzer})

    # Check if need to retrain
    model_processed, retrain = is_model_needs_retrain(force_retrain, model_expiration, model_name)

    if not retrain:
        if debug:
            return_outputs(
                readable_output=global_msg + tableToMarkdown(
                    "Summary",
                    model_processed.summary  # pylint: disable=E1101
                )
            )
        data_clusters_json = model_processed.json  # pylint: disable=E1101
        search_query = demisto.args().get('searchQuery')
        if search_query:
            data_clusters = json.loads(model_processed.json)  # pylint: disable=E1101
            filtered_clusters_data = []
            for row in data_clusters['data']:
                if row['pivot'] in search_query.split(" "):
                    filtered_clusters_data.append(row)
            data_clusters['data'] = filtered_clusters_data
            data_clusters_json = json.dumps(data_clusters)

        return_entry_clustering(output_clustering=data_clusters_json, tag="trained")
        return model_processed, model_processed.json, ""  # pylint: disable=E1101
    else:
        # Check if user gave a field for cluster name - if not use generic cluster name
        if not field_for_cluster_name:
            generic_cluster_name = True

        # Get all the incidents from query, date and field similarity and field family
        populate_fields = fields_for_clustering + field_for_cluster_name + display_fields
        populate_high_level_fields = keep_high_level_field(populate_fields)
        incidents, msg = get_all_incidents_for_time_window_and_type(populate_high_level_fields, from_date, to_date,
                                                                    query,
                                                                    # type: ignore
                                                                    limit, incident_type)  # type: ignore
        global_msg += "%s \n" % msg
        # If no incidents found with those criteria
        if not incidents:
            demisto.results(global_msg)
            return None, {}, global_msg

        incidents_df = pd.DataFrame(incidents).fillna('')
        incidents_df.index = incidents_df.id

        # Fill nested fields with appropriate values
        incidents_df = transform_names_if_list(incidents_df, field_for_cluster_name)
        incidents_df = fill_nested_fields(incidents_df, incidents, fields_for_clustering)
        incidents_df = fill_nested_fields(incidents_df, incidents, field_for_cluster_name, keep_unique_value=True)

        # Check Field that appear in populate_fields but are not in the incidents_df and return message
        global_msg, incorrect_fields = find_incorrect_field(populate_fields, incidents_df, global_msg)

        fields_for_clustering, field_for_cluster_name, display_fields = \
            remove_fields_not_in_incident(fields_for_clustering, field_for_cluster_name, display_fields,
                                          incorrect_fields=incorrect_fields)

        # Remove fields that are not valid (like too small number of sample)
        fields_for_clustering, global_msg = remove_not_valid_field(fields_for_clustering, incidents_df, global_msg,
                                                                   max_percentage_of_missing_value)  # type: ignore

        # Case where no field for clustrering or field for cluster name if not empty and incorrect)
        if not fields_for_clustering or (not field_for_cluster_name and not generic_cluster_name):
            global_msg += "%s \n" % MESSAGE_NO_FIELD_NAME_OR_CLUSTERING
            demisto.results(global_msg)
            return None, {}, global_msg

        # Create data for training
        labels = prepare_data_for_training(generic_cluster_name, incidents_df, field_for_cluster_name)

        # TFIDF pipeline
        tfidf_pipe = Pipeline(steps=[
            ('tfidf', Tfidf(normalize_function=normalize_global))
        ])

        # preprocessor
        transformers_list = [('tfidf' + field, tfidf_pipe, [field]) for field in fields_for_clustering]
        preprocessor = ColumnTransformer(
            transformers=transformers_list)

        # Model pipeline
        model = Pipeline(steps=[(PREPROCESSOR_STEP_PIPELINE, preprocessor),
                                (CLUSTERING_STEP_PIPELINE, Clustering(HDBSCAN_PARAMS))
                                ])
        # Fit of the model on incidents_df and labels
        model.fit(incidents_df, labels)

        # Check is clustering is valid
        if not is_clustering_valid(model.named_steps[CLUSTERING_STEP_PIPELINE]):
            global_msg += "%s \n" % MESSAGE_CLUSTERING_NOT_VALID
            return None, {}, global_msg

        # Reduce dimension
        model.named_steps[CLUSTERING_STEP_PIPELINE].compute_centers()
        model.named_steps[CLUSTERING_STEP_PIPELINE].reduce_dimension()
        model_processed = PostProcessing(model.named_steps[CLUSTERING_STEP_PIPELINE], min_homogeneity_cluster,
                                         generic_cluster_name)

        # Create summary of the training and assign it the the summary attribute of the model
        summary = create_summary(model_processed, fields_for_clustering, field_for_cluster_name)
        model_processed.summary = summary
        model_processed.global_msg = global_msg

        if debug:
            return_outputs(readable_output='## Warning \n {}'.format(global_msg) + tableToMarkdown("Summary", summary))
        else:
            field_clustering = ' , '.join(fields_for_clustering)
            field_name = field_for_cluster_name[0] if field_for_cluster_name else ""
            number_of_sample, number_clusters_selected, number_of_outliers = get_results(model_processed)
            training_date = str(model_processed.date_training)
            msg = GENERAL_MESSAGE_RESULTS % (number_of_sample, number_clusters_selected,
                                             field_clustering, field_name, number_of_outliers, training_date)
            return_outputs(
                readable_output='## General results \n {}'.format(msg) + '## Warning \n {}'.format(global_msg))
            model_processed.summary_description = msg

        # return Entry and summary
        output_clustering_json = create_clusters_json(model_processed, incidents_df, incident_type, display_fields,
                                                      fields_for_clustering)
        model_processed.json = output_clustering_json
        return_entry_clustering(output_clustering=model_processed.json, tag="trained")  # type: ignore
        if store_model:
            store_model_in_demisto(model_processed, model_name, model_override, model_hidden)
        return model_processed, output_clustering_json, global_msg


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
