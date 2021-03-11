# from CommonServerPython import *
# import pytest
from DBotFindSimilarIncidents import Tfidf, normalize_command_line, cdist_new, Identity, normalize_identity, \
    normalize_json, identity, main, demisto, keep_high_level_field, preprocess_incidents_field, PREFIXES_TO_REMOVE, \
    check_list_of_dict, REGEX_IP, match_one_regex, SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME
import json
import numpy as np

CURRENT_INCIDENT = [
    {'id': '123', 'commandline': 'powershell IP=1.1.1.1', 'CustomFields': {"nested_field": 'value_nested_field'},
     'empty_current_incident_field': None, 'empty_fetched_incident_field': 'empty_fetched_incident_field_1'}]

FETCHED_INCIDENT = [
    {'id': '1', 'created': "2021-01-30", 'commandline': 'powershell IP=1.1.1.1',
     'CustomFields': {"nested_field": 'value_nested_field_1'},
     'empty_current_incident_field': 'empty_current_incident_field_1', 'empty_fetched_incident_field': None,
     "name": "incident_name_1"},
    {'id': '2', 'created': "2021-01-30", 'commandline': 'powershell IP=2.2.2.2',
     'CustomFields': {"nested_field": 'value_nested_field_2'},
     'empty_current_incident_field': 'empty_current_incident_field2', 'empty_fetched_incident_field': "",
     "name": "incident_name_2"},
    {'id': '3', 'created': "2021-01-30", 'commandline': 'powershell IP=1.1.1.1',
     'CustomFields': {"nested_field": 'value_nested_field_3'},
     'empty_current_incident_field': 'empty_current_incident_field_3', 'empty_fetched_incident_field': None,
     "name": "incident_name_3"}
]

SIMILAR_INDICATORS = [
    {"ID": "inc_1", "Identical indicators": "ind_1, ind_2", "created": "2021-01-30", "id": "1",
     "name": "incident_name_1", "similarity indicators": 0.2},
    {"ID": "inc_3", "Identical indicators": "ind_2", "created": "2021-01-30", "id": "3", "name": "incident_name_3",
     "similarity indicators": 0.4},
]

TRANSFORMATION = {
    'commandline': {'transformer': Tfidf,
                    'normalize': normalize_command_line,
                    'params': {'analyzer': 'char', 'max_features': 2000, 'ngram_range': (1, 5)},
                    'scoring': {'scoring_function': cdist_new, 'min': 0.5}
                    },

    'url': {'transformer': Tfidf,
            'normalize': normalize_identity,
            'params': {'analyzer': 'char', 'max_features': 100, 'ngram_range': (1, 5)},
            'scoring': {'scoring_function': cdist_new, 'min': 0.5}
            },
    'potentialMatch': {'transformer': Identity,
                       'normalize': None,
                       'params': {},
                       'scoring': {'scoring_function': identity, 'min': 0.5}
                       },
    'json': {'transformer': Tfidf,
             'normalize': normalize_json,
             'params': {'analyzer': 'word', 'max_features': 5000, 'ngram_range': (1, 5)},  # , 'max_df': 0.2
             'scoring': {'scoring_function': cdist_new, 'min': 0.5}
             }
}


def executeCommand(command, args):
    if command == 'DBotFindSimilarIncidentsByIndicators':
        return [[], {'Contents': SIMILAR_INDICATORS, 'Type': 'note'}]
    if command == 'GetIncidentsByQuery':
        if 'limit' in args:
            return [{'Contents': json.dumps(FETCHED_INCIDENT), 'Type': 'note'}]
        else:
            return [{'Contents': json.dumps(CURRENT_INCIDENT), 'Type': 'note'}]


def check_exist_dataframe_columns(*fields, df):
    for field in fields:
        if field not in df.columns.tolist():
            return False
    return True


def test_main_regular(mocker):
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': 'incident.commandline, commandline, command, '
                                                'empty_current_incident_field, empty_fetched_incident_field',
                            'similarCategoricalField': 'signature, filehash',
                            'similarJsonField': 'CustomFields',
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': 'filehash, destinationip, closeNotes, sourceip, alertdescription',
                            'showIncidentSimilarityForAllFields': True,
                            'MinimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'True',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res.loc['3', 'Identical indicators'] == 'ind_2')
    assert (res.loc['2', 'Identical indicators'] == "")
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, 'ID', 'created', 'name', df=res)
    assert res.loc['3', 'similarity indicators'] == 0.4
    assert res.loc['2', 'similarity indicators'] == 0.0


def test_main_no_indicators_found(mocker):
    global SIMILAR_INDICATORS
    SIMILAR_INDICATORS = []
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': 'incident.commandline, commandline, command,'
                                                ' empty_current_incident_field, empty_fetched_incident_field',
                            'similarCategoricalField': 'signature, filehash',
                            'similarJsonField': 'CustomFields',
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': 'filehash, destinationip, closeNotes, sourceip, alertdescription',
                            'showIncidentSimilarityForAllFields': True,
                            'MinimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'True',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res['Identical indicators'] == ["", "", ""]).all()
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, 'ID', 'created', 'name', df=res)
    assert (res['similarity indicators'] == [0.0, 0.0, 0.0]).all()


def test_main_no_fetched_incidents_found(mocker):
    global SIMILAR_INDICATORS, FETCHED_INCIDENT
    FETCHED_INCIDENT = []
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': 'incident.commandline, commandline, command, '
                                                'empty_current_incident_field, empty_fetched_incident_field',
                            'similarCategoricalField': 'signature, filehash',
                            'similarJsonField': 'CustomFields',
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': 'filehash, destinationip, closeNotes, sourceip, alertdescription',
                            'showIncidentSimilarityForAllFields': True,
                            'MinimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'True',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = main()
    assert (not res)


def test_keep_high_level_field():
    incidents_field = ['xdralerts.comandline', 'commandline', 'CustomsFields.commandline']
    res = ['xdralerts', 'commandline', 'CustomsFields']
    assert keep_high_level_field(incidents_field) == res


def test_preprocess_incidents_field():
    assert preprocess_incidents_field('incident.commandline', PREFIXES_TO_REMOVE) == 'commandline'
    assert preprocess_incidents_field('commandline', PREFIXES_TO_REMOVE) == 'commandline'


def test_check_list_of_dict():
    assert check_list_of_dict([{'test': 'value_test'}, {'test1': 'value_test1'}]) is True
    assert check_list_of_dict({'test': 'value_test'}) is False


def test_recursive_filter():
    pass


def test_match_one_regex():
    assert match_one_regex('123.123.123.123', [REGEX_IP]) is True
    assert match_one_regex('123.123.123', [REGEX_IP]) is False
    assert match_one_regex('abc', [REGEX_IP]) is False
    assert match_one_regex(1, [REGEX_IP]) is False


def test_normalize_command_line():
    assert normalize_command_line('cmd -k IP=1.1.1.1 [1.1.1.1]') == 'cmd -k ip = IP IP'
    assert normalize_command_line('powershell "remove_quotes"') == 'powershell remove_quotes'


def test_cdist_new():
    x = np.array([[1, 1, 1], [2, 2, 2]])
    y = np.array([[2.1, 2.1, 2.1]])
    distance = cdist_new(x, y)
    assert distance[0] == 0
    assert distance[1] > 0
