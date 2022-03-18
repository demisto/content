# from CommonServerPython import *
import pytest
from DBotFindSimilarIncidents import normalize_command_line, main, demisto, keep_high_level_field, \
    preprocess_incidents_field, PREFIXES_TO_REMOVE, check_list_of_dict, REGEX_IP, match_one_regex, \
    SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, euclidian_similarity_capped, find_incorrect_fields, \
    MESSAGE_NO_INCIDENT_FETCHED, MESSAGE_INCORRECT_FIELD, MESSAGE_WARNING_TRUNCATED, COLUMN_ID, COLUMN_TIME, \
    TAG_SCRIPT_INDICATORS

import json
import numpy as np
import pandas as pd

CURRENT_INCIDENT_NOT_EMPTY = [
    {'id': '123', 'commandline': 'powershell IP=1.1.1.1', 'CustomFields': {"nested_field": 'value_nested_field'},
     'empty_current_incident_field': None, 'empty_fetched_incident_field': 'empty_fetched_incident_field_1'}]

FETCHED_INCIDENT_NOT_EMPTY = [
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

FETCHED_INCIDENT_EMPTY = []

SIMILAR_INDICATORS_NOT_EMPTY = [
    {"ID": "inc_1", "Identical indicators": "ind_1, ind_2", "created": "2021-01-30", "id": "1",
     "name": "incident_name_1", "similarity indicators": 0.2},
    {"ID": "inc_3", "Identical indicators": "ind_2", "created": "2021-01-30", "id": "3", "name": "incident_name_3",
     "similarity indicators": 0.4},
]

SIMILAR_INDICATORS_EMPTY = []


def executeCommand(command, args):
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    if command == 'DBotFindSimilarIncidentsByIndicators':
        return [[], {'Contents': SIMILAR_INDICATORS, 'Type': 'note', 'Tags': [TAG_SCRIPT_INDICATORS]}]
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


def test_match_one_regex():
    assert match_one_regex('123.123.123.123', [REGEX_IP]) is True
    assert match_one_regex('123.123.123', [REGEX_IP]) is False
    assert match_one_regex('abc', [REGEX_IP]) is False
    assert match_one_regex(1, [REGEX_IP]) is False


def test_normalize_command_line():
    assert normalize_command_line('cmd -k IP=1.1.1.1 [1.1.1.1]') == 'cmd -k ip = IP IP'
    assert normalize_command_line('powershell "remove_quotes"') == 'powershell remove_quotes'


def test_euclidian_similarity_capped():
    x = np.array([[1, 1, 1], [2, 2, 2]])
    y = np.array([[2.1, 2.1, 2.1]])
    distance = euclidian_similarity_capped(x, y)
    assert distance[0] == 0
    assert distance[1] > 0


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning", "ignore::UserWarning")
def test_main_regular(mocker):
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_NOT_EMPTY
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': 'incident.commandline, commandline, command, '
                                                'empty_current_incident_field, empty_fetched_incident_field',
                            'similarCategoricalField': 'signature, filehash, incident.commandline',
                            'similarJsonField': 'CustomFields',
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': 'filehash, destinationip, closeNotes, sourceip, alertdescription',
                            'showIncidentSimilarityForAllFields': True,
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res, msg = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res.loc['3', 'Identical indicators'] == 'ind_2')
    assert (res.loc['2', 'Identical indicators'] == "")
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME,
                                         COLUMN_ID, COLUMN_TIME, 'name', df=res)
    assert res.loc['3', 'similarity indicators'] == 0.4
    assert res.loc['2', 'similarity indicators'] == 0.0


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning")
def test_main_no_indicators_found(mocker):
    """
    Test if no indicators found
    :param mocker:
    :return:
    """
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_EMPTY
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
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res, msg = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res['Identical indicators'] == ["", "", ""]).all()
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, COLUMN_ID,
                                         COLUMN_TIME, 'name', df=res)
    assert (res['similarity indicators'] == [0.0, 0.0, 0.0]).all()


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning")
def test_main_no_fetched_incidents_found(mocker):
    """
    Test output if no related incidents found - Should return None and MESSAGE_NO_INCIDENT_FETCHED
    :param mocker:
    :return:
    """
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_NOT_EMPTY
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
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = main()
    assert (not res[0])
    assert MESSAGE_NO_INCIDENT_FETCHED in res[1]


def test_main_some_incorrect_fields():
    wrong_field_1 = 'wrong_field_1'
    wrong_field_2 = 'wrong_field_2'
    correct_field_1 = 'empty_fetched_incident_field'
    current_incident_df = pd.DataFrame(CURRENT_INCIDENT)
    global_msg, incorrect_fields = find_incorrect_fields([correct_field_1, wrong_field_1, wrong_field_2],
                                                         current_incident_df, '')
    assert incorrect_fields == ['wrong_field_1', 'wrong_field_2']
    assert wrong_field_1 in global_msg
    assert wrong_field_2 in global_msg
    assert correct_field_1 not in global_msg


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning")
def test_main_all_incorrect_field(mocker):
    """
    Test if only incorrect fields  -  Should return None and MESSAGE_INCORRECT_FIELD message for wrong fields
    :param mocker:
    :return:
    """
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_NOT_EMPTY
    wrong_field_1 = 'wrong_field_1'
    wrong_field_2 = 'wrong_field_2'
    wrong_field_3 = 'wrong_field_3'
    wrong_field_4 = 'wrong_field_4'
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': wrong_field_1,
                            'similarCategoricalField': wrong_field_2,
                            'similarJsonField': wrong_field_3,
                            'limit': 10000,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': wrong_field_4,
                            'showIncidentSimilarityForAllFields': True,
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, msg = main()
    assert (not df)
    assert MESSAGE_INCORRECT_FIELD % ' , '.join([wrong_field_1, wrong_field_3, wrong_field_2, wrong_field_4]) in msg
    assert all(field in msg for field in [wrong_field_1, wrong_field_2, wrong_field_3, wrong_field_4])


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning")
def test_main_incident_truncated(mocker):
    """
    Test if fetched incident truncated  -  Should return MESSAGE_WARNING_TRUNCATED in the message
    :param mocker:
    :return:
    """
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_NOT_EMPTY
    correct_field_1 = 'commandline'
    wrong_field_2 = 'wrong_field_2'
    wrong_field_3 = 'wrong_field_3'
    wrong_field_4 = 'wrong_field_4'
    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': correct_field_1,
                            'similarCategoricalField': wrong_field_2,
                            'similarJsonField': wrong_field_3,
                            'limit': 3,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': wrong_field_4,
                            'showIncidentSimilarityForAllFields': True,
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=None)
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, msg = main()
    limit = demisto.args()['limit']
    assert not df.empty
    assert MESSAGE_WARNING_TRUNCATED % (limit, limit) in msg


@pytest.mark.filterwarnings("ignore::pandas.core.common.SettingWithCopyWarning")
def test_main_incident_nested(mocker):
    """
    Test if fetched incident truncated  -  Should return MESSAGE_WARNING_TRUNCATED in the message
    :param mocker:
    :return:
    """
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = FETCHED_INCIDENT_NOT_EMPTY
    CURRENT_INCIDENT = CURRENT_INCIDENT_NOT_EMPTY
    SIMILAR_INDICATORS = SIMILAR_INDICATORS_NOT_EMPTY
    wrong_field_2 = 'wrong_field_2'
    wrong_field_3 = 'wrong_field_3'
    wrong_field_4 = 'wrong_field_4'
    nested_field = 'xdralerts.cmd'

    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': nested_field,
                            'similarCategoricalField': wrong_field_2,
                            'similarJsonField': wrong_field_3,
                            'limit': 3,
                            'fieldExactMatch': '',
                            'fieldsToDisplay': wrong_field_4,
                            'showIncidentSimilarityForAllFields': True,
                            'minimunIncidentSimilarity': 0.2,
                            'maxIncidentsToDisplay': 100,
                            'query': '',
                            'aggreagateIncidentsDifferentDate': 'False',
                            'includeIndicatorsSimilarity': 'True'
                        })
    mocker.patch.object(demisto, 'dt', return_value=['nested_val_1', 'nested_val_2'])
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, msg = main()
    assert not df.empty
    assert (df['similarity %s' % nested_field] == [1.0, 1.0, 1.0]).all()
