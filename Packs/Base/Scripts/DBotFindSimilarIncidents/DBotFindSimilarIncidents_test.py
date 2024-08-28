from CommonServerPython import DemistoException
import demistomock as demisto
import numpy as np
import pandas as pd
import pytest
from copy import deepcopy

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


@pytest.fixture(autouse=True)
def mock_demistoVersion(mocker):
    mocker.patch.object(demisto, 'demistoVersion', return_value={'platform': 'xsoar'})


def executeCommand(command, args):
    from DBotFindSimilarIncidents import TAG_SCRIPT_INDICATORS
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    if command == 'DBotFindSimilarIncidentsByIndicators':
        return [[], {'Contents': SIMILAR_INDICATORS, 'Type': 'note', 'Tags': [TAG_SCRIPT_INDICATORS]}]
    if command == 'getIncidents':
        if '-id:' in args.get("query"):  # query for similar incidents
            return [{'Contents': {"data": FETCHED_INCIDENT}, 'Type': 'note'}]
        else:  # query for current incident
            return [{'Contents': {"data": CURRENT_INCIDENT}, 'Type': 'note'}]
    return None


def check_exist_dataframe_columns(*fields, df):
    return all(field in df.columns.tolist() for field in fields)


def test_keep_high_level_field():
    from DBotFindSimilarIncidents import keep_high_level_field
    incidents_field = ['xdralerts.comandline', 'commandline', 'CustomsFields.commandline']
    res = ['xdralerts', 'commandline', 'CustomsFields']
    assert keep_high_level_field(incidents_field) == res


def test_preprocess_incidents_field():
    from DBotFindSimilarIncidents import preprocess_incidents_field, PREFIXES_TO_REMOVE
    assert preprocess_incidents_field('incident.commandline', PREFIXES_TO_REMOVE) == 'commandline'
    assert preprocess_incidents_field('commandline', PREFIXES_TO_REMOVE) == 'commandline'


def test_check_list_of_dict():
    from DBotFindSimilarIncidents import check_list_of_dict
    assert check_list_of_dict([{'test': 'value_test'}, {'test1': 'value_test1'}]) is True
    assert check_list_of_dict({'test': 'value_test'}) is False


def test_match_one_regex():
    from DBotFindSimilarIncidents import match_one_regex, REGEX_IP
    assert match_one_regex('123.123.123.123', [REGEX_IP]) is True
    assert match_one_regex('123.123.123', [REGEX_IP]) is False
    assert match_one_regex('abc', [REGEX_IP]) is False
    assert match_one_regex(1, [REGEX_IP]) is False


def test_normalize_command_line():
    from DBotFindSimilarIncidents import normalize_command_line
    assert normalize_command_line('cmd -k IP=1.1.1.1 [1.1.1.1]') == 'cmd -k ip = IP IP'
    assert normalize_command_line('powershell "remove_quotes"') == 'powershell remove_quotes'


def test_euclidian_similarity_capped():
    from DBotFindSimilarIncidents import euclidian_similarity_capped
    x = np.array([[1, 1, 1], [2, 2, 2]])
    y = np.array([[2.1, 2.1, 2.1]])
    distance = euclidian_similarity_capped(x, y)
    assert distance[0] == 0
    assert distance[1] > 0


def test_main_regular(mocker):
    from DBotFindSimilarIncidents import SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, main, COLUMN_ID, COLUMN_TIME
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res, _ = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res.loc['3', 'Identical indicators'] == 'ind_2')
    assert (res.loc['2', 'Identical indicators'] == "")
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME,
                                         COLUMN_ID, COLUMN_TIME, 'name', df=res)
    assert res.loc['3', 'similarity indicators'] == 0.4
    assert res.loc['2', 'similarity indicators'] == 0.0


def test_main_no_indicators_found(mocker):
    """
    Test if no indicators found
    :param mocker:
    :return:
    """
    from DBotFindSimilarIncidents import SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, main, COLUMN_ID, COLUMN_TIME
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_EMPTY)
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res, _ = main()
    assert ('empty_current_incident_field' not in res.columns)
    assert (res['Identical indicators'] == ["", "", ""]).all()
    assert check_exist_dataframe_columns(SIMILARITY_COLUNM_NAME_INDICATOR, SIMILARITY_COLUNM_NAME, COLUMN_ID,
                                         COLUMN_TIME, 'name', df=res)
    assert (res['similarity indicators'] == [0.0, 0.0, 0.0]).all()


def test_main_no_fetched_incidents_found(mocker):
    """
    Test output if no related incidents found - Should return None and MESSAGE_NO_INCIDENT_FETCHED
    :param mocker:
    :return:
    """
    from DBotFindSimilarIncidents import MESSAGE_NO_INCIDENT_FETCHED, main
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    res = main()
    assert (not res[0])
    assert MESSAGE_NO_INCIDENT_FETCHED in res[1]


def test_main_some_incorrect_fields():
    from DBotFindSimilarIncidents import find_incorrect_fields
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


def test_main_all_incorrect_field(mocker):
    """
    Test if only incorrect fields  -  Should return None and MESSAGE_INCORRECT_FIELD message for wrong fields
    :param mocker:
    :return:
    """
    from DBotFindSimilarIncidents import MESSAGE_INCORRECT_FIELD, main
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, msg = main()
    assert (not df)
    assert MESSAGE_INCORRECT_FIELD % ' , '.join([wrong_field_1, wrong_field_3, wrong_field_2, wrong_field_4]) in msg
    assert all(field in msg for field in [wrong_field_1, wrong_field_2, wrong_field_3, wrong_field_4])


def test_main_incident_truncated(mocker):
    """
    Test if fetched incident truncated  -  Should return MESSAGE_WARNING_TRUNCATED in the message
    :param mocker:
    :return:
    """
    from DBotFindSimilarIncidents import main, MESSAGE_WARNING_TRUNCATED
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, msg = main()
    limit = demisto.args()['limit']
    assert not df.empty
    assert MESSAGE_WARNING_TRUNCATED % (limit, limit) in msg


def test_main_incident_nested(mocker):
    """
    Given: Same test case as in test_main_regular but with a nested field as a similarTextField
    When: Running main()
    Then: Ensure the nested field exists in the results
    """
    from DBotFindSimilarIncidents import main
    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    nested_field = 'CustomFields.nested_field'

    mocker.patch.object(demisto, 'args',
                        return_value={
                            'incidentId': 12345,
                            'similarTextField': f'{nested_field},incident.commandline, commandline, command, '
                                                'empty_current_incident_field, empty_fetched_incident_field',
                            'similarCategoricalField': 'signature, filehash, incident.commandline',
                            'similarJsonField': '',
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
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    df, _ = main()
    assert not df.empty
    assert (df[f"similarity {nested_field}"] > 0).all()


def test_get_get_data_from_indicators_automation():
    from DBotFindSimilarIncidents import TAG_SCRIPT_INDICATORS, get_data_from_indicators_automation

    res = get_data_from_indicators_automation(None, TAG_SCRIPT_INDICATORS)
    assert res is None


@pytest.fixture
def sample_data():
    # Create sample data for testing
    data = {'created': ["2019-02-20T15:47:23.962164+02:00"],
            'Name': ["t"],
            'Id': [["123"]],
            'test': [None],
            'xdralerts': ['N/A'],
            "test2": [""]}
    return pd.DataFrame(data)


fields_to_match = ['created', 'Name', 'test', 'Id', 'test2', 'xdralerts', 'hello']
expected_results = ['created']


def test_remove_empty_or_short_fields(sample_data):
    from DBotFindSimilarIncidents import Model, FIELD_SKIP_REASON_DOESNT_EXIST, \
        FIELD_SKIP_REASON_FALSY_VALUE, FIELD_SKIP_REASON_TOO_SHORT
    """
    Given:
        - sample_data: a dataframe with a column of strings
    When:
        - calling remove_empty_or_short_fields function
    Then:
        - assert that the function removes empty or short or None or 'N/A' or list objects fields
    """
    # Create an instance of Model
    my_instance = Model({})
    my_instance.incident_to_match = sample_data

    my_instance.field_for_command_line = fields_to_match
    my_instance.field_for_potential_exact_match = []
    my_instance.field_for_json = []

    should_proceed, all_skip_reasons = my_instance.remove_empty_or_short_fields()
    assert my_instance.field_for_command_line == expected_results
    assert should_proceed
    assert all("created" not in reason for reason in all_skip_reasons)
    assert f'  - {FIELD_SKIP_REASON_TOO_SHORT.format(field="Name", val="t", len=1)}' in all_skip_reasons
    assert f'  - {FIELD_SKIP_REASON_TOO_SHORT.format(field="Id", val=["123"], len=1)}' in all_skip_reasons
    assert f'  - {FIELD_SKIP_REASON_FALSY_VALUE.format(field="test", val=None)}' in all_skip_reasons
    assert f'  - {FIELD_SKIP_REASON_FALSY_VALUE.format(field="test2", val="")}' in all_skip_reasons
    assert f'  - {FIELD_SKIP_REASON_FALSY_VALUE.format(field="xdralerts", val="N/A")}' in all_skip_reasons
    assert f'  - {FIELD_SKIP_REASON_DOESNT_EXIST.format(field="hello")}' in all_skip_reasons


def test_predict_without_similarity_fields(sample_data):
    """
    Given:
        - A Model object
    When:
        - No similarity fields were provided
        - Calling Model.predict()
    Then:
        - Ensure the correct exception is raised
    """
    from DBotFindSimilarIncidents import Model
    model = Model({})
    model.incident_to_match = sample_data
    model.field_for_command_line = []
    model.field_for_potential_exact_match = []
    model.field_for_json = []

    with pytest.raises(DemistoException) as e:
        model.predict()

    assert "No fields were provided for similarity calculation" in str(e)
