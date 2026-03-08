import sys
from copy import deepcopy
from unittest.mock import MagicMock

import demistomock as demisto
import numpy as np
import pandas as pd
import pytest
from CommonServerPython import DemistoException

# Mock GetIncidentsApiModule before importing DBotFindSimilarIncidents
mock_get_incidents = MagicMock()
def get_incidents_by_query_mock(args):
    global FETCHED_INCIDENT, CURRENT_INCIDENT
    if "-id:" in args.get("query", ""):
        return FETCHED_INCIDENT
    else:
        return CURRENT_INCIDENT

mock_get_incidents.get_incidents_by_query = get_incidents_by_query_mock
sys.modules['GetIncidentsApiModule'] = mock_get_incidents

CURRENT_INCIDENT_NOT_EMPTY = [
    {
        "id": "123",
        "commandline": "powershell IP=1.1.1.1",
        "CustomFields": {"nested_field": "value_nested_field"},
        "empty_current_incident_field": None,
        "empty_fetched_incident_field": "empty_fetched_incident_field_1",
    }
]

FETCHED_INCIDENT_NOT_EMPTY = [
    {
        "id": "1",
        "created": "2021-01-30",
        "commandline": "powershell IP=1.1.1.1",
        "CustomFields": {"nested_field": "value_nested_field_1"},
        "empty_current_incident_field": "empty_current_incident_field_1",
        "empty_fetched_incident_field": None,
        "name": "incident_name_1",
    },
    {
        "id": "2",
        "created": "2021-01-30",
        "commandline": "powershell IP=2.2.2.2",
        "CustomFields": {"nested_field": "value_nested_field_2"},
        "empty_current_incident_field": "empty_current_incident_field2",
        "empty_fetched_incident_field": "",
        "name": "incident_name_2",
    },
    {
        "id": "3",
        "created": "2021-01-30",
        "commandline": "powershell IP=1.1.1.1",
        "CustomFields": {"nested_field": "value_nested_field_3"},
        "empty_current_incident_field": "empty_current_incident_field_3",
        "empty_fetched_incident_field": None,
        "name": "incident_name_3",
    },
]

FETCHED_INCIDENT_EMPTY = []

SIMILAR_INDICATORS_NOT_EMPTY = [
    {
        "ID": "inc_1",
        "Identical indicators": "ind_1, ind_2",
        "created": "2021-01-30",
        "id": "1",
        "name": "incident_name_1",
        "similarity indicators": 0.2,
    },
    {
        "ID": "inc_3",
        "Identical indicators": "ind_2",
        "created": "2021-01-30",
        "id": "3",
        "name": "incident_name_3",
        "similarity indicators": 0.4,
    },
]

SIMILAR_INDICATORS_EMPTY = []


@pytest.fixture(autouse=True)
def mock_demistoVersion(mocker):
    mocker.patch.object(demisto, "demistoVersion", return_value={"platform": "xsoar"})


def executeCommand(command, args):
    global SIMILAR_INDICATORS
    if command == "DBotFindSimilarIncidentsByIndicators":
        return [[], {"Contents": SIMILAR_INDICATORS, "Type": "note", "Tags": ["similarIncidents"]}]
    return None


def check_exist_dataframe_columns(*fields, df):
    return all(field in df.columns.tolist() for field in fields)


def test_keep_high_level_field():
    from DBotFindSimilarIncidents import keep_high_level_field

    incidents_field = ["xdralerts.comandline", "commandline", "CustomsFields.commandline"]
    res = ["xdralerts", "commandline", "CustomsFields"]
    assert keep_high_level_field(incidents_field) == res


def test_preprocess_incidents_field():
    from DBotFindSimilarIncidents import PREFIXES_TO_REMOVE, preprocess_incidents_field

    assert preprocess_incidents_field("incident.commandline", PREFIXES_TO_REMOVE) == "commandline"
    assert preprocess_incidents_field("commandline", PREFIXES_TO_REMOVE) == "commandline"


def test_check_list_of_dict():
    from DBotFindSimilarIncidents import check_list_of_dict

    assert check_list_of_dict([{"test": "value_test"}, {"test1": "value_test1"}]) is True
    assert check_list_of_dict({"test": "value_test"}) is False


def test_match_one_regex():
    from DBotFindSimilarIncidents import REGEX_IP, match_one_regex

    assert match_one_regex("123.123.123.123", [REGEX_IP]) is True
    assert match_one_regex("123.123.123", [REGEX_IP]) is False
    assert match_one_regex("abc", [REGEX_IP]) is False
    assert match_one_regex(1, [REGEX_IP]) is False


def test_normalize_command_line():
    from DBotFindSimilarIncidents import normalize_command_line

    assert normalize_command_line("cmd -k IP=1.1.1.1 [1.1.1.1]") == "cmd -k ip = IP IP"
    assert normalize_command_line('powershell "remove_quotes"') == "powershell remove_quotes"


def test_euclidian_similarity_capped():
    from DBotFindSimilarIncidents import euclidian_similarity_capped

    x = np.array([[1, 1, 1], [2, 2, 2]])
    y = np.array([[2.1, 2.1, 2.1]])
    distance = euclidian_similarity_capped(x, y)
    assert distance[0] == 0
    assert distance[1] > 0


def test_main_regular(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    args = {
        "incidentId": 12345,
        "similarTextField": "incident.commandline, commandline, command, "
        "empty_current_incident_field, empty_fetched_incident_field",
        "similarCategoricalField": "signature, filehash, incident.commandline",
        "similarJsonField": "CustomFields",
        "limit": 10000,
        "fieldExactMatch": "",
        "fieldsToDisplay": "filehash, destinationip, closeNotes, sourceip, alertdescription",
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    res, _ = finder.run()
    
    assert "empty_current_incident_field" not in res.columns
    assert res.loc["3", "Identical indicators"] == "ind_2"
    assert res.loc["2", "Identical indicators"] == ""
    assert check_exist_dataframe_columns(
        "similarity indicators", "similarity incident", "id", "created", "name", df=res
    )
    assert res.loc["3", "similarity indicators"] == 0.4
    assert res.loc["2", "similarity indicators"] == 0.0


def test_main_no_indicators_found(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_EMPTY)
    args = {
        "incidentId": 12345,
        "similarTextField": "incident.commandline, commandline, command,"
        " empty_current_incident_field, empty_fetched_incident_field",
        "similarCategoricalField": "signature, filehash",
        "similarJsonField": "CustomFields",
        "limit": 10000,
        "fieldExactMatch": "",
        "fieldsToDisplay": "filehash, destinationip, closeNotes, sourceip, alertdescription",
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    res, _ = finder.run()
    
    assert "empty_current_incident_field" not in res.columns
    assert (res["Identical indicators"] == ["", "", ""]).all()
    assert check_exist_dataframe_columns(
        "similarity indicators", "similarity incident", "id", "created", "name", df=res
    )
    assert (res["similarity indicators"] == [0.0, 0.0, 0.0]).all()


def test_main_no_fetched_incidents_found(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    args = {
        "incidentId": 12345,
        "similarTextField": "incident.commandline, commandline, command, "
        "empty_current_incident_field, empty_fetched_incident_field",
        "similarCategoricalField": "signature, filehash",
        "similarJsonField": "CustomFields",
        "limit": 10000,
        "fieldExactMatch": "",
        "fieldsToDisplay": "filehash, destinationip, closeNotes, sourceip, alertdescription",
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    res = finder.run()
    assert not res[0]
    assert "- 0 incidents fetched with these exact match for the given dates." in res[1]


def test_main_some_incorrect_fields():
    from DBotFindSimilarIncidents import find_incorrect_fields

    wrong_field_1 = "wrong_field_1"
    wrong_field_2 = "wrong_field_2"
    correct_field_1 = "empty_fetched_incident_field"
    current_incident_df = pd.DataFrame(CURRENT_INCIDENT_NOT_EMPTY)
    global_msg, incorrect_fields = find_incorrect_fields([correct_field_1, wrong_field_1, wrong_field_2], current_incident_df, "")
    assert incorrect_fields == ["wrong_field_1", "wrong_field_2"]
    assert wrong_field_1 in global_msg
    assert wrong_field_2 in global_msg
    assert correct_field_1 not in global_msg


def test_main_all_incorrect_field(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    wrong_field_1 = "wrong_field_1"
    wrong_field_2 = "wrong_field_2"
    wrong_field_3 = "wrong_field_3"
    wrong_field_4 = "wrong_field_4"
    args = {
        "incidentId": 12345,
        "similarTextField": wrong_field_1,
        "similarCategoricalField": wrong_field_2,
        "similarJsonField": wrong_field_3,
        "limit": 10000,
        "fieldExactMatch": "",
        "fieldsToDisplay": wrong_field_4,
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    df, msg = finder.run()
    assert df is None
    assert all(field in msg for field in [wrong_field_1, wrong_field_2, wrong_field_3, wrong_field_4])


def test_main_incident_truncated(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    correct_field_1 = "commandline"
    wrong_field_2 = "wrong_field_2"
    wrong_field_3 = "wrong_field_3"
    wrong_field_4 = "wrong_field_4"
    args = {
        "incidentId": 12345,
        "similarTextField": correct_field_1,
        "similarCategoricalField": wrong_field_2,
        "similarJsonField": wrong_field_3,
        "limit": 3,
        "fieldExactMatch": "",
        "fieldsToDisplay": wrong_field_4,
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    df, msg = finder.run()
    limit = args["limit"]
    assert df is not None and not df.empty
    assert f"- Incident fetched have been truncated to {limit}, please either add incident fields in fieldExactMatch, enlarge the time period or increase the limit argument to more than {limit}." in msg


def test_main_incident_nested(mocker):
    from DBotFindSimilarIncidents import SimilarIncidentFinder

    global SIMILAR_INDICATORS, FETCHED_INCIDENT, CURRENT_INCIDENT
    FETCHED_INCIDENT = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    CURRENT_INCIDENT = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    SIMILAR_INDICATORS = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)
    nested_field = "CustomFields.nested_field"

    args = {
        "incidentId": 12345,
        "similarTextField": f"{nested_field},incident.commandline, commandline, command, "
        "empty_current_incident_field, empty_fetched_incident_field",
        "similarCategoricalField": "signature, filehash, incident.commandline",
        "similarJsonField": "",
        "limit": 10000,
        "fieldExactMatch": "",
        "fieldsToDisplay": "filehash, destinationip, closeNotes, sourceip, alertdescription",
        "showIncidentSimilarityForAllFields": True,
        "minimunIncidentSimilarity": 0.2,
        "maxIncidentsToDisplay": 100,
        "query": "",
        "aggreagateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    
    finder = SimilarIncidentFinder(args)
    df, _ = finder.run()
    assert df is not None and not df.empty
    assert (df[f"similarity {nested_field}"] > 0).all()


@pytest.fixture
def sample_data():
    # Create sample data for testing
    data = {
        "created": ["2019-02-20T15:47:23.962164+02:00"],
        "Name": ["t"],
        "Id": [["123"]],
        "test": [None],
        "xdralerts": ["N/A"],
        "test2": [""],
    }
    return pd.DataFrame(data)


fields_to_match = ["created", "Name", "test", "Id", "test2", "xdralerts", "hello"]
expected_results = ["created"]


def test_remove_empty_or_short_fields(sample_data):
    from DBotFindSimilarIncidents import Model

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
    assert f"  - Value of the 'Name' field in incident: 't' has length of 1" in all_skip_reasons
    assert f"  - Value of the 'Id' field in incident: '['123']' has length of 1" in all_skip_reasons
    assert f"  - The 'test' field has a falsy value in current incident: 'None'" in all_skip_reasons
    assert f"  - The 'test2' field has a falsy value in current incident: ''" in all_skip_reasons
    assert f"  - The 'xdralerts' field has a falsy value in current incident: 'N/A'" in all_skip_reasons
    assert f"  - The 'hello' field does not exist in incident" in all_skip_reasons


def test_predict_without_similarity_fields(sample_data):
    from DBotFindSimilarIncidents import Model

    model = Model({})
    model.incident_to_match = sample_data
    model.field_for_command_line = []
    model.field_for_potential_exact_match = []
    model.field_for_json = []

    with pytest.raises(DemistoException) as e:
        model.predict()

    assert "No fields were provided for similarity calculation" in str(e)


@pytest.mark.parametrize(
    "similar_text_field",
    [
        (
            "incident.xdralerts.osactorprocesscommandline,incident.xdralerts.actorprocesscommandline,incident.xdralerts."
            "actionprocessimagecommandline,incident.xdralerts.causalityactorprocesscommandline,incident.xdralerts.host_name,"
            "incident.xdralerts.user_name"
        ),
        (
            "alert.xdralerts.osactorprocesscommandline,alert.xdralerts.actorprocesscommandline,alert.xdralerts."
            "actionprocessimagecommandline,alert.xdralerts.causalityactorprocesscommandline,alert.xdralerts.host_name,"
            "alert.xdralerts.user_name"
        ),
        (
            "issue.xdralerts.osactorprocesscommandline,issue.xdralerts.actorprocesscommandline,issue.xdralerts."
            "actionprocessimagecommandline,issue.xdralerts.causalityactorprocesscommandline,issue.xdralerts.host_name,incident."
            "xdralerts.user_name"
        ),
    ],
)
def test_extract_fields_from_args(similar_text_field):
    from DBotFindSimilarIncidents import extract_fields_from_args

    results = extract_fields_from_args(similar_text_field)
    expected_results = [
        "xdralerts.osactorprocesscommandline",
        "xdralerts.actorprocesscommandline",
        "xdralerts.actionprocessimagecommandline",
        "xdralerts.causalityactorprocesscommandline",
        "xdralerts.host_name",
        "xdralerts.user_name",
    ]
    assert results == expected_results
