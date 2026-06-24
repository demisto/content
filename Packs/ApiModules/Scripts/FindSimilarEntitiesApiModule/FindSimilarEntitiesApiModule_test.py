from copy import deepcopy

import demistomock as demisto
import numpy as np
import pandas as pd
import pytest
from CommonServerPython import DemistoException
from FindSimilarEntitiesApiModule import (
    PREFIXES_TO_REMOVE,
    REGEX_IP,
    BaseSimilarEntityFinder,
    EntityArgs,
    Model,
    SimilarIncidentFinder,
    SimilarIssueFinder,
    check_list_of_dict,
    euclidian_similarity_capped,
    match_one_regex,
    normalize_command_line,
)


def get_incidents_by_query_mock(fetched_incident, current_incident):
    def _mock(args):
        if "-id:" in args.get("query", ""):
            return fetched_incident
        else:
            return current_incident

    return _mock


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


def executeCommand_mock(similar_indicators):
    def _mock(command, args):
        if command == "DBotFindSimilarIncidentsByIndicators":
            return [[], {"Contents": similar_indicators, "Type": "note", "Tags": ["similarIncidents"]}]
        return None

    return _mock


def check_exist_dataframe_columns(*fields, df):
    return all(field in df.columns.tolist() for field in fields)


def test_keep_high_level_field():
    entity_fields = ["xdralerts.comandline", "commandline", "CustomsFields.commandline"]
    res = ["xdralerts", "commandline", "CustomsFields"]
    assert BaseSimilarEntityFinder.keep_high_level_field(entity_fields) == res


def test_preprocess_entity_field():
    assert BaseSimilarEntityFinder.preprocess_entity_field("incident.commandline", PREFIXES_TO_REMOVE) == "commandline"
    assert BaseSimilarEntityFinder.preprocess_entity_field("commandline", PREFIXES_TO_REMOVE) == "commandline"


def test_check_list_of_dict():
    assert check_list_of_dict([{"test": "value_test"}, {"test1": "value_test1"}]) is True
    assert check_list_of_dict({"test": "value_test"}) is False


def test_match_one_regex():
    assert match_one_regex("123.123.123.123", [REGEX_IP]) is True
    assert match_one_regex("123.123.123", [REGEX_IP]) is False
    assert match_one_regex("abc", [REGEX_IP]) is False
    assert match_one_regex("1", [REGEX_IP]) is False


def test_normalize_command_line():
    assert normalize_command_line("cmd -k IP=1.1.1.1 [1.1.1.1]") == "cmd -k ip = IP IP"
    assert normalize_command_line('powershell "remove_quotes"') == "powershell remove_quotes"


def test_euclidian_similarity_capped():
    x = np.array([[1, 1, 1], [2, 2, 2]])
    y = np.array([[2.1, 2.1, 2.1]])
    distance = euclidian_similarity_capped(x, y)
    assert distance[0] == 0
    assert distance[1] > 0


def test_main_regular(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
        "aggregateIncidentsDifferentDate": "False",
        "includeIndicatorsSimilarity": "True",
    }
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    res, _ = finder.run()

    assert res is not None
    assert "empty_current_incident_field" not in res.columns
    assert res.loc["3", "Identical indicators"] == "ind_2"
    assert res.loc["2", "Identical indicators"] == ""
    assert check_exist_dataframe_columns("similarity indicators", "similarity incident", "id", "created", "name", df=res)
    assert res.loc["3", "similarity indicators"] == 0.4
    assert res.loc["2", "similarity indicators"] == 0.0


def test_main_no_indicators_found(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    res, _ = finder.run()

    assert res is not None
    assert "empty_current_incident_field" not in res.columns
    assert (res["Identical indicators"] == ["", "", ""]).all()
    assert check_exist_dataframe_columns("similarity indicators", "similarity incident", "id", "created", "name", df=res)
    assert (res["similarity indicators"] == [0.0, 0.0, 0.0]).all()


def test_main_no_fetched_incidents_found(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    res = finder.run()
    assert res[0] is None
    assert "- 0 incidents fetched with these exact match for the given dates." in res[1]


def test_main_some_incorrect_fields():
    wrong_field_1 = "wrong_field_1"
    wrong_field_2 = "wrong_field_2"
    correct_field_1 = "empty_fetched_incident_field"
    current_incident_df = pd.DataFrame(CURRENT_INCIDENT_NOT_EMPTY)

    finder = SimilarIncidentFinder(EntityArgs({}))
    incorrect_fields = finder.find_missing_entity_fields([correct_field_1, wrong_field_1, wrong_field_2], current_incident_df)
    assert incorrect_fields == ["wrong_field_1", "wrong_field_2"]
    assert wrong_field_1 in finder.global_msg
    assert wrong_field_2 in finder.global_msg
    assert correct_field_1 not in finder.global_msg


def test_main_all_incorrect_field(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    df, msg = finder.run()
    assert df is None
    assert all(field in msg for field in [wrong_field_1, wrong_field_2, wrong_field_3, wrong_field_4])


def test_main_incident_truncated(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    df, msg = finder.run()
    limit = args["limit"]
    assert df is not None
    assert not df.empty
    assert (
        f"- Incident fetched have been truncated to {limit}, please either add incident fields in fieldExactMatch, "
        f"enlarge the time period or increase the limit argument to more than {limit}." in msg
    )


def test_main_incident_nested(mocker):
    fetched_incident = deepcopy(FETCHED_INCIDENT_NOT_EMPTY)
    current_incident = deepcopy(CURRENT_INCIDENT_NOT_EMPTY)
    similar_indicators = deepcopy(SIMILAR_INDICATORS_NOT_EMPTY)

    mocker.patch(
        "FindSimilarEntitiesApiModule.get_incidents_by_query",
        side_effect=get_incidents_by_query_mock(fetched_incident, current_incident),
    )

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
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand_mock(similar_indicators))

    finder = SimilarIncidentFinder(EntityArgs(args))
    df, _ = finder.run()
    assert df is not None
    assert not df.empty
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
    # Create an instance of Model
    my_instance = Model({})
    my_instance.entity_to_match = sample_data

    my_instance.field_for_command_line = fields_to_match
    my_instance.field_for_potential_exact_match = []
    my_instance.field_for_json = []

    should_proceed, all_skip_reasons = my_instance.remove_empty_or_short_fields()
    assert my_instance.field_for_command_line == expected_results
    assert should_proceed
    assert all("created" not in reason for reason in all_skip_reasons)
    assert "  - Value of the 'Name' field in incident: 't' has length of 1" in all_skip_reasons
    assert "  - Value of the 'Id' field in incident: '['123']' has length of 1" in all_skip_reasons
    assert "  - The 'test' field has a falsy value in current incident: 'None'" in all_skip_reasons
    assert "  - The 'test2' field has a falsy value in current incident: ''" in all_skip_reasons
    assert "  - The 'xdralerts' field has a falsy value in current incident: 'N/A'" in all_skip_reasons
    assert "  - The 'hello' field does not exist in incident" in all_skip_reasons


def test_predict_without_similarity_fields(sample_data):
    model = Model({})
    model.entity_to_match = sample_data
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
    finder = BaseSimilarEntityFinder(EntityArgs({}))
    results = finder.extract_fields_from_args(similar_text_field)
    expected_results = [
        "xdralerts.osactorprocesscommandline",
        "xdralerts.actorprocesscommandline",
        "xdralerts.actionprocessimagecommandline",
        "xdralerts.causalityactorprocesscommandline",
        "xdralerts.host_name",
        "xdralerts.user_name",
    ]
    assert results == expected_results


def test_similar_issue_finder_preprocess_args():
    args = {
        "text_similarity_fields": "name, description, status",
        "filter_equal_fields": "status, assignee, type",
        "discrete_match_fields": "category, domain",
        "issue_id": "123",
        "min_similarity": "0.5",
        "max_issues_to_display": "10",
        "max_issues_in_indicators_for_white_list": "5",
        "fields_to_display": "name, status",
        "from_date": "2023-01-01",
        "to_date": "2023-12-31",
        "include_indicators_similarity": "False",
        "min_number_of_indicators": "2",
        "indicators_types": "IP, Domain",
        "show_current_issue": "True",
        "show_issue_fields_similarity": "True",
    }
    finder = SimilarIssueFinder(EntityArgs(args))
    finder.preprocess_args()

    assert finder.similar_text_field == "issue_name,issue_description,resolution_status"
    assert finder.field_exact_match == "status,assignee,issue_type"
    assert finder.similar_categorical_field == "issue_category,issue_domain"
    assert finder.object_id == "123"
    assert finder.min_object_similarity == "0.5"
    assert finder.max_objects_to_display == "10"
    assert finder.max_objects_in_indicators_for_white_list == "5"
    assert finder.fields_to_display == "name, status"
    assert finder.from_date == "2023-01-01"
    assert finder.to_date == "2023-12-31"
    assert finder.include_indicators_similarity == "False"
    assert finder.min_number_of_indicators == "2"
    assert finder.indicators_types == "IP, Domain"
    assert finder.show_current_object == "True"
    assert finder.show_object_fields_similarity == "True"


def test_similar_issue_finder_get_display_fields():
    args = {"fieldsToDisplay": "status, assignee"}
    finder = SimilarIssueFinder(EntityArgs(args))
    display_fields = finder.get_display_fields()
    assert set(display_fields) == {"internal_id", "issue_name", "issue_description", "status", "assignee"}


def test_similar_issue_finder_load_current_entity(mocker):
    args = {}
    finder = SimilarIssueFinder(EntityArgs(args))

    mock_execute_command = mocker.patch.object(demisto, "executeCommand")
    mock_execute_command.return_value = [{"Type": 1, "Contents": [{"internal_id": "123", "issue_name": "test"}]}]

    issue, entity_id = finder.load_current_entity("123", [], [], [], [], [], "2023-01-01", "2023-12-31")

    assert issue == {"internal_id": "123", "issue_name": "test"}
    assert entity_id == "123"
    mock_execute_command.assert_called_once_with("core-get-issues", {"issue_id": "123"})


def test_similar_issue_finder_get_all_entities(mocker):
    args = {}
    finder = SimilarIssueFinder(EntityArgs(args))

    mock_execute_command_batch = mocker.patch.object(demisto, "executeCommandBatch")
    mock_execute_command_batch.return_value = [[{"Type": 1, "Contents": [{"internal_id": "456", "issue_name": "test2"}]}]]

    entity = {"internal_id": "123", "issue_name": "test", "status": "Open"}
    exact_match_fields = ["status"]

    all_issues, msg = finder.get_all_entities(exact_match_fields, [], [], [], [], entity, "2023-01-01", "2023-12-31", 50)

    assert all_issues is not None
    assert len(all_issues) == 1
    assert all_issues[0] == {"internal_id": "456", "issue_name": "test2"}
    mock_execute_command_batch.assert_called_once()
    called_commands = mock_execute_command_batch.call_args[0][0]
    assert len(called_commands) == 1
    assert called_commands[0]["core-get-issues"]["status"] == "Open"
    assert called_commands[0]["core-get-issues"]["start_time"] == "2023-01-01"
    assert called_commands[0]["core-get-issues"]["end_time"] == "2023-12-31"


def test_similar_issue_finder_create_context():
    args = {}
    finder = SimilarIssueFinder(EntityArgs(args))

    df = pd.DataFrame(
        [
            {
                "similarity issue": 0.9,
                "internal_id": "123",
                "issue_name": "test",
                "Identical indicators": "ind1",
                "similarity indicators": 0.8,
            }
        ]
    )
    context = finder.create_context(df)

    assert context["is_similar_issue_found"] is True
    assert context["similar_issue"][0]["similarity_score"] == 0.9
    assert context["similar_issue"][0]["issue_id"] == "123"
    assert context["similar_issue"][0]["issue_name"] == "test"


def test_recursive_filter():
    from FindSimilarEntitiesApiModule import recursive_filter
    import re

    regex = [re.compile(r"drop_me")]
    item = {
        "keep": "value",
        "drop": "drop_me_now",
        "nested": [{"a": 1, "b": "drop_me_too"}, {"c": 2}],
        "remove_field": "some_val",
    }
    result = recursive_filter(item, regex, "remove_field", "None")
    assert "keep" in result
    assert "drop" not in result
    assert "remove_field" not in result
    assert result["nested"] == [{"a": 1}, {"c": 2}]


def test_normalize_json():
    from FindSimilarEntitiesApiModule import normalize_json
    import json

    obj = {"key": "Value!", "date": "2023-01-01T12:00:00Z"}
    normalized = normalize_json(json.dumps(obj))
    # normalize_json removes punctuation and dates, and lowercases
    assert "key" in normalized
    assert "value" in normalized
    assert "2023" not in normalized


def test_identity():
    from FindSimilarEntitiesApiModule import identity

    X = pd.Series(["a", "b", "c"])
    y = pd.Series(["a", "x", "c"])
    result = identity(X, y)
    assert result[0] == 1.0
    assert np.isnan(result[1])
    assert result[2] == 1.0


def test_extract_values():
    data = {"A": [{"B": 1}, {"B": 2}, {"B": "N/A"}]}
    res = BaseSimilarEntityFinder.extract_values(data, "A.B", ["N/A"])
    assert res == [1, 2]


def test_remove_duplicates():
    seq = ["a", "b", "a", "c", "b"]
    assert BaseSimilarEntityFinder.remove_duplicates(seq) == ["a", "b", "c"]


def test_return_clean_date():
    assert BaseSimilarEntityFinder.return_clean_date("2023-01-01T12:00:00Z") == "2023-01-01"
    assert BaseSimilarEntityFinder.return_clean_date("short") == ""


def test_get_context_key():
    finder = SimilarIncidentFinder(EntityArgs({}))
    assert finder.get_context_key() == "DBotFindSimilarIncidents"
    issue_finder = SimilarIssueFinder(EntityArgs({}))
    assert issue_finder.get_context_key() == "SimilarIssues"
