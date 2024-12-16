import numpy as np
import pandas as pd
import pytest
from dateparser import parse
from DBotFindSimilarIncidentsByIndicators import *

PLAYGROUND_ID = "00000000-0000-0000-0000-0000000000000"

IND_A = {"id": "a", "investigationIDs": ["1", "2", "3"], "value": "value_a", "indicator_type": "File", "score": 0}
IND_B = {"id": "b", "investigationIDs": ["2", "3"], "value": "value_b", "indicator_type": "Domain", "score": 1}
IND_C = {"id": "c", "investigationIDs": ["5", "6"], "value": "value_c", "indicator_type": "Email", "score": 2}
IND_D = {"id": "d", "investigationIDs": ["1", "6"], "value": "value_d", "indicator_type": "File", "score": 2}
IND_E = {"id": "e", "investigationIDs": ["2", "3", "4"], "value": "value_e", "indicator_type": "File", "score": 1}
IND_F = {"id": "f", "investigationIDs": ["2", "3", "4", "5"], "value": "value_f", "indicator_type": "File", "score": 1}
INDICATORS_LIST = [IND_A, IND_B, IND_C, IND_D, IND_E, IND_F]
for i in INDICATORS_LIST:
    i["name"] = i["value"]

INC_1 = {"id": "1", "created": "2022-01-01", "status": 0, "name": "inc_a"}  # A D
INC_2 = {"id": "2", "created": "2022-01-01", "status": 1, "name": "inc_b"}  # A B E F
INC_3 = {"id": "3", "created": "2024-01-01", "status": 2, "name": "inc_c"}  # A B E F
INC_4 = {"id": "4", "created": "2024-01-01", "status": 3, "name": "inc_d"}  # E F
INC_5 = {"id": "5", "created": "2024-01-01", "status": 2, "name": "inc_e"}  # C F
INC_6 = {"id": "6", "created": "2024-01-01", "status": 1, "name": "inc_f"}  # C D
INCIDENTS_LIST = [INC_1, INC_2, INC_3, INC_4, INC_5, INC_6]


def ids_of(items) -> set:
    return {item["id"] for item in items}


def get_related_indicators(incident_id: str):
    return [i for i in INDICATORS_LIST if incident_id in i["investigationIDs"]]


def mock_execute_command(command: str, args: dict):
    match command:
        case "getIncidents":
            query: str = args.get("query") or ""
            from_date: str = args.get("fromdate") or ""
            match = re.search(r"incident\.id:\(([^\)]*)\)", query)
            incident_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
            res = {"data": [
                {k: v for k, v in i.items() if k in args["populateFields"] or k == "id"} for i in INCIDENTS_LIST
                if i["id"] in incident_ids
                and (not from_date or parse(i["created"]) >= parse(from_date).replace(tzinfo=None))
            ]}
        case _:
            raise Exception(f"Unmocked command: {command}")
    return [{"Contents": res, "Type": "json"}]


def mock_search_indicators(**kwargs):
    match = re.search(r"investigationIDs:\(([^\)]*)\)", kwargs.get("query"))
    incident_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
    res = [i for i in INDICATORS_LIST if set(i["investigationIDs"]) & incident_ids]
    if populate_fields := argToList(kwargs.get("populateFields")):
        res = [{k: v for k, v in i.items() if k in populate_fields or k == "id"} for i in res]
    return {"iocs": res, "total": len(res)}


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch.object(demisto, "searchIndicators", side_effect=mock_search_indicators)


@pytest.mark.parametrize("indicator_types, expected_indicators", [
    (["file"], [IND_A, IND_E]),
    (["file", "domain"], [IND_A, IND_B, IND_E]),
    ([], [IND_A, IND_B, IND_E]),
])
def test_get_indicators_of_actual_incident(indicator_types: list, expected_indicators: list) -> None:
    """
    Given:
    - An incident INC_2 with file (IND_A, IND_E) and domain (IND_B) indicators associated with it
    - Different `indicator_types` values
    When:
    - Running get_indicators_of_actual_incident() on INC_2 for each `indicator_types` value
    Then:
    - Ensure the expected indicators are returned
    """
    expected_ids = {inc["id"] for inc in expected_indicators}
    res: dict = get_indicators_of_actual_incident(
        incident_id=INC_2["id"],
        indicator_types=indicator_types,
        min_number_of_indicators=2,
        max_incidents_per_indicator=3,
    )
    assert set(res.keys()) == expected_ids


def test_get_indicators_of_actual_incident__below_minimal_num_of_indicators() -> None:
    """
    Given:
    - An incident INC_2 with only one domain indicator (IND_B) associated with it
    When:
    - Running get_indicators_of_actual_incident() on INC_2 for domain indicators only
    - min_nb_of_indicators=2, meaning, we allow collecting at least two indicators otherwise nothing is returned
    Then:
    - Ensure nothing is returned
    """
    res: dict = get_indicators_of_actual_incident(
        incident_id=INC_2["id"],
        indicator_types=["domain"],
        min_number_of_indicators=2,
        max_incidents_per_indicator=3,
    )
    assert not res


@pytest.mark.parametrize("indicators, query, from_date, expected_incidents", [
    ([], "", None, []),
    ([IND_A, IND_B, IND_C], "query", None, [INC_1, INC_2, INC_3, INC_5, INC_6]),
    ([IND_A, IND_B, IND_C], "", None, [INC_1, INC_2, INC_3, INC_5, INC_6]),
])
def test_get_related_incidents(indicators: list, query: str, from_date: str, expected_incidents: list) -> None:
    """
    Given:
    - Different sets of indicators
    When:
    - Running get_related_incidents()
    Then:
    - Ensure the expected incidents ids are returned
    """
    indicators = {ind["id"]: ind for ind in indicators}
    expected_ids = {inc["id"] for inc in expected_incidents}
    assert set(get_related_incidents(indicators, query, from_date)) == expected_ids


def test_get_related_incidents_filtered() -> None:
    """
    Given:
    - A set of indicators: IND_A, IND_B, IND_C
    When:
    - Running get_related_incidents() with from_date="2023-01-01"
    Then:
    - Ensure only INC_3, INC_5, INC_6 are returned since INC_1, INC_2 have created dates of 2022-01-01
    """
    indicators = {inc["id"]: inc for inc in [IND_A, IND_B, IND_C]}
    expected_ids = {inc["id"] for inc in [INC_3, INC_5, INC_6]}
    assert set(get_related_incidents(indicators, "", from_date="2023-01-01")) == expected_ids


def test_get_related_incidents_playground() -> None:
    """
    Given:
    - A playground incident ID
    When:
    - Running get_related_incidents()
    Then:
    - Ensure nothing is returned
    """
    indicators = {"ind": {"investigationIDs": [PLAYGROUND_ID]}}
    assert get_related_incidents(indicators, "query", None) == []


@pytest.mark.parametrize("incidents, indicators, expected_indicators", [
    ([INC_1, INC_6], [IND_A, IND_B, IND_C, IND_D, IND_E], [IND_A, IND_C, IND_D]),
    ([INC_1, INC_6], [], []),
    ([], [IND_A, IND_B, IND_C, IND_D, IND_E], []),
])
def test_get_mutual_indicators(incidents: list[dict], indicators: list[dict], expected_indicators: list[dict]) -> None:
    """
    Given:
    - Different sets of incidents
    - A list of indicators of the actual incident
    When:
    - Running get_indicators_of_related_incidents() with max_incidents_per_indicator=10
    - Running get_mutual_indicators() on the result and the indicators of the actual incident
    Then:
    - Ensure the expected mutual indicators (which must be a subset of the given indicators)
      of the given incidents are returned
    """
    incident_ids = [inc["id"] for inc in incidents]
    indicators_of_actual_incidents = {ind["id"]: ind for ind in indicators}
    related_incidents = get_indicators_of_related_incidents(incident_ids, max_incidents_per_indicator=10)
    assert ids_of(
        get_mutual_indicators(related_incidents, indicators_of_actual_incidents)
    ) == ids_of(expected_indicators)


def test_find_similar_incidents_by_indicators_end_to_end() -> None:
    """
    Given:
    - An incident INC_2 with file (IND_A, IND_E, IND_F) and domain (IND_B) indicators associated with it
    - INC_1, INC_3, INC_4 are incidents associated with indicators IND_A, IND_B, IND_E
    - IND_F has 4 indicators associated with it
    When:
    - Running find_similar_incidents_by_indicators() on INC_2
    - showActualIncident is true
    - maxIncidentsInIndicatorsForWhiteList is 3
    - threshold is 0.2
    Then:
    - Ensure the actual incident (INC_2) is included in the results
    - Ensure IND_A, IND_B, IND_E are collected as mutual indicators
    - Ensure IND_F is not included as a mutual indicator
    - Ensure INC_1, INC_3, INC_4 are collected as similar incidents, and ensure their expected similarity scores
    """
    command_results_list = find_similar_incidents_by_indicators(
        INC_2["id"],
        args={
            "showActualIncident": "true",
            "minNumberOfIndicators": "2",
            "maxIncidentsInIndicatorsForWhiteList": "3",
            "threshold": "0.2",
            "maxIncidentsToDisplay": "3",
            "fieldsIncidentToDisplay": "created,name",
        },
    )

    actual_incident_results = command_results_list[0].readable_output
    assert "Actual Incident" in actual_incident_results

    mutual_indicators = command_results_list[1].outputs
    assert {i["id"] for i in mutual_indicators} == {i["id"] for i in [IND_A, IND_B, IND_E]}

    similar_incidents = command_results_list[2].outputs["similarIncident"]
    expected_similar_incidents_to_similarity = {
        INC_1["id"]: 0.3,  # ([A] D) / [A B E]
        INC_3["id"]: 1.0,  # [A B E] / [A B E]
        INC_4["id"]: 0.3,  # ([E]) / [A B E]
    }
    assert len(similar_incidents) == len(expected_similar_incidents_to_similarity)
    for inc in similar_incidents:
        assert inc["id"] in expected_similar_incidents_to_similarity
        assert inc["similarity indicators"] == expected_similar_incidents_to_similarity[inc["id"]]


def run_args_validations(
    command_results_list: list[CommandResults],
    min_number_of_indicators: int,
    max_incs_in_indicators: int,
    from_date: str,
    threshold: float,
    max_incidents: int,
    fields_to_display: list[str],
) -> None:
    # a helper method for the end to end test below
    mutual_indicators = command_results_list[0].outputs
    assert len(mutual_indicators) >= min_number_of_indicators or mutual_indicators == []
    for mutual_indicator in mutual_indicators:
        i = [ind for ind in INDICATORS_LIST if ind["id"] == mutual_indicator["id"]][0]
        rel_inc_count = len(i["investigationIDs"])
        assert rel_inc_count <= max_incs_in_indicators, f"{i=}"

    similar_incidents = command_results_list[1].outputs["similarIncident"] or []
    assert len(similar_incidents) <= max_incidents
    for similar_incident in similar_incidents:
        assert similar_incident["similarity indicators"] >= threshold, f"{similar_incident=}"
        assert all(field in similar_incident for field in fields_to_display)
        i = [inc for inc in INCIDENTS_LIST if inc["id"] == similar_incident["id"]][0]
        assert not from_date or dateparser.parse(from_date) <= dateparser.parse(i["created"]), f"{i=}"


def test_find_similar_incidents_by_indicators_end_to_end__different_args() -> None:
    """
    Given:
    - Different arguments for the script
    - showActualIncident is always "false"
    When:
    - Running find_similar_incidents_by_indicators()
    Then:
    - Ensure the outputs always match all requirements according to the given arguments
    """
    fields_to_display = ["created", "name"]
    for inc in INCIDENTS_LIST:
        for min_number_of_indicators in range(0, 7, 3):
            for max_incs_in_indicators in range(0, 7, 3):
                for threshold in np.linspace(0, 1, 4):
                    for max_incidents in range(0, 7, 3):
                        for from_date in ["", "2023-01-01"]:
                            results = find_similar_incidents_by_indicators(
                                inc["id"],
                                args={
                                    "minNumberOfIndicators": str(min_number_of_indicators),
                                    "maxIncidentsInIndicatorsForWhiteList": str(max_incs_in_indicators),
                                    "threshold": str(threshold),
                                    "fromDate": from_date,
                                    "maxIncidentsToDisplay": str(max_incidents),
                                    "showActualIncident": "false",
                                    "fieldsIncidentToDisplay": ",".join(fields_to_display),
                                },
                            )
                            run_args_validations(
                                results,
                                min_number_of_indicators,
                                max_incs_in_indicators,
                                from_date,
                                threshold,
                                max_incidents,
                                fields_to_display,
                            )


def test_find_similar_incidents_by_indicators_end_to_end__no_results() -> None:
    """
    Given:
    - Inputs that would not return any mutual indicators or similar incidents
    When:
    - Running find_similar_incidents_by_indicators()
    Then:
    - Ensure the command succeeds with empty lists for mutual_indicators and similar_incidents
    """
    command_results_list = find_similar_incidents_by_indicators(
        INC_1["id"],
        args={
            "minNumberOfIndicators": "7",
            "maxIncidentsInIndicatorsForWhiteList": "0",
            "threshold": "1",
            "maxIncidentsToDisplay": "0",
            "showActualIncident": "false",
            "fieldsIncidentToDisplay": "",
        },
    )
    mutual_indicators = command_results_list[0].outputs
    assert not mutual_indicators
    similar_incidents = command_results_list[1].outputs["similarIncident"]
    assert not similar_incidents


def test_score():
    """ Runs some sanity tests for the FrequencyIndicators transformer
    """
    incident = pd.DataFrame({"indicators": ["1 2 3 4 5 6"]})
    # Check if incident is rare then the score is higher
    incidents_1 = pd.DataFrame({"indicators": ["1 2", "1 3", "1 3"]})
    tfidf = FrequencyIndicators("indicators", incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if same rarity then same scores
    incidents_1 = pd.DataFrame({"indicators": ["1 2", "3 4"]})
    tfidf = FrequencyIndicators("indicators", incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] == scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if more indicators in commun them better score
    incidents_1 = pd.DataFrame({"indicators": ["1 2 3", "4 5", "6"]})
    tfidf = FrequencyIndicators("indicators", incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))


def test_enrich_incidents_with_data(mocker):
    """
    Given:
        A DataFrame of incidents and a list of fields to display.
    When:
        The enrich_incidents function is called.
    Then:
        The function should return an enriched DataFrame with the specified fields.
    """
    incidents = pd.DataFrame({
        'id': ['1', '2'],
        'name': ['Incident 1', 'Incident 2']
    })
    fields_to_display = ['created', 'status', 'type']

    mock_get_incidents = mocker.patch('DBotFindSimilarIncidentsByIndicators.get_incidents_by_query')
    mock_get_incidents.return_value = [
        {'id': '1', 'created': '2023-05-01T10:00:00Z', 'status': 1, 'type': 'Malware'},
        {'id': '2', 'created': '2023-05-02T11:00:00Z', 'status': 2, 'type': 'Phishing'}
    ]

    result = enrich_incidents(incidents, fields_to_display)

    assert 'created' in result.columns
    assert 'status' in result.columns
    assert 'type' in result.columns
    assert result['created'].tolist() == ['2023-05-01', '2023-05-02']
    assert result['status'].tolist() == ['Active', 'Closed']
    assert result['type'].tolist() == ['Malware', 'Phishing']


def test_enrich_incidents_empty_dataframe(mocker):
    """
    Given:
        An empty DataFrame of incidents and a list of fields to display.
    When:
        The enrich_incidents function is called.
    Then:
        The function should return the empty DataFrame without modifications.
    """
    incidents = pd.DataFrame()
    fields_to_display = ['created', 'status', 'type']

    result = enrich_incidents(incidents, fields_to_display)

    assert result.empty


def test_enrich_incidents_missing_field(mocker):
    """
    Given:
        A DataFrame of incidents and a list of fields to display, including a field not returned by get_incidents_by_query.
    When:
        The enrich_incidents function is called.
    Then:
        The function should return the DataFrame with empty values for the missing field.
    """
    incidents = pd.DataFrame({
        'id': ['1', '2'],
        'name': ['Incident 1', 'Incident 2']
    })
    fields_to_display = ['created', 'status', 'type', 'missing_field']

    mock_get_incidents = mocker.patch('DBotFindSimilarIncidentsByIndicators.get_incidents_by_query')
    mock_get_incidents.return_value = [
        {'id': '1', 'created': '2023-05-01T10:00:00Z', 'status': 1, 'type': 'Malware'},
        {'id': '2', 'created': '2023-05-02T11:00:00Z', 'status': 2, 'type': 'Phishing'}
    ]

    result = enrich_incidents(incidents, fields_to_display)

    assert 'created' in result.columns
    assert 'status' in result.columns
    assert 'type' in result.columns
    assert 'missing_field' in result.columns
    assert result['created'].tolist() == ['2023-05-01', '2023-05-02']
    assert result['status'].tolist() == ['Active', 'Closed']
    assert result['type'].tolist() == ['Malware', 'Phishing']
    assert result['missing_field'].tolist() == ['', '']
