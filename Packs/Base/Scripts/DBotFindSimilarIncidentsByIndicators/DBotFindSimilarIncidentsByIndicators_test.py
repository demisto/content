import json
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

INC_1 = {"id": "1", "created": "2022-01-01", "status": 0, "name": "inc_a"}
INC_2 = {"id": "2", "created": "2022-01-01", "status": 1, "name": "inc_b"}
INC_3 = {"id": "3", "created": "2024-01-01", "status": 2, "name": "inc_c"}
INC_4 = {"id": "4", "created": "2024-01-01", "status": 3, "name": "inc_d"}
INC_5 = {"id": "5", "created": "2024-01-01", "status": 2, "name": "inc_e"}
INC_6 = {"id": "6", "created": "2024-01-01", "status": 1, "name": "inc_f"}
INCIDENTS_LIST = [INC_1, INC_2, INC_3, INC_4, INC_5, INC_6]


def mock_execute_command(command: str, args: dict):
    match command:
        case "findIndicators":
            if match := re.search("investigationIDs:(.*)", args["query"]):
                incident_id = match.group(1)
            res = [i for i in INDICATORS_LIST if incident_id in i["investigationIDs"]]
        case "GetIndicatorsByQuery":
            match = re.search(r"id:\(([^\)]*)\)", args["query"])
            indicator_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
            match = re.search(r"investigationIDs:\(([^\)]*)\)", args["query"])
            incident_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
            res = [
                i for i in INDICATORS_LIST if i["id"] in indicator_ids and set(i["investigationIDs"]) & incident_ids
            ]
            res = [{k: v for k, v in i.items() if k in args["populateFields"] or k == "id"} for i in res]
        case "GetIncidentsByQuery":
            match = re.search(r"incident\.id:\((.*)\)", args["query"])
            incident_ids = set(match.group(1).split(" ") if match and match.group(1) else [])
            res = json.dumps([
                {k: v for k, v in i.items() if k in args["populateFields"] or k == "id"} for i in INCIDENTS_LIST
                if i["id"] in incident_ids and (not args.get("fromDate") or parse(i["created"]) >= parse(args["fromDate"]))
            ])
        case _:
            raise Exception(f"Unmocked command: {command}")
    return [{"Contents": res, "Type": "json"}]


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)


@pytest.mark.parametrize("indicator_types, expected_indicators", [
    (["domain"], []),
    (["file"], [IND_A, IND_E]),
    (["file", "domain"], [IND_A, IND_B, IND_E]),
    ([], [IND_A, IND_B, IND_E]),
])
def test_get_indicators_of_actual_incident(indicator_types: list, expected_indicators: list) -> None:
    expected_ids = {inc["id"] for inc in expected_indicators}
    res: dict = get_indicators_of_actual_incident(
        incident_id=INC_2["id"],
        indicator_types=indicator_types,
        min_nb_of_indicators=2,
        max_indicators_for_white_list=3,
    )
    assert set(res.keys()) == expected_ids


@pytest.mark.parametrize("indicators, query, from_date, expected_incidents", [
    ([], "", None, []),
    ([IND_A, IND_B, IND_C], "", None, [INC_1, INC_2, INC_3, INC_5, INC_6]),
    ([IND_A, IND_B, IND_C], "query", None, [INC_1, INC_2, INC_3, INC_5, INC_6]),
    ([IND_A, IND_B, IND_C], "", "2023-01-01", [INC_3, INC_5, INC_6]),
])
def test_get_related_incidents(indicators: list, query: str, from_date: str, expected_incidents: list) -> None:
    indicators = {ind["id"]: ind for ind in indicators}
    expected_ids = {inc["id"] for inc in expected_incidents}
    assert set(get_related_incidents(indicators, query, from_date)) == expected_ids


def test_get_related_incidents_playground() -> None:
    indicators = {"ind": {"investigationIDs": [PLAYGROUND_ID]}}
    assert get_related_incidents(indicators, "query", None) == []


@pytest.mark.parametrize("incidents, indicators, expected_indicators", [
    ([INC_1, INC_6], [IND_A, IND_B, IND_C, IND_D, IND_E], [IND_A, IND_C, IND_D]),
])
def test_get_mutual_indicators(incidents: list[dict], indicators: list[dict], expected_indicators: list[dict]) -> None:
    incident_ids = [inc["id"] for inc in incidents]
    indicators = {ind["id"]: ind for ind in indicators}
    assert get_mutual_indicators(incident_ids, indicators) == expected_indicators


@pytest.mark.parametrize("incident, args, expected_mutual_indicators, expected_similar_incidents", [
    (
        INC_2,
        {
            "minNumberOfIndicators": "2",
            "maxIncidentsInIndicatorsForWhiteList": "3",
            "threshold": "0.2",
            "maxIncidentsToDisplay": "3",
            "showActualIncident": "true",
            "fieldsIncidentToDisplay": "created,name",
        },
        [IND_A, IND_B, IND_E],
        [INC_1, INC_3, INC_4],
    ),
])
def test_find_similar_incidents_by_indicators(
    incident: dict,
    args: dict[str, str],
    expected_mutual_indicators: list[dict],
    expected_similar_incidents: list[dict],
) -> None:
    command_results_list = find_similar_incidents_by_indicators(incident["id"], args)

    actual_incident_results = command_results_list[0].readable_output
    assert "Actual Incident" in actual_incident_results

    mutual_indicators = command_results_list[1].outputs
    assert len(mutual_indicators) == len(expected_mutual_indicators)
    for ind in mutual_indicators:
        assert ind["id"] in [i["id"] for i in mutual_indicators]

    similar_incidents = command_results_list[2].outputs["similarIncident"]
    assert len(similar_incidents) == len(expected_similar_incidents)
    for inc in similar_incidents:
        assert inc["id"] in [i["id"] for i in expected_similar_incidents]
        assert all(field in inc for field in args["fieldsIncidentToDisplay"].split(","))


def test_score(mocker):
    normalize_function = TRANSFORMATION["frequency_indicators"]["normalize"]
    incident = pd.DataFrame({"indicators": ["1 2 3 4 5 6"]})
    # Check if incident is rare then the score is higher
    incidents_1 = pd.DataFrame({"indicators": ["1 2", "1 3", "1 3"]})
    tfidf = FrequencyIndicators("indicators", normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if same rarity then same scores
    incidents_1 = pd.DataFrame({"indicators": ["1 2", "3 4"]})
    tfidf = FrequencyIndicators("indicators", normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] == scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
    # Check if more indicators in commun them better score
    incidents_1 = pd.DataFrame({"indicators": ["1 2 3", "4 5", "6"]})
    tfidf = FrequencyIndicators("indicators", normalize_function, incident)
    tfidf.fit(incidents_1)
    res = tfidf.transform(incidents_1)
    scores = res.values.tolist()
    assert (all(scores[i] >= scores[i + 1] for i in range(len(scores) - 1)))
    assert (all(scores[i] >= 0 for i in range(len(scores) - 1)))
