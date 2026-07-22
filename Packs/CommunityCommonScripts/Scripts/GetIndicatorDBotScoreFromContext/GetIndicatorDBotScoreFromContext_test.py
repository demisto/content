import demistomock as demisto
from CommonServerPython import *  # noqa: F401
import GetIndicatorDBotScoreFromContext
import pytest


def equals_object(obj1, obj2) -> bool:
    if not isinstance(obj1, type(obj2)):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _i1, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


@pytest.mark.parametrize(
    argnames="source_dbot_score, final_dbot_score, indicator_value",
    argvalues=[
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.B,
                    "Score": 2,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
                {"Indicator": "8.8.8.8", "Reliability": DBotScoreReliability.A, "Score": 3, "Type": "ip", "Vendor": "VirusTotal"},
            ],
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.B, "Score": 2, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        ),
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.A_PLUS,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.B,
                    "Score": 2,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
                {"Indicator": "8.8.8.8", "Reliability": DBotScoreReliability.A, "Score": 3, "Type": "ip", "Vendor": "VirusTotal"},
            ],
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.A_PLUS, "Score": 1, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        ),
    ],
)
def test_having_reliabilites(mocker, source_dbot_score, final_dbot_score, indicator_value):
    """
    Given:
        - List of DBotScores having 'Reliability' parameters
        - An existing indicator value.

    When:
        Running get_final_verdict() to get the DBotScore of the final verdict.

    Then:
        Validate the right output returns.
    """
    dbot_score = GetIndicatorDBotScoreFromContext.get_final_verdict(source_dbot_score, indicator_value)
    assert equals_object(dbot_score, final_dbot_score)


@pytest.mark.parametrize(
    argnames="source_dbot_score, final_dbot_score, indicator_value",
    argvalues=[
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.B,
                    "Score": 2,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
            ],
            None,
            "2.2.2.2",
        )
    ],
)
def test_indicator_not_found(mocker, source_dbot_score, final_dbot_score, indicator_value):
    """
    Given:
        - List of DBotScores having 'Reliability' parameters
        - An indicator value not in the list.

    When:
        Running get_final_verdict() to get the DBotScore of the final verdict.

    Then:
        Validate the right output returns.
    """
    dbot_score = GetIndicatorDBotScoreFromContext.get_final_verdict(source_dbot_score, indicator_value)
    assert equals_object(dbot_score, final_dbot_score)


@pytest.mark.parametrize(
    argnames="source_dbot_score, final_dbot_score, indicator_value",
    argvalues=[
        (
            [
                {"Indicator": "1.1.1.1", "Score": 1, "Type": "ip", "Vendor": "AlienVault OTX v2"},
                {"Indicator": "1.1.1.1", "Score": 2, "Type": "ip", "Vendor": "AutoFocus V2"},
            ],
            None,
            "1.1.1.1",
        )
    ],
)
def test_no_reliable_dbot_score(mocker, source_dbot_score, final_dbot_score, indicator_value):
    """
    Given:
        - List of DBotScores which don't have 'Reliability' parameters
        - An existing indicator value.

    When:
        Running get_final_verdict() to get the DBotScore of the final verdict.

    Then:
        Validate the right output returns.
    """
    dbot_score = GetIndicatorDBotScoreFromContext.get_final_verdict(source_dbot_score, indicator_value)
    assert equals_object(dbot_score, final_dbot_score)


@pytest.mark.parametrize(
    argnames="source_dbot_score, final_dbot_score, indicator_value",
    argvalues=[
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {"Indicator": "1.1.1.1", "Score": 2, "Type": "ip", "Vendor": "Manual"},
            ],
            {"Indicator": "1.1.1.1", "Score": 2, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        )
    ],
)
def test_manual_dbot_score(mocker, source_dbot_score, final_dbot_score, indicator_value):
    """
    Given:
        - List of DBotScores in which a DBotScore vendor is 'Manual'.
        - The indicator value of the DBotScore whose vendor is 'Manual'.

    When:
        Running get_final_verdict() to get the DBotScore of the final verdict.

    Then:
        Validate the right output returns.
    """
    dbot_score = GetIndicatorDBotScoreFromContext.get_final_verdict(source_dbot_score, indicator_value)
    assert equals_object(dbot_score, final_dbot_score)


@pytest.mark.parametrize(
    argnames="source_dbot_score, final_dbot_score, indicator_value",
    argvalues=[
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 2,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
            ],
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.C, "Score": 2, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        ),
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 1,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 0,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
            ],
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.C, "Score": 1, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        ),
        (
            [
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 3,
                    "Type": "ip",
                    "Vendor": "AlienVault OTX v2",
                },
                {
                    "Indicator": "1.1.1.1",
                    "Reliability": DBotScoreReliability.C,
                    "Score": 3,
                    "Type": "ip",
                    "Vendor": "AutoFocus V2",
                },
            ],
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.C, "Score": 3, "Type": "ip", "Vendor": "XSOAR"},
            "1.1.1.1",
        ),
    ],
)
def test_same_reliability(mocker, source_dbot_score, final_dbot_score, indicator_value):
    """
    Given:
        - List of DBotScores having the same reliability to the indicator value.

    When:
        Running get_final_verdict() to get the DBotScore of the final verdict.

    Then:
        Validate the right output returns.
    """
    dbot_score = GetIndicatorDBotScoreFromContext.get_final_verdict(source_dbot_score, indicator_value)
    assert equals_object(dbot_score, final_dbot_score)


def test_main_final_dbot_score_found(mocker):
    """
    Given:
        An indicator that exists in DBotScore.

    When:
        Running script.

    Then:
        Validate the right output returns.
    """
    mocker.patch.object(
        demisto,
        "dt",
        return_value=[
            {"Indicator": "1.1.1.1", "Reliability": DBotScoreReliability.C, "Score": 3, "Type": "ip", "Vendor": "AutoFocus V2"}
        ],
    )
    mocker.patch.object(demisto, "args", return_value={"indicator_value": "1.1.1.1"})
    return_results = mocker.patch("GetIndicatorDBotScoreFromContext.return_results")

    GetIndicatorDBotScoreFromContext.main()

    assert return_results.call_count == 1
    results = return_results.call_args[0][0].to_context()

    assert equals_object(
        results["EntryContext"],
        {
            "FinalDBotScore(val.Indicator && val.Indicator == obj.Indicator)": {
                "Indicator": "1.1.1.1",
                "Reliability": DBotScoreReliability.C,
                "Score": 3,
                "Type": "ip",
                "Vendor": "XSOAR",
            }
        },
    )


def test_main_final_dbot_score_not_found(mocker):
    """
    Given:
        An indicator that dosn't exist in DBotScore.

    When:
        Running script.

    Then:
        Validate the right output returns.
    """
    mocker.patch.object(demisto, "dt", return_value=[])
    mocker.patch.object(demisto, "args", return_value={"indicator_value": "1.1.1.1"})
    return_results = mocker.patch("GetIndicatorDBotScoreFromContext.return_results")

    GetIndicatorDBotScoreFromContext.main()

    assert return_results.call_count == 1
    assert "No DBotScore found" in return_results.call_args[0][0]
