import MITREIndicatorsByOpenIncidentsv2
import pytest
from CommonServerPython import *


def test_mitre_indicators_by_open_incidents_v2(mocker):
    """
    Given:
        - A search_indicators_by_version result with iocs.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure that the iocs values appear in the Human Readable result.
    """

    mocker.patch.object(
        IndicatorsSearcher,
        "search_indicators_by_version",
        return_value={
            "total": 0,
            "iocs": [{"value": "1"}, {"value": "2"}, {"value": "3"}],
            "searchAfter": None,
            "accountErrors": None,
            "totalAccounts": 0,
        },
    )
    mocker.patch.object(demisto, "args", return_value={"from": "2023-07-25", "to": "2023-07-26"})
    mocker.patch.object(demisto, "results")
    MITREIndicatorsByOpenIncidentsv2.main()

    assert "\n| 1 |  |  |  |\n| 2 |  |  |  |\n| 3 |  |  |  |\n" in demisto.results.call_args_list[0].args[0]["HumanReadable"]


def test_mitre_indicators_by_open_incidents_v2_empty_iocs(mocker):
    """
    Given:
        - A search_indicators_by_version result with empty iocs (iocs: None which is a valid response from the server).
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure that the scripts completed the run with no errors.
    """
    mocker.patch.object(
        IndicatorsSearcher,
        "search_indicators_by_version",
        return_value={"total": 0, "iocs": None, "searchAfter": None, "accountErrors": None, "totalAccounts": 0},
    )
    mocker.patch.object(demisto, "args", return_value={"from": "2023-07-25", "to": "2023-07-26"})
    mocker.patch.object(demisto, "results")
    MITREIndicatorsByOpenIncidentsv2.main()

    assert (
        "### MITRE ATT&CK techniques by related Incidents\n**No entries.**\n"
        in demisto.results.call_args_list[0].args[0]["HumanReadable"]
    )


IOCS = [
    {"value": "Phishing", "investigationsCount": 2, "CustomFields": {"mitreid": "T1566"}},
    {"value": "Valid Accounts", "investigationsCount": 5, "CustomFields": {"mitreid": "T1078"}},
    {"value": "No ID", "investigationsCount": 1},
]


def test_relative_dates_are_sent_as_iso(mocker):
    """
    Given:
        - Relative "from"/"to" arguments ("30 days ago", "now"), which the server cannot parse for fromDate/toDate.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure searchIndicators gets ISO 8601 dates instead of the raw relative strings.
    """
    search_mock = mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": []})
    mocker.patch.object(demisto, "args", return_value={"from": "30 days ago", "to": "now"})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    kwargs = search_mock.call_args.kwargs
    assert datetime.fromisoformat(kwargs["from_date"]) < datetime.fromisoformat(kwargs["to_date"])
    assert "ago" not in kwargs["from_date"]


def test_empty_dates_are_not_sent(mocker):
    """
    Given:
        - Empty "from"/"to" arguments (the widget builder default).
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure no dates are sent to searchIndicators.
    """
    search_mock = mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": []})
    mocker.patch.object(demisto, "args", return_value={"from": "", "to": ""})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    assert search_mock.call_args.kwargs["from_date"] is None
    assert search_mock.call_args.kwargs["to_date"] is None


@pytest.mark.parametrize("widget_type", ["pie", "column", "line", "bar"])
def test_chart_widget_output(mocker, widget_type):
    """
    Given:
        - A chart widget type (pie/column/line/bar) and attack patterns with investigation counts.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure the output is a JSON group list sorted by investigationsCount and limited by size.
    """
    mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": IOCS})
    mocker.patch.object(demisto, "args", return_value={"widgetType": widget_type, "size": "2"})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    assert json.loads(demisto.results.call_args.args[0]) == [
        {"name": "T1078 - Valid Accounts", "data": [5]},
        {"name": "T1566 - Phishing", "data": [2]},
    ]


def test_table_widget_output(mocker):
    """
    Given:
        - The table widget type.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure the output is a JSON object with total and data rows.
    """
    mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": IOCS})
    mocker.patch.object(demisto, "args", return_value={"widgetType": "table"})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    output = json.loads(demisto.results.call_args.args[0])
    assert output["total"] == 3
    assert output["data"][0] == {"Value": "Phishing", "Name": "T1566", "Phase Name": None, "Description": None}


def test_number_widget_output(mocker):
    """
    Given:
        - The number (Single Value) widget type.
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure the output is the number of attack patterns.
    """
    mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": IOCS})
    mocker.patch.object(demisto, "args", return_value={"widgetType": "number"})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    assert demisto.results.call_args.args[0] == 3


@pytest.mark.parametrize("widget_type", ["text", ""])
def test_text_widget_output_holds_markdown_in_contents(mocker, widget_type):
    """
    Given:
        - The text widget type, or no widget type (War Room / Playground).
    When:
        - Running the MITREIndicatorsByOpenIncidentsv2 script.
    Then:
        - Ensure the markdown table is in Contents, which is what text widgets render.
    """
    mocker.patch.object(IndicatorsSearcher, "search_indicators_by_version", return_value={"iocs": IOCS})
    mocker.patch.object(demisto, "args", return_value={"widgetType": widget_type})
    mocker.patch.object(demisto, "results")

    MITREIndicatorsByOpenIncidentsv2.main()

    entry = demisto.results.call_args.args[0]
    assert entry["Contents"].startswith("### MITRE ATT&CK techniques by related Incidents")
    assert entry["Contents"] == entry["HumanReadable"]
