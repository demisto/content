import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import EntryType


def util_load_json(path):
    with open(path, mode="r") as f:
        return json.loads(f.read())


def test_get_asm_args(mocker):
    """Tests get_asm_args helper function.

        Given:
            - Mock JSON that mimics Demisto.args() object.
        When:
            - Sending JSON to get_asm_args helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import get_asm_args

    args = util_load_json("test_data/args.json")
    result = get_asm_args(args)
    assert isinstance(result, dict)
    assert result["asmdatacollection"] == [
        {
            "Answerer": "fake_user@domain.com",
            "Options": "NoAutomatedRemediation",
            "Selected": "File a ServiceNow Ticket",
            "Timestamp": "1666033665586",
        }
    ]


def test_color_for_severity(mocker):
    """Tests color_for_severity helper function.

        Given:
            - Mock severity (string).
        When:
            - Sending severity (string) to color_for_severity helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import color_for_severity

    result = color_for_severity("High")
    assert result == "red"


def test_build_template(mocker):
    """Tests build_template command function.

        Given:
            - Mock current date and output from get_asm_args helper function.
        When:
            - Running the 'build_template' function.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from GenerateASMReport import build_template

    date_result = [
        {
            "Contents": "2022-10-26T16:06:49.164Z",
        }
    ]
    mocker.patch.object(demisto, "executeCommand", return_value=date_result)
    args = util_load_json("test_data/args.json")
    result = build_template(args)
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, dict)
    assert result[1] == {
        "type": "header",
        "data": "ASM Investigation Summary Report",
        "layout": {
            "rowPos": 1,
            "columnPos": 2,
            "style": {
                "textAlign": "center",
                "fontSize": 28,
                "color": "black",
                "background-color": "white",
            },
        },
    }


def test_build_report(mocker):
    """Tests build_report command function.

        Given:
            - Mock template list from build_template function and alert ID.
        When:
            - Running the 'build_report' function.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from GenerateASMReport import build_report

    template = util_load_json("test_data/template.json")
    sanepdf_raw = util_load_json("test_data/sanepdf_raw.json")
    mocker.patch.object(demisto, "executeCommand", return_value=sanepdf_raw)
    result = build_report(template, 1234)
    assert isinstance(result, dict)
    assert result["Type"] == EntryType.ENTRY_INFO_FILE


def test_RPR_criteria(mocker):
    """Tests RPR_criteria helper function.

        Given:
            - Mock criteria_str (string).
        When:
            - Sending criteria_str (string) to RPR_criteria helper function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from GenerateASMReport import RPR_criteria

    result = RPR_criteria("""[{"field": "provider", "value": "amazon web services", "operator": "eq"}]""")
    assert result == "(provider = amazon web services)"
