import json
import demistomock as demisto  # noqa: F401
from CommonServerPython import EntryType


def util_load_json(path):
    with open(path, mode="r") as f:
        return json.loads(f.read())


def test_get_asm_args(mocker):
    from GenerateASMReport import get_asm_args

    args = util_load_json("test_data/args.json")
    result = get_asm_args(args)
    assert isinstance(result, dict)
    assert result["asmdatacollection"] == [
        {
            "answerer": "fake_user@domain.com",
            "options": "NoAutomatedRemediation",
            "selected": "File a ServiceNow Ticket",
            "timestamp": "1666033665586",
        }
    ]


def test_build_template(mocker):
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
    assert result[0] == {
        "type": "header",
        "data": "Investigation Summary Report",
        "layout": {
            "rowPos": 1,
            "columnPos": 1,
            "style": {"textAlign": "center", "fontSize": 32},
        },
    }


def test_build_report(mocker):
    from GenerateASMReport import build_report

    template = util_load_json("test_data/template.json")
    sanepdf_raw = util_load_json("test_data/sanepdf_raw.json")
    mocker.patch.object(demisto, "executeCommand", return_value=sanepdf_raw)
    result = build_report(template)
    assert isinstance(result, dict)
    assert result["Type"] == EntryType.ENTRY_INFO_FILE
