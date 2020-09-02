import pytest
import json
from Packs.QRadar.Integrations.QRadar_v2.QRadar_v2 import (
    QRadarClient,
    search_command,
    get_search_command,
    get_search_results_command,
    get_assets_command,
    get_asset_by_id_command,
    get_closing_reasons_command,
    create_note_command,
    get_note_command,
)

with open("TestData/commands_outputs.json", "r") as f:
    COMMAND_OUTPUTS = json.load(f)
with open("TestData/raw_responses.json", "r") as f:
    RAW_RESPONSES = json.load(f)


command_tests = [
    ("qradar-searches", search_command, {"query_expression": "SELECT sourceip AS 'MY Source IPs' FROM events"},),
    ("qradar-get-search", get_search_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-search-results", get_search_results_command, {"search_id": "6212b614-074e-41c1-8fcf-1492834576b8"},),
    ("qradar-get-assets", get_assets_command, {"range": "0-1"}),
    ("qradar-get-asset-by-id", get_asset_by_id_command, {"asset_id": "1928"}),
    ("qradar-get-closing-reasons", get_closing_reasons_command, {}),
    (
        "qradar-create-note",
        create_note_command,
        {"offense_id": "450", "note_text": "XSOAR has the best documentation!"},
    ),
    ("qradar-get-note", get_note_command, {"offense_id": "450", "note_id": "1232"}),
]


@pytest.mark.parametrize("command,command_func,args", command_tests)
def test_commands(command, command_func, args, mocker):

    client = QRadarClient("", {}, {"identifier": "*", "password": "*"})
    mocker.patch.object(client, "send_request", return_value=RAW_RESPONSES[command])
    res = command_func(client, **args)
    assert COMMAND_OUTPUTS[command] == res.get("EntryContext")
