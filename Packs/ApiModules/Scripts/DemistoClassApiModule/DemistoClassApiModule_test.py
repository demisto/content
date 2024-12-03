import importlib.util
from pathlib import Path
import tempfile

import pytest


def Demisto(context, is_debug=False):
    demisto_class = (Path(__file__).absolute().parent / "test_data/Demisto.py").read_text()
    api_module = (Path(__file__).absolute().parent / "DemistoClassApiModule.py").read_text()

    api_module = api_module.replace(
        "import demistomock as demisto  # noqa: F401",
        "{}\n\ndemisto = Demisto({}, {})".format(demisto_class, context, is_debug)
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file.write(api_module.encode("utf-8"))

    spec = importlib.util.spec_from_file_location("dynamic_module", temp_file.name)
    dynamic_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dynamic_module)

    return getattr(dynamic_module, "demisto")


SCRIPT_CONTEXT = {
    "command": "",
    "context": {
        "ScriptName": "script",
        "CommandsExecuted": {"CurrLevel": 0},
        "ExecutedCommands": []
    },
}

COMMAND_CALLED_BY_EXECUTE_COMMAND_CONTEXT = {
    "command": "cmd",
    "context": {
        "IntegrationBrand": "int",
        "CommandsExecuted": {"CurrLevel": 1},
        "ExecutedCommands": [{"name": "caller"}]
    },
}


def test_execute_command():
    demisto = Demisto(SCRIPT_CONTEXT, False)
    result = demisto.executeCommand("test", {})
    assert len(result) == 2
    assert result[0]["Type"] == 16
    assert result[1]["Type"] == 4


def test_execute_command_debug_mode():
    demisto = Demisto(SCRIPT_CONTEXT, True)
    result = demisto.executeCommand("test", {})
    assert len(result) == 1
    assert result[0]["Type"] == 4
