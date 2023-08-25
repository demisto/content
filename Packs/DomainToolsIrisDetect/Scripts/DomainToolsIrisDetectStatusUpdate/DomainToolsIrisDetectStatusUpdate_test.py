import json
import DomainToolsIrisDetectStatusUpdate as dt_script


def test_main_success(monkeypatch):
    # Mock demisto.args
    def mock_args():
        return {
            "old": json.dumps([{"state": "watched", "id": "1", "domain": "xyz"}]),
            "new": json.dumps([{"state": "ignored", "id": "1", "domain": "xyz"}]),
        }

    # Mock demisto.executeCommand
    def mock_executeCommand(command, args):
        return True

    # Mock demisto.error
    def mock_error(message):
        return

    # Mock demisto.get
    def mock_get(dictionary, key):
        return dictionary.get(key)

    # Apply the monkeypatches for the demisto methods
    monkeypatch.setattr(dt_script.demisto, "args", mock_args)
    monkeypatch.setattr(dt_script.demisto, "executeCommand", mock_executeCommand)
    monkeypatch.setattr(dt_script.demisto, "error", mock_error)
    monkeypatch.setattr(dt_script.demisto, "get", mock_get)

    # Execute the main method and verify no exception is thrown
    dt_script.main()
