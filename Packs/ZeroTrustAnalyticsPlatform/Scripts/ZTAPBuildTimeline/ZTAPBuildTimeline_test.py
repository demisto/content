import json
import io
import demistomock as demisto


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_build_timeline(mocker):
    from ZTAPBuildTimeline import build_timeline

    def executeCommand(name, args=None):
        if name == "markAsEvidence":
            return [{"Contents": "done"}]
        else:
            raise ValueError("Unimplemented command called: {name}")

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)

    entries = util_load_json("test_data/entries.json")
    output = build_timeline(entries)

    mock_markdown_result = util_load_json("test_data/output.json")
    assert output == mock_markdown_result
