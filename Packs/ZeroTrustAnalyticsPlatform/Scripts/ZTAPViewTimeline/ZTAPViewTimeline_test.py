import json


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_raw(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_view_timeline(mocker):
    from ZTAPViewTimeline import view_timeline

    ztap_tags = ["ztap", "comment", "escalate"]
    entries = util_load_json("test_data/entries.json")
    output = view_timeline(entries, ztap_tags)

    mock_output = util_load_raw("test_data/output.md")
    assert output == mock_output
