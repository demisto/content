import json
import io


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def test_extract_fields():
    from ZTAPExtractFields import extract_fields

    events = util_load_json("test_data/event.json")
    output = extract_fields(events)

    mock_markdown_result = util_load_json("test_data/output.json")
    assert output == mock_markdown_result
