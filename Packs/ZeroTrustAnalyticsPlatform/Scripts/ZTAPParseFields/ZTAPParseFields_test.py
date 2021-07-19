import json
import io


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_raw(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return f.read()


def test_parse_fields_truncated():
    from ZTAPParseFields import parse_fields

    events = util_load_json("test_data/event.json")
    output = parse_fields(events, full=False, max_fields=30, max_value_length=50)

    mock_markdown_result = util_load_raw("test_data/output-truncated.md")
    assert output == mock_markdown_result


def test_parse_fields_full():
    from ZTAPParseFields import parse_fields

    events = util_load_json("test_data/event.json")
    output = parse_fields(events, full=True, max_fields=1, max_value_length=1)

    mock_markdown_result = util_load_raw("test_data/output-full.md")
    assert output == mock_markdown_result
