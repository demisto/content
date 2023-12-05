import json
from pathlib import Path

def util_load_json(path):
    with open(Path(__file__).parent / path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_raw(path):
    with open(Path(__file__).parent / path, encoding="utf-8") as f:
        return f.read()


def test_parse_links():
    from ZTAPParseLinks import parse_links

    events = util_load_json("test_data/events.json")
    output = parse_links(events)

    mock_markdown_result = util_load_raw("test_data/output.md")

    assert output == mock_markdown_result
