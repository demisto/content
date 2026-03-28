"""Base Script for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

"""

import json
import pytest
import demistomock as demisto
from GetListContent import DemistoException, get_list_content_internal, get_list_content, get_list_content_command


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    "list_name, output",
    [
        ("plainTextList", "This is the content of an example plaintext list"),
        ("exampleJsonList", '{\n\t"UserID": "123-456-789",\n\t"UserName": "Example User"\n\t}'),
        ("RandomListName", None),
    ],
)
def test_get_list_content_internal(list_name, output, mocker):
    lists_body = util_load_json("test_data/getlistcontent_lists.json")
    mocker.patch.object(demisto, "internalHttpRequest", return_value={"body": json.dumps(lists_body)})
    res = get_list_content_internal(list_name)
    assert res == output


@pytest.mark.parametrize(
    "list_name, return_type, output",
    [
        ("plainTextList", "string", "This is the content of an example plaintext list"),
        ("exampleJsonList", "json", {"UserID": "123-456-789", "UserName": "Example User"}),
        ("RandomListName", "string", None),
        ("plainTextList", "other", "This is the content of an example plaintext list"),
    ],
)
def test_get_list_content(list_name, return_type, output, mocker):
    lists_body = util_load_json("test_data/getlistcontent_lists.json")
    mocker.patch.object(demisto, "internalHttpRequest", return_value={"body": json.dumps(lists_body)})
    assert get_list_content(list_name, return_type) == output


@pytest.mark.parametrize(
    "args, output",
    [
        ({"value": "exampleJsonList", "type": "json"}, {"UserID": "123-456-789", "UserName": "Example User"}),
        ({"value": "plainTextList", "type": "string"}, "This is the content of an example plaintext list"),
        ({"value": "exampleJsonList", "type": "string"}, '{\n\t"UserID": "123-456-789",\n\t"UserName": "Example User"\n\t}'),
    ],
)
def test_get_list_content_command(args, output, mocker):
    lists_body = util_load_json("test_data/getlistcontent_lists.json")
    mocker.patch.object(demisto, "internalHttpRequest", return_value={"body": json.dumps(lists_body)})
    assert get_list_content_command(args) == output


@pytest.mark.parametrize(
    "args",
    [
        ({"value": "", "type": "json"}),
        ({"value": "", "type": "string"}),
        ({"type": "string"}),
        ({}),
    ],
)
def test_get_list_comment_command_exception(args):
    with pytest.raises(DemistoException, match="Value must not be empty"):
        get_list_content_command({"value": "", "type": "json"})
