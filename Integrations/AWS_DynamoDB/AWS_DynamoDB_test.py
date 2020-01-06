import json


def test_safe_load_json():
    from AWS_DynamoDB import safe_load_json

    sample_dict = {
        "foo": "bar"
    }
    sample_json = json.dumps(sample_dict)
    test_result = safe_load_json(sample_json)

    assert isinstance(test_result, dict)


def test_remove_empty_elements():
    from AWS_DynamoDB import remove_empty_elements

    empty_dict = {}
    sample_dict = {
        "foo": None
    }
    empty_dict_result = remove_empty_elements(sample_dict)
    assert empty_dict_result == empty_dict


def test_parse_tag_field():
    from AWS_DynamoDB import parse_tag_field

    sample_tag_string = 'key=foo,value=bar;key=baz,value=qux'
    tags = parse_tag_field(sample_tag_string)
    expected_result = [
        {
            "key": "foo",
            "value": "bar"
        },
        {
            "key": "baz",
            "value": "qux"
        }
    ]
    assert tags == expected_result
