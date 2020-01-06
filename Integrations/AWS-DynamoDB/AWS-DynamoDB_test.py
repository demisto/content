import pytest
import json

def test_safe_load_json():
    from AWS-DynamoDB import safe_load_json

    sample_dict = {
        "foo": "bar"
    }
    sample_json = json.dumps(sample_dict)
    test_result = safe_load_json(sample_json)

    assert isinstance(test_result, dict)
