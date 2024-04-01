import json
import pytest
import demistomock as demisto
from CertStream import get_homographs_list, levenshtein_distance


@pytest.mark.parametrize("list_name", [
    ("testdomainlist")])
def test_get_homographs_list(list_name: str, mocker):
    mocker.patch.object(
        demisto,
        'internalHttpRequest',
        return_value={
            'body': json.dumps([{'id': 'testdomainlist', 'data': '{"test.com": "test.domain.com"}'}]),
            'headers': json.dumps({'statusCode': '200'})
        })
    result = get_homographs_list(list_name)

    assert result


@pytest.mark.parametrize("original_string,reference_string,expected_result", [
    ("test.domain.com", "test.domain.com", 0),
    ("test.domain.com", "", 15),
    ("paypal.com", "paypàl.com", 1)
])
def test_levenshtein_distance(original_string: str, reference_string: str, expected_result: int):

    result = levenshtein_distance(original_string, reference_string)

    assert result == expected_result


# Additional tests for other commands
