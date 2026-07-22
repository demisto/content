import json
import pytest
import demistomock as demisto
from CertStream import get_homographs_list, levenshtein_distance, check_homographs


@pytest.mark.parametrize("list_name", [("testdomainlist")])
def test_get_homographs_list(list_name: str, mocker):
    mocker.patch.object(
        demisto,
        "internalHttpRequest",
        return_value={
            "body": json.dumps([{"id": "testdomainlist", "data": '{"test.com": "test.domain.com"}'}]),
            "headers": json.dumps({"statusCode": "200"}),
        },
    )
    result = get_homographs_list(list_name)

    assert result


@pytest.mark.parametrize(
    "original_string,reference_string,expected_result",
    [("test.domain.com", "test.domain.com", 0), ("test.domain.com", "", 15), ("paypal.com", "paypàl.com", 1)],
)
def test_levenshtein_distance(original_string: str, reference_string: str, expected_result: int):
    result = levenshtein_distance(original_string, reference_string)

    assert result == expected_result


@pytest.mark.parametrize(
    "domain, levenshtein_distance_threshold, expected_result",
    [("test.com", 0.3, True), ("another.org", 0.3, False), ("lest.com", 0.3, True)],
)
def test_check_homographs(domain: str, levenshtein_distance_threshold, expected_result, mocker, capfd):
    expected_result = expected_result
    homographs = {"test.com": ["best.com", "last.com"]}
    mocker.patch("CertStream.homographs", homographs)
    mocker.patch("CertStream.levenshtein_distance_threshold", levenshtein_distance_threshold)
    result = check_homographs(domain)

    assert result[0] == expected_result
