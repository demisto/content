import pytest
import demistomock as demisto
from unittest.mock import patch, MagicMock, call
from CommonServerPython import CommandResults
from StringSimilarity import stringSimilarity

@pytest.mark.parametrize("first_string, second_string, similarity_threshold, expected_result", [
    ("hello", "hello", 0.9, {
        "StringA": "hello",
        "StringB": "hello",
        "SimilarityScore": 1.0,
    }),
    ("apple", "orange", 0.5, {
        "StringA": "apple",
        "StringB": "orange",
        "SimilarityScore": 0.0,
    }),
    ("deeply", "deeply", 0.6, {
        "StringA": "deeply",
        "StringB": "deeply",
        "SimilarityScore": 1.0,
    }),
    ("testing", "test", 0.7, {
        "StringA": "testing",
        "StringB": "test",
        "SimilarityScore": 0.7272727272727273,
    }),
])
def test_string_similarity(first_string, second_string, similarity_threshold, expected_result):
    try:
        result = stringSimilarity(first_string, second_string, similarity_threshold)
        print(result.outputs)
        assert result.outputs == expected_result
    except ValueError as e:
        assert "No similarity score calculated" in str(e)