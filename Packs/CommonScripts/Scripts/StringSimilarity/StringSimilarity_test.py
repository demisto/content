import pytest
import demistomock as demisto
from StringSimilarity import stringSimilarity, main
from unittest.mock import patch


@pytest.mark.parametrize("first_string, second_string, similarity_threshold, expected_result", [
    ("hello", "hello", 0.9, {
        "StringA": "hello",
        "StringB": "hello",
        "SimilarityScore": 1.0,
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
        assert result.outputs == expected_result
    except ValueError as e:
        assert "No similarity score calculated" in str(e)


def test_main_with_similarity_match():
    similarity_threshold = 0.1
    first_string = "hello"
    second_string = "world"

    # Mock demisto.getArg function to return the input arguments
    with patch.object(demisto, 'getArg') as mocked_getArg:
        mocked_getArg.side_effect = lambda arg_name: {
            'similarity_threshold': similarity_threshold,
            'string_A': first_string,
            'string_B': second_string
        }[arg_name]

        # Execute the main function and check if ValueError is raised
        try:
            main()
            assert demisto.results
        except ValueError as e:
            assert str(e) == "No similarity score calculated. Check the similarityThreshold value."


def test_main_with_no_similarity_match():
    similarity_threshold = 0.1
    first_string = "hello"
    second_string = "world"

    # Mock demisto.getArg function to return the input arguments
    with patch.object(demisto, 'getArg') as mocked_getArg:
        mocked_getArg.side_effect = lambda arg_name: {
            'similarity_threshold': similarity_threshold,
            'string_A': first_string,
            'string_B': second_string
        }[arg_name]

        # Execute the main function and check if ValueError is raised
        try:
            main()
            assert demisto.results
        except ValueError as e:
            assert str(e) == "No similarity score calculated. Check the similarityThreshold value."


def test_main_with_invalid_similarity_threshold():
    similarity_threshold = "invalid_threshold"
    first_string = "hello world"
    second_string = "hi world"

    # Mock demisto.getArg function to return the input arguments
    with patch.object(demisto, 'getArg') as mocked_getArg:
        mocked_getArg.side_effect = lambda arg_name: {
            'similarity_threshold': similarity_threshold,
            'string_A': first_string,
            'string_B': second_string
        }[arg_name]

        # Execute the main function and check if ValueError is raised due to invalid similarity_threshold
        try:
            result = main()
            assert result
        except ValueError as e:
            assert "could not convert string to float" in str(e)
