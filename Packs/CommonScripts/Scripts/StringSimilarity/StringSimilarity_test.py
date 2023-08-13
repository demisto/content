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
    ("a", "b", 0.1, {
     None})
])
def test_string_similarity(first_string, second_string, similarity_threshold, expected_result, mocker):
    """
        given two strings and similarity threshold
        when calling stringSimilarity
        then make sure a None value is returned when similarityScore < threshold, else is expected_result
        """
    result = stringSimilarity(first_string, second_string, similarity_threshold)
    if result is not None:
        assert result.outputs == expected_result
    else:
        assert result is None


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


def test_main_with_no_similarity_match(mocker):

    similarity_threshold = 0.1
    first_string = "hello"
    second_string = "world"
    expected_results = {'StringA': 'hello', 'StringB': 'world', 'SimilarityScore': 0.2}
    # Mock demisto.getArg function to return the input arguments
    with patch.object(demisto, 'getArg') as mocked_getArg:
        mocked_getArg.side_effect = lambda arg_name: {
            'similarity_threshold': similarity_threshold,
            'string_A': first_string,
            'string_B': second_string
        }[arg_name]
        return_results = mocker.patch('StringSimilarity.return_results')
        # Execute the main function and check if ValueError is raised
        try:
            main()
            assert return_results.call_args[0][0].to_context()['Contents'] == expected_results
        except ValueError as e:
            assert str(e) == "No similarity score calculated. Check the similarityThreshold value."


def test_main_with_invalid_similarity_threshold(mocker):
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
        return_results = mocker.patch('StringSimilarity.return_error')
        # Execute the main function and check if ValueError is raised due to invalid similarity_threshold
        main()
        result = return_results.call_args[0][0]
        assert result == "Failed to check string similarity. Problem: could not convert string to float: 'invalid_threshold'"
