from SetIndicatorstype import parse_data, main
from unittest.mock import patch
import demistomock as demisto
import random

# Tests that the function returns the expected dictionary when given valid data.


def test_parse_data_happy_path():
    # Arrange
    list_content = ['apple', 'banana', 'orange', 'apple', 'banana', 'grape', 'kiwi', 'pear', 'peach', 'watermelon']
    # Act
    result = parse_data(list_content)

    # Assert
    assert result['Type'] == 17
    assert result['ContentsFormat'] == 'pie'
    assert len(result['Contents']['stats']) == 8
    assert result['Contents']['params']['layout'] == 'horizontal'


# Tests that the function returns an empty dictionary when given an empty list.
def test_parse_data_empty_list():
    # Arrange
    list_content: list = []
    # Act
    result = parse_data(list_content)
    # Assert
    assert result['Type'] == 17
    assert result['ContentsFormat'] == 'pie'
    assert len(result['Contents']['stats']) == 0
    assert result['Contents']['params']['layout'] == 'horizontal'


# Tests that the function correctly handles duplicate values in the list_content parameter.
def test_parse_data_duplicate_values():
    # Arrange
    list_content = ['apple', 'banana', 'orange', 'apple', 'banana', 'grape', 'kiwi', 'pear', 'peach', 'watermelon', 'watermelon']
    # Act
    result = parse_data(list_content)
    # Assert
    assert result['Type'] == 17
    assert result['ContentsFormat'] == 'pie'
    assert len(result['Contents']['stats']) == 8
    assert result['Contents']['params']['layout'] == 'horizontal'


# Tests that the function returns an empty dictionary when the top_lists parameter is empty.
def test_parse_data_empty_top_lists():
    # Arrange
    list_content = ['apple', 'banana', 'orange']
    # Act
    result = parse_data(list_content)
    # Assert
    assert result['Type'] == 17
    assert result['ContentsFormat'] == 'pie'
    assert len(result['Contents']['stats']) == 3
    assert result['Contents']['params']['layout'] == 'horizontal'


# Tests that the function correctly handles cases where there are less than 10 unique values in list_content.
def test_parse_data_less_than_10_unique_values():
    # Arrange
    list_content = ['apple', 'banana', 'orange', 'grape', 'kiwi', 'pear', 'peach']
    # Act
    result = parse_data(list_content)
    # Assert
    assert result['Type'] == 17
    assert result['ContentsFormat'] == 'pie'
    assert len(result['Contents']['stats']) == 7
    assert result['Contents']['params']['layout'] == 'horizontal'


# Helper function to generate random data for testing
def generate_test_data():
    data = []
    for i in range(5):
        data.append({"Indicator" + str(i): ["value"] * random.randint(1, 10)})
    return data


def test_parse_data():
    test_list_content = ["List1", "List1", "List2", "List1", "List2", "List3"]

    # Patch random.randint to return a fixed value for consistent testing
    with patch.object(random, 'randint', return_value=123456) as mocked_randint:
        actual_results = parse_data(test_list_content)
        mocked_randint.assert_called_with(0, 16777215)  # Check if randint was called with the correct parameters
        assert actual_results['Type'] == 17
        assert actual_results['ContentsFormat'] == 'pie'
        assert len(actual_results['Contents']['stats']) == 3
        assert actual_results['Contents']['params']['layout'] == 'horizontal'


def test_main():
    test_data = [
        {"Indicator1": ["value1", "value2"]},
        {"Indicator2": ["value1"]},
        {"Indicator3": ["value1", "value2", "value3"]},
    ]

    # Patch demisto.context and argToList functions
    with patch.object(demisto, 'context', return_value={'ExtractedIndicators': test_data}), patch.object(demisto, 'results'),\
            patch.object(random, 'randint', return_value=123456):
        main()
        result = demisto.results.call_args[0][0]

        assert result.get('Type') == 17
        assert result.get('ContentsFormat') == 'pie'
        assert result.get('Contents', {}).get('params', {}).get('layout') == 'horizontal'


def test_main_without_data():
    # Mock the demisto context and argToList functions
    with patch.object(demisto, 'context', return_value={'ExtractedIndicators': None}), \
            patch.object(demisto, 'results') as mocked_results:

        main()

        # Check if the results function was called with the correct parameters for the empty data case
        mocked_results.assert_called_with({
            "Type": 17,
            "ContentsFormat": "bar",
            "Contents": {
                "stats": [
                    {
                        "data": [0],
                        "groups": None,
                        "name": "N/A",
                        "label": "N/A",
                        "color": "rgb(255, 23, 68)"
                    },
                ],
                "params": {
                    "layout": "horizontal"
                }
            }
        })
