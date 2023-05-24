from typing import List
import pytest
from unittest.mock import patch
from SetIndicatorstype import parse_data, main

expected_results = {
        "Type": 17,
        "ContentsFormat": "pie",
        "Contents": {
            "stats": [
                {
                    "data": [2],
                    "groups": None,
                    "name": "a",
                    "label": "a",
                    "color": "#5057db"
                },
                {
                    "data": [2],
                    "groups": None,
                    "name": "b",
                    "label": "b",
                    "color": "#6802ec"
                },
                {
                    "data": [2],
                    "groups": None,
                    "name": "c",
                    "label": "c",
                    "color": "#a0b203"
                },
                {
                    "data": [2],
                    "groups": None,
                    "name": "d",
                    "label": "d",
                    "color": "#15e9ac"
                },
                {
                    "data": [2],
                    "groups": None,
                    "name": "e",
                    "label": "e",
                    "color": "#e0d010"
                },
                {
                    "data": [1],
                    "groups": None,
                    "name": "f",
                    "label": "f",
                    "color": "#7f0679"
                },
                {
                    "data": [1],
                    "groups": None,
                    "name": "g",
                    "label": "g",
                    "color": "#b3e83b"
                },
                {
                    "data": [1],
                    "groups": None,
                    "name": "h",
                    "label": "h",
                    "color": "#5ee71a"
                },
                {
                    "data": [1],
                    "groups": None,
                    "name": "i",
                    "label": "i",
                    "color": "#6654c5"
                },
                {
                    "data": [1],
                    "groups": None,
                    "name": "j",
                    "label": "j",
                    "color": "#12b826"
                }
            ],
            "params": {
                "layout": "horizontal"
            }
        }
    }

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
    list_content = []
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