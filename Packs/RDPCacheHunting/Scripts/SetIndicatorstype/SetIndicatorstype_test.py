from SetIndicatorstype import parse_data, main
import demistomock as demisto

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
