def test_get_score_color():
    '''
    Tests get_score_color function
    Given
        A score as an integer
    When
        - A score is provided
    Then
        - Return a string with the result
    '''
    from OpenCVE import get_score_color

    color = get_score_color(5)
    assert type(color) == str
