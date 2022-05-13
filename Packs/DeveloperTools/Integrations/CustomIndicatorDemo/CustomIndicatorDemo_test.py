from CustomIndicatorDemo import Client, custom_indicator_creation


def test_custom_indicator_test():
    """
    Given
        - Dummy result
    When
        - dummy client is passed
    Then
        - return enriched indicator and result
    """
    client = Client(base_url='some_mock_url', verify=False)
    res = custom_indicator_creation(client)
    indicator = res.indicator
    assert indicator.data['param1'] == 'value1'
    assert indicator.data['param2'] == 'value2'
    assert indicator.value == 'custom_value'
    assert res.outputs['dummy'] == 'test'
