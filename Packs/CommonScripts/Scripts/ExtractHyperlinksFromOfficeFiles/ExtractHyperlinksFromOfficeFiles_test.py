

def test_basescript_dummy():
    """
    Given:
    When:
    Then:
    """
    from BaseScript import basescript_dummy_command

    args = {
        'dummy': 'this is a dummy response'
    }
    response = basescript_dummy_command(args)

    mock_response = util_load_json('test_data/basescript-dummy.json')

    assert response.outputs == mock_response

