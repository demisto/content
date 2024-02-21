

def test_basescript_dummy():
    """
    Given:
    When:
    Then:
    """
    from ExtractHyperlinksFromOfficeFiles import extract_hyperlink_by_file_type

    args = {
        'dummy': 'this is a dummy response'
    }
    response = basescript_dummy_command(args)

    mock_response = util_load_json('test_data/basescript-dummy.json')

    assert response.outputs == mock_response

