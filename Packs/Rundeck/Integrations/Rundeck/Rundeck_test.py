from Rundeck import filter_results, attribute_pairs_to_dict, convert_str_to_int, project_list_command, Client

from CommonServerPython import DemistoException


def test_filter_results_when_response_is_dict():
    """
    Given:
        - response as dict
    When
        - performing an api request and the api response is a dict
    Then
        - filter out all selected fields and signs
    """
    results_to_filter = {
        "key1": "val1",
        "key2": "val2",
        "key_3": "val3"
    }

    result = filter_results(results_to_filter, 'key1', "_")
    assert 'key1' not in result.keys()
    assert 'key3' in result.keys()


def test_filter_results_when_response_is_list():
    """
    Given:
        - response as list
    When
        - performing an api request and the api response is a list
    Then
        - filter out all selected fields and signs
    """
    results_to_filter = [
        {"key1": "val1", "key2": "val2"},
        {"key_3": "val3"}
    ]

    result = filter_results(results_to_filter, 'key1', "_")

    assert 'key1' not in result[0].keys()
    assert 'key3' in result[1].keys()


def test_attribute_pairs_to_dict():
    """
    Given:
        - string convert to a dict
    When
        - getting a dict from Demisto
    Then
        - a string is converted to dict
    """
    result = attribute_pairs_to_dict('key1=val1,key2=val2')
    assert result == {'key1': 'val1', 'key2': 'val2'}


def test_convert_str_to_int():
    """
    Given:
        - string convert to a int
    When
        - getting an integer from Demisto
    Then
        - the passed string is converted to int
    """
    result = convert_str_to_int('5', 'argument')
    assert result == 5


def test_convert_str_to_int_with_bad_input():
    """
    Given:
        - string convert to a int that can't be converted to int
    When
        - getting it from Demisto as a command's input
    Then
        - DemistoExeption is raised
    """
    try:
        convert_str_to_int('\\', 'argument')
    except DemistoException:
        pass
    else:
        assert 1 == 2, 'error when try converting string to int should throw DemistoException'


def test_project_list_command(mocker):
    """
    Given:
        - None.
    When
        - a user wants to get a list of all the existing projects.
    Then
        - CommonResults object returns with the api response.
    """
    return_value = [{'url': 'https://test/api/35/project/Demisto', 'name': 'Demisto', 'description': 'Demisto Test'}]
    client = Client(
            base_url='base_url',
            verify=False,
            params={'authtoken': '123'},
            project_name='Demisto')
    mocker.patch.object(client, 'get_project_list', return_value=return_value)
    result = project_list_command(client)
    assert result.outputs == [{'name': 'Demisto', 'description': 'Demisto Test'}]
    assert result.outputs_key_field == 'name'
    assert result.outputs_prefix == 'Rundeck.Projects'
    assert result.readable_output == '### Projects List:\n|Name|Description|\n|---|---|\n| Demisto | Demisto Test |\n'


