import pytest

from FeedOpenCTI_v2 import *
from test_data.feed_data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS
from CommonServerPython import CommandResults
from pycti import StixCyberObservable


class Client:
    temp = ''
    stix_cyber_observable = StixCyberObservable
    identity = Identity


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - `fetch_indicators_command` or `get_indicators_command` are calling the get_indicators function
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    new_last_id, indicators = get_indicators(client, indicator_type=['registry key', 'account'], limit=10)
    assert len(indicators) == 2
    assert new_last_id == 'YXJyYXljb25uZWN0aW9uOjI='


def test_fetch_indicators_command(mocker):
    """Tests fetch_indicators_command function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - Calling `fetch_indicators_command`
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    indicators = fetch_indicators_command(client, indicator_type=['registry key', 'account'], max_fetch=200)
    assert len(indicators) == 2


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user and 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'indicator_types': 'registry key,account',
        'limit': 2
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators from OpenCTI" in results.readable_output


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - Calling `get_indicators_command`
    Then
        - validate the response to have a "No indicators" string
    """
    client = Client
    args = {
        'indicator_types': ['registry key', 'account']
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_WITHOUT_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert "No indicators" in results.readable_output


def test_indicator_delete_command(mocker):
    """Tests indicator_delete_command function
    Given
        id of indicator to delete
    When
        - Calling `indicator_delete_command`
    Then
        - validate the response to have a "Indicator deleted." string
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_cyber_observable, 'delete', return_value="Indicator deleted")
    results: CommandResults = indicator_delete_command(client, args)
    assert "Indicator deleted" in results.readable_output


@pytest.mark.parametrize(argnames="field, value",
                         argvalues=[('score', '50'),
                                    ('description', 'new description')])
def test_indicator_field_update_command(mocker, field, value):
    """Tests indicator_field_update_command function
    Given
        id of indicator to update
        field to update
        value to update
    When
        - Calling `indicator_field_update_command`
    Then
        - validate the response to have a "Indicator deleted." string and context as expected
    """
    client = Client
    args = {
        'id': '123456',
        'field': field,
        'value': value
    }
    mocker.patch.object(client.stix_cyber_observable, 'update_field', return_value={'id': '123456'})
    results: CommandResults = indicator_field_update_command(client, args)
    assert "Indicator updated successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


def test_indicator_create_command(mocker):
    """Tests indicator_create_command function
    Given
        type of indicator to create
        score to create
        data to create
    When
        - Calling `indicator_create_command`
    Then
        - validate the response to have a "Indicator created successfully." string and context as expected
    """
    client = Client
    args = {
        'score': '20',
        'type': 'Domain',
        'data': "{\"value\": \"devtest.com\"}"
    }
    mocker.patch.object(client.stix_cyber_observable, 'create', return_value={'id': '123456'})
    results: CommandResults = indicator_create_command(client, args)
    assert "Indicator created successfully" in results.readable_output
    assert 'id' in results.outputs


@pytest.mark.parametrize(argnames="field, value, mock_obj_name, function_name",
                         argvalues=[('marking', 'TLP:RED', 'MarkingDefinition', 'add_marking_definition'),
                                    ('label', 'new-label', 'Label', 'add_label')])
def test_indicator_field_add_command(mocker, field, value, mock_obj_name, function_name):
    """Tests indicator_field_add_command function
        Given
            id of indicator to add
            field to add
            value to add
        When
            - Calling `indicator_field_add_command`
        Then
            - validate the response to have a "added successfully." string at human readable
        """
    client = Client
    args = {
        'id': '123456',
        'field': field,
        'value': value
    }

    magic_mock = mocker.MagicMock()
    magic_mock.create.return_value = {'id': '123'}
    mocker.patch(f'FeedOpenCTI_v2.{mock_obj_name}', return_value=magic_mock)
    mocker.patch.object(client.stix_cyber_observable, function_name, return_value=True)

    results: CommandResults = indicator_field_add_command(client, args)
    assert "successfully" in results.readable_output


@pytest.mark.parametrize(argnames="field, value, mock_obj_name, function_name",
                         argvalues=[('marking', 'TLP:RED', 'MarkingDefinition', 'remove_marking_definition'),
                                    ('label', 'new-label', 'Label', 'remove_label')])
def test_indicator_field_remove_command(mocker, field, value, mock_obj_name, function_name):
    """Tests indicator_field_remove_command function
    Given
        id of indicator to remove
        field to remove
        value to remove
    When
        - Calling `indicator_field_remove_command`
    Then
        - validate the response to have a "removed successfully." string at human readable
    """
    client = Client
    args = {
        'id': '123456',
        'field': field,
        'value': value
    }

    magic_mock = mocker.MagicMock()
    magic_mock.create.return_value = {'id': '123'}
    mocker.patch(f'FeedOpenCTI_v2.{mock_obj_name}', return_value=magic_mock)
    mocker.patch.object(client.stix_cyber_observable, function_name, return_value=True)

    results: CommandResults = indicator_field_remove_command(client, args)
    assert "successfully" in results.readable_output


def test_organization_list_command(mocker):
    """Tests organization_list_command function
    Given

    When
        - Calling `organization_list_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    mocker.patch.object(client.identity, 'list', return_value=[{'id': '1', 'name': 'test organization'}])
    results: CommandResults = organization_list_command(client, {})
    assert "Organizations from OpenCTI" in results.readable_output
    assert [{'id': '1', 'name': 'test organization'}] == results.outputs


def test_organization_create_command(mocker):
    """Tests organization_create_command function
    Given

    When
        - Calling `organization_create_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    args = {
        'name': 'Test Organization',
    }
    mocker.patch.object(client.identity, 'create', return_value={'id': '1'})
    results: CommandResults = organization_create_command(client, args)
    assert "Organization created successfully" in results.readable_output
    assert {'id': '1'} == results.outputs
