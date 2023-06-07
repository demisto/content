import pytest

from OpenCTI import *
from test_data.data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS
from CommonServerPython import CommandResults
from pycti import StixCyberObservable, MarkingDefinition, Label, ExternalReference


class Client:
    temp = ''
    stix_cyber_observable = StixCyberObservable
    identity = Identity
    label = Label
    marking_definition = MarkingDefinition
    external_reference = ExternalReference


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
    indicators = get_indicators(client, indicator_types=['registry key', 'account'], limit=10)
    assert len(indicators) == 2


@pytest.mark.parametrize(
    'response_mock, value, expected_length, expected_value', [
        ([{"created_at": "2022-10-24T18:16:52.678Z", "entity_type": "IPv4-Addr", "id": "id", "observable_value": "8.8.8.8",
           "spec_version": "2.1", "standard_id": "standard_id", "updated_at": "2022-10-24T18:16:52.678Z", "value": "8.8.8.8",
           "x_opencti_score": 50}], "8.8.8.8", 1, "8.8.8.8")])
def test_get_indicators_value_argument(mocker, response_mock, value, expected_length, expected_value):
    """Tests get_indicators function
    Given
        A value to filter by
    When
        - calling get_indicators
    Then
        - Ensure that only the result with the same given value is returned.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=response_mock)
    indicators = get_indicators(client, ["ALL"], search=value)
    assert len(indicators) == expected_length
    indicators[0].get('value') == expected_value


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
    assert "Indicators" in results.readable_output


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
    assert "updated successfully" in results.readable_output
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
        'value': 'devtest.com'
    }
    mocker.patch.object(client.stix_cyber_observable, 'create', return_value={'id': '123456'})
    results: CommandResults = indicator_create_command(client, args)
    assert "Indicator created successfully" in results.readable_output
    assert 'id' in results.outputs


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'add_marking_definition'),
                                    ('label', 'new-label', 'add_label')])
def test_indicator_field_add_command(mocker, field, value, function_name):
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
    mocker.patch.object(client.label, 'create', return_value={'id': '123456'})
    mocker.patch.object(client.marking_definition, 'create', return_value={'id': '123456'})
    mocker.patch.object(client.stix_cyber_observable, function_name, return_value=True)

    results: CommandResults = indicator_field_add_command(client, args)
    assert "successfully" in results.readable_output


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'remove_marking_definition'),
                                    ('label', 'new-label', 'remove_label')])
def test_indicator_field_remove_command(mocker, field, value, function_name):
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

    mocker.patch.object(client.label, 'create', return_value={'id': '123456'})
    mocker.patch.object(client.marking_definition, 'create', return_value={'id': '123456'})
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
    mocker.patch.object(client.identity, 'list',
                        return_value={
                            'entities': [{'id': '1', 'name': 'test organization'}],
                            'pagination': {'endCursor': 'XYZ123'}
                        })
    results: CommandResults = organization_list_command(client, {})
    assert "Organizations" in results.readable_output
    assert [{'id': '1', 'name': 'test organization'}] == \
        results.outputs.get('OpenCTI.Organizations.OrganizationsList(val.id === obj.id)')


def test_organization_create_command(mocker):
    """Tests organization_create_command function
    Given
        - name: organization name to create
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
    assert "was created successfully" in results.readable_output
    assert {'id': '1'} == results.outputs


def test_label_list_command(mocker):
    """Tests label_list_command function
    Given

    When
        - Calling `label_list_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    mocker.patch.object(client.label, 'list',
                        return_value={
                            'entities': [{'id': '1', 'value': 'test-label'}],
                            'pagination': {'endCursor': 'XYZ123'}
                        })
    results: CommandResults = label_list_command(client, {})
    assert "Labels" in results.readable_output
    assert [{'id': '1', 'value': 'test-label'}] == results.outputs.get('OpenCTI.Labels.LabelsList(val.id === obj.id)')


def test_label_create_command(mocker):
    """Tests label_create_command function
    Given
        - name: label name to create
    When
        - Calling `label_create_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    args = {
        'name': 'test-label-1',
    }
    mocker.patch.object(client.label, 'create', return_value={'id': '1'})
    results: CommandResults = label_create_command(client, args)
    assert "was created successfully" in results.readable_output
    assert {'id': '1'} == results.outputs


def test_external_reference_create_command(mocker):
    """Tests external_reference_create_command function
    Given
        - source_name: name of external reference source
        - url: url of external reference
    When
        - Calling `external_reference_create_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    args = {
        'source_name': 'test-label-1',
        'url': 'testurl.com'
    }
    mocker.patch.object(client.external_reference, 'create', return_value={'id': '1'})
    results: CommandResults = external_reference_create_command(client, args)
    assert "was created successfully" in results.readable_output
    assert {'id': '1'} == results.outputs


def test_marking_list_command(mocker):
    """Tests marking_list_command function
    Given

    When
        - Calling `marking_list_command`
    Then
        - validate the readable_output ,context
    """
    client = Client
    mocker.patch.object(client.marking_definition, 'list',
                        return_value={
                            'entities': [{'id': '1', 'definition': 'TLP:RED'}],
                            'pagination': {'endCursor': 'XYZ123'}
                        })
    results: CommandResults = marking_list_command(client, {})
    assert "Markings" in results.readable_output
    assert [{'id': '1', 'value': 'TLP:RED'}] \
        == results.outputs.get('OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)')
