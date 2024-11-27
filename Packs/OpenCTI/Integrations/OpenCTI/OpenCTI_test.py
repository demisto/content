import pytest

from OpenCTI import *
from test_data.data import RESPONSE_DATA_OBSERVABLES, RESPONSE_DATA_INDICATORS, RESPONSE_DATA_WITHOUT_OBSERVABLES
from CommonServerPython import CommandResults
from pycti import StixCyberObservable, MarkingDefinition, Label, ExternalReference, Indicator, Incident, StixDomainObject, StixCoreRelationship


class Client:
    temp = ''
    incident = Incident
    indicator = Indicator
    stix_domain_object = StixDomainObject
    stix_cyber_observable = StixCyberObservable
    stix_core_relationship = StixCoreRelationship
    identity = Identity
    label = Label
    marking_definition = MarkingDefinition
    external_reference = ExternalReference


def test_get_observables(mocker):
    """Tests get_observables function
    Given
        The following observable types: 'registry key', 'account' that were chosen by the user.
    When
        - `fetch_observables_command` or `get_observables_command` are calling the get_observables function
    Then
        - convert the result to observables list
        - validate the length of the observables list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    observables = get_observables(client, observable_types=['registry key', 'account'], limit=10)
    assert len(observables) == 2


@pytest.mark.parametrize(
    'response_mock, value, expected_length, expected_value', [
        ([{"created_at": "2022-10-24T18:16:52.678Z", "entity_type": "IPv4-Addr", "id": "id", "observable_value": "8.8.8.8",
           "spec_version": "2.1", "standard_id": "standard_id", "updated_at": "2022-10-24T18:16:52.678Z", "value": "8.8.8.8",
           "x_opencti_score": 50}], "8.8.8.8", 1, "8.8.8.8")])
def test_get_observables_value_argument(mocker, response_mock, value, expected_length, expected_value):
    """Tests get_observables function
    Given
        A value to filter by
    When
        - calling get_observables
    Then
        - Ensure that only the result with the same given value is returned.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=response_mock)
    observables = get_observables(client, ["ALL"], search=value)
    assert len(observables) == expected_length
    assert observables[0].get('value') == expected_value


def test_get_observables_command(mocker):
    """Tests get_observables_command function
    Given
        The following observable types: 'registry key', 'account' that were chosen by the user and 'limit': 2
    When
        - Calling `get_observables_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'observable_types': 'registry key,account',
        'limit': 2
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    results: CommandResults = get_observables_command(client, args)
    assert len(results.raw_response) == 2
    assert "Observables" in results.readable_output


def test_get_observables_command_no_parameters(mocker):
    """Test get_observables_command function where there is no parameters to filter by
    Given
        No parameters to filter by
    When
        Calling the `get_observables_command`
    Then
        Return all observables
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    all_observables = get_observables_command(client, args={'observable_types': 'ALL'})
    default_observables = get_observables_command(client, {})
    assert len(all_observables.raw_response) == len(default_observables.raw_response)


def test_get_observables_command_with_just_score_end(mocker):
    """Test get_observables_command function where there is just score_end parameter
    Given
        Filter score_end = 50
    When
        Calling the `get_observables_command`
    Then
        Return all observables with score = 0 until score = 50
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    observables_with_end = get_observables_command(client, args={'score_end': 50})
    observables_with_end_start = get_observables_command(client, args={'score_end': 50, 'score_start': 0})
    assert len(observables_with_end.raw_response) == len(observables_with_end_start.raw_response)


def test_get_observables_command_with_just_score_start(mocker):
    """Test get_observables_command function where there is just score_end parameter
    Given
        Filter score_start = 50
    When
        Calling the `get_observables_command`
    Then
        Return all observables with score = 50 until score = 100
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    observables_with_end = get_observables_command(client, args={'score_start': 50})
    observables_with_end_start = get_observables_command(client, args={'score_start': 50, 'score_end': 100})
    assert len(observables_with_end.raw_response) == len(observables_with_end_start.raw_response)


def test_get_observables_command_with_score(mocker):
    """Tests get_observables_command function with a specified score
    Given
        The following observable types: 'registry key', 'account' that were chosen by the user and a specified 'score': 50
    When
        - Calling `get_observables_command`
    Then
        - Verify that the result includes observables with a score of 50.
    """
    client = Client
    args = {
        'observable_types': 'registry key,account',
        'score': '50'
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_OBSERVABLES)
    results: CommandResults = get_observables_command(client, args)
    assert len(results.raw_response) == 2
    for observable in results.raw_response:
        assert observable.get('x_opencti_score') == 50


def test_get_observables_command_with_no_data_to_return(mocker):
    """Tests get_observables_command function with no data to return
    Given
        The following observable types: 'registry key', 'account' that were chosen by the user.
    When
        - Calling `get_observables_command`
    Then
        - validate the response to have a "No observables" string
    """
    client = Client
    args = {
        'observable_types': ['registry key', 'account']
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_WITHOUT_OBSERVABLES)
    results: CommandResults = get_observables_command(client, args)
    assert "No observables" in results.readable_output


def test_observable_delete_command(mocker):
    """Tests observable_delete_command function
    Given
        id of observable to delete
    When
        - Calling `observable_delete_command`
    Then
        - validate the response to have a "Observable deleted." string
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_cyber_observable, 'delete', return_value="Observable deleted")
    results: CommandResults = observable_delete_command(client, args)
    assert "Observable deleted" in results.readable_output


@pytest.mark.parametrize(argnames="field, value",
                         argvalues=[('score', '50'),
                                    ('description', 'new description')])
def test_observable_field_update_command(mocker, field, value):
    """Tests observable_field_update_command function
    Given
        id of observable to update
        field to update
        value to update
    When
        - Calling `observable_field_update_command`
    Then
        - validate the response to have a "Observable deleted." string and context as expected
    """
    client = Client
    args = {
        'id': '123456',
        'field': field,
        'value': value
    }
    mocker.patch.object(client.stix_cyber_observable, 'update_field', return_value={'id': '123456'})
    results: CommandResults = observable_field_update_command(client, args)
    assert "updated successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


def test_observable_create_command(mocker):
    """Tests observable_create_command function
    Given
        type of observable to create
        score to create
        data to create
    When
        - Calling `observable_create_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    args = {
        'score': '20',
        'type': 'Domain',
        'value': 'devtest.com'
    }
    mocker.patch.object(client.stix_cyber_observable, 'create', return_value={'id': '123456'})
    results: CommandResults = observable_create_command(client, args)
    assert "Observable created successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'add_marking_definition'),
                                    ('label', 'new-label', 'add_label')])
def test_observable_field_add_command(mocker, field, value, function_name):
    """Tests observable_field_add_command function
        Given
            id of observable to add
            field to add
            value to add
        When
            - Calling `observable_field_add_command`
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

    results: CommandResults = observable_field_add_command(client, args)
    assert "successfully" in results.readable_output


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'remove_marking_definition'),
                                    ('label', 'new-label', 'remove_label')])
def test_observable_field_remove_command(mocker, field, value, function_name):
    """Tests observable_field_remove_command function
    Given
        id of observable to remove
        field to remove
        value to remove
    When
        - Calling `observable_field_remove_command`
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

    results: CommandResults = observable_field_remove_command(client, args)
    assert "successfully" in results.readable_output


def test_organization_list_command(mocker):
    """Tests organization_list_command function
    Given

    When
        - Calling `organization_list_command`
    Then
        - validate the readable_output, context
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
        - validate the readable_output, context
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
        - validate the readable_output, context
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
        - validate the readable_output, context
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
        - validate the readable_output, context
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
        - validate the readable_output, context
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


def test_incident_create_command(mocker):
    """Tests incident_create_command function
    Given
        type of incident to create
        name of incident to create
        confidence of incident to create
        description of incident to create
    When
        - Calling `incident_create_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    args = {
        'incident_type': 'Lorem',
        'name': 'Lorem ipsum dolor',
        'confidence': '100',
        'description': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    }
    mocker.patch.object(client.incident, 'create', return_value={'id': '123456', 'name': 'Lorem ipsum dolor'})
    results: CommandResults = incident_create_command(client, args)
    assert "Incident created successfully" in results.readable_output
    assert {'id': '123456', 'name': 'Lorem ipsum dolor'} == results.outputs


def test_incident_create_command_exception(mocker):
    """Tests incident_create_command function
    Given
        type of incident to create
        name of incident to create
        confidence of incident to create
        description of incident to create
    When
        - Calling `incident_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'incident_type': 'Lorem',
        'name': 'Lorem ipsum dolor',
        'confidence': '100',
        'description': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    }
    mocker.patch.object(client.incident, 'create', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't create incident."):
        incident_create_command(client, args)


def test_incident_create_command_exception_id_not_returned(mocker):
    """Tests incident_create_command function
    Given
        type of incident to create
        name of incident to create
        confidence of incident to create
        description of incident to create
    When
        - Calling `incident_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'incident_type': 'Lorem',
        'name': 'Lorem ipsum dolor',
        'confidence': '100',
        'description': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    }
    mocker.patch.object(client.incident, 'create', return_value={})
    with pytest.raises(DemistoException, match="Can't create incident."):
        incident_create_command(client, args)


def test_incident_delete_command(mocker):
    """Tests incident_delete_command function
    Given
        id of incident to delete
    When
        - Calling `incident_delete_command`
    Then
        - validate the response to have a "Incident deleted." string
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_domain_object, 'delete', return_value="Incident deleted")
    results: CommandResults = incident_delete_command(client, args)
    assert "Incident deleted" in results.readable_output


def test_incident_delete_command_exception(mocker):
    """Tests incident_delete_command function
    Given
        id of incident to delete
    When
        - Calling `incident_delete_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_domain_object, 'delete', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't delete incident."):
        incident_delete_command(client, args)


def test_incident_types_list_command(mocker):
    """Tests incident_types_list_command function
    Given

    When
        - Calling `incident_types_list_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    mocker.patch.object(client, 'query',
                        return_value={
                            'data': {
                                'vocabularies': {
                                    'edges': [
                                        {'node': {'id': '1', 'name': 'Phishing', 'description': 'Phishing incident type'}},
                                    ]
                                }
                            }
                        })
    results: CommandResults = incident_types_list_command(client, {})
    assert "Incident Types" in results.readable_output
    assert [{'id': '1', 'name': 'Phishing', 'description': 'Phishing incident type'}] == \
        results.outputs.get('OpenCTI.IncidentTypes.IncidentTypesList(val.id === obj.id)')


def test_incident_types_list_command_with_no_data_to_return(mocker):
    """Tests incident_types_list_command function
    Given

    When
        - Calling `incident_types_list_command`
    Then
        - validate the response to have a "No observables" string
    """
    client = Client
    mocker.patch.object(client, 'query',
                        return_value={
                            'data': {
                                'vocabularies': {
                                    'edges': []
                                }
                            }
                        })
    results: CommandResults = incident_types_list_command(client, {})
    assert "No incident types" in results.readable_output


def test_incident_types_list_command_exception(mocker):
    """Tests incident_types_list_command function
    Given

    When
        - Calling `incident_types_list_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(client, 'query', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't list incident types."):
        incident_types_list_command(client, {})


def test_relationship_create_command(mocker):
    """Tests relationship_create_command function
    Given
        from_id entity
        to_id entity
        relationship_type
    When
        - Calling `relationship_create_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    args = {
        'from_id': '123456',
        'to_id': '123457',
        'relationship_type': 'related-to'
    }
    mocker.patch.object(client.stix_core_relationship, 'create', return_value=mocker.patch.object(
        client.incident, 'create', return_value={'id': '123456'}))
    results: CommandResults = relationship_create_command(client, args)
    assert "Relationship created successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


def test_relationship_create_command_with_no_data_to_return(mocker):
    """Tests relationship_create_command function
    Given
        from_id entity
        to_id entity
        relationship_type
    When
        - Calling `relationship_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'from_id': '123456',
        'to_id': '123457',
        'relationship_type': 'related-to'
    }
    mocker.patch.object(client.stix_core_relationship, 'create',
                        return_value=mocker.patch.object(client.incident, 'create', return_value={}))
    with pytest.raises(DemistoException, match="Can't create relationship."):
        relationship_create_command(client, args)


def test_relationship_create_command_exception(mocker):
    """Tests relationship_create_command function
    Given
        from_id entity
        to_id entity
        relationship_type
    When
        - Calling `relationship_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'from_id': '123456',
        'to_id': '123457',
        'relationship_type': 'related-to'
    }
    mocker.patch.object(client.stix_core_relationship, 'create', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't create relationship."):
        relationship_create_command(client, args)


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
    mocker.patch.object(client.indicator, 'list', return_value=RESPONSE_DATA_INDICATORS)
    indicators = get_indicators(client, indicator_types=['indicator_type_1', 'indicator_type_2'], limit=10)
    assert len(indicators) == 2

    """
    FILL more
    """
