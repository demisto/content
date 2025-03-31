import pytest

from OpenCTI import *
from test_data.data import (
    RESPONSE_DATA_OBSERVABLES,
    RESPONSE_DATA_INDICATORS,
    RESPONSE_DATA_INCIDENTS,
    RESPONSE_DATA_EMPTY,
)
from CommonServerPython import CommandResults
from pycti import (
    StixCyberObservable,
    MarkingDefinition,
    Label,
    ExternalReference,
    Indicator,
    Incident,
    StixDomainObject,
    StixCoreRelationship,
)


class Client:
    temp = ''
    query = None
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
        The following observable types: 'registry key', 'account' that were chosen by the user and other additional_filters
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
    observables = get_observables(
        client,
        observable_types=['registry key', 'account'],
        limit=10,
        additional_filters=[{'key': 'score', 'values': ['0', '50'], 'operator': 'AND'}]
    )
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
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA_EMPTY)
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
    assert results.outputs == {'id': '123456'}


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
    mocker.patch.object(client.stix_cyber_observable, 'create', return_value={
                        'id': '123456', 'value': 'devtest.com', 'type': 'Domain'})
    results: CommandResults = observable_create_command(client, args)
    assert "Observable created successfully" in results.readable_output
    assert results.outputs == {'id': '123456', 'value': 'devtest.com', 'type': 'Domain'}


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
    assert results.outputs.get('OpenCTI.Organizations.OrganizationsList(val.id === obj.id)') == \
        [{'id': '1', 'name': 'test organization'}]


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
    assert results.outputs == {'id': '1'}


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
    assert results.outputs.get('OpenCTI.Labels.LabelsList(val.id === obj.id)') == [{'id': '1', 'value': 'test-label'}]


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
    assert results.outputs == {'id': '1'}


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
    assert results.outputs == {'id': '1'}


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
    assert results.outputs.get('OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)') \
        == [{'id': '1', 'value': 'TLP:RED'}]


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
    mocker.patch.object(client.incident, 'create', return_value={'id': '123456'})
    results: CommandResults = incident_create_command(client, args)
    assert "Incident created successfully" in results.readable_output
    assert results.outputs == {'id': '123456'}


def test_incident_create_command_exception(mocker, capfd):
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
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_incident_create_command_exception_data_not_returned(mocker):
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


def test_incident_delete_command_exception(mocker, capfd):
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
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_get_incidents(mocker):
    """Tests get_incidents function
    Given
        The following incident types: 'registry key', 'account' that were chosen by the user.
    When
        - `get_incidents_command` is calling the get_incidents function
    Then
        - convert the result to incidents list
        - validate the length of the incidents list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.incident, 'list', return_value=RESPONSE_DATA_INCIDENTS)
    incidents = get_incidents(
        client,
        incident_types=['incident_type_1', 'incident_type_2'],
        limit=10,
        additional_filters=[{'key': 'score', 'values': ['0', '50'], 'operator': 'AND'}]
    )
    assert len(incidents) == 2


def test_get_incidents_exception(mocker, capfd):
    """Tests get_incidents function
    Given
        The following incident types: 'registry key', 'account' that were chosen by the user.
    When
        - `get_incidents_command` is calling the get_incidents function
    Then
         Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(client.incident, 'list', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Failed to retrieve incidents."):
        get_incidents(client, incident_types=['incident_type_1', 'incident_type_2'], limit=10)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_get_incidents_command(mocker):
    """Tests get_incidents_command function
    Given
        The following incident types: 'compromised' that were chosen by the user and 'limit': 2
    When
        - Calling `get_incidents_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'incident_types': 'compromised',
        'limit': 2
    }
    mocker.patch.object(client.incident, 'list', return_value=RESPONSE_DATA_INCIDENTS)
    results: CommandResults = get_incidents_command(client, args)
    assert len(results.raw_response) == 2
    assert "Incidents" in results.readable_output
    assert RESPONSE_DATA_INCIDENTS.get('pagination', {}).get('endCursor') == \
        results.outputs.get('OpenCTI.Incidents(val.lastRunID)').get('lastRunID')


def test_get_incidents_command_with_no_data_to_return(mocker):
    """Tests get_incidents_command function with no data to return
    Given
        The following incident types: 'compromised' that were chosen by the user.
    When
        - Calling `get_incidents_command`
    Then
        - validate the response to have a "No incidents" string
    """
    client = Client
    args = {
        'incident_types': 'compromised'
    }
    mocker.patch.object(client.incident, 'list', return_value=RESPONSE_DATA_EMPTY)
    results: CommandResults = get_incidents_command(client, args)
    assert "No incidents" in results.readable_output


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
    assert results.outputs.get('OpenCTI.IncidentTypes.IncidentTypesList(val.id === obj.id)') == \
        [{'id': '1', 'name': 'Phishing', 'description': 'Phishing incident type'}]


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


def test_incident_types_list_command_exception(mocker, capfd):
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
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


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
    mocker.patch.object(client.stix_core_relationship, 'create', return_value={'id': '123456', 'relationship_type': 'related-to'})
    results: CommandResults = relationship_create_command(client, args)
    assert "Relationship created successfully" in results.readable_output
    assert results.outputs == {'id': '123456', 'relationshipType': 'related-to'}


def test_relationship_delete_command(mocker):
    """Tests relationship_delete_command function
    Given
        id of relationship to delete
    When
        - Calling `relationship_delete_command`
    Then
        - validate the response to have a "Relationship deleted." string
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_core_relationship, 'delete', return_value="Relationship deleted")
    results: CommandResults = relationship_delete_command(client, args)
    assert "Relationship deleted" in results.readable_output


def test_relationship_delete_command_exception(mocker, capfd):
    """Tests relationship_delete_command function
    Given
        id of relationship to delete
    When
        - Calling `relationship_delete_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'id': '123456'
    }
    mocker.patch.object(client.stix_core_relationship, 'delete', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't delete relationship."):
        relationship_delete_command(client, args)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_relationship_list_command(mocker):
    """Tests relationship_list_command function
    Given

    When
        - Calling `relationship_list_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    mocker.patch.object(client.stix_core_relationship, 'list',
                        return_value={
                            'entities': [{
                                'id': '4acaed3c-5683-4caa-b87d-28ba32c72056',
                                'relationship_type': 'related-to',
                                'from': {
                                    'id': '17282d6a-2da1-491a-b1ad-13b29bead0c8'
                                },
                                'to': {
                                    'id': 'a4ff07c2-3ea8-42fc-b227-947e74a3a551',
                                    'entity_type': 'IPv4-Addr'
                                },
                            }],
                            'pagination': {'endCursor': 'XYZ123'}
                        })
    results: CommandResults = relationship_list_command(client, {'from_id': '17282d6a-2da1-491a-b1ad-13b29bead0c8'})
    assert "Relationships" in results.readable_output
    assert results.outputs.get('OpenCTI.Relationships.RelationshipsList(val.id === obj.id)') == \
        [{'id': '4acaed3c-5683-4caa-b87d-28ba32c72056', 'relationshipType': 'related-to',
          'fromId': '17282d6a-2da1-491a-b1ad-13b29bead0c8', 'toId': 'a4ff07c2-3ea8-42fc-b227-947e74a3a551',
          'toEntityType': 'IPv4-Addr'}]


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
    mocker.patch.object(client.stix_core_relationship, 'create', return_value={})
    with pytest.raises(DemistoException, match="Can't create relationship."):
        relationship_create_command(client, args)


def test_relationship_create_command_exception(mocker, capfd):
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
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_indicator_create_command(mocker):
    """Tests indicator_create_command function
    Given
        name of indicator to create
        indicator value to create
        main_observable_type of indicator to create
    When
        - Calling `indicator_create_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    args = {
        'name': 'Lorem ipsum dolor',
        'indicator': '192.168.1.1',
        'main_observable_type': 'ip'
    }
    mocker.patch.object(client.indicator, 'create', return_value={'id': '123456'})
    results: CommandResults = indicator_create_command(client, args)
    assert "Indicator created successfully" in results.readable_output
    assert results.outputs == {'id': '123456'}


def test_indicator_create_command_exception(mocker, capfd):
    """Tests indicator_create_command function
    Given
        name of indicator to create
        indicator value to create
        main_observable_type of indicator to create
    When
        - Calling `indicator_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'name': 'Lorem ipsum dolor',
        'indicator': '192.168.1.1',
        'main_observable_type': 'ip'
    }
    mocker.patch.object(client.indicator, 'create', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't create indicator."):
        indicator_create_command(client, args)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_indicator_create_command_exception_data_not_returned(mocker):
    """Tests indicator_create_command function
    Given
        name of indicator to create
        indicator value to create
        main_observable_type of indicator to create
    When
        - Calling `indicator_create_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'name': 'Lorem ipsum dolor',
        'indicator': '192.168.1.1',
        'main_observable_type': 'ip'
    }
    mocker.patch.object(client.indicator, 'create', return_value={})
    with pytest.raises(DemistoException, match="Can't create indicator."):
        indicator_create_command(client, args)


def test_indicator_update_command(mocker):
    """Tests indicator_update_command function
    Given
        id of indicator to update
        description to update
        valid_until to update
    When
        - Calling `indicator_update_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    args = {
        'id': '123456',
        'description': 'Lorem ipsum dolor',
        'valid_until': '2023-12-31T23:59:59.000Z'
    }
    mocker.patch.object(client, 'query', return_value={
        'data': {
            'indicatorFieldPatch': {
                'id': '123456',
                'name': 'Lorem ipsum dolor',
                'valid_from': '2023-01-01T00:00:00.000Z',
                'valid_until': '2023-12-31T23:59:59.000Z'
            }
        }
    })
    results: CommandResults = indicator_update_command(client, args)
    assert "Indicator updated successfully" in results.readable_output
    assert results.outputs == {'id': '123456', 'name': 'Lorem ipsum dolor', 'validFrom': '2023-01-01T00:00:00.000Z',
                               'validUntil': '2023-12-31T23:59:59.000Z'}


def test_indicator_update_command_exception(mocker, capfd):
    """Tests indicator_update_command function
    Given
        id of indicator to update
        description to update
        valid_until to update
    When
        - Calling `indicator_update_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'id': '123456',
        'description': 'Lorem ipsum dolor',
        'valid_until': '2023-12-31T23:59:59.000Z'
    }
    mocker.patch.object(client, 'query', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't update indicator."):
        indicator_update_command(client, args)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_indicator_update_command_exception_data_not_returned(mocker):
    """Tests indicator_update_command function
    Given
        id of indicator to update
        description to update
        valid_until to update
    When
        - Calling `indicator_update_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    args = {
        'id': '123456',
        'description': 'Lorem ipsum dolor',
        'valid_until': '2023-12-31T23:59:59.000Z'
    }
    mocker.patch.object(client, 'query', return_value={'data': {'indicatorFieldPatch': {}}})
    with pytest.raises(DemistoException, match="Can't update indicator."):
        indicator_update_command(client, args)


@pytest.mark.parametrize(argnames="field, value, function_name,",
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
    mocker.patch.object(client.stix_domain_object, function_name, return_value=True)
    results: CommandResults = indicator_field_add_command(client, args)
    assert f'Added {field} successfully.' in results.readable_output


@pytest.mark.parametrize(argnames="field, value, function_name,",
                         argvalues=[('marking', 'TLP:RED', 'add_marking_definition'),
                                    ('label', 'new-label', 'add_label')])
def test_indicator_field_add_command_field_not_added(mocker, field, value, function_name):
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
    mocker.patch.object(client.stix_domain_object, function_name, return_value=False)
    with pytest.raises(DemistoException, match=f"Can't add {field}."):
        indicator_field_add_command(client, args)


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
    mocker.patch.object(client.stix_domain_object, function_name, return_value=True)
    results: CommandResults = indicator_field_remove_command(client, args)
    assert f'{field}: {value} was removed successfully from indicator: 123456.' in results.readable_output


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'remove_marking_definition'),
                                    ('label', 'new-label', 'remove_label')])
def test_indicator_field_remove_command_field_not_removed(mocker, field, value, function_name):
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
    mocker.patch.object(client.stix_domain_object, function_name, return_value=False)
    with pytest.raises(DemistoException, match=f"Can't remove {field}."):
        indicator_field_remove_command(client, args)


@pytest.mark.parametrize(argnames="field, value, function_name",
                         argvalues=[('marking', 'TLP:RED', 'remove_marking_definition'),
                                    ('label', 'new-label', 'remove_label')])
def test_indicator_field_remove_command_exception(mocker, capfd, field, value, function_name):
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
    mocker.patch.object(client.stix_domain_object, function_name, side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match=f"Can't remove {field} from indicator."):
        indicator_field_remove_command(client, args)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - `get_indicators_command` is calling the get_indicators function
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
        - validate the new_last_id that is saved into the integration context is the same as the ID returned by the
            command.
    """
    client = Client
    mocker.patch.object(client.indicator, 'list', return_value=RESPONSE_DATA_INDICATORS)
    indicators = get_indicators(
        client,
        indicator_types=['indicator_type_1', 'indicator_type_2'],
        limit=10,
        additional_filters=[{'key': 'score', 'values': ['0', '50'], 'operator': 'AND'}]
    )
    assert len(indicators) == 2


def test_get_indicators_exception(mocker, capfd):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry key', 'account' that were chosen by the user.
    When
        - `get_indicators_command` is calling the get_indicators function
    Then
         Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(client.indicator, 'list', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Failed to retrieve indicators."):
        get_indicators(client, indicator_types=['indicator_type_1', 'indicator_type_2'], limit=10)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        The following indicator types: 'compromised' that were chosen by the user and 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'indicator_types': 'compromised',
        'limit': 2
    }
    mocker.patch.object(client.indicator, 'list', return_value=RESPONSE_DATA_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators" in results.readable_output
    assert RESPONSE_DATA_INDICATORS.get('pagination', {}).get('endCursor') == \
        results.outputs.get('OpenCTI.Indicators(val.lastRunID)').get('lastRunID')


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        The following indicator types: 'compromised' that were chosen by the user.
    When
        - Calling `get_indicators_command`
    Then
        - validate the response to have a "No indicators" string
    """
    client = Client
    args = {
        'indicator_types': 'compromised'
    }
    mocker.patch.object(client.indicator, 'list', return_value=RESPONSE_DATA_EMPTY)
    results: CommandResults = get_indicators_command(client, args)
    assert "No indicators" in results.readable_output


def test_indicator_types_list_command(mocker):
    """Tests indicator_types_list_command function
    Given

    When
        - Calling `indicator_types_list_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    mocker.patch.object(client, 'query',
                        return_value={
                            'data': {
                                'vocabularies': {
                                    'edges': [
                                        {'node': {'id': '1', 'name': 'compromised', 'description': 'compromised'}},
                                    ]
                                }
                            }
                        })
    results: CommandResults = indicator_types_list_command(client, {})
    assert "Indicator Types" in results.readable_output
    assert results.outputs.get('OpenCTI.IndicatorTypes.IndicatorTypesList(val.id === obj.id)') == \
        [{'id': '1', 'name': 'compromised', 'description': 'compromised'}]


def test_indicator_types_list_command_with_no_data_to_return(mocker):
    """Tests indicator_types_list_command function
    Given

    When
        - Calling `indicator_types_list_command`
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
    results: CommandResults = indicator_types_list_command(client, {})
    assert "No indicator types" in results.readable_output


def test_indicator_types_list_command_exception(mocker, capfd):
    """Tests indicator_types_list_command function
    Given

    When
        - Calling `indicator_types_list_command`
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(client, 'query', side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't list indicator types."):
        indicator_types_list_command(client, {})
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"
