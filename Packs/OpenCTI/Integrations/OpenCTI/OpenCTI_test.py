import pytest
from CommonServerPython import CommandResults
from OpenCTI import *
from pycti import (
    Campaign,
    CaseIncident,
    CaseRfi,
    CaseRft,
    ExternalReference,
    Grouping,
    Incident,
    Indicator,
    IntrusionSet,
    Label,
    Malware,
    MarkingDefinition,
    Report,
    StixCoreRelationship,
    StixCyberObservable,
    StixDomainObject,
    ThreatActorGroup,
    Vulnerability,
)
from test_data.data import (
    RESPONSE_DATA_EMPTY,
    RESPONSE_DATA_INCIDENTS,
    RESPONSE_DATA_INDICATORS,
    RESPONSE_DATA_OBSERVABLES,
)


class Client:
    temp = ""
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
    case_incident = CaseIncident
    case_rfi = CaseRfi
    case_rft = CaseRft
    malware = Malware
    vulnerability = Vulnerability
    intrusion_set = IntrusionSet
    threat_actor_group = ThreatActorGroup
    campaign = Campaign
    grouping = Grouping
    report = Report


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
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
    observables = get_observables(
        client,
        observable_types=["registry key", "account"],
        limit=10,
        additional_filters=[{"key": "score", "values": ["0", "50"], "operator": "AND"}],
    )
    assert len(observables) == 2


@pytest.mark.parametrize(
    "response_mock, value, expected_length, expected_value",
    [
        (
            [
                {
                    "created_at": "2022-10-24T18:16:52.678Z",
                    "entity_type": "IPv4-Addr",
                    "id": "id",
                    "observable_value": "8.8.8.8",
                    "spec_version": "2.1",
                    "standard_id": "standard_id",
                    "updated_at": "2022-10-24T18:16:52.678Z",
                    "value": "8.8.8.8",
                    "x_opencti_score": 50,
                }
            ],
            "8.8.8.8",
            1,
            "8.8.8.8",
        )
    ],
)
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
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=response_mock)
    observables = get_observables(client, ["ALL"], search=value)
    assert len(observables) == expected_length
    assert observables[0].get("value") == expected_value


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
    args = {"observable_types": "registry key,account", "limit": 2}
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
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
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
    all_observables = get_observables_command(client, args={"observable_types": "ALL"})
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
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
    observables_with_end = get_observables_command(client, args={"score_end": 50})
    observables_with_end_start = get_observables_command(client, args={"score_end": 50, "score_start": 0})
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
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
    observables_with_end = get_observables_command(client, args={"score_start": 50})
    observables_with_end_start = get_observables_command(client, args={"score_start": 50, "score_end": 100})
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
    args = {"observable_types": "registry key,account", "score": "50"}
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_OBSERVABLES)
    results: CommandResults = get_observables_command(client, args)
    assert len(results.raw_response) == 2
    for observable in results.raw_response:
        assert observable.get("x_opencti_score") == 50


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
    args = {"observable_types": ["registry key", "account"]}
    mocker.patch.object(client.stix_cyber_observable, "list", return_value=RESPONSE_DATA_EMPTY)
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
    args = {"id": "123456"}
    mocker.patch.object(client.stix_cyber_observable, "delete", return_value="Observable deleted")
    results: CommandResults = observable_delete_command(client, args)
    assert "Observable deleted" in results.readable_output


@pytest.mark.parametrize(
    argnames="field, value, expected_input",
    argvalues=[
        ("score", "50", [{"key": "x_opencti_score", "value": 50}]),
        ("description", "new description", [{"key": "x_opencti_description", "value": "new description"}]),
    ],
)
def test_observable_field_update_command(mocker, field, value, expected_input):
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
    args = {"id": "123456", "field": field, "value": value}
    update_mock = mocker.patch.object(client.stix_cyber_observable, "update_field", return_value={"id": "123456"})
    results: CommandResults = observable_field_update_command(client, args)
    update_mock.assert_called_once_with(id="123456", input=expected_input)
    assert "updated successfully" in results.readable_output
    assert results.outputs == {"id": "123456"}


def test_observable_field_update_command_data_not_returned(mocker):
    """Tests observable_field_update_command function
    Given
        id of observable to update, field and value
    When
        - Calling `observable_field_update_command` and pycti returns None (invalid input)
    Then
        - Ensure a DemistoException is raised instead of an AttributeError.
    """
    client = Client
    args = {"id": "123456", "field": "score", "value": "50"}
    mocker.patch.object(client.stix_cyber_observable, "update_field", return_value=None)
    with pytest.raises(DemistoException, match="Can't update observable."):
        observable_field_update_command(client, args)


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
    args = {"score": "20", "type": "Domain", "value": "devtest.com"}
    mocker.patch.object(
        client.stix_cyber_observable, "create", return_value={"id": "123456", "value": "devtest.com", "type": "Domain"}
    )
    results: CommandResults = observable_create_command(client, args)
    assert "Observable created successfully" in results.readable_output
    assert results.outputs == {"id": "123456", "value": "devtest.com", "type": "Domain"}


@pytest.mark.parametrize(
    argnames="field, value, function_name",
    argvalues=[("marking", "TLP:RED", "add_marking_definition"), ("label", "new-label", "add_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
    mocker.patch.object(client.label, "create", return_value={"id": "123456"})
    mocker.patch.object(client.marking_definition, "create", return_value={"id": "123456"})
    mocker.patch.object(client.stix_cyber_observable, function_name, return_value=True)

    results: CommandResults = observable_field_add_command(client, args)
    assert "successfully" in results.readable_output


@pytest.mark.parametrize(
    argnames="field, value, function_name",
    argvalues=[("marking", "TLP:RED", "remove_marking_definition"), ("label", "new-label", "remove_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}

    mocker.patch.object(client.label, "create", return_value={"id": "123456"})
    mocker.patch.object(client.marking_definition, "create", return_value={"id": "123456"})
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
    mocker.patch.object(
        client.identity,
        "list",
        return_value={"entities": [{"id": "1", "name": "test organization"}], "pagination": {"endCursor": "XYZ123"}},
    )
    results: CommandResults = organization_list_command(client, {})
    assert "Organizations" in results.readable_output
    assert results.outputs.get("OpenCTI.Organizations.OrganizationsList(val.id === obj.id)") == [
        {"id": "1", "name": "test organization"}
    ]


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
        "name": "Test Organization",
    }
    mocker.patch.object(client.identity, "create", return_value={"id": "1"})
    results: CommandResults = organization_create_command(client, args)
    assert "was created successfully" in results.readable_output
    assert results.outputs == {"id": "1"}


def test_label_list_command(mocker):
    """Tests label_list_command function
    Given

    When
        - Calling `label_list_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    mocker.patch.object(
        client.label,
        "list",
        return_value={"entities": [{"id": "1", "value": "test-label"}], "pagination": {"endCursor": "XYZ123"}},
    )
    results: CommandResults = label_list_command(client, {})
    assert "Labels" in results.readable_output
    assert results.outputs.get("OpenCTI.Labels.LabelsList(val.id === obj.id)") == [{"id": "1", "value": "test-label"}]


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
        "name": "test-label-1",
    }
    mocker.patch.object(client.label, "create", return_value={"id": "1"})
    results: CommandResults = label_create_command(client, args)
    assert "was created successfully" in results.readable_output
    assert results.outputs == {"id": "1"}


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
    args = {"source_name": "test-label-1", "url": "testurl.com"}
    mocker.patch.object(client.external_reference, "create", return_value={"id": "1"})
    results: CommandResults = external_reference_create_command(client, args)
    assert "was created successfully" in results.readable_output
    assert results.outputs == {"id": "1"}


def test_marking_list_command(mocker):
    """Tests marking_list_command function
    Given

    When
        - Calling `marking_list_command`
    Then
        - validate the readable_output, context
    """
    client = Client
    mocker.patch.object(
        client.marking_definition,
        "list",
        return_value={"entities": [{"id": "1", "definition": "TLP:RED"}], "pagination": {"endCursor": "XYZ123"}},
    )
    results: CommandResults = marking_list_command(client, {})
    assert "Markings" in results.readable_output
    assert results.outputs.get("OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)") == [
        {"id": "1", "value": "TLP:RED"}
    ]


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
        "incident_type": "Lorem",
        "name": "Lorem ipsum dolor",
        "confidence": "100",
        "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    }
    mocker.patch.object(client.incident, "create", return_value={"id": "123456"})
    results: CommandResults = incident_create_command(client, args)
    assert "Incident created successfully" in results.readable_output
    assert results.outputs == {"id": "123456"}


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
        "incident_type": "Lorem",
        "name": "Lorem ipsum dolor",
        "confidence": "100",
        "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    }
    mocker.patch.object(client.incident, "create", side_effect=Exception("Test exception"))
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
        "incident_type": "Lorem",
        "name": "Lorem ipsum dolor",
        "confidence": "100",
        "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    }
    mocker.patch.object(client.incident, "create", return_value={})
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
    args = {"id": "123456"}
    mocker.patch.object(client.stix_domain_object, "delete", return_value="Incident deleted")
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
    args = {"id": "123456"}
    mocker.patch.object(client.stix_domain_object, "delete", side_effect=Exception("Test exception"))
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
    mocker.patch.object(client.incident, "list", return_value=RESPONSE_DATA_INCIDENTS)
    incidents = get_incidents(
        client,
        incident_types=["incident_type_1", "incident_type_2"],
        limit=10,
        additional_filters=[{"key": "score", "values": ["0", "50"], "operator": "AND"}],
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
    mocker.patch.object(client.incident, "list", side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Failed to retrieve incidents."):
        get_incidents(client, incident_types=["incident_type_1", "incident_type_2"], limit=10)
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
    args = {"incident_types": "compromised", "limit": 2}
    mocker.patch.object(client.incident, "list", return_value=RESPONSE_DATA_INCIDENTS)
    results: CommandResults = get_incidents_command(client, args)
    assert len(results.raw_response) == 2
    assert "Incidents" in results.readable_output
    assert RESPONSE_DATA_INCIDENTS.get("pagination", {}).get("endCursor") == results.outputs.get(
        "OpenCTI.Incidents(val.lastRunID)"
    ).get("lastRunID")


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
    args = {"incident_types": "compromised"}
    mocker.patch.object(client.incident, "list", return_value=RESPONSE_DATA_EMPTY)
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
    mocker.patch.object(
        client,
        "query",
        return_value={
            "data": {
                "vocabularies": {
                    "edges": [
                        {"node": {"id": "1", "name": "Phishing", "description": "Phishing incident type"}},
                    ]
                }
            }
        },
    )
    results: CommandResults = incident_types_list_command(client, {})
    assert "Incident Types" in results.readable_output
    assert results.outputs.get("OpenCTI.IncidentTypes.IncidentTypesList(val.id === obj.id)") == [
        {"id": "1", "name": "Phishing", "description": "Phishing incident type"}
    ]


def test_incident_types_list_command_with_no_data_to_return(mocker):
    """Tests incident_types_list_command function
    Given

    When
        - Calling `incident_types_list_command`
    Then
        - validate the response to have a "No observables" string
    """
    client = Client
    mocker.patch.object(client, "query", return_value={"data": {"vocabularies": {"edges": []}}})
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
    mocker.patch.object(client, "query", side_effect=Exception("Test exception"))
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
    args = {"from_id": "123456", "to_id": "123457", "relationship_type": "related-to"}
    mocker.patch.object(client.stix_core_relationship, "create", return_value={"id": "123456", "relationship_type": "related-to"})
    results: CommandResults = relationship_create_command(client, args)
    assert "Relationship created successfully" in results.readable_output
    assert results.outputs == {"id": "123456", "relationshipType": "related-to"}


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
    args = {"id": "123456"}
    mocker.patch.object(client.stix_core_relationship, "delete", return_value="Relationship deleted")
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
    args = {"id": "123456"}
    mocker.patch.object(client.stix_core_relationship, "delete", side_effect=Exception("Test exception"))
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
    mocker.patch.object(
        client.stix_core_relationship,
        "list",
        return_value={
            "entities": [
                {
                    "id": "4acaed3c-5683-4caa-b87d-28ba32c72056",
                    "relationship_type": "related-to",
                    "from": {"id": "17282d6a-2da1-491a-b1ad-13b29bead0c8"},
                    "to": {"id": "a4ff07c2-3ea8-42fc-b227-947e74a3a551", "entity_type": "IPv4-Addr"},
                }
            ],
            "pagination": {"endCursor": "XYZ123"},
        },
    )
    results: CommandResults = relationship_list_command(client, {"from_id": "17282d6a-2da1-491a-b1ad-13b29bead0c8"})
    assert "Relationships" in results.readable_output
    assert results.outputs.get("OpenCTI.Relationships.RelationshipsList(val.id === obj.id)") == [
        {
            "id": "4acaed3c-5683-4caa-b87d-28ba32c72056",
            "relationshipType": "related-to",
            "fromId": "17282d6a-2da1-491a-b1ad-13b29bead0c8",
            "toId": "a4ff07c2-3ea8-42fc-b227-947e74a3a551",
            "toEntityType": "IPv4-Addr",
        }
    ]


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
    args = {"from_id": "123456", "to_id": "123457", "relationship_type": "related-to"}
    mocker.patch.object(client.stix_core_relationship, "create", return_value={})
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
    args = {"from_id": "123456", "to_id": "123457", "relationship_type": "related-to"}
    mocker.patch.object(client.stix_core_relationship, "create", side_effect=Exception("Test exception"))
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
    args = {"name": "Lorem ipsum dolor", "indicator": "192.168.1.1", "main_observable_type": "ip"}
    mocker.patch.object(client.indicator, "create", return_value={"id": "123456"})
    results: CommandResults = indicator_create_command(client, args)
    assert "Indicator created successfully" in results.readable_output
    assert results.outputs == {"id": "123456"}


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
    args = {"name": "Lorem ipsum dolor", "indicator": "192.168.1.1", "main_observable_type": "ip"}
    mocker.patch.object(client.indicator, "create", side_effect=Exception("Test exception"))
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
    args = {"name": "Lorem ipsum dolor", "indicator": "192.168.1.1", "main_observable_type": "ip"}
    mocker.patch.object(client.indicator, "create", return_value={})
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
    args = {"id": "123456", "description": "Lorem ipsum dolor", "valid_until": "2023-12-31T23:59:59.000Z"}
    mocker.patch.object(
        client,
        "query",
        return_value={
            "data": {
                "indicatorFieldPatch": {
                    "id": "123456",
                    "name": "Lorem ipsum dolor",
                    "valid_from": "2023-01-01T00:00:00.000Z",
                    "valid_until": "2023-12-31T23:59:59.000Z",
                }
            }
        },
    )
    results: CommandResults = indicator_update_command(client, args)
    assert "Indicator updated successfully" in results.readable_output
    assert results.outputs == {
        "id": "123456",
        "name": "Lorem ipsum dolor",
        "validFrom": "2023-01-01T00:00:00.000Z",
        "validUntil": "2023-12-31T23:59:59.000Z",
    }


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
    args = {"id": "123456", "description": "Lorem ipsum dolor", "valid_until": "2023-12-31T23:59:59.000Z"}
    mocker.patch.object(client, "query", side_effect=Exception("Test exception"))
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
    args = {"id": "123456", "description": "Lorem ipsum dolor", "valid_until": "2023-12-31T23:59:59.000Z"}
    mocker.patch.object(client, "query", return_value={"data": {"indicatorFieldPatch": {}}})
    with pytest.raises(DemistoException, match="Can't update indicator."):
        indicator_update_command(client, args)


@pytest.mark.parametrize(
    argnames="field, value, function_name,",
    argvalues=[("marking", "TLP:RED", "add_marking_definition"), ("label", "new-label", "add_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
    mocker.patch.object(client.stix_domain_object, function_name, return_value=True)
    results: CommandResults = indicator_field_add_command(client, args)
    assert f"Added {field} successfully." in results.readable_output


@pytest.mark.parametrize(
    argnames="field, value, function_name,",
    argvalues=[("marking", "TLP:RED", "add_marking_definition"), ("label", "new-label", "add_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
    mocker.patch.object(client.stix_domain_object, function_name, return_value=False)
    with pytest.raises(DemistoException, match=f"Can't add {field}."):
        indicator_field_add_command(client, args)


@pytest.mark.parametrize(
    argnames="field, value, function_name",
    argvalues=[("marking", "TLP:RED", "remove_marking_definition"), ("label", "new-label", "remove_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
    mocker.patch.object(client.stix_domain_object, function_name, return_value=True)
    results: CommandResults = indicator_field_remove_command(client, args)
    assert f"{field}: {value} was removed successfully from indicator: 123456." in results.readable_output


@pytest.mark.parametrize(
    argnames="field, value, function_name",
    argvalues=[("marking", "TLP:RED", "remove_marking_definition"), ("label", "new-label", "remove_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
    mocker.patch.object(client.stix_domain_object, function_name, return_value=False)
    with pytest.raises(DemistoException, match=f"Can't remove {field}."):
        indicator_field_remove_command(client, args)


@pytest.mark.parametrize(
    argnames="field, value, function_name",
    argvalues=[("marking", "TLP:RED", "remove_marking_definition"), ("label", "new-label", "remove_label")],
)
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
    args = {"id": "123456", "field": field, "value": value}
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
    mocker.patch.object(client.indicator, "list", return_value=RESPONSE_DATA_INDICATORS)
    indicators = get_indicators(
        client,
        indicator_types=["indicator_type_1", "indicator_type_2"],
        limit=10,
        additional_filters=[{"key": "score", "values": ["0", "50"], "operator": "AND"}],
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
    mocker.patch.object(client.indicator, "list", side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Failed to retrieve indicators."):
        get_indicators(client, indicator_types=["indicator_type_1", "indicator_type_2"], limit=10)
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
    args = {"indicator_types": "compromised", "limit": 2}
    mocker.patch.object(client.indicator, "list", return_value=RESPONSE_DATA_INDICATORS)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators" in results.readable_output
    assert RESPONSE_DATA_INDICATORS.get("pagination", {}).get("endCursor") == results.outputs.get(
        "OpenCTI.Indicators(val.lastRunID)"
    ).get("lastRunID")


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
    args = {"indicator_types": "compromised"}
    mocker.patch.object(client.indicator, "list", return_value=RESPONSE_DATA_EMPTY)
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
    mocker.patch.object(
        client,
        "query",
        return_value={
            "data": {
                "vocabularies": {
                    "edges": [
                        {"node": {"id": "1", "name": "compromised", "description": "compromised"}},
                    ]
                }
            }
        },
    )
    results: CommandResults = indicator_types_list_command(client, {})
    assert "Indicator Types" in results.readable_output
    assert results.outputs.get("OpenCTI.IndicatorTypes.IndicatorTypesList(val.id === obj.id)") == [
        {"id": "1", "name": "compromised", "description": "compromised"}
    ]


def test_indicator_types_list_command_with_no_data_to_return(mocker):
    """Tests indicator_types_list_command function
    Given

    When
        - Calling `indicator_types_list_command`
    Then
        - validate the response to have a "No observables" string
    """
    client = Client
    mocker.patch.object(client, "query", return_value={"data": {"vocabularies": {"edges": []}}})
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
    mocker.patch.object(client, "query", side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match="Can't list indicator types."):
        indicator_types_list_command(client, {})
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


CREATE_COMMANDS = [
    (
        incident_response_create_command,
        "case_incident",
        {"name": "Lorem", "severity": "high", "priority": "P2", "description": "Lorem ipsum"},
        "OpenCTI.IncidentResponse",
        "Incident response created successfully",
        "Can't create incident response.",
    ),
    (
        malware_create_command,
        "malware",
        {"name": "Lorem", "malware_types": "ransomware,worm", "is_family": "true"},
        "OpenCTI.Malware",
        "Malware created successfully",
        "Can't create malware.",
    ),
    (
        vulnerability_create_command,
        "vulnerability",
        {"name": "CVE-2025-0001", "description": "Lorem ipsum"},
        "OpenCTI.Vulnerability",
        "Vulnerability created successfully",
        "Can't create vulnerability.",
    ),
    (
        intrusion_set_create_command,
        "intrusion_set",
        {"name": "Lorem", "description": "Lorem ipsum"},
        "OpenCTI.IntrusionSet",
        "Intrusion set created successfully",
        "Can't create intrusion set.",
    ),
    (
        threat_actor_group_create_command,
        "threat_actor_group",
        {"name": "Lorem", "description": "Lorem ipsum"},
        "OpenCTI.ThreatActorGroup",
        "Threat Actor Group created successfully",
        "Can't create threat-actor-group.",
    ),
    (
        campaign_create_command,
        "campaign",
        {"name": "Lorem", "first_seen": "2025-01-01T00:00:00Z", "last_seen": "2025-06-30T00:00:00Z"},
        "OpenCTI.Campaign",
        "Campaign created successfully",
        "Can't create campaign.",
    ),
    (
        grouping_create_command,
        "grouping",
        {"name": "Lorem", "context": "suspicious-activity"},
        "OpenCTI.Grouping",
        "Grouping created successfully",
        "Can't create grouping.",
    ),
    (
        report_create_command,
        "report",
        {"name": "Lorem", "published": "2025-01-01T00:00:00Z"},
        "OpenCTI.Report",
        "Report created successfully",
        "Can't create report.",
    ),
]
CREATE_COMMAND_IDS = [command[1] for command in CREATE_COMMANDS]


@pytest.mark.parametrize(
    "command, client_attribute, args, outputs_prefix, success_message, error_message",
    CREATE_COMMANDS,
    ids=CREATE_COMMAND_IDS,
)
def test_create_commands(mocker, command, client_attribute, args, outputs_prefix, success_message, error_message):
    """Tests the entity creation commands
    Given
        arguments of the entity to create
    When
        - Calling the creation command and OpenCTI returns the new entity
    Then
        - validate the readable_output, outputs_prefix and context
    """
    client = Client
    mocker.patch.object(getattr(client, client_attribute), "create", return_value={"id": "123456"})
    results: CommandResults = command(client, args)
    assert success_message in results.readable_output
    assert "123456" in results.readable_output
    assert results.outputs_prefix == outputs_prefix
    assert results.outputs == {"id": "123456"}


@pytest.mark.parametrize(
    "command, client_attribute, args, outputs_prefix, success_message, error_message",
    CREATE_COMMANDS,
    ids=CREATE_COMMAND_IDS,
)
def test_create_commands_exception(
    mocker, capfd, command, client_attribute, args, outputs_prefix, success_message, error_message
):
    """Tests the entity creation commands
    Given
        arguments of the entity to create
    When
        - Calling the creation command and the OpenCTI client raises an exception
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(getattr(client, client_attribute), "create", side_effect=Exception("Test exception"))
    with pytest.raises(DemistoException, match=f"{error_message} Test exception"):
        command(client, args)
    captured = capfd.readouterr()
    assert "Test exception" in captured.out


@pytest.mark.parametrize("returned_value", [{}, None], ids=["empty", "none"])
@pytest.mark.parametrize(
    "command, client_attribute, args, outputs_prefix, success_message, error_message",
    CREATE_COMMANDS,
    ids=CREATE_COMMAND_IDS,
)
def test_create_commands_data_not_returned(
    mocker, command, client_attribute, args, outputs_prefix, success_message, error_message, returned_value
):
    """Tests the entity creation commands
    Given
        arguments of the entity to create
    When
        - Calling the creation command and OpenCTI returns no entity (pycti returns None on invalid input)
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(getattr(client, client_attribute), "create", return_value=returned_value)
    with pytest.raises(DemistoException, match=error_message):
        command(client, args)


def test_malware_create_command_arguments(mocker):
    """Tests malware_create_command function
    Given
        a comma-separated list of malware types and the is_family flag
    When
        - Calling `malware_create_command`
    Then
        - Ensure the malware types are sent as a list and is_family as a boolean.
    """
    client = Client
    create_mock = mocker.patch.object(client.malware, "create", return_value={"id": "123456"})
    malware_create_command(client, {"name": "Lorem", "malware_types": "ransomware, worm", "is_family": "true"})
    create_mock.assert_called_once_with(name="Lorem", description=None, is_family=True, malware_types=["ransomware", "worm"])


@pytest.mark.parametrize(
    "container_type, client_attribute",
    [
        ("report", "report"),
        ("grouping", "grouping"),
        ("case-incident", "case_incident"),
        ("case-rft", "case_rft"),
        ("case-rfi", "case_rfi"),
    ],
)
def test_add_object_to_container_create_command(mocker, container_type, client_attribute):
    """Tests add_object_to_container_create_command function
    Given
        a container type, a container ID and an object ID
    When
        - Calling `add_object_to_container_create_command`
    Then
        - Ensure the matching container API is called and the readable_output is returned.
    """
    client = Client
    add_mock = mocker.patch.object(getattr(client, client_attribute), "add_stix_object_or_stix_relationship", return_value=True)
    args = {"container_type": container_type, "container_id": "container-id", "object_id": "object-id"}
    results: CommandResults = add_object_to_container_create_command(client, args)
    add_mock.assert_called_once_with(id="container-id", stixObjectOrStixRelationshipId="object-id")
    assert results.readable_output == f"Object added into {container_type}"


def test_add_object_to_container_create_command_exception(mocker, capfd):
    """Tests add_object_to_container_create_command function
    Given
        a container type, a container ID and an object ID
    When
        - Calling `add_object_to_container_create_command` and the OpenCTI client raises an exception
    Then
        - Ensure a DemistoException is raised with the correct error message.
    """
    client = Client
    mocker.patch.object(client.report, "add_stix_object_or_stix_relationship", side_effect=Exception("Test exception"))
    args = {"container_type": "report", "container_id": "container-id", "object_id": "object-id"}
    with pytest.raises(DemistoException, match="Can't add object into report. Test exception"):
        add_object_to_container_create_command(client, args)
    captured = capfd.readouterr()
    assert captured.out.strip() == "Test exception"


def test_add_object_to_container_create_command_not_added(mocker):
    """Tests add_object_to_container_create_command function
    Given
        a container type, a container ID and an object ID
    When
        - Calling `add_object_to_container_create_command` and OpenCTI does not add the object
    Then
        - Ensure a DemistoException is raised instead of reporting a success.
    """
    client = Client
    mocker.patch.object(client.grouping, "add_stix_object_or_stix_relationship", return_value=False)
    args = {"container_type": "grouping", "container_id": "container-id", "object_id": "object-id"}
    with pytest.raises(DemistoException, match="Can't add object into grouping."):
        add_object_to_container_create_command(client, args)


def test_add_object_to_container_create_command_invalid_container_type(capfd):
    """Tests add_object_to_container_create_command function
    Given
        an unsupported container type
    When
        - Calling `add_object_to_container_create_command`
    Then
        - Ensure a DemistoException is raised listing the supported container types.
    """
    args = {"container_type": "note", "container_id": "container-id", "object_id": "object-id"}
    with pytest.raises(DemistoException, match="Invalid container_type: note. Supported containers are: 'report'"):
        add_object_to_container_create_command(Client, args)
    assert "Invalid container_type: note" in capfd.readouterr().out


@pytest.mark.parametrize(
    "score, suspicious_threshold, threshold, expected",
    [
        (None, 20, 70, 0),
        ("not a number", 20, 70, 0),
        (0, 20, 70, 1),
        (20, 20, 70, 1),
        (21, 20, 70, 2),
        (70, 20, 70, 2),
        (71, 20, 70, 3),
        (90, 20, 70, 3),
        (150, 20, 70, 3),
        (-5, 20, 70, 1),
        (60, 30, 50, 3),
        (40, 30, 50, 2),
        (0, 0, 70, 1),
        (1, 0, 70, 2),
        (80, None, None, 3),
        (50, None, None, 2),
        (10, None, None, 1),
    ],
)
def test_opencti_score_to_dbot_score(score, suspicious_threshold, threshold, expected):
    """Tests opencti_score_to_dbot_score function
    Given
        an OpenCTI indicator score (x_opencti_score), a suspicious and a malicious threshold
    When
        - Calling `opencti_score_to_dbot_score`
    Then
        - Ensure no score is Unknown, a score above the malicious threshold Malicious, above the suspicious threshold
          Suspicious, and Good otherwise (default thresholds: 20 and 70, like FeedOpenCTI).
    """
    assert opencti_score_to_dbot_score(score, threshold, suspicious_threshold) == expected


@pytest.mark.parametrize(
    "params, expected",
    [
        ({}, (20, 70)),
        ({"reputation_suspicious_threshold": "", "reputation_threshold": ""}, (20, 70)),
        ({"reputation_suspicious_threshold": "0", "reputation_threshold": "100"}, (0, 100)),
        ({"reputation_suspicious_threshold": "50", "reputation_threshold": "50"}, (50, 50)),
    ],
)
def test_get_reputation_thresholds(params, expected):
    """Tests get_reputation_thresholds function
    Given
        the integration parameters
    When
        - Calling `get_reputation_thresholds`
    Then
        - Ensure the (suspicious, malicious) thresholds are returned, with 20 and 70 by default.
    """
    assert get_reputation_thresholds(params) == expected


@pytest.mark.parametrize(
    "params, error",
    [
        ({"reputation_suspicious_threshold": "80", "reputation_threshold": "70"}, "must not be above the malicious"),
        ({"reputation_threshold": "101"}, "reputation_threshold parameter must be between 0 and 100"),
        ({"reputation_suspicious_threshold": "-1"}, "reputation_suspicious_threshold parameter must be between 0 and 100"),
    ],
)
def test_get_reputation_thresholds_invalid(params, error):
    """Tests get_reputation_thresholds function
    Given
        invalid thresholds: suspicious above malicious, or out of the 0-100 range
    When
        - Calling `get_reputation_thresholds`
    Then
        - Ensure a DemistoException explains the configuration error.
    """
    with pytest.raises(DemistoException, match=error):
        get_reputation_thresholds(params)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", ("MD5", "md5")),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", ("SHA-1", "sha1")),
        ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", ("SHA-256", "sha256")),
        ("d41d8cd98f00b204e9800998ecf8427", None),
        ("not-a-hash-not-a-hash-not-a-hash", None),
        ("", None),
    ],
)
def test_get_file_hash_type(value, expected):
    """Tests get_file_hash_type function
    Given
        a value given to the file command
    When
        - Calling `get_file_hash_type`
    Then
        - Ensure MD5, SHA-1 and SHA-256 hashes are recognized by their length and anything else is rejected.
    """
    assert get_file_hash_type(value) == expected


@pytest.mark.parametrize(
    "value, indicator_type, expected",
    [
        ("1.2.3.4", "ip", "[ipv4-addr:value = '1.2.3.4']"),
        ("2001:db8::1", "ip", "[ipv6-addr:value = '2001:db8::1']"),
        ("example.com", "domain", "[domain-name:value = 'example.com']"),
        ("user@example.com", "email", "[email-addr:value = 'user@example.com']"),
        ("https://example.com/a", "url", "[url:value = 'https://example.com/a']"),
        ("d41d8cd98f00b204e9800998ecf8427e", "file", "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"),
        (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "file",
            "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
        ),
    ],
)
def test_build_reputation_pattern(value, indicator_type, expected):
    """Tests build_reputation_pattern function
    Given
        a value and the reputation command type
    When
        - Calling `build_reputation_pattern`
    Then
        - Ensure the STIX pattern is the one OpenCTI gives to an indicator of this value.
    """
    assert build_reputation_pattern(value, indicator_type) == expected


REPUTATION_OBSERVABLE = {
    "id": "observable-id",
    "entity_type": "IPv4-Addr",
    "observable_value": "1.2.3.4",
    "x_opencti_score": 40,
    "x_opencti_description": "Observable description",
    "createdBy": {"name": "Filigran"},
    "creators": [{"name": "admin"}],
    "objectLabel": [{"value": "c2"}],
    "objectMarking": [{"definition": "TLP:AMBER"}],
    "externalReferences": [{"source_name": "source", "url": "https://example.com/ref"}],
    "created_at": "2025-01-01T00:00:00.000Z",
    "updated_at": "2025-01-02T00:00:00.000Z",
}
REPUTATION_INDICATOR = {
    "id": "indicator-id",
    "name": "1.2.3.4",
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
    "pattern_type": "stix",
    "x_opencti_main_observable_type": "IPv4-Addr",
    "x_opencti_score": 90,
    "confidence": 20,
    "revoked": False,
    "x_opencti_detection": True,
    "indicator_types": ["malicious-activity"],
    "objectLabel": [{"value": "c2"}, {"value": "apt"}],
    "objectMarking": [{"definition": "TLP:AMBER"}],
}
REPUTATION_RELATIONSHIP = {
    "id": "relationship-id",
    "relationship_type": "related-to",
    "from": {"id": "observable-id", "entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"},
    "to": {"id": "malware-id", "entity_type": "Malware", "name": "Example Malware"},
}
# The based-on relationship only links the indicator and the observable returned by the command.
BASED_ON_RELATIONSHIP = {
    "id": "based-on-id",
    "relationship_type": "based-on",
    "from": {"id": "indicator-id", "entity_type": "Indicator", "name": "1.2.3.4"},
    "to": {"id": "observable-id", "entity_type": "IPv4-Addr", "observable_value": "1.2.3.4"},
}
INDICATES_RELATIONSHIP = {
    "id": "indicates-id",
    "relationship_type": "indicates",
    "from": {"id": "indicator-id", "entity_type": "Indicator", "name": "1.2.3.4"},
    "to": {"id": "intrusion-set-id", "entity_type": "Intrusion-Set", "name": "Example Intrusion Set"},
}


def mock_reputation_lookups(mocker, observables, indicators, relationships=None):
    """Mock the OpenCTI lookups. `relationships` = one list per relationship lookup, in the order they are made."""
    client = Client
    observable_list = mocker.patch.object(client.stix_cyber_observable, "list", return_value=observables)
    indicator_list = mocker.patch.object(client.indicator, "list", side_effect=indicators)
    relationship_list = mocker.patch.object(client.stix_core_relationship, "list", side_effect=relationships or [[], []])
    return client, observable_list, indicator_list, relationship_list


def test_reputation_command_found(mocker):
    """Tests reputation_command function
    Given
        an IP that has an observable related to a malware, and a malicious indicator (score 90, confidence 20)
        that indicates an intrusion set, the indicator being based on the observable
    When
        - Calling `reputation_command` for the ip command
    Then
        - Ensure the DBot score comes from x_opencti_score, not from confidence: Malicious.
        - Ensure the observable, the indicator and the relationships of both are in the context, without the
          based-on relationship between them.
    """
    client, _, _, relationship_list = mock_reputation_lookups(
        mocker,
        [REPUTATION_OBSERVABLE],
        [[REPUTATION_INDICATOR]],
        [[REPUTATION_RELATIONSHIP, BASED_ON_RELATIONSHIP], [INDICATES_RELATIONSHIP, BASED_ON_RELATIONSHIP]],
    )
    results = reputation_command(client, {"ip": "1.2.3.4"}, "ip", 70, "A - Completely reliable")
    assert len(results) == 1
    context = results[0].to_context()["EntryContext"]
    dbot = context[
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"
    ]
    assert dbot == [
        {"Indicator": "1.2.3.4", "Type": "ip", "Vendor": "OpenCTI", "Score": 3, "Reliability": "A - Completely reliable"}
    ]
    ip_context = context["IP(val.Address && val.Address == obj.Address)"]
    assert ip_context == [
        {
            "Address": "1.2.3.4",
            "Malicious": {"Vendor": "OpenCTI", "Description": "OpenCTI score: 90"},
            "Relationships": [
                {
                    "Relationship": "indicator-of",
                    "EntityA": "1.2.3.4",
                    "EntityAType": "IP",
                    "EntityB": "Example Intrusion Set",
                    "EntityBType": "Intrusion Set",
                },
                {
                    "Relationship": "related-to",
                    "EntityA": "1.2.3.4",
                    "EntityAType": "IP",
                    "EntityB": "Example Malware",
                    "EntityBType": "Malware",
                },
            ],
        }
    ]
    observable = context["OpenCTI.Observable(val.value && val.value == obj.value)"]
    assert observable["found"] is True
    assert observable["score"] == 40
    assert observable["labels"] == ["c2"]
    assert observable["externalReferences"] == [{"sourceName": "source", "url": "https://example.com/ref"}]
    assert observable["relationships"] == [
        {
            "id": "relationship-id",
            "relationshipType": "related-to",
            "fromId": "observable-id",
            "fromName": "1.2.3.4",
            "fromEntityType": "IPv4-Addr",
            "toId": "malware-id",
            "toName": "Example Malware",
            "toEntityType": "Malware",
            "relatedEntityId": "malware-id",
            "relatedEntityName": "Example Malware",
            "relatedEntityType": "Malware",
        }
    ]
    indicator = context["OpenCTI.Indicator(val.id && val.id == obj.id)"]
    assert indicator["score"] == 90
    assert indicator["confidence"] == 20
    assert [(r["relationshipType"], r["fromId"], r["relatedEntityName"]) for r in indicator["relationships"]] == [
        ("indicates", "indicator-id", "Example Intrusion Set")
    ]
    assert all("direction" not in r for r in indicator["relationships"] + observable["relationships"])
    assert [call.kwargs["fromOrToId"] for call in relationship_list.call_args_list] == ["observable-id", "indicator-id"]
    assert "OpenCTI reputation for ip 1.2.3.4" in results[0].readable_output
    assert "Indicator relationships" in results[0].readable_output
    assert "Example Intrusion Set" in results[0].readable_output
    assert "Observable relationships" in results[0].readable_output
    assert "Example Malware" in results[0].readable_output
    assert "based-on" not in results[0].readable_output


def test_reputation_command_not_found(mocker):
    """Tests reputation_command function
    Given
        a domain that is neither an observable nor an indicator in OpenCTI
    When
        - Calling `reputation_command` for the domain command
    Then
        - Ensure the DBot score is Unknown, the observable is flagged as not found and there is no indicator context.
    """
    client, _, _, relationship_list = mock_reputation_lookups(mocker, [], [[], []])
    results = reputation_command(client, {"domain": "example.com"}, "domain")
    context = results[0].to_context()["EntryContext"]
    dbot = context[
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"
    ]
    assert dbot[0]["Score"] == 0
    assert context["Domain(val.Name && val.Name == obj.Name)"] == [{"Name": "example.com"}]
    assert context["OpenCTI.Observable(val.value && val.value == obj.value)"] == {
        "found": False,
        "value": "example.com",
        "type": "domain",
    }
    assert "OpenCTI.Indicator(val.id && val.id == obj.id)" not in context
    relationship_list.assert_not_called()


def test_reputation_command_suspicious_below_threshold(mocker):
    """Tests reputation_command function
    Given
        a URL whose indicator score (50) is under the threshold (70)
    When
        - Calling `reputation_command` for the url command
    Then
        - Ensure the DBot score is Suspicious and there is no Malicious context.
    """
    indicator = {**REPUTATION_INDICATOR, "pattern": "[url:value = 'https://example.com/a']", "x_opencti_score": 50}
    client, _, _, _ = mock_reputation_lookups(mocker, [], [[indicator]])
    results = reputation_command(client, {"url": "https://example.com/a"}, "url", 70)
    context = results[0].to_context()["EntryContext"]
    dbot = context[
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"
    ]
    assert dbot[0]["Score"] == 2
    assert context["URL(val.Data && val.Data == obj.Data)"] == [{"Data": "https://example.com/a"}]


@pytest.mark.parametrize(
    "indicator_type, value, context_key, expected_context",
    [
        (
            "email",
            "user@example.com",
            "Account(val.Email.Address && val.Email.Address == obj.Email.Address)",
            {"Email": {"Address": "user@example.com"}},
        ),
        (
            "file",
            "d41d8cd98f00b204e9800998ecf8427e",
            "File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 "
            "|| val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == "
            "obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)",
            {"Hashes": [{"type": "MD5", "value": "d41d8cd98f00b204e9800998ecf8427e"}], "MD5": "d41d8cd98f00b204e9800998ecf8427e"},
        ),
    ],
)
def test_reputation_command_standard_context(mocker, indicator_type, value, context_key, expected_context):
    """Tests reputation_command function
    Given
        an email address or a file hash unknown to OpenCTI
    When
        - Calling `reputation_command` for the email or file command
    Then
        - Ensure the XSOAR standard context of the indicator type is returned.
    """
    client, _, _, _ = mock_reputation_lookups(mocker, [], [[], []])
    context = reputation_command(client, {indicator_type: value}, indicator_type)[0].to_context()["EntryContext"]
    assert context[context_key] == [expected_context]


def test_reputation_command_file_lookup_filters(mocker):
    """Tests reputation_command function
    Given
        a SHA-256 hash
    When
        - Calling `reputation_command` for the file command
    Then
        - Ensure the observable is searched on its exact hash and the indicator on its exact STIX pattern.
    """
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    client, observable_list, indicator_list, _ = mock_reputation_lookups(mocker, [], [[], []])
    reputation_command(client, {"file": sha256}, "file")
    observable_filters = observable_list.call_args.kwargs["filters"]["filters"]
    assert {"key": "hashes.SHA-256", "values": [sha256], "operator": "eq"} in observable_filters
    exact_indicator_filters = indicator_list.call_args_list[0].kwargs["filters"]["filters"]
    assert {"key": "pattern", "values": [f"[file:hashes.'SHA-256' = '{sha256}']"], "operator": "eq"} in exact_indicator_filters


def test_reputation_command_indicator_fallback_search(mocker):
    """Tests reputation_command function
    Given
        an IP whose indicator is not found by the exact pattern filter
    When
        - Calling `reputation_command` for the ip command and the full-text search returns several indicators
    Then
        - Ensure only the indicator with the exact same pattern is kept.
    """
    other_indicator = {**REPUTATION_INDICATOR, "id": "other-id", "pattern": "[ipv4-addr:value = '1.2.3.40']"}
    client, _, indicator_list, _ = mock_reputation_lookups(mocker, [], [[], [other_indicator, REPUTATION_INDICATOR]])
    results = reputation_command(client, {"ip": "1.2.3.4"}, "ip")
    context = results[0].to_context()["EntryContext"]
    assert context["OpenCTI.Indicator(val.id && val.id == obj.id)"]["id"] == "indicator-id"
    assert indicator_list.call_args_list[1].kwargs["search"] == '"1.2.3.4"'


def test_reputation_command_invalid_values(mocker):
    """Tests reputation_command function
    Given
        an invalid IP address and an invalid file hash
    When
        - Calling `reputation_command` for the ip and file commands
    Then
        - Ensure a message is returned for each value without querying OpenCTI.
    """
    client, observable_list, indicator_list, _ = mock_reputation_lookups(mocker, [], [])
    assert reputation_command(client, {"ip": "999.1.1.1"}, "ip")[0].readable_output == "999.1.1.1 is not a valid IP address."
    assert reputation_command(client, {"file": "abc"}, "file")[0].readable_output == (
        "abc is not a valid MD5, SHA-1 or SHA-256 hash."
    )
    observable_list.assert_not_called()
    indicator_list.assert_not_called()


def test_reputation_command_error_does_not_stop_other_values(mocker, capfd):
    """Tests reputation_command function
    Given
        two IPs, the first one failing in OpenCTI
    When
        - Calling `reputation_command` for the ip command
    Then
        - Ensure the first value returns a warning and the second one is still checked.
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, "list", side_effect=[Exception("Test exception"), []])
    mocker.patch.object(client.indicator, "list", side_effect=[[], []])
    results = reputation_command(client, {"ip": "1.2.3.4,5.6.7.8"}, "ip")
    assert len(results) == 2
    assert results[0].entry_type == EntryType.WARNING
    assert "Can't check the reputation of 1.2.3.4 in OpenCTI. Test exception" in results[0].readable_output
    assert "OpenCTI reputation for ip 5.6.7.8" in results[1].readable_output
    assert "Test exception" in capfd.readouterr().out


def test_reputation_command_relationships_error(mocker, capfd):
    """Tests reputation_command function
    Given
        an IP whose observable and indicator relationships can't be listed
    When
        - Calling `reputation_command` for the ip command
    Then
        - Ensure the reputation is still returned, without relationships.
    """
    client, _, _, relationship_list = mock_reputation_lookups(mocker, [REPUTATION_OBSERVABLE], [[REPUTATION_INDICATOR]])
    relationship_list.side_effect = Exception("Test exception")
    results = reputation_command(client, {"ip": "1.2.3.4"}, "ip")
    context = results[0].to_context()["EntryContext"]
    assert context["OpenCTI.Observable(val.value && val.value == obj.value)"]["relationships"] == []
    assert context["OpenCTI.Indicator(val.id && val.id == obj.id)"]["relationships"] == []
    assert results[0].entry_type == EntryType.NOTE
    assert "Can't list the relationships of observable-id. Test exception" in capfd.readouterr().out


def test_reputation_command_no_value():
    """Tests reputation_command function
    Given
        no value
    When
        - Calling `reputation_command` for the url command
    Then
        - Ensure a DemistoException is raised.
    """
    with pytest.raises(DemistoException, match="Please provide at least one value in the 'url' argument."):
        reputation_command(Client, {}, "url")


def test_relationships_to_markdown():
    """Tests relationships_to_markdown function
    Given
        an outgoing relationship and an incoming one (whose related entity is the source)
    When
        - Calling `relationships_to_markdown`
    Then
        - Ensure a Relationship / Entity type / Entity table is returned, the incoming relationship marked with ←.
    """
    relationships = [
        {
            "relationshipType": "indicates",
            "relatedEntityType": "Malware",
            "relatedEntityName": "LockBit 3.0",
        },
        {
            "relationshipType": "related-to",
            "fromId": "campaign-id",
            "relatedEntityId": "campaign-id",
            "relatedEntityType": "Campaign",
            "relatedEntityName": "Example",
        },
    ]
    assert relationships_to_markdown("Indicator relationships", relationships) == (
        "### Indicator relationships\n"
        "|Relationship|Entity type|Entity|\n"
        "|---|---|---|\n"
        "| indicates | Malware | LockBit 3.0 |\n"
        "| ← related-to | Campaign | Example |\n"
    )


def test_build_entity_relationships():
    """Tests build_entity_relationships function
    Given
        OpenCTI relationships of an IP: an indicates relationship, an incoming uses relationship, a type unknown to
        XSOAR, a relationship to an entity type with no XSOAR equivalent and a duplicate
    When
        - Calling `build_entity_relationships`
    Then
        - Ensure indicates becomes indicator-of, an incoming relationship gets the reverse name, an unknown type
          becomes related-to, and entities with no XSOAR type and duplicates are left out.
    """
    relationships = [
        {
            "relationshipType": "indicates",
            "relatedEntityName": "LockBit 3.0",
            "relatedEntityType": "Malware",
        },
        {
            "relationshipType": "uses",
            "fromId": "apt1-id",
            "relatedEntityId": "apt1-id",
            "relatedEntityName": "APT1",
            "relatedEntityType": "Intrusion-Set",
        },
        {
            "relationshipType": "belongs-to",
            "relatedEntityName": "AS1234",
            "relatedEntityType": "Autonomous-System",
        },
        {"relationshipType": "related-to", "relatedEntityName": "A note", "relatedEntityType": "Note"},
        {
            "relationshipType": "indicates",
            "relatedEntityName": "LockBit 3.0",
            "relatedEntityType": "Malware",
        },
    ]
    entries = [r.to_entry() for r in build_entity_relationships("1.2.3.4", "ip", relationships, "B - Usually reliable")]
    assert [(e["name"], e["reverseName"], e["entityA"], e["entityAType"], e["entityB"], e["entityBType"]) for e in entries] == [
        ("indicator-of", "indicated-by", "1.2.3.4", "IP", "LockBit 3.0", "Malware"),
        ("used-by", "uses", "1.2.3.4", "IP", "APT1", "Intrusion Set"),
        ("related-to", "related-to", "1.2.3.4", "IP", "AS1234", "ASN"),
    ]
    assert {(e["brand"], e["reliability"]) for e in entries} == {("OpenCTI", "B - Usually reliable")}


def test_build_entity_relationships_ipv6():
    """Tests build_entity_relationships function
    Given
        a relationship of an IPv6 address
    When
        - Calling `build_entity_relationships`
    Then
        - Ensure entity A is an IPv6 indicator.
    """
    relationships = [{"relationshipType": "related-to", "relatedEntityName": "X", "relatedEntityType": "Malware"}]
    entry = build_entity_relationships("2001:db8::1", "ip", relationships, "B - Usually reliable")[0].to_entry()
    assert entry["entityAType"] == "IPv6"


@pytest.mark.parametrize("create_relationships, expected_count", [(True, 2), (False, 0)])
def test_reputation_command_create_relationships(mocker, create_relationships, expected_count):
    """Tests reputation_command function
    Given
        an IP whose observable is related to a malware and whose indicator indicates an intrusion set
    When
        - Calling `reputation_command` with create_relationships enabled or disabled
    Then
        - Ensure the XSOAR relationships are returned only when enabled, and the OpenCTI context in both cases.
    """
    client, _, _, _ = mock_reputation_lookups(
        mocker,
        [REPUTATION_OBSERVABLE],
        [[REPUTATION_INDICATOR]],
        [[REPUTATION_RELATIONSHIP, BASED_ON_RELATIONSHIP], [INDICATES_RELATIONSHIP, BASED_ON_RELATIONSHIP]],
    )
    result = reputation_command(client, {"ip": "1.2.3.4"}, "ip", 70, "B - Usually reliable", create_relationships)[0]
    entry = result.to_context()
    relationships = entry.get("Relationships") or []
    assert len(relationships) == expected_count
    if create_relationships:
        assert {(r["name"], r["entityB"], r["entityBType"]) for r in relationships} == {
            ("indicator-of", "Example Intrusion Set", "Intrusion Set"),
            ("related-to", "Example Malware", "Malware"),
        }
    indicator = entry["EntryContext"]["OpenCTI.Indicator(val.id && val.id == obj.id)"]
    assert len(indicator["relationships"]) == 1


@pytest.mark.parametrize(
    "platform_url, entity_id, text, expected",
    [
        ("https://opencti.example.com", "id-1", "LockBit 3.0", "[LockBit 3.0](https://opencti.example.com/dashboard/id/id-1)"),
        ("https://opencti.example.com", "id-1", None, "[id-1](https://opencti.example.com/dashboard/id/id-1)"),
        ("", "id-1", "LockBit 3.0", "LockBit 3.0"),
        ("https://opencti.example.com", None, "LockBit 3.0", "LockBit 3.0"),
    ],
)
def test_opencti_link(platform_url, entity_id, text, expected):
    """Tests opencti_link function
    Given
        an OpenCTI URL, an entity ID and a link text
    When
        - Calling `opencti_link`
    Then
        - Ensure a link to {url}/dashboard/id/{id} is returned, or the plain text without URL or ID.
    """
    assert opencti_link(platform_url, entity_id, text) == expected


def test_reputation_command_platform_links(mocker):
    """Tests reputation_command function
    Given
        an IP with an observable and an indicator that indicates an intrusion set, and the OpenCTI URL
    When
        - Calling `reputation_command` with the platform URL
    Then
        - Ensure the indicator and observable IDs stay plain, with a link column each, and the related entity links to
          its OpenCTI page.
    """
    client, _, _, _ = mock_reputation_lookups(
        mocker, [REPUTATION_OBSERVABLE], [[REPUTATION_INDICATOR]], [[], [INDICATES_RELATIONSHIP]]
    )
    readable = reputation_command(client, {"ip": "1.2.3.4"}, "ip", platform_url="https://opencti.example.com")[0].readable_output
    assert "|Value|OpenCTI Score|Indicator ID|Indicator Link|Observable ID|Observable Link|Labels|Markings|" in readable
    assert (
        "| indicator-id | [View in OpenCTI](https://opencti.example.com/dashboard/id/indicator-id) "
        "| observable-id | [View in OpenCTI](https://opencti.example.com/dashboard/id/observable-id) |"
    ) in readable
    assert (
        "| indicates | Intrusion-Set | [Example Intrusion Set](https://opencti.example.com/dashboard/id/intrusion-set-id) |"
        in readable
    )


def test_reputation_command_without_platform_url(mocker):
    """Tests reputation_command function
    Given
        an IP with an observable and an indicator, and no OpenCTI URL
    When
        - Calling `reputation_command`
    Then
        - Ensure there is no link column.
    """
    client, _, _, _ = mock_reputation_lookups(mocker, [REPUTATION_OBSERVABLE], [[REPUTATION_INDICATOR]])
    readable = reputation_command(client, {"ip": "1.2.3.4"}, "ip")[0].readable_output
    assert "|Value|OpenCTI Score|Indicator ID|Observable ID|Labels|Markings|" in readable
    assert "View in OpenCTI" not in readable


def test_reputation_command_good(mocker):
    """Tests reputation_command function
    Given
        a domain whose indicator score (10) is not above the suspicious threshold (20)
    When
        - Calling `reputation_command` for the domain command
    Then
        - Ensure the DBot score is Good.
    """
    indicator = {**REPUTATION_INDICATOR, "pattern": "[domain-name:value = 'example.com']", "x_opencti_score": 10}
    client, _, _, _ = mock_reputation_lookups(mocker, [], [[indicator]])
    context = reputation_command(client, {"domain": "example.com"}, "domain", 70, suspicious_threshold=20)[0].to_context()
    dbot = context["EntryContext"][
        "DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)"
    ]
    assert dbot[0]["Score"] == 1
