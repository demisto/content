
from FeedOpenCTI_v2 import *
from test_data.feed_data import RESPONSE_DATA, RESPONSE_DATA_WITHOUT_INDICATORS
from CommonServerPython import CommandResults


class StixCyberObservable:
    def list(self):
        return self

    def delete(self):
        return self

    def update_field(self):
        return self

    def create(self):
        return self

    def remove_marking_definition(self):
        return self

    def add_label(self):
        return self

    def remove_label(self):
        return self

    def add_marking_definition(self):
        return self


class Client:
    temp = ''
    stix_cyber_observable = StixCyberObservable
    identity = Identity


def test_get_indicators(mocker):
    """Tests get_indicators function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
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
    new_last_id, indicators = get_indicators(client, indicator_type=['registry-key-value', 'user-account'], limit=10)
    assert len(indicators) == 2
    assert new_last_id == 'YXJyYXljb25uZWN0aW9uOjI='


def test_fetch_indicators_command(mocker):
    """Tests fetch_indicators_command function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
    When
        - Calling `fetch_indicators_command`
    Then
        - convert the result to indicators list
        - validate the length of the indicators list
    """
    client = Client
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    indicators = fetch_indicators_command(client, indicator_type=['registry-key-value', 'user-account'], max_fetch=200)
    assert len(indicators) == 2


def test_get_indicators_command(mocker):
    """Tests get_indicators_command function
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user and 'limit': 2
    When
        - Calling `get_indicators_command`
    Then
        - convert the result to human readable table
        - validate the readable_output, raw_response.
    """
    client = Client
    args = {
        'indicator_types': 'registry-key-value,user-account',
        'limit': 2
    }
    mocker.patch.object(client.stix_cyber_observable, 'list', return_value=RESPONSE_DATA)
    results: CommandResults = get_indicators_command(client, args)
    assert len(results.raw_response) == 2
    assert "Indicators from OpenCTI" in results.readable_output


def test_get_indicators_command_with_no_data_to_return(mocker):
    """Tests get_indicators_command function with no data to return
    Given
        The following indicator types: 'registry-key-value', 'user-account' that were chosen by the user.
    When
        - Calling `get_indicators_command`
    Then
        - validate the response to have a "No indicators" string
    """
    client = Client
    args = {
        'indicator_types': ['registry-key-value', 'user-account']
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


def test_indicator_score_update_command(mocker):
    """Tests indicator_score_update_command function
    Given
        id of indicator to update
        key to update
        value to update
    When
        - Calling `indicator_score_update_command`
    Then
        - validate the response to have a "Indicator deleted." string and context as expected
    """
    client = Client
    args = {
        'id': '123456',
        'score': 80,
    }
    mocker.patch.object(client.stix_cyber_observable, 'update_field', return_value={'id': '123456'})
    results: CommandResults = indicator_score_update_command(client, args)
    assert "updated successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


def test_indicator_description_update_command(mocker):
    """Tests indicator_field_update_command function
    Given
        id of indicator to update
        key to update
        value to update
    When
        - Calling `indicator_field_update_command`
    Then
        - validate the response to have a "Indicator deleted." string and context as expected
    """
    client = Client
    args = {
        'id': '123456',
        'description': 'new description'
    }
    mocker.patch.object(client.stix_cyber_observable, 'update_field', return_value={'id': '123456'})
    results: CommandResults = indicator_description_update_command(client, args)
    assert "updated successfully" in results.readable_output
    assert {'id': '123456'} == results.outputs


def test_indicator_create_or_update_command(mocker):
    """Tests indicator_field_update_command function
    Given
        id of indicator to update
        key to update
        value to update
    When
        - Calling `indicator_field_update_command`
    Then
        - validate the response to have a "Indicator deleted." string and context as expected
    """
    client = Client
    args = {
        'id': '123456',
        'score': '20',
        'type': 'Domain-Name',
        'data': "{\"value\": \"devtest.com\"}"
    }
    mocker.patch.object(client.stix_cyber_observable, 'create', return_value={'id': '123456'})
    results: CommandResults = indicator_create_or_update_command(client, args)
    assert "Indicator created successfully" in results.readable_output
    assert 'id' in results.outputs


def test_indicator_marking_add_command(mocker):
    """Tests indicator_marking_add_command function
    Given
        id of indicator to remove
        marking to remove
    When
        - Calling `indicator_marking_add_command`
    Then
        - validate the response to have a "Marking definition added successfully." string at human readable
    """
    client = Client
    args = {
        'id': '123456',
        'marking': 'TLP:RED'
    }
    mark_mock = mocker.MagicMock()
    mark_mock.create.return_value = {'id': '123'}
    mocker.patch('FeedOpenCTI_v2.MarkingDefinition', return_value=mark_mock)
    mocker.patch.object(client.stix_cyber_observable, 'add_marking_definition', return_value=True)
    results: CommandResults = indicator_marking_add_command(client, args)
    assert "Added marking definition successfully" in results.readable_output


def test_indicator_marking_remove_command(mocker):
    """Tests indicator_marking_remove_command function
    Given
        id of indicator to remove
        marking to remove
    When
        - Calling `indicator_marking_remove_command`
    Then
        - validate the response to have a "Marking definition removed successfully." string at human readable
    """
    client = Client
    args = {
        'id': '123456',
        'marking': 'TLP:RED'
    }
    mark_mock = mocker.MagicMock()
    mark_mock.create.return_value = {'id': '123'}
    mocker.patch('FeedOpenCTI_v2.MarkingDefinition', return_value=mark_mock)
    mocker.patch.object(client.stix_cyber_observable, 'remove_marking_definition', return_value=True)
    results: CommandResults = indicator_marking_remove_command(client, args)
    assert "Marking definition removed successfully" in results.readable_output


def test_indicator_label_add_command(mocker):
    """Tests indicator_label_add_command function
    Given
        id of indicator to add label
        label to add
    When
        - Calling `indicator_label_add_command`
    Then
        - validate the response to have a "Label added successfully" string at human readable
    """
    client = Client
    args = {
        'id': '123456',
        'label': 'test-label'
    }
    label_mock = mocker.MagicMock()
    label_mock.create.return_value = {'id': '123'}
    mocker.patch('FeedOpenCTI_v2.Label', return_value=label_mock)
    mocker.patch.object(client.stix_cyber_observable, 'add_label', return_value=True)
    results: CommandResults = indicator_label_add_command(client, args)
    assert "Label added successfully" in results.readable_output


def test_indicator_label_remove_command(mocker):
    """Tests indicator_label_remove_command function
    Given
        id of indicator to remove label
        label to remove
    When
        - Calling `indicator_label_remove_command`
    Then
        - validate the response to have a "Label removed successfully" string at human readable
    """
    client = Client
    args = {
        'id': '123456',
        'label': 'test-label'
    }
    label_mock = mocker.MagicMock()
    label_mock.create.return_value = {'id': '123'}
    mocker.patch('FeedOpenCTI_v2.Label', return_value=label_mock)
    mocker.patch.object(client.stix_cyber_observable, 'remove_label', return_value=True)
    results: CommandResults = indicator_label_remove_command(client, args)
    assert "Label removed successfully" in results.readable_output


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
    results: CommandResults = organization_list_command(client)
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
