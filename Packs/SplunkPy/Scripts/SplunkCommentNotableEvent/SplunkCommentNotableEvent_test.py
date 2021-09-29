import SplunkCommentNotableEvent
import demistomock as demisto
from CommonServerPython import DemistoException
import pytest


def patch_exec_command(mocker, data):
    return mocker.patch.object(demisto, 'executeCommand', return_value=data)


class TestGetNotableDataFromIncident:

    def test_with_empty_data(self, mocker):
        patch_exec_command(mocker, [])
        with pytest.raises(DemistoException):
            SplunkCommentNotableEvent.get_notable_data_from_incident('1')

    def test_with_not_relevant_data(self, mocker):
        patch_exec_command(mocker, [{'Contents': {'data': [{'test': 'test'}]}}])
        with pytest.raises(DemistoException):
            SplunkCommentNotableEvent.get_notable_data_from_incident('1')

    def test_with_notable_id(self, mocker):
        data = [{'Contents': {'data': [{'dbotMirrorId': 'notable_id'}]}}]
        patch_exec_command(mocker, data)
        cmd_args = SplunkCommentNotableEvent.get_notable_data_from_incident('1')
        assert cmd_args == {'eventIDs': 'notable_id'}

    def test_with_notable_id_and_mirror_instance(self, mocker):
        data = [{'Contents': {'data': [{
            'dbotMirrorId': 'notable_id',
            'sourceInstance': 'instance_name'
        }]}}]
        patch_exec_command(mocker, data)
        cmd_args = SplunkCommentNotableEvent.get_notable_data_from_incident('1')
        assert cmd_args == {'eventIDs': 'notable_id', 'using': 'instance_name'}


class TestGetCommandArgs:
    def test_error_raised(self):
        with pytest.raises(DemistoException):
            SplunkCommentNotableEvent.get_command_args({})

    def test_with_notable_id(self):
        cmd_args = SplunkCommentNotableEvent.get_command_args({'notable_id': 'notable_id'})
        assert cmd_args == {'eventIDs': 'notable_id'}

    def test_with_notable_id_and_ncident_id(self):
        cmd_args = SplunkCommentNotableEvent.get_command_args({'notable_id': 'notable_id', 'incident_id': 'incident_id'})
        assert cmd_args == {'eventIDs': 'notable_id'}

    def test_with_incident_id(self, mocker):
        data = [{'Contents': {'data': [{
            'dbotMirrorId': 'notable_id',
            'sourceInstance': 'instance_name'
        }]}}]
        patch_exec_command(mocker, data)
        cmd_args = SplunkCommentNotableEvent.get_command_args({'incident_id': 'incident_id'})
        assert cmd_args == {'eventIDs': 'notable_id', 'using': 'instance_name'}


class TestMain:
    def test_with_notable_id(self, mocker):
        mocker.patch.object(demisto, 'args', return_value={'comment': 'comment', 'notable_id': 'notable_id'})
        execute_command = mocker.patch.object(demisto, 'executeCommand')
        results = mocker.patch.object(demisto, 'results')
        SplunkCommentNotableEvent.main()
        execute_command.assert_called_once_with('splunk-notable-event-edit', {'comment': 'comment', 'eventIDs': 'notable_id'})
        results.assert_called_once_with('ok')

    def test_with_incident_id(self, mocker):
        mocker.patch.object(demisto, 'args', return_value={'comment': 'comment', 'incident_id': 'incident_id'})
        data = [{'Contents': {'data': [{
            'dbotMirrorId': 'notable_id',
            'sourceInstance': 'instance_name'
        }]}}]
        execute_command = patch_exec_command(mocker, data)
        results = mocker.patch.object(demisto, 'results')
        SplunkCommentNotableEvent.main()
        execute_command.assert_any_call("getIncidents", {'id': 'incident_id'})
        execute_command.assert_called_with(
            'executeCommandAt', {
                "command": "splunk-notable-event-edit",
                "incidents": 'incident_id',
                "arguments": {
                    'comment': 'comment',
                    'eventIDs': 'notable_id',
                    'using': 'instance_name'
                }
            }
        )
        assert execute_command.call_count == 2
        results.assert_called_once_with('ok')
