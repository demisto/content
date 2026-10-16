import pytest
from CloseFromXSOAR import extract_field, map_close_reason, main


class TestExtractField:
    def test_extracts_simple_field(self):
        desc = 'XSOAR Incident ID: 123\nName: Test'
        assert extract_field(desc, 'XSOAR Incident ID') == '123'

    def test_extracts_field_at_end(self):
        desc = 'Status: Done'
        assert extract_field(desc, 'Status') == 'Done'

    def test_returns_empty_when_missing(self):
        desc = 'Name: Test'
        assert extract_field(desc, 'Status') == ''

    def test_extracts_multiword_value(self):
        desc = 'Close Reason: False Positive\nNext: field'
        assert extract_field(desc, 'Close Reason') == 'False Positive'

    def test_strips_whitespace(self):
        desc = 'Status:   Done  \nNext: x'
        assert extract_field(desc, 'Status') == 'Done'


class TestMapCloseReason:
    def test_resolved(self):
        assert map_close_reason('Resolved') == 'Resolved'

    def test_false_positive(self):
        assert map_close_reason('False Positive') == 'False Positive'

    def test_duplicate(self):
        assert map_close_reason('Duplicate') == 'Duplicate'

    def test_other(self):
        assert map_close_reason('Other') == 'Other'

    def test_case_insensitive(self):
        assert map_close_reason('RESOLVED') == 'Resolved'

    def test_unknown_maps_to_other(self):
        assert map_close_reason('Custom Reason') == 'Other'

    def test_empty_maps_to_other(self):
        assert map_close_reason('') == 'Other'


class TestMain:
    def _build_incident(self, status='Done', close_reason='Resolved', close_notes='Fixed it'):
        desc = (
            f'XSOAR Incident ID: 42\n'
            f'Name: Test Incident\n'
            f'Status: {status}\n'
            f'Close Reason: {close_reason}\n'
            f'Close Notes: {close_notes}'
        )
        return {
            'CustomFields': {'alertdescription': desc},
            'labels': [],
            'details': '',
        }

    def test_closed_incident_closes_case(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        mock_demisto.incident.return_value = self._build_incident()
        mock_demisto.executeCommand.return_value = [{'Type': 1, 'Contents': 'ok'}]

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        mock_demisto.executeCommand.assert_called_once_with(
            'closeInvestigation',
            {
                'closeReason': 'Resolved',
                'closeNotes': 'Closed in XSOAR as: Resolved\nXSOAR Close Notes: Fixed it',
            },
        )
        result = mock_return.call_args[0][0]
        assert 'Closed XSIAM Case' in result.readable_output
        assert result.outputs['Action'] == 'closed'

    def test_open_incident_no_action(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        mock_demisto.incident.return_value = self._build_incident(status='Active')

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        mock_demisto.executeCommand.assert_not_called()
        result = mock_return.call_args[0][0]
        assert result.outputs['Action'] == 'none'

    def test_archive_status_closes_case(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        mock_demisto.incident.return_value = self._build_incident(status='Archive')
        mock_demisto.executeCommand.return_value = [{'Type': 1, 'Contents': 'ok'}]

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        mock_demisto.executeCommand.assert_called_once()
        result = mock_return.call_args[0][0]
        assert result.outputs['Action'] == 'closed'

    def test_falls_back_to_labels(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        desc = 'XSOAR Incident ID: 55\nStatus: Done\nClose Reason: Duplicate\nClose Notes: dup'
        mock_demisto.incident.return_value = {
            'CustomFields': {},
            'labels': [{'type': 'alertdescription', 'value': desc}],
            'details': '',
        }
        mock_demisto.executeCommand.return_value = [{'Type': 1, 'Contents': 'ok'}]

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        result = mock_return.call_args[0][0]
        assert result.outputs['XSIAMCloseReason'] == 'Duplicate'

    def test_falls_back_to_details(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        desc = 'XSOAR Incident ID: 77\nStatus: Done\nClose Reason: Other\nClose Notes: '
        mock_demisto.incident.return_value = {
            'CustomFields': {},
            'labels': [],
            'details': desc,
        }
        mock_demisto.executeCommand.return_value = [{'Type': 1, 'Contents': 'ok'}]

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        result = mock_return.call_args[0][0]
        assert result.outputs['Action'] == 'closed'

    def test_no_close_notes(self, mocker):
        mocker.patch('CloseFromXSOAR.demisto')
        from CloseFromXSOAR import demisto as mock_demisto

        mock_demisto.incident.return_value = self._build_incident(close_notes='')
        mock_demisto.executeCommand.return_value = [{'Type': 1, 'Contents': 'ok'}]

        mock_return = mocker.patch('CloseFromXSOAR.return_results')

        main()

        call_args = mock_demisto.executeCommand.call_args[0][1]
        assert 'XSOAR Close Notes' not in call_args['closeNotes']
