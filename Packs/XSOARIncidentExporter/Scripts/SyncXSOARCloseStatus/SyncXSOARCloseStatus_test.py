import pytest
from SyncXSOARCloseStatus import extract_field, map_close_reason, XSIAMClient, main


class TestExtractField:
    def test_extracts_simple_field(self):
        desc = 'XSOAR Incident ID: 123\nName: Test'
        assert extract_field(desc, 'XSOAR Incident ID') == '123'

    def test_returns_empty_when_missing(self):
        assert extract_field('Name: Test', 'Status') == ''

    def test_extracts_field_at_end_of_string(self):
        assert extract_field('Status: Done', 'Status') == 'Done'


class TestMapCloseReason:
    def test_resolved(self):
        assert map_close_reason('Resolved') == 'STATUS_030_RESOLVED_THREAT_HANDLED'

    def test_false_positive(self):
        assert map_close_reason('False Positive') == 'STATUS_060_RESOLVED_FALSE_POSITIVE'

    def test_duplicate(self):
        assert map_close_reason('Duplicate') == 'STATUS_050_RESOLVED_DUPLICATE'

    def test_other(self):
        assert map_close_reason('Other') == 'STATUS_080_RESOLVED_OTHER'

    def test_case_insensitive(self):
        assert map_close_reason('RESOLVED') == 'STATUS_030_RESOLVED_THREAT_HANDLED'

    def test_unknown_maps_to_other(self):
        assert map_close_reason('Custom') == 'STATUS_080_RESOLVED_OTHER'

    def test_empty_maps_to_other(self):
        assert map_close_reason('') == 'STATUS_080_RESOLVED_OTHER'


CLOSED_ALERT_DESC = (
    'XSOAR Incident ID: 42\n'
    'Status: Done\n'
    'Close Reason: Resolved\n'
    'Close Notes: Fixed the issue'
)

OPEN_ALERT_DESC = (
    'XSOAR Incident ID: 43\n'
    'Status: Active\n'
    'Close Reason: \n'
    'Close Notes: '
)


def _make_alert(alert_id, description, name='Test Alert'):
    return {
        'alert_id': alert_id,
        'name': name,
        'description': description,
        'events': [],
    }


class TestMain:
    def test_no_alerts_found(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
            'max_alerts': '100',
        }

        mock_http = mocker.patch.object(
            XSIAMClient, '_http_request',
            return_value={'reply': {'alerts': [], 'total_count': 0}},
        )
        mock_return = mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        result = mock_return.call_args[0][0]
        assert 'No open XSOAR-sourced alerts' in result.readable_output

    def test_closes_resolved_alerts(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
            'max_alerts': '100',
        }

        alerts = [_make_alert(1001, CLOSED_ALERT_DESC)]
        responses = [
            {'reply': {'alerts': alerts, 'total_count': 1}},
            {'reply': True},
        ]
        call_count = iter(responses)
        mock_http = mocker.patch.object(
            XSIAMClient, '_http_request',
            side_effect=lambda **kwargs: next(call_count),
        )
        mock_return = mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        assert mock_http.call_count == 2
        update_call = mock_http.call_args_list[1]
        assert update_call.kwargs['url_suffix'] == '/public_api/v1/alerts/update_alerts'
        body = update_call.kwargs['json_data']
        assert body['request_data']['alert_id_list'] == [1001]
        assert body['request_data']['resolution_status'] == 'STATUS_030_RESOLVED_THREAT_HANDLED'

        result = mock_return.call_args[0][0]
        assert result.outputs['ClosedCount'] == 1

    def test_skips_open_alerts(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
            'max_alerts': '100',
        }

        alerts = [_make_alert(1002, OPEN_ALERT_DESC)]
        mock_http = mocker.patch.object(
            XSIAMClient, '_http_request',
            return_value={'reply': {'alerts': alerts, 'total_count': 1}},
        )
        mock_return = mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        assert mock_http.call_count == 1
        result = mock_return.call_args[0][0]
        assert result.outputs['ClosedCount'] == 0
        assert result.outputs['SkippedCount'] == 1

    def test_mixed_alerts(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
            'max_alerts': '100',
        }

        alerts = [
            _make_alert(1001, CLOSED_ALERT_DESC),
            _make_alert(1002, OPEN_ALERT_DESC),
        ]
        responses = [
            {'reply': {'alerts': alerts, 'total_count': 2}},
            {'reply': True},
        ]
        call_count = iter(responses)
        mocker.patch.object(
            XSIAMClient, '_http_request',
            side_effect=lambda **kwargs: next(call_count),
        )
        mock_return = mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        result = mock_return.call_args[0][0]
        assert result.outputs['ClosedCount'] == 1
        assert result.outputs['SkippedCount'] == 1

    def test_missing_credentials_returns_error(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': '',
            'xsiam_api_key': '',
            'xsiam_api_key_id': '',
        }

        mock_error = mocker.patch('SyncXSOARCloseStatus.return_error')

        main()

        mock_error.assert_called_once()
        assert 'required' in mock_error.call_args[0][0].lower()

    def test_insecure_default_false(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
        }

        mock_http = mocker.patch.object(
            XSIAMClient, '_http_request',
            return_value={'reply': {'alerts': [], 'total_count': 0}},
        )
        mock_init = mocker.patch.object(XSIAMClient, '__init__', return_value=None)
        mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        init_kwargs = mock_init.call_args
        assert init_kwargs.kwargs.get('verify') is True or init_kwargs[1].get('verify') is True

    def test_description_from_events_fallback(self, mocker):
        mocker.patch('SyncXSOARCloseStatus.demisto')
        from SyncXSOARCloseStatus import demisto as mock_demisto

        mock_demisto.args.return_value = {
            'xsiam_url': 'https://api-test.xdr.us.paloaltonetworks.com',
            'xsiam_api_key': 'test-key',
            'xsiam_api_key_id': '1',
            'max_alerts': '100',
        }

        alert = {
            'alert_id': 2001,
            'name': 'Event Alert',
            'description': '',
            'events': [{'alert_description': CLOSED_ALERT_DESC}],
        }
        responses = [
            {'reply': {'alerts': [alert], 'total_count': 1}},
            {'reply': True},
        ]
        call_count = iter(responses)
        mocker.patch.object(
            XSIAMClient, '_http_request',
            side_effect=lambda **kwargs: next(call_count),
        )
        mock_return = mocker.patch('SyncXSOARCloseStatus.return_results')

        main()

        result = mock_return.call_args[0][0]
        assert result.outputs['ClosedCount'] == 1
