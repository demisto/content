def create_client():
    import os
    from RecordedFuturePlaybookAlerts import (
        Client,
        __version__
        )

    base_url = 'https://api.recordedfuture.com/gw/xsoar/'
    verify_ssl = True
    token = os.environ.get('RF_TOKEN')
    headers = {
        'X-RFToken': token,
        'X-RF-User-Agent': f"RecordedFuturePlaybookAlerts.py/{__version__} (Linux-5.13.0-1031-aws-x86_64-with) "
                           "XSOAR/2.4 RFClient/2.4 (Cortex_XSOAR_6.5.0)",
    }

    return Client(
        base_url=base_url, verify=verify_ssl, headers=headers, proxy=False
    )

class TestRFClient:

    def test_whoami(self, mocker):
        client = create_client()

        mock_http_request = mocker.patch.object(client, '_http_request')

        client.whoami()

        mock_http_request.assert_called_once_with(
            method='get',
            url_suffix='info/whoami',
            timeout=60,
        )

    def test_call_with_kwargs(self, mocker):
        """
        Test _call() with kwargs.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        client = create_client()

        mock_http_request = mocker.patch.object(client, '_http_request')

        mock_url_suffix = 'mock_url_suffix'

        client._call(url_suffix=mock_url_suffix, timeout=120, any_other_kwarg=True)

        json_data = {
            'demisto_command': mock_command_name,
            'demisto_args': mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method='post',
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=120,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
            any_other_kwarg=True,
        )

    def test_call_returns_response(self, mocker):
        """
        Test _call() returns response.
        """

        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        client = create_client()

        mock_response = {
            'response': {
                'data': 'mock data'
            }
        }

        mocker.patch.object(
            client,
            '_http_request',
            return_value=mock_response
        )

        mock_url_suffix = 'mock_url_suffix'

        response = client._call(url_suffix=mock_url_suffix)
        assert response == mock_response

    def test_call_response_processing_return_error(self, mocker):
        """
        Test _call() return_error response processing.
        """

        import os
        import demistomock as demisto

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        mock_return_error = mocker.patch('RecordedFuture.return_error')

        client = create_client()

        mock_http_request = mocker.patch.object(
            client,
            '_http_request',
            return_value={
                'return_error': {
                    'message': 'mock error'
                }
            }
        )

        mock_url_suffix = 'mock_url_suffix'

        client._call(url_suffix=mock_url_suffix)

        json_data = {
            'demisto_command': mock_command_name,
            'demisto_args': mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method='post',
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        mock_return_error.assert_called_once_with(
            message='mock error'
        )

    def test_call_response_processing_404(self, mocker):
        """
        Test _call() response processing.
        """

        import os
        import demistomock as demisto
        from CommonServerPython import DemistoException, CommandResults

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        mocker.patch('RecordedFuture.return_error')

        client = create_client()

        def mock_http_request_method(*args, **kwargs):
            # Imitate how CommonServerPython handles bad responses (when status code not in ok_codes,
            # or if ok_codes=None - it uses requests.Response.ok to check whether response is good).
            raise DemistoException('404')

        mocker.patch.object(
            client,
            '_http_request',
            mock_http_request_method
        )

        spy_http_request = mocker.spy(client, '_http_request')

        mock_url_suffix = 'mock_url_suffix'

        result = client._call(url_suffix=mock_url_suffix)

        json_data = {
            'demisto_command': mock_command_name,
            'demisto_args': mock_command_args,
        }

        spy_http_request.assert_called_once_with(
            method='post',
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        assert isinstance(result, CommandResults)

        assert result.outputs_prefix == ''
        assert result.outputs_key_field == ''
        assert result.outputs == dict()
        assert result.raw_response == dict()
        assert result.readable_output == 'No results found.'


    # TODO REWRITE THIS TO WORK WITH PLAYBOOK ALERTS
    def test_fetch_incidents(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}
        mock_params = {'param1': 'param1 value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)
        mocker.patch.object(demisto, 'params', return_value=mock_params)

        mock_last_run_dict = {"lastRun": "2022-08-31T12:12:20+00:00"}
        mocker.patch.object(demisto, 'getLastRun', return_value=mock_last_run_dict)

        client = create_client()

        mock_call_response = {
            'response': {
                'data': 'mock response'
            }
        }
        mock_call = mocker.patch.object(client, '_call', return_value=mock_call_response)

        response = client.fetch_incidents()

        mock_call.assert_called_once_with(
            json_data={
                'demisto_command': mock_command_name,
                'demisto_args': mock_command_args,
                'demisto_last_run': mock_last_run_dict,
                'demisto_params': mock_params
            },
            timeout=120,
            url_suffix='/v2/alert/fetch_incidents'
        )

        assert response == mock_call_response

    # TODO REWRITE THIS TO WORK WITH PLAYBOOK ALERTS (SEARCH)
    def test_entity_search(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        client = create_client()

        mock_call_response = {
            'response': {
                'data': 'mock response'
            }
        }
        mock_call = mocker.patch.object(client, '_call', return_value=mock_call_response)

        response = client.entity_search()

        mock_call.assert_called_once_with(
            url_suffix='/v2/search'
        )

        assert response == mock_call_response
        
    # TODO REWRITE THIS TO WORK WITH PLAYBOOK ALERTS (DETAILS)
    def test_get_intelligence(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        client = create_client()

        mock_call_response = {
            'response': {
                'data': 'mock response'
            }
        }
        mock_call = mocker.patch.object(client, '_call', return_value=mock_call_response)

        response = client.get_intelligence()

        mock_call.assert_called_once_with(
            url_suffix='/v2/lookup/intelligence'
        )

        assert response == mock_call_response
    
    # TODO REWRITE THIS TO WORK WITH PLAYBOOK ALERTS (update)
    def test_alert_set_status(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ['COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS'] = 'True'

        # Mock demisto command and args.
        mock_command_name = 'command_name'
        mock_command_args = {'arg1': 'arg1_value', 'arg2': 'arg2_value'}

        mocker.patch.object(demisto, 'command', return_value=mock_command_name)
        mocker.patch.object(demisto, 'args', return_value=mock_command_args)

        client = create_client()

        mock_call_response = {
            'response': {
                'data': 'mock response'
            }
        }
        mock_call = mocker.patch.object(client, '_call', return_value=mock_call_response)

        alert_data = {
            'mock': 'data'
        }
        response = client.alert_set_status(alert_data)

        mock_call.assert_called_once_with(
            url_suffix='/v2/alert/set_status',
            json_data={
                'demisto_command': mock_command_name,
                'demisto_args': mock_command_args,
                'alerts_update_data': alert_data
            },
        )

        assert response == mock_call_response

        response = client.alert_set_status()

        mock_call.assert_called_with(
            url_suffix='/v2/alert/set_status',
            json_data={
                'demisto_command': mock_command_name,
                'demisto_args': mock_command_args,
                'alerts_update_data': None
            },
        )

        assert response == mock_call_response

class TestActions:

    def test_init(self, mocker):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)
        assert actions.client == mock_client

    def test_process_result_actions_404(self, mocker):
        from RecordedFuture import Actions
        from CommonServerPython import CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is CommandResults
        # (case when we got 404 on response, and it was processed in self.client._call() method).
        response = CommandResults(readable_output='Mock')
        result_actions = actions._process_result_actions(response=response)
        assert result_actions == [response]

    def test_process_result_actions_response_is_not_dict(self, mocker):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is not CommandResults and not Dict.
        response = 'Mock string - not CommandResults and not dict'
        result_actions = actions._process_result_actions(response=response)  # type: ignore
        assert result_actions is None

    def test_process_result_actions_no_or_empty_result_actions_in_response(self, mocker):
        from RecordedFuture import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test no results_actions in response.
        response = {
            'data': 'mock'
        }
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        # Test case when bool(results_actions) in response is False.
        response = {
            'data': 'mock',
            'result_actions': None
        }
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {
            'data': 'mock',
            'result_actions': list()
        }
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {
            'data': 'mock',
            'result_actions': dict()
        }
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

    def test_process_result_actions_command_results_only(self, mocker):
        from RecordedFuture import Actions, CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        response = {
            'data': 'mock',
            'result_actions': [{
                'CommandResults': {
                    'outputs_prefix': 'mock_outputs_prefix',
                    'outputs': 'mock_outputs',
                    'raw_response': 'mock_raw_response',
                    'readable_output': 'mock_readable_output',
                    'outputs_key_field': 'mock_outputs_key_field'
                },
            }]
        }
        result_actions = actions._process_result_actions(response=response)

        assert len(result_actions) == 1

        r_a = result_actions[0]

        assert isinstance(r_a, CommandResults)

        assert r_a.outputs_prefix == 'mock_outputs_prefix'
        assert r_a.outputs == 'mock_outputs'
        assert r_a.raw_response == 'mock_raw_response'
        assert r_a.readable_output == 'mock_readable_output'
        assert r_a.outputs_key_field == 'mock_outputs_key_field'
    
    # TODO REWRITE THIS TO WORK WITH PLAYBOOK ALERTS
    def test_fetch_incidents_with_incidents_present(self, mocker):
        from RecordedFuture import Actions
        import demistomock as demisto

        client = create_client()

        mock_incidents_value = [
            {'mock_incident_key1': 'mock_incident_value1'},
            {'mock_incident_key2': 'mock_incident_value2'},
        ]

        mock_demisto_last_run_value = 'mock_demisto_last_run'

        mock_alerts_update_data_value = 'mock_alerts_update_data_value'

        mock_client_fetch_incidents_response = {
            'incidents': mock_incidents_value,
            'demisto_last_run': mock_demisto_last_run_value,
            'data': 'mock',
            'alerts_update_data': mock_alerts_update_data_value
        }
        mock_client_fetch_incidents = mocker.patch.object(
            client,
            'fetch_incidents',
            return_value=mock_client_fetch_incidents_response
        )

        mock_client_alert_set_status = mocker.patch.object(
            client,
            'alert_set_status',
        )

        mock_demisto_incidents = mocker.patch.object(demisto, 'incidents')
        mock_demisto_set_last_run = mocker.patch.object(demisto, 'setLastRun')

        actions = Actions(client)

        actions.fetch_incidents()

        mock_client_fetch_incidents.assert_called_once_with()

        mock_demisto_incidents.assert_called_once_with(mock_incidents_value)
        mock_demisto_set_last_run.assert_called_once_with(mock_demisto_last_run_value)

        # Verify that we update alert status.
        mock_client_alert_set_status.assert_called_once_with(mock_alerts_update_data_value)

    def test_get_single_alert_command_with_result_actions(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = 'mock_response'

        mock_client_get_single_alert = mocker.patch.object(
            client,
            'get_single_alert',
            return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = 'mock_process_result_actions_return_value'
        mock_process_result_actions = mocker.patch.object(
            actions,
            '_process_result_actions',
            return_value=mock_process_result_actions_return_value
        )

        result = actions.get_single_alert_command()

        mock_client_get_single_alert.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        # As there are some result actions - return those result actions.
        assert result == mock_process_result_actions_return_value

    def test_get_single_alert_command_without_result_actions(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = 'mock_response'

        mock_client_get_single_alert = mocker.patch.object(
            client,
            'get_single_alert',
            return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = None
        mock_process_result_actions = mocker.patch.object(
            actions,
            '_process_result_actions',
            return_value=mock_process_result_actions_return_value
        )

        result = actions.get_single_alert_command()

        mock_client_get_single_alert.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        # As there is no result actions - just return response.
        assert result == mock_response

    def test_get_alerts_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = 'mock_response'

        mock_client_get_alerts = mocker.patch.object(
            client,
            'get_alerts',
            return_value=mock_response
        )

        actions = Actions(client)

        result = actions.get_alerts_command()

        mock_client_get_alerts.assert_called_once_with()

        assert result == mock_response


    def test_alert_set_status_command(self, mocker):
        from RecordedFuture import Actions

        client = create_client()

        mock_response = 'mock_response'

        mock_client_alert_set_status = mocker.patch.object(
            client,
            'alert_set_status',
            return_value=mock_response
        )

        actions = Actions(client)

        mock_process_result_actions_return_value = 'mock_process_result_actions_return_value'
        mock_process_result_actions = mocker.patch.object(
            actions,
            '_process_result_actions',
            return_value=mock_process_result_actions_return_value
        )

        result = actions.alert_set_status_command()

        mock_client_alert_set_status.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value



