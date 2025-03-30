from pytest import raises   # noqa: PT013


def create_client():
    import os
    from RecordedFutureLists import Client, __version__

    base_url = "https://api.recordedfuture.com/gw/xsoar/"
    verify_ssl = True
    token = os.environ.get("RF_TOKEN")
    headers = {
        "X-RFToken": token,
        "X-RF-User-Agent": f"RecordedFutureLists.py/{__version__} (Linux-5.13.0-1031-aws-x86_64-with) "
        f"XSOAR/{__version__} RFClient/{__version__} (Cortex_XSOAR_6.5.0)",
    }

    return Client(base_url=base_url, verify=verify_ssl, headers=headers, proxy=False)


class TestRFClient:
    def test_whoami(self, mocker):
        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        client.whoami()

        mock_http_request.assert_called_once_with(
            method="get",
            url_suffix="info/whoami",
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
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_http_request = mocker.patch.object(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix, timeout=120, any_other_kwarg=True)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method="post",
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
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_response = {"response": {"data": "mock data"}}

        mocker.patch.object(client, "_http_request", return_value=mock_response)

        mock_url_suffix = "mock_url_suffix"

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
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        mock_return_error = mocker.patch("RecordedFutureLists.return_error")

        client = create_client()

        mock_http_request = mocker.patch.object(
            client,
            "_http_request",
            return_value={"return_error": {"message": "mock error"}},
        )

        mock_url_suffix = "mock_url_suffix"

        client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        mock_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        mock_return_error.assert_called_once_with(message="mock error")

    def test_call_raising_demisto_exception(self, mocker):
        from CommonServerPython import DemistoException
        import demistomock as demisto

        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)
        client = create_client()
        mocked_http_request = mocker.patch.object(client, "_http_request")
        mocked_http_request.side_effect = DemistoException("Some exception as a side effect")
        raises(DemistoException, client._call, "mocked")

    def test_call_response_processing_404(self, mocker):
        """
        Test _call() response processing.
        """

        import os
        import demistomock as demisto
        from CommonServerPython import DemistoException, CommandResults

        STATUS_TO_RETRY = [500, 501, 502, 503, 504]

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {"arg1": "arg1_value", "arg2": "arg2_value"}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        mocker.patch("RecordedFutureLists.return_error")

        client = create_client()

        def mock_http_request_method(*args, **kwargs):
            # Imitate how CommonServerPython handles bad responses (when status code not in ok_codes,
            # or if ok_codes=None - it uses requests.Response.ok to check whether response is good).
            raise DemistoException("404")

        mocker.patch.object(client, "_http_request", mock_http_request_method)

        spy_http_request = mocker.spy(client, "_http_request")

        mock_url_suffix = "mock_url_suffix"

        result = client._call(url_suffix=mock_url_suffix)

        json_data = {
            "demisto_command": mock_command_name,
            "demisto_args": mock_command_args,
        }

        spy_http_request.assert_called_once_with(
            method="post",
            url_suffix=mock_url_suffix,
            json_data=json_data,
            timeout=90,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
        )

        assert isinstance(result, CommandResults)

        assert result.outputs_prefix == ""
        assert result.outputs_key_field == ""
        assert result.outputs == {}
        assert result.raw_response == {}
        assert result.readable_output == "No results found."

    def test_list_search(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {
            "list_names": "arg1_value,arg1_value2",
            "contains": "arg2_value",
        }
        mock_call_args = {
            "list_names": ["arg1_value", "arg1_value2"],
            "contains": ["arg2_value"],
        }

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

        response = client.list_search()

        mock_call.assert_called_once_with(demisto_args=mock_call_args, url_suffix="/v2/lists/search")

        assert response == mock_call_response

    def test_entites_fetch(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        # Mock demisto command and args.
        mock_command_name = "command_name"
        mock_command_args = {
            "list_ids": "arg1_value,arg1_value2",
        }
        mock_call_args = {"list_ids": ["arg1_value", "arg1_value2"]}

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

        response = client.entity_fetch()

        mock_call.assert_called_once_with(demisto_args=mock_call_args, url_suffix="/v2/lists/entities/lookup")

        assert response == mock_call_response

    def test_entity_add_freetext(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        mocked_list_id = "mockvalue"
        mocked_entity_type = "mock"
        mocked_entity_ids = ""
        mocked_freetext_names = "mockedmalwarename"
        mock_command_args = {
            "list_id": mocked_list_id,
            "entity_types": mocked_entity_type,
            "entity_ids": mocked_entity_ids,
            "freetext_names": mocked_freetext_names,
        }
        # Mock demisto command and args.
        mock_command_name = "command_name"

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

        response = client.entity_operation(operation="add")
        mock_call.assert_called_once_with(
            demisto_args=mock_command_args,
            url_suffix=f"/v2/lists/{mocked_list_id}/entities/add",
        )

        assert response == mock_call_response

    def test_entity_add_ids(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        mocked_list_id = "mockvalue"
        mocked_entity_type = "mock"
        mocked_entity_ids = "mockedmalwarename"
        mocked_freetext_names = ""
        mock_command_args = {
            "list_id": mocked_list_id,
            "entity_type": mocked_entity_type,
            "entity_ids": mocked_entity_ids,
            "freetext_names": mocked_freetext_names,
        }
        # Mock demisto command and args.
        mock_command_name = "command_name"

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

        response = client.entity_operation(operation="add")
        mock_call.assert_called_once_with(
            demisto_args=mock_command_args,
            url_suffix=f"/v2/lists/{mocked_list_id}/entities/add",
        )

        assert response == mock_call_response

    def test_entity_remove_ids(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        mocked_list_id = "mockvalue"
        mocked_entity_type = "mock"
        mocked_entity_ids = "mockedmalwarename"
        mocked_freetext_names = ""
        mock_command_args = {
            "list_id": mocked_list_id,
            "entity_type": mocked_entity_type,
            "entity_ids": mocked_entity_ids,
            "freetext_names": mocked_freetext_names,
        }
        # Mock demisto command and args.
        mock_command_name = "command_name"

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mock_call = mocker.patch.object(client, "_call", return_value=mock_call_response)

        response = client.entity_operation(operation="remove")
        mock_call.assert_called_once_with(
            demisto_args=mock_command_args,
            url_suffix=f"/v2/lists/{mocked_list_id}/entities/remove",
        )

        assert response == mock_call_response

    def test_entity_add_invalid_both(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        mocked_list_id = "mockvalue"
        mocked_entity_type = "mock"
        mocked_entity_ids = "mockedmalwarename"
        mocked_freetext_names = "mockedmalwarename"
        mock_command_args = {
            "list_id": mocked_list_id,
            "entity_type": mocked_entity_type,
            "entity_ids": mocked_entity_ids,
            "freetext_names": mocked_freetext_names,
        }
        # Mock demisto command and args.
        mock_command_name = "command_name"

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mocker.patch.object(client, "_call", return_value=mock_call_response)
        raises(ValueError, client.entity_operation, operation="add")

    def test_entity_add_invalid_none(self, mocker):
        import os
        import demistomock as demisto

        # This is needed for CommonServerPython module to not add demisto.params() into callingContext.
        os.environ["COMMON_SERVER_NO_AUTO_PARAMS_REMOVE_NULLS"] = "True"

        mocked_list_id = "mockvalue"
        mocked_entity_type = "mock"
        mocked_entity_ids = ""
        mocked_freetext_names = ""
        mock_command_args = {
            "list_id": mocked_list_id,
            "entity_types": mocked_entity_type,
            "entity_ids": mocked_entity_ids,
            "freetext_names": mocked_freetext_names,
        }
        # Mock demisto command and args.
        mock_command_name = "command_name"

        mocker.patch.object(demisto, "command", return_value=mock_command_name)
        mocker.patch.object(demisto, "args", return_value=mock_command_args)

        client = create_client()

        mock_call_response = {"response": {"data": "mock response"}}
        mocker.patch.object(client, "_call", return_value=mock_call_response)

        raised = False
        try:
            client.entity_operation(operation="add")
        except ValueError:
            raised = True
        assert raised


class TestActions:
    def test_init(self, mocker):
        from RecordedFutureLists import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)
        assert actions.client == mock_client

    def test_process_result_actions_404(self, mocker):
        from RecordedFutureLists import Actions
        from CommonServerPython import CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is CommandResults
        # (case when we got 404 on response, and it was processed in self.client._call() method).
        response = CommandResults(readable_output="Mock")
        result_actions = actions._process_result_actions(response=response)
        assert result_actions == [response]

    def test_process_result_actions_response_is_not_dict(self, mocker):
        from RecordedFutureLists import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test if response is not CommandResults and not Dict.
        response = "Mock string - not CommandResults and not dict"
        result_actions = actions._process_result_actions(response=response)  # type: ignore
        assert result_actions is None

    def test_process_result_actions_no_or_empty_result_actions_in_response(self, mocker):
        from RecordedFutureLists import Actions

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        # Test no results_actions in response.
        response = {"data": "mock"}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        # Test case when bool(results_actions) in response is False.
        response = {"data": "mock", "result_actions": None}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {"data": "mock", "result_actions": []}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

        response = {"data": "mock", "result_actions": {}}
        result_actions = actions._process_result_actions(response=response)
        assert result_actions is None

    def test_process_result_actions_command_results_only(self, mocker):
        from RecordedFutureLists import Actions, CommandResults

        mock_client = mocker.Mock()
        actions = Actions(mock_client)

        response = {
            "data": "mock",
            "result_actions": [
                {
                    "CommandResults": {
                        "outputs_prefix": "mock_outputs_prefix",
                        "outputs": "mock_outputs",
                        "raw_response": "mock_raw_response",
                        "readable_output": "mock_readable_output",
                        "outputs_key_field": "mock_outputs_key_field",
                    },
                }
            ],
        }
        result_actions = actions._process_result_actions(response=response)

        assert len(result_actions) == 1

        r_a = result_actions[0]

        assert isinstance(r_a, CommandResults)

        assert r_a.outputs_prefix == "mock_outputs_prefix"
        assert r_a.outputs == "mock_outputs"
        assert r_a.raw_response == "mock_raw_response"
        assert r_a.readable_output == "mock_readable_output"
        assert r_a.outputs_key_field == "mock_outputs_key_field"

    def test_list_search_command_without_result_actions(self, mocker):
        from RecordedFutureLists import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_lists_list_search = mocker.patch.object(client, "list_search", return_value=mock_response)

        actions = Actions(client)

        mock_process_result_actions_return_value = None
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        actions.list_search_command()

        mock_client_lists_list_search.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

    def test_list_search_command_with_result_actions(self, mocker):
        from RecordedFutureLists import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_lists_list_search = mocker.patch.object(client, "list_search", return_value=mock_response)

        actions = Actions(client)

        mock_process_result_actions_return_value = "mocked_process_return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.list_search_command()

        mock_client_lists_list_search.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_list_entities_command_with_result_actions(self, mocker):
        from RecordedFutureLists import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_lists_list_search = mocker.patch.object(client, "entity_fetch", return_value=mock_response)

        actions = Actions(client)

        mock_process_result_actions_return_value = "mocked_process_return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.entities_get_command()

        mock_client_lists_list_search.assert_called_once_with()

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_entity_add_command_with_result_action(self, mocker):
        from RecordedFutureLists import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_entity_add = mocker.patch.object(client, "entity_operation", return_value=mock_response)

        actions = Actions(client)

        mock_process_result_actions_return_value = "mock_process_result_actions_return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.entity_add_command()

        mock_client_entity_add.assert_called_once_with("add")

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_entity_remove_command_with_result_action(self, mocker):
        from RecordedFutureLists import Actions

        client = create_client()

        mock_response = "mock_response"

        mock_client_entity_add = mocker.patch.object(client, "entity_operation", return_value=mock_response)

        actions = Actions(client)

        mock_process_result_actions_return_value = "mock_process_result_actions_return_value"
        mock_process_result_actions = mocker.patch.object(
            actions,
            "_process_result_actions",
            return_value=mock_process_result_actions_return_value,
        )

        result = actions.entity_remove_command()

        mock_client_entity_add.assert_called_once_with("remove")

        mock_process_result_actions.assert_called_once_with(response=mock_response)

        assert result == mock_process_result_actions_return_value

    def test_test_module(self, mocker):
        import RecordedFutureLists
        import demistomock as demisto
        import platform

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "demistoVersion", return_value={"version": "mock_version"})
        mocker.patch.object(demisto, "params", return_value={"token": {"password": "mocktoken"}})
        mocker.patch.object(platform, "platform", return_value="mock_platform")
        mocker.patch.object(RecordedFutureLists.Client, "whoami")
        mocked_return_res = mocker.patch.object(RecordedFutureLists, "return_results")
        RecordedFutureLists.main()
        mocked_return_res.assert_called_with("ok")

    def test_test_module_with_boom(self, mocker):
        import RecordedFutureLists
        import demistomock as demisto
        import platform

        mocker.patch.object(demisto, "command", return_value="test-module")
        mocker.patch.object(demisto, "demistoVersion", return_value={"version": "mock_version"})
        mocker.patch.object(demisto, "params", return_value={"token": {"password": "mocktoken"}})
        mocker.patch.object(platform, "platform", return_value="mock_platform")
        mock_whoami = mocker.patch.object(RecordedFutureLists.Client, "whoami")
        mock_whoami.side_effect = Exception("Side effect triggered")
        mocked_return_err = mocker.patch.object(RecordedFutureLists, "return_error")
        RecordedFutureLists.main()
        mocked_return_err.assert_called_with(
            message=(
                f"Failed to execute {demisto.command()} command: Failed due to - "
                "Unknown error. Please verify that the API URL and Token are correctly configured. "
                "RAW Error: Side effect triggered"
            )
        )
