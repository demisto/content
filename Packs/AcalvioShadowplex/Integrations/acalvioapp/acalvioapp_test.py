from test_data.api_responses \
    import test_connection_success, test_connection_failure, \
    test_connection_invalid_api_key, test_decoy_host_true, \
    test_decoy_host_false, test_decoy_user_true, test_decoy_user_false, \
    test_decoy_file_true, test_decoy_file_false, test_mute_decoy_true, \
    test_mute_decoy_false, test_mute_again_already_muted_decoy, \
    test_unmute_decoy_true, test_unmute_decoy_false, test_unmute_host_false, \
    test_mute_host_true, test_unmute_again_already_unmuted_decoy, \
    test_missing_parameter, test_mute_host_false, test_unmute_host_true, \
    test_server_error, test_unmute_already_unmuted_host, \
    test_mute_already_muted_host

from test_data.api_request_data import BASE_URL, \
    apikey, content_type, decoy_host, ep_host, decoy_filename, \
    decoy_user, domain

from acalvioapp import Client


headers = {
    'api_key': apikey,
    'content-type': content_type
}

client = Client(
    base_url=BASE_URL,
    verify=False,
    headers=headers
)


class MockRequestsResponse:
    def __init__(self, json_data, status_code, reason, text=''):
        self.json_data = json_data
        self.status_code = status_code
        self.reason = reason
        self.text = text

    def json(self):
        return self.json_data


def test_do_test_connection_success(mocker):
    from acalvioapp import do_test_connection
    mock_response = MockRequestsResponse(
        json_data=test_connection_success.__getitem__('HTTP Body'),
        status_code=test_connection_success.__getitem__('HTTP Status Code'),
        reason=test_connection_success.__getitem__('HTTP Reason'),
        text=test_connection_success.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_test_connection(client)
    assert result.lower() == 'ok'
    assert error is None


def test_do_test_connection_failure(mocker):
    from acalvioapp import do_test_connection
    mock_response = MockRequestsResponse(
        json_data=test_connection_failure.__getitem__('HTTP Body'),
        status_code=test_connection_failure.__getitem__('HTTP Status Code'),
        reason=test_connection_failure.__getitem__('HTTP Reason'),
        text=test_connection_failure.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_test_connection(client)
    assert result is None
    assert error.outputs['error'] is True
    assert error.outputs['details']['result'] is False


def test_do_test_connection_unauthorized(mocker):
    from acalvioapp import do_test_connection
    mock_response = MockRequestsResponse(
        json_data=test_connection_invalid_api_key.__getitem__('HTTP Body'),
        status_code=test_connection_invalid_api_key
        .__getitem__('HTTP Status Code'),
        reason=test_connection_invalid_api_key.__getitem__('HTTP Reason'),
        text=test_connection_invalid_api_key.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_test_connection(client)
    assert result is None
    assert error.outputs['error'] is True
    assert error.outputs['details']['msg'] == "Invalid API KEY"


def test_do_test_connection_error(mocker):
    from acalvioapp import do_test_connection
    mock_response = MockRequestsResponse(
        json_data=test_server_error.__getitem__('HTTP Body'),
        status_code=test_server_error.__getitem__('HTTP Status Code'),
        reason=test_server_error.__getitem__('HTTP Reason'),
        text=test_server_error.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_test_connection(client)
    assert result is None
    assert error.outputs['error'] is True
    assert error.outputs['details']['msg'] == "Internal Server Error"


def test_do_deception_host_command_decoy_exists(mocker):
    from acalvioapp import \
        do_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_host_true.__getitem__('HTTP Body'),
        status_code=test_decoy_host_true.__getitem__('HTTP Status Code'),
        reason=test_decoy_host_true.__getitem__('HTTP Reason'),
        text=test_decoy_host_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_host_command(client, {"host": decoy_host})
    assert result.outputs['is_deception'] is True
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_deception_host_command_decoy_not_exists(mocker):
    from acalvioapp import \
        do_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_host_false.__getitem__('HTTP Body'),
        status_code=test_decoy_host_false.__getitem__('HTTP Status Code'),
        reason=test_decoy_host_false.__getitem__('HTTP Reason'),
        text=test_decoy_host_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_host_command(client, {"host": decoy_host})
    assert result.outputs['is_deception'] is False
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_deception_file_command_decoy_file_exists(mocker):
    from acalvioapp import \
        do_deception_file_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_file_true.__getitem__('HTTP Body'),
        status_code=test_decoy_file_true.__getitem__('HTTP Status Code'),
        reason=test_decoy_file_true.__getitem__('HTTP Reason'),
        text=test_decoy_file_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_file_command(client,
                                              {"filename": decoy_filename,
                                               'endpoint': ep_host})
    assert result.outputs['is_deception'] is True
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_deception_file_command_decoy_file_not_exists(mocker):
    from acalvioapp import \
        do_deception_file_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_file_false.__getitem__('HTTP Body'),
        status_code=test_decoy_file_false.__getitem__('HTTP Status Code'),
        reason=test_decoy_file_false.__getitem__('HTTP Reason'),
        text=test_decoy_file_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_file_command(client,
                                              {"filename": decoy_filename,
                                               'endpoint': ep_host})
    assert result.outputs['is_deception'] is False
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_deception_user_command_user_exists(mocker):
    from acalvioapp import \
        do_deception_user_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_user_true.__getitem__('HTTP Body'),
        status_code=test_decoy_user_true.__getitem__('HTTP Status Code'),
        reason=test_decoy_user_true.__getitem__('HTTP Reason'),
        text=test_decoy_user_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_user_command(client,
                                              {"username": decoy_user,
                                               "domain": domain})
    assert result.outputs['is_deception'] is True
    assert result.outputs['username'] == decoy_user
    assert result.outputs['domain'] == domain
    assert error is None


def test_do_deception_user_command_user_not_exists(mocker):
    from acalvioapp import \
        do_deception_user_command
    mock_response = MockRequestsResponse(
        json_data=test_decoy_user_false.__getitem__('HTTP Body'),
        status_code=test_decoy_user_false.__getitem__('HTTP Status Code'),
        reason=test_decoy_user_false.__getitem__('HTTP Reason'),
        text=test_decoy_user_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_user_command(client,
                                              {"username": decoy_user,
                                               "domain": domain})
    assert result.outputs['is_deception'] is False
    assert result.outputs['username'] == decoy_user
    assert result.outputs['domain'] == domain
    assert error is None


def test_do_mute_deception_host_command_decoy_exists(mocker):
    from acalvioapp import \
        do_mute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_decoy_true.__getitem__('HTTP Body'),
        status_code=test_mute_decoy_true.__getitem__('HTTP Status Code'),
        reason=test_mute_decoy_true.__getitem__('HTTP Reason'),
        text=test_mute_decoy_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_host_command(client,
                                                   {"host": decoy_host})
    assert result.outputs['is_mute'] is True
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_mute_deception_host_command_decoy_not_exists(mocker):
    from acalvioapp import \
        do_mute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_decoy_false.__getitem__('HTTP Body'),
        status_code=test_mute_decoy_false.__getitem__('HTTP Status Code'),
        reason=test_mute_decoy_false.__getitem__('HTTP Reason'),
        text=test_mute_decoy_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_host_command(client,
                                                   {"host": decoy_host})
    assert result.outputs['is_mute'] is False
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_mute_deception_host_command_decoy_already_muted(mocker):
    from acalvioapp import \
        do_mute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_again_already_muted_decoy.__getitem__('HTTP Body'),
        status_code=test_mute_again_already_muted_decoy.
        __getitem__('HTTP Status Code'),
        reason=test_mute_again_already_muted_decoy.__getitem__('HTTP Reason'),
        text=test_mute_again_already_muted_decoy.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_host_command(client,
                                                   {"host": decoy_host})
    assert result.outputs['is_mute'] is True
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_unmute_deception_host_command_decoy_exists(mocker):
    from acalvioapp import \
        do_unmute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_decoy_true.__getitem__('HTTP Body'),
        status_code=test_unmute_decoy_true.__getitem__('HTTP Status Code'),
        reason=test_unmute_decoy_true.__getitem__('HTTP Reason'),
        text=test_unmute_decoy_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_host_command(client,
                                                     {"host": decoy_host})
    assert result.outputs['is_unmute'] is True
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_unmute_deception_host_command_decoy_not_exists(mocker):
    from acalvioapp import \
        do_unmute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_decoy_false.__getitem__('HTTP Body'),
        status_code=test_unmute_decoy_false.__getitem__('HTTP Status Code'),
        reason=test_unmute_decoy_false.__getitem__('HTTP Reason'),
        text=test_unmute_decoy_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_host_command(client,
                                                     {"host": decoy_host})
    assert result.outputs['is_unmute'] is False
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_unmute_deception_host_command_decoy_already_unmuted(mocker):
    from acalvioapp import \
        do_unmute_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_again_already_unmuted_decoy.
        __getitem__('HTTP Body'),
        status_code=test_unmute_again_already_unmuted_decoy.
        __getitem__('HTTP Status Code'),
        reason=test_unmute_again_already_unmuted_decoy.
        __getitem__('HTTP Reason'),
        text=test_unmute_again_already_unmuted_decoy.
        __getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_host_command(client,
                                                     {"host": decoy_host})
    assert result.outputs['is_unmute'] is True
    assert result.outputs['host'] == decoy_host
    assert error is None


def test_do_mute_deception_ep_command_ep_exists(mocker):
    from acalvioapp import \
        do_mute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_host_true.__getitem__('HTTP Body'),
        status_code=test_mute_host_true.__getitem__('HTTP Status Code'),
        reason=test_mute_host_true.__getitem__('HTTP Reason'),
        text=test_mute_host_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_ep_command(client,
                                                 {"endpoint": ep_host})
    assert result.outputs['is_mute'] is True
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_mute_deception_ep_command_ep_not_exists(mocker):
    from acalvioapp import \
        do_mute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_host_false.__getitem__('HTTP Body'),
        status_code=test_mute_host_false.__getitem__('HTTP Status Code'),
        reason=test_mute_host_false.__getitem__('HTTP Reason'),
        text=test_mute_host_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_ep_command(client,
                                                 {"endpoint": ep_host})
    assert result.outputs['is_mute'] is False
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_mute_deception_ep_command_ep_already_muted(mocker):
    from acalvioapp import \
        do_mute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_mute_already_muted_host.__getitem__('HTTP Body'),
        status_code=test_mute_already_muted_host.
        __getitem__('HTTP Status Code'),
        reason=test_mute_already_muted_host.__getitem__('HTTP Reason'),
        text=test_mute_already_muted_host.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_mute_deception_ep_command(client,
                                                 {"endpoint": ep_host})
    assert result.outputs['is_mute'] is True
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_unmute_deception_ep_command_ep_exists(mocker):
    from acalvioapp import \
        do_unmute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_host_true.__getitem__('HTTP Body'),
        status_code=test_unmute_host_true.__getitem__('HTTP Status Code'),
        reason=test_unmute_host_true.__getitem__('HTTP Reason'),
        text=test_unmute_host_true.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_ep_command(client,
                                                   {"endpoint": ep_host})
    assert result.outputs['is_unmute'] is True
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_unmute_deception_ep_command_ep_not_exists(mocker):
    from acalvioapp import \
        do_unmute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_host_false.__getitem__('HTTP Body'),
        status_code=test_unmute_host_false.__getitem__('HTTP Status Code'),
        reason=test_unmute_host_false.__getitem__('HTTP Reason'),
        text=test_unmute_host_false.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_ep_command(client,
                                                   {"endpoint": ep_host})
    assert result.outputs['is_unmute'] is False
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_unmute_deception_ep_command_ep_already_unmuted(mocker):
    from acalvioapp import \
        do_unmute_deception_ep_command
    mock_response = MockRequestsResponse(
        json_data=test_unmute_already_unmuted_host.__getitem__('HTTP Body'),
        status_code=test_unmute_already_unmuted_host.
        __getitem__('HTTP Status Code'),
        reason=test_unmute_already_unmuted_host.__getitem__('HTTP Reason'),
        text=test_unmute_already_unmuted_host.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_unmute_deception_ep_command(client,
                                                   {"endpoint": ep_host})
    assert result.outputs['is_unmute'] is True
    assert result.outputs['endpoint'] == ep_host
    assert error is None


def test_do_deception_host_command_missing_parameter(mocker):
    from acalvioapp import \
        do_deception_host_command
    mock_response = MockRequestsResponse(
        json_data=test_missing_parameter.__getitem__('HTTP Body'),
        status_code=test_missing_parameter.__getitem__('HTTP Status Code'),
        reason=test_missing_parameter.__getitem__('HTTP Reason'),
        text=test_missing_parameter.__getitem__('HTTP Body')
    )
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    result, error = do_deception_host_command(client, {})
    assert result is None
    assert error.outputs['error'] is True
    assert error.outputs['details']['msg'] == "Missing required parameter"
