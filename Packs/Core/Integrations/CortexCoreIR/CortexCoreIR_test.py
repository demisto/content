import json

Core_URL = 'https://api.xdrurl.com'


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_report_incorrect_wildfire_command(mocker):
    """
    Given:
        - FilterObject and name to get by exclisions.
    When
        - A user desires to get exclusions.
    Then
        - returns markdown, context data and raw response.
    """
    from CortexCoreIR import report_incorrect_wildfire_command, Client
    wildfire_response = load_test_data('./test_data/wildfire_response.json')
    mock_client = Client(base_url=f'{Core_URL}/public_api/v1', headers={})
    mocker.patch.object(mock_client, 'report_incorrect_wildfire', return_value=wildfire_response)
    file_hash = "11d69fb388ff59e5ba6ca217ca04ecde6a38fa8fb306aa5f1b72e22bb7c3a252"
    args = {
        "email": "a@a.gmail.com",
        "file_hash": file_hash,
        "new_verdict": 0,
        "reason": "test1"
    }
    res = report_incorrect_wildfire_command(client=mock_client, args=args)
    assert res.readable_output == f'Reported incorrect WildFire on {file_hash}'


class TestPrevalenceCommands:

    def test_get_domain_analytics(self, mocker):
        """
            Given:
                - A domain name.
            When:
                - Calling handle_prevalence_command as part of core-get-domain-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('domain'))
        res = handle_prevalence_command(mock_client, 'core-get-domain-analytics-prevalence',
                                        {'domain': 'some_name'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('domain_name') == 'some_name'

    def test_get_ip_analytics(self, mocker):
        """
            Given:
                - An Ip address.
            When:
                - Calling handle_prevalence_command as part of core-get-IP-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('ip'))
        res = handle_prevalence_command(mock_client, 'core-get-IP-analytics-prevalence',
                                        {'ip': 'some ip'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('ip_address') == 'some_ip'

    def test_get_registry_analytics(self, mocker):
        """
            Given:
                - A registry name.
            When:
                - Calling handle_prevalence_command as part of core-get-registry-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import handle_prevalence_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        mock_res = load_test_data('./test_data/prevalence_response.json')
        mocker.patch.object(mock_client, 'get_prevalence', return_value=mock_res.get('registry'))
        res = handle_prevalence_command(mock_client, 'core-get-registry-analytics-prevalence',
                                        {'key_name': 'some key', 'value_name': 'some value'})
        assert res.outputs[0].get('value') is True
        assert res.outputs[0].get('key_name') == 'some key'

    def test_blocklist_files_command(self, mocker):
        """
            Given:
                - An hash list and incident ID.
            When:
                - Calling blocklist_files_command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import blocklist_files_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        args = {'incident_id': '1', 'hash_list': ['hash']}

        error_message = '[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:' \
            'request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: ' \
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": ' \
            '"All hashes have already been added to the allow or block list"}}\n'
        mocker.patch.object(mock_client, '_http_request', side_effect=Exception(error_message))
        mocker.patch('CoreIRApiModule.validate_sha256_hashes', return_value='')

        res = blocklist_files_command(mock_client, args)
        assert res.readable_output == 'All hashes have already been added to the block list.'

    def test_allowlist_files_command(self, mocker):
        """
            Given:
                - An hash list and incident ID.
            When:
                - Calling allowlist_files_command.
            Then:
                - Verify response is as expected.
        """
        from CortexCoreIR import allowlist_files_command, Client
        mock_client = Client(base_url=f'{Core_URL}/xsiam/', headers={})
        args = {'incident_id': '1', 'hash_list': ['hash']}

        error_message = '[/api/webapp/public_api/v1/hash_exceptions/blocklist/] failed client execute - error:' \
            'request to [/api/webapp/public_api/v1/hash_exceptions/blocklist/] returned non-whitelisted status [500] body: ' \
            '{"reply": {"err_code": 500, "err_msg": "An error occurred while processing XDR public API", "err_extra": ' \
            '"All hashes have already been added to the allow or block list"}}\n'
        mocker.patch.object(mock_client, '_http_request', side_effect=Exception(error_message))
        mocker.patch('CoreIRApiModule.validate_sha256_hashes', return_value='')

        res = allowlist_files_command(mock_client, args)
        assert res.readable_output == 'All hashes have already been added to the allow list.'
