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
    Client.base_url_suffix = 'xsiam/'
    prevalence_client = Client({'url': 'https://example.com'})
    api_responses = util_load_json(f'test_data/prevalence_response.json')

    def test_get_domain_analytics(self, mocker):
        """
            Given:
                - A domain name.
            When:
                - Calling handle_prevalence_command as part of core-get-domain-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """
        api_res = self.api_responses['domain']
        mocker.patch.object(Client, 'http_request', return_value=api_res)
        res = handle_prevalence_command(self.prevalence_client, 'core-get-domain-analytics-prevalence',
                                        {'domain': 'some-web.com'})
        x = 5

    def test_get_ip_analytics(self, mocker):
        """
            Given:
                - An Ip address.
            When:
                - Calling handle_prevalence_command as part of core-get-IP-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """

    def test_get_hash_analytics(self, mocker):
        """
            Given:
                - A sha256 address.
            When:
                - Calling handle_prevalence_command as part of core-get-sha-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """

    def test_get_process_analytics(self, mocker):
        """
            Given:
                - A process name.
            When:
                - Calling handle_prevalence_command as part of core-get-process-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """

    def test_get_registry_analytics(self, mocker):
        """
            Given:
                - A registry name.
            When:
                - Calling handle_prevalence_command as part of core-get-registry-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """

    def test_get_cmd_analytics(self, mocker):
        """
            Given:
                - A process command line.
            When:
                - Calling handle_prevalence_command as part of core-get-cmd-analytics-prevalence command.
            Then:
                - Verify response is as expected.
        """

