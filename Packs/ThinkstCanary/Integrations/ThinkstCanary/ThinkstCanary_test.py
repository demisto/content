import demistomock as demisto
import pytest

MOCK_PARAMS = {
    'access-key': 'fake_access_key',
    'secret-key': 'fake_access_key',
    'server': 'http://123-fake-api.com/',
    'unsecure': True,
    'proxy': True,
    'authentication_token': {'password': 1}
}


def test_fetch_incidents(mocker, requests_mock):
    """
    Given: An existing last run time.
    When:  Running a fetch incidents command normally (not a first run).
    Then:  The last run time object should increment by 1 second.
           2020-01-07-04:58:18 -> 2020-01-07-04:58:19
    """
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2020-07-01-04:58:18'})
    mocker.patch.object(demisto, 'setLastRun')
    requests_mock.get('http://123-fake-api.com/api/v1/incidents/unacknowledged?newer_than=2020-07-01-04%3A58%3A18',
                      json={'incidents': [{'description': {'created': 1593579498}}]})
    from ThinkstCanary import fetch_incidents_command
    fetch_incidents_command()
    assert demisto.setLastRun.call_args[0][0]['time'] == '2020-07-01-04:58:19'


def test_check_whitelist_command_not_whitelisted(mocker):
    """
    Given: An IP to check
    When:  Running check_whitelist_command.
    Then:  The IP should not be ignored (not in the whitelist).
    """
    ip_to_check = "1.2.3.4"
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'ip': ip_to_check})

    import ThinkstCanary
    mocker.patch.object(ThinkstCanary, 'check_whitelist', return_value={'is_ip_ignored': False,
                                                                        'is_whitelist_enabled': True})
    ThinkstCanary.check_whitelist_command()
    assert demisto.results.call_args_list[0][0][0].get('HumanReadable') == 'The IP address 1.2.3.4:Any is not ' \
                                                                           'Whitelisted'


def test_check_whitelist_commands_whitelisted(mocker):
    """
    Given: An already whitelisted IP to check
    When:  Inserting IP to whitelist (whitelist_ip_command) and checking if it is whitelisted (check_whitelist_command).
    Then:  The IP should be ignored (in the whitelist), and an appropriate message to the user should be prompted.
    """
    ip_to_whitelist = "1.2.3.4"
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'ip': ip_to_whitelist})

    import ThinkstCanary
    mocker.patch.object(ThinkstCanary, 'whitelist_ip', return_value={'message': 'Whitelist added',
                                                                     'result': 'success'})
    mocker.patch.object(ThinkstCanary, 'check_whitelist', return_value={'is_ip_ignored': True,
                                                                        'is_whitelist_enabled': True})
    ThinkstCanary.whitelist_ip_command()
    ThinkstCanary.check_whitelist_command()
    assert demisto.results.call_args_list[1][0][0].get('HumanReadable') == 'The IP address 1.2.3.4:Any is Whitelisted'


@pytest.mark.parametrize('arg_status, return_status, expected_result',
                         [('Acknowledge', 'acknowledged', 'The Alert alert_id was acknowledged'),
                          ('Unacknowledge', 'unacknowledged', 'The Alert alert_id was unacknowledged')])
def test_alert_status_command(mocker, arg_status, return_status, expected_result):
    """
    Given: An alert id to check.
    When:  Running alert_status_command.
    Then:  ensure the expected result returned.
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert_id': 'alert_id', 'status': arg_status})

    import ThinkstCanary
    mocker.patch.object(ThinkstCanary, 'http_request', return_value={'action': return_status})
    ThinkstCanary.alert_status_command()
    assert expected_result in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_list_canaries_command(mocker):
    """
    Given: demisto params.
    When:  Running list_canaries_command.
    Then:  ensure the expected result returned.
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)

    import ThinkstCanary
    mocker.patch.object(ThinkstCanary, 'http_request', return_value={'devices': [{'description': 'Description',
                                                                                  'id': 'ID',
                                                                                  'ip_address': 'Address',
                                                                                  'last_seen': 'LastSeen',
                                                                                  'live': 'Status',
                                                                                  'location': 'Location',
                                                                                  'name': 'Name',
                                                                                  'updated_std': 'LastUpdated',
                                                                                  'version': 'Version'}]})
    ThinkstCanary.list_canaries_command()
    assert 'Canary Devices' in demisto.results.call_args_list[0][0][0].get('HumanReadable')


def test_list_tokens_command(mocker):
    """
    Given: demisto params.
    When:  Running list_tokens_command.
    Then:  ensure the expected result returned.
    """

    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)

    import ThinkstCanary
    mocker.patch.object(ThinkstCanary, 'http_request', return_value={'tokens': [{'canarytoken': 'CanaryToken',
                                                                                 'created_printable': 'CreatedTime',
                                                                                 'enabled': 'Enabled',
                                                                                 'kind': 'Kind',
                                                                                 'triggered_count': 'Triggered',
                                                                                 'doc_name': 'DocName',
                                                                                 'url': 'TokenURL'}]})
    ThinkstCanary.list_tokens_command()
    assert 'Canary Tools Tokens' in demisto.results.call_args_list[0][0][0].get('HumanReadable')
