import demistomock as demisto

RAW_RESPONSE_MOCK_1 = {
    'ip': '1.1.1.1',
    'country_name': 'country_name',
    'latitude': '1234',
    'longitude': '5678',
    'continent_name': 'continent_name',
    'type': 'type'
}
RAW_RESPONSE_MOCK_2 = {
    'ip': '8.8.8.8',
    'country_name': 'country_name',
    'latitude': '8888',
    'longitude': '9999',
    'continent_name': 'continent_name',
    'type': 'type'
}
CONTEXT_PATH = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor ' \
               '&& val.Type == obj.Type)'
CONTEXT_PATH_PRIOR_V5_5 = 'DBotScore'


def test_right_location_format(mocker, requests_mock):
    """
    When:
      - Calling ip_command
    Then:
      - Ensure that the Response was constructed correctly.
      - Case 1: The response should contain Location key with a value in the format of lon:lat
        and contain DBotScore calculations.
    """
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'proxy',
                                                         'credentials': {'password': 'password'},
                                                         'integrationReliability': 'C - Fairly reliable'})
    mocker.patch.object(demisto, 'args', return_value={'ip': '1.2.3.4,8.8.8.8'})
    mocker_results = mocker.patch.object(demisto, 'results')
    requests_mock.get(
        'http://api.ipstack.com/1.2.3.4?access_key=password',
        json=RAW_RESPONSE_MOCK_1
    )
    requests_mock.get(
        'http://api.ipstack.com/8.8.8.8?access_key=password',
        json=RAW_RESPONSE_MOCK_2
    )
    from Ipstack import do_ip_command
    do_ip_command()

    results_1234 = mocker_results.call_args_list[0][0][0]
    output = results_1234.get('EntryContext').get('IP(val.Address == obj.Address)')
    assert output.get('Geo').get('Location') == '1234:5678'
    assert CONTEXT_PATH in results_1234.get('EntryContext') or CONTEXT_PATH_PRIOR_V5_5 in results_1234.get('EntryContext')

    results_8888 = mocker_results.call_args_list[1][0][0]
    output = results_8888.get('EntryContext').get('IP(val.Address == obj.Address)')
    assert output.get('Geo').get('Location') == '8888:9999'
    assert CONTEXT_PATH in results_8888.get('EntryContext') or CONTEXT_PATH_PRIOR_V5_5 in results_8888.get('EntryContext')


def test_test_module(mocker, requests_mock):
    """
    When:
      - Calling test_module
    Then:
      - No errors occurred
    """
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'proxy',
                                                         'credentials': {'password': 'password'},
                                                         'integrationReliability': 'C - Fairly reliable'})
    results_mock = mocker.patch.object(demisto, 'results')
    requests_mock.get(
        'http://api.ipstack.com/1.2.3.4?access_key=password',
        json={'ip': '1.2.3.4'}
    )
    from Ipstack import test_module
    test_module()
    assert 'ok' in results_mock.call_args[0][0]
