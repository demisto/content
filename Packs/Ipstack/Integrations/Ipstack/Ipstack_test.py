import pytest
import demistomock as demisto

RAW_RESPONSE_MOCK = {
    'ip': '1.1.1.1',
    'country_name': 'country_name',
    'latitude': '1234',
    'longitude': '5678',
    'continent_name': 'continent_name',
    'type': 'type'
}
CONTEXT_PATH = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor ' \
               '&& val.Type == obj.Type)'
CONTEXT_PATH_PRIOR_V5_5 = 'DBotScore'


@pytest.mark.parametrize('raw_response_mock', [
    (RAW_RESPONSE_MOCK)
])
def test_right_location_format(mocker, raw_response_mock):
    """
    When:
      - Calling ip_command
    Then:
      - Ensure that the Response was constructed correctly.
      - Case 1: The response should contain Location key with a value in the format of lon:lat
        and contain DBotScore calculations.
    """
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'proxy', 'integrationReliability': 'C - Fairly reliable'})
    mocker.patch('Ipstack.do_ip', return_value=raw_response_mock)
    mocker.patch.object(demisto, 'results')
    from Ipstack import do_ip_command
    do_ip_command()
    results = demisto.results.call_args[0][0]
    output = results.get('EntryContext').get('IP(val.Address == obj.Address)')
    assert output.get('Geo').get('Location') == '1234:5678'
    assert CONTEXT_PATH in results.get('EntryContext') or CONTEXT_PATH_PRIOR_V5_5 in results.get('EntryContext')
