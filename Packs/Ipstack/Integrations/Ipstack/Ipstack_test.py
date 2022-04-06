import pytest
import demistomock as demisto

RAW_RESPONSE_MOCK = {
    'ip': '98.136.103.23',
    'country_name': 'country_name',
    'latitude': '1234',
    'longitude': '5678',
    'continent_name': 'continent_name',
    'type': 'type'
}


@pytest.mark.parametrize('raw_response_mock', [
    (RAW_RESPONSE_MOCK)
])
def test_right_location_format(mocker, raw_response_mock):
    """
    Given:
      - Case 1: raw_response mock
    When:
      - Calling ip_command
    Then:
      - Ensure that the foramtting worked as needed.
      - Case 1: Should return Location key in the format of lon:lat.
    """
    mocker.patch.object(demisto, 'params', return_value={'proxy': 'proxy'})
    mocker.patch('Ipstack.do_ip', return_value=raw_response_mock)
    mocker.patch.object(demisto, 'results')
    from Ipstack import do_ip_command
    do_ip_command()
    results = demisto.results.call_args[0][0]
    output = results.get('EntryContext').get('IP(val.Address == obj.Address)')
    assert output.get('Geo').get('Location') == '1234:5678'
