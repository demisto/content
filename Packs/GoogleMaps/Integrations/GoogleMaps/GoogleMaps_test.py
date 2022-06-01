"""GoogleMaps Integration for Cortex XSOAR - Unit Tests file"""

import io
import json

import pytest

from CommonServerPython import DemistoException
from GoogleMaps import Client, google_maps_geocode_command, MESSAGE_ZERO_RESULTS, STATUS_ZERO_RESULTS

search_address = 'Paloalto Networks TLV office'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_google_maps_geocode_command(requests_mock):
    """
    Given:
        A string describing a location
    When:
        Calling google-maps-geocode
    Then:
        Validate the output compared to the mock output
    """

    mock_response = util_load_json('test_data/geocode_paloalto_tlv_response.json')
    requests_mock.get('https://maps.googleapis.com/maps/api/geocode/json?', json=mock_response)

    client = Client(api_key='',
                    base_url='https://maps.googleapis.com/maps/api',
                    proxy=False,
                    insecure=False)

    result_note, result_map = google_maps_geocode_command(client=client,
                                                          search_address=search_address,
                                                          error_on_no_results=False)
    expected_note_outputs = util_load_json('test_data/geocode_paloalto_tlv_note_outputs.json')
    actual_note_outputs = result_note.outputs
    assert actual_note_outputs == expected_note_outputs

    # noinspection PyTypeChecker
    actual_map_contents = result_map.to_context()['Contents']
    expected_map_contents = util_load_json('test_data/geocode_paloalto_tlv_map_contents.json')
    assert actual_map_contents == expected_map_contents


def test_google_maps_geocode_bad_api_key(requests_mock):
    """
    Given:
        An invalid API key for GoogleMaps, and a string describing a location
    When:
        Calling google-maps-geocode
    Then:
        Make sure an appropriate exception is raised, with an indicative message.
    """

    client = Client(api_key='invalid-api-key',
                    base_url='https://maps.googleapis.com/maps/api',
                    proxy=False,
                    insecure=False)

    mock_bad_api_response = util_load_json('test_data/geocode_bad_api_key_response.json')
    requests_mock.get('https://maps.googleapis.com/maps/api/geocode/json?', json=mock_bad_api_response)
    with pytest.raises(DemistoException) as e:
        google_maps_geocode_command(client=client,
                                    search_address=search_address,
                                    error_on_no_results=False)
    assert e.value.args[0] == 'The provided API key is invalid.'


def test_google_maps_geocode_zero_results(requests_mock):
    """
    Given:
        A string describing a location of which there are no geocoding results
    When:
        Calling google-maps-geocode
    Then:
        Make sure an appropriate exception is raised if and only if the `error_on_no_results` is True.
    """

    zero_results_search_address = ' '
    client = Client(api_key='',
                    base_url='https://maps.googleapis.com/maps/api',
                    proxy=False,
                    insecure=False)

    mock_response = util_load_json('test_data/geocode_zero_results_response.json')
    requests_mock.get('https://maps.googleapis.com/maps/api/geocode/json?', json=mock_response)

    actual_result = google_maps_geocode_command(client=client,
                                                search_address=zero_results_search_address,
                                                error_on_no_results=False)
    assert len(actual_result) == 1
    expected_context = util_load_json('test_data/geocode_zero_results_context.json')
    assert actual_result[0].to_context() == expected_context

    # And now, with error_on_no_results=True, should raise an exception.
    with pytest.raises(DemistoException) as e:
        google_maps_geocode_command(client=client,
                                    search_address=zero_results_search_address,
                                    error_on_no_results=True)
    assert e.value.args[0] == MESSAGE_ZERO_RESULTS
    assert e.value.res['results'] == []
    assert e.value.res['status'] == STATUS_ZERO_RESULTS
