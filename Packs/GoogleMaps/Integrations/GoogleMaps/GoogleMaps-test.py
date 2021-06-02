"""GoogleMaps Integration for Cortex XSOAR - Unit Tests file"""

import json
import io

from CommonServerPython import DBotScoreReliability
from Packs.GoogleMaps.Integrations.GoogleMaps.GoogleMaps import Client, parse_response


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
    from GoogleMaps import google_maps_geocode_command
    search_address = 'Paloalto Networks TLV office'
    import os
    print(os.path.curdir)

    mock_response = util_load_json('test_data/geocode_paloalto_tlv.json')
    requests_mock.get('https://maps.googleapis.com/maps/api/geocode/json?', json=mock_response)

    client = Client(api_key='',
                    base_url='https://maps.googleapis.com/maps/api',
                    proxy=False,
                    insecure=False)

    result_note, result_map = google_maps_geocode_command(client=client,
                                                          search_address=search_address,
                                                          error_on_no_results=False)

    actual_note_outputs = util_load_json('test_data/geocode_paloalto_tlv_note_outputs.json')
    expected_note_outputs = actual_note_outputs
    assert json.dumps(result_note.outpus) == expected_note_outputs

    # noinspection PyTypeChecker
    actual_map_contents = json.dumps(result_map.to_context())['Contents']
    expected_map_contents = util_load_json('test_data/geocode_paloalto_tlv_map_contents.json')
    assert actual_map_contents == expected_map_contents
