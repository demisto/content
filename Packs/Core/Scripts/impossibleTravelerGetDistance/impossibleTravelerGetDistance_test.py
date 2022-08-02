import pytest

from impossibleTravelerGetDistance import *

COORDS = "[\"32.0123, 34.7705\",\"50.8847, 4.5049\"]"
BAD_DEST_COORDS = "[\"32.0123, 34.7705\"]"
BAD_ARGS = {'src_coords': COORDS, 'dest_coords': BAD_DEST_COORDS}

EXISTING_MOCK = [
    {
        'Country': 'IL',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '32.0123, 34.7705'
    },
    {
        'Country': 'BE',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip',
        'location': '50.8847, 4.5049'
    }]

EXPECTED_EVENTS_DICT = {
    '32.0123, 34.7705': {
        'Country': 'IL',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip', 'location': '32.0123, 34.7705'
    },
    '50.8847, 4.5049': {
        'Country': 'BE',
        'event_timestamp': '2022-03-02T10: 06: 09Z',
        'identity_display_name': 'paanalyticstest',
        'ip': 'ip', 'location': '50.8847, 4.5049'
    }
}


def test_get_distances_list():
    """

    Given:
        Coordinations list to calculate distances between
    When:
        Calculating impossible traveler distances
    Then
        Return valid distances

    """
    events_dict = {}
    for o in EXISTING_MOCK:
        events_dict[o["location"]] = o
    result = get_distances_list(argToList(COORDS), events_dict)
    assert result[0].outputs.get('distance') == 2016.25
    assert result[0].outputs.get('source_country') == 'IL'


def test_impossible_traveler_det_distance_bad_dest_coords(mocker):
    """
    Given:
        Coordinations lists to calculate distances between, when the two are different
    When:
        Calculating impossible traveler distances
    Then
        Raise an error

    """
    with pytest.raises(ValueError) as e:
        verify_coords(BAD_ARGS)
        if not e:
            assert False


def test_generate_events_dict(mocker):
    """
    Given:
        demisto context
    When:
        Calculating impossible traveler distances
    Then
        generate the exiting events dict

    """
    mocker.patch.object(demisto, 'get', return_value=EXISTING_MOCK)
    assert generate_evetns_dict() == EXPECTED_EVENTS_DICT
