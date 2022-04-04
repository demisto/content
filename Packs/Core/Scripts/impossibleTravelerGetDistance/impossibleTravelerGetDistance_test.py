from impossibleTravelerGetDistance import *
import pytest

COORDS="[\"32.0123, 34.7705\",\"50.8847, 4.5049\"]"
BAD_DEST_COORDS = "[\"32.0123, 34.7705\"]"

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
