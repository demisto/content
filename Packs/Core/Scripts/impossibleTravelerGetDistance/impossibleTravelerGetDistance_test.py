from impossibleTravelerGetDistance import *
import mocker.

COORDS="[\"32.0123, 34.7705\",\"50.8847, 4.5049\",\"40.7157, -74\",\"31.9522, 34.8943\"]"

def test_impossible_traveler_get_distance(mocker):
    """

    Given:
        Coordinations list to calculate distances between
    When:
        Calculating impossible traveler distances
    Then
        Return valid distances

    """
    mocker.patch.object(demisto, 'get', return_value=[])
    mocker.patch.object(demisto, 'args', return_value={'src_coords': COORDS, 'dest_coords': COORDS})

