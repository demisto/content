from impossibleTravelerGetDistance import *
import mocker

def test_impossible_traveler_get_distance(mocker):
    """

    Given:
        Coordinations list to calculate distances between
    When:
        Calculating impossible traveler distances
    Then
        Return valid distances

    """
    mocker.patch.object(demisto, 'get', return_value=INCIDENT_IDS)
