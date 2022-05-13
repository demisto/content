import demistomock as demisto
from ReverseList import main


def test_in_range(mocker):
    """
    Given:
        - A list ["Mars", "Jupiter", "Saturn"] to revert

    When:
        - Running ReverseList

    Then:
        - Verify ["Saturn", "Jupiter", "Mars"] is returned
    """
    mocker.patch.object(demisto, 'args', return_value={
        'value': ['Mars', 'Jupiter', 'Saturn'],
    })
    mocker.patch.object(demisto, 'results')
    main()
    demisto.results.assert_called_with(['Saturn', 'Jupiter', 'Mars'])
