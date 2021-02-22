from OnionURLReputation import main
import demistomock as demisto

# the onion urls used in the unittests are not a valid ones so they would not be caught as an Onion URL in XSOAR.
ARGS = {
    'input': 'http://testforurls.onion/,http://testforurls2.onion/'}
EXPECTED_RESULTS = [
    {'Type': 1, 'ContentsFormat': 'json', 'Contents': 2,
     'EntryContext': {'DBotScore': {
         'Indicator': 'http://testforurls.onion/', 'Type': 'Onion URL', 'Score': 2, 'Vendor': 'DBot'}}},
    {'Type': 1, 'ContentsFormat': 'json', 'Contents': 2,
     'EntryContext': {'DBotScore': {
         'Indicator': 'http://testforurls2.onion/', 'Type': 'Onion URL', 'Score': 2, 'Vendor': 'DBot'}}}]


def test_main(mocker):
    """Verifies that a reputation data is being set for a given onion url.
       Given
       - list of Onion URL's.
       When
       - When an Onion URL is being auto extracted.
       Then
       - Return the updated context for each URL.
       """
    mocker.patch.object(demisto, 'args', return_value=ARGS)
    mocker.patch.object(demisto, 'results')
    main()
    assert EXPECTED_RESULTS == demisto.results.call_args[0][0]
