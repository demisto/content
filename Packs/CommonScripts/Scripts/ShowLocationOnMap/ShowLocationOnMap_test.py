import pytest
import sys

import CommonServerPython
import demistomock as demisto

LOC_VALID = ['41.40338,2.17403', '41.40338,2.17403 ', ' 41.40338 ,   2.17403    ', '32.0868197,34.7810571',
             '41.40338:2.17403']


@pytest.mark.parametrize('loc', LOC_VALID)
def test_valid_loc(loc, mocker):
    """
    Given:
    - Valid coordinate str of lat and lng.

    When:
    - Parsing them into lat and lng separately.

    Then:
    - Ensure parsing is done as expected.

    """
    mocker.patch.object(demisto, 'args', return_value={'indicator': {'CustomFields': {'geolocation': loc}}})
    return_results_mock = mocker.patch.object(demisto, 'results')
    # This will trigger the script
    if 'ShowLocationOnMap' in sys.modules:
        del (sys.modules['ShowLocationOnMap'])
    import ShowLocationOnMap  # noqa: F401
    splitter = ',' if ',' in loc else ':'
    lat, lng = loc.split(splitter)
    expected_lat = float(lat)
    expected_lng = float(lng)
    results = return_results_mock.call_args[0][0]
    assert results['Contents']['lat'] == expected_lat
    assert results['Contents']['lng'] == expected_lng


INVALID_LOC = ['unknown,unknown2', '123saas4as', '41.40338,41.40338,41.40338', '']


def return_error_called():
    raise Exception('return_error_called')


@pytest.mark.parametrize('loc', INVALID_LOC)
def test_invalid_loc(loc, mocker):
    """
    Given:
    - Invalid coordinate str of lat and lng.

    When:
    - Parsing them into lat and lng separately.

    Then:
    - Ensure return error is called.

    """
    mocker.patch.object(demisto, 'args', return_value={'indicator': {'CustomFields': {'geolocation': loc}}})
    mocker.patch.object(CommonServerPython, 'return_error', side_effect=return_error_called)
    # This will trigger the script
    if 'ShowLocationOnMap' in sys.modules:
        del (sys.modules['ShowLocationOnMap'])
    with pytest.raises(Exception, match='return_error_called'):
        import ShowLocationOnMap  # noqa: F401


INVALID_LOC_TYPE = [None, {}, []]


@pytest.mark.parametrize('loc', INVALID_LOC_TYPE)
def test_invalid_indicator_value_type(mocker, loc):
    """
    Given:
    - Demisto args with invalid types as indicator value (not a string).

    When:
    - Trying to parse it into lat and lng separately.

    Then:
    - Ensure that return error is raised.
    """
    mocker.patch.object(demisto, 'args', return_value={'indicator': loc})
    mocker.patch.object(CommonServerPython, 'return_error', side_effect=return_error_called)

    if 'ShowLocationOnMap' in sys.modules:
        del (sys.modules['ShowLocationOnMap'])
    with pytest.raises(Exception, match='return_error_called'):
        import ShowLocationOnMap  # noqa: F401
