from unittest.mock import patch
import demistomock as demisto

import ChroniclePotentiallyBlockedIPWidgetScript

INDICATOR_DATA = {'indicator': {'CustomFields': {'chronicleassethostname': '0.0.0.0',
                                                 'chroniclepotentiallyblockedip': 'No'}}}


def test_main_success(mocker):
    """
        When main function is called, get_html_representation should be called.
    """

    mocker.patch.object(demisto, 'args', return_value=INDICATOR_DATA)
    mocker.patch.object(ChroniclePotentiallyBlockedIPWidgetScript, 'get_html_representation',
                        return_value='')
    ChroniclePotentiallyBlockedIPWidgetScript.main()
    assert ChroniclePotentiallyBlockedIPWidgetScript.get_html_representation.called


@patch('ChroniclePotentiallyBlockedIPWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(demisto, 'args', return_value=INDICATOR_DATA)
    mocker.patch.object(ChroniclePotentiallyBlockedIPWidgetScript, 'get_html_representation',
                        side_effect=Exception)
    with capfd.disabled():
        ChroniclePotentiallyBlockedIPWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_get_html_representation_when_no_ip_is_attached():
    """
        When no ip is attached, get_html_representation should return html representation accordingly.
    """

    html_representation = ChroniclePotentiallyBlockedIPWidgetScript.get_html_representation(None, 'No')
    assert "<div style='color:grey; text-align:center;'><h1>No IP Address associated with the ChronicleAsset</h1></div>"\
           == html_representation


def test_get_html_representation_when_ip_is_not_blocked():
    """
        When ip is not blocked, get_html_representation should return html representation accordingly.
    """

    html_representation = ChroniclePotentiallyBlockedIPWidgetScript.get_html_representation('0.0.0.0', 'No')
    assert "<div style='color:green; text-align:center;'><h1>0.0.0.0<br/>IP Address Not Blocked</h1>" \
           "</div>" == html_representation


def test_get_html_representation_when_ip_is_potentially_blocked():
    """
        When ip is potentially blocked, get_html_representation should return html representation accordingly.
    """

    html_representation = ChroniclePotentiallyBlockedIPWidgetScript\
        .get_html_representation('0.0.0.0', 'Yes')
    assert "<div style='color:orange; text-align:center;'><h1>0.0.0.0<br/>IP Address Potentially Blocked</h1>" \
           "</div>" == html_representation
