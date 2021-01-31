from unittest.mock import patch
import demistomock as demisto

import ChronicleIsolatedIPWidgetScript

INDICATOR_DATA = {'indicator': {'CustomFields': {'chronicleassetip': '0.0.0.0',
                                                 'chronicleisolatedip': 'No'}}}


def test_main_success(mocker):
    """
        When main function is called, get_html_representation should be called.
    """

    mocker.patch.object(demisto, 'args', return_value=INDICATOR_DATA)
    mocker.patch.object(ChronicleIsolatedIPWidgetScript, 'get_html_representation',
                        return_value='')
    ChronicleIsolatedIPWidgetScript.main()
    assert ChronicleIsolatedIPWidgetScript.get_html_representation.called


@patch('ChronicleIsolatedIPWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(demisto, 'args', return_value=INDICATOR_DATA)
    mocker.patch.object(ChronicleIsolatedIPWidgetScript, 'get_html_representation',
                        side_effect=Exception)
    with capfd.disabled():
        ChronicleIsolatedIPWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_get_html_representation_when_no_ip_is_attached():
    """
        When no ip is attached, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleIsolatedIPWidgetScript.get_html_representation(None, 'No')
    assert "<div style='color:grey; text-align:center;'><h1>No IP Address associated with the ChronicleAsset</h1></div>"\
           == html_representation


def test_get_html_representation_when_ip_is_not_isolated():
    """
        When ip is not blocked, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleIsolatedIPWidgetScript.get_html_representation('0.0.0.0', 'No')
    assert "<div style='color:green; text-align:center;'><h1>0.0.0.0<br/>IP Address Not Isolated</h1>" \
           "</div>" == html_representation


def test_get_html_representation_when_ip_is_potentially_isolated():
    """
        When ip is potentially blocked, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleIsolatedIPWidgetScript\
        .get_html_representation('0.0.0.0', 'Yes')
    assert "<div style='color:red; text-align:center;'><h1>0.0.0.0<br/>IP Address Isolated</h1>" \
           "</div>" == html_representation
