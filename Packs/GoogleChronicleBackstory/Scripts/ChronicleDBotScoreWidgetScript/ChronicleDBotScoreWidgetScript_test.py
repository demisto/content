from unittest.mock import patch
import demistomock as demisto

import ChronicleDBotScoreWidgetScript

DBOT_SCORE = [{'CustomFields': {'chronicledbotscore': 2}}]


def test_main_success(mocker):
    """
        When main function is called, get_html_representation should be called.
    """

    mocker.patch.object(demisto, 'incidents', return_value=DBOT_SCORE)
    mocker.patch.object(ChronicleDBotScoreWidgetScript, 'get_html_representation',
                        return_value='')
    ChronicleDBotScoreWidgetScript.main()
    assert ChronicleDBotScoreWidgetScript.get_html_representation.called


@patch('ChronicleDBotScoreWidgetScript.return_error')
def test_main_failure(mock_return_error, capfd, mocker):
    """
        When main function gets some exception then valid message should be printed.
    """

    mocker.patch.object(demisto, 'incidents', return_value=DBOT_SCORE)
    mocker.patch.object(ChronicleDBotScoreWidgetScript, 'get_html_representation', side_effect=Exception)
    with capfd.disabled():
        ChronicleDBotScoreWidgetScript.main()

    mock_return_error.assert_called_once_with('Could not load widget:\n')


def test_get_html_representation_when_dbotscore_is_1(mocker):
    """
        When DBotscore is 1, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleDBotScoreWidgetScript.get_html_representation(1)
    assert "<div style='color:green; text-align:center;'><h1>1<br/>Good</h1></div>" == html_representation


def test_get_html_representation_when_dbotscore_is_2(mocker):
    """
        When DBotscore is 2, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleDBotScoreWidgetScript.get_html_representation(2)
    assert "<div style='color:orange; text-align:center;'><h1>2<br/>Suspicious</h1></div>"\
           == html_representation


def test_get_html_representation_when_dbotscore_is_3(mocker):
    """
        When DBotscore is 3, get_html_representation should return html representation accordingly.
    """

    html_representation = ChronicleDBotScoreWidgetScript.get_html_representation(3)
    assert "<div style='color:red; text-align:center;'><h1>3<br/>Bad</h1></div>" == html_representation
