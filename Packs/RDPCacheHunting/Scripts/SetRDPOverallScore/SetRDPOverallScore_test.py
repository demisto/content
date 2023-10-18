import demistomock as demisto
from SetRDPOverallScore import main


def test_happy_path_score_zero(mocker):
    """
    Given:
        - OverallScore zero
    When:
        - Calling the main function
    Then:
        - Ensure that the expected HTML is returned
    """
    mocker.patch.object(demisto, 'results', return_value={'OverallScore': '0'})
    expected_html = ("<div style='color:#1DB846;font-size:38px;padding: 60px; text-align:center;padding-left: 70px'>0/100<br>"
                     "No suspicious strings found</div>")
    main()
    result = demisto.results.call_args[0][0]['Contents']

    assert result == expected_html


def test_happy_path_score_50(mocker):
    """
    Given:
        - OverallScore 50
    When:
        - Calling the main function
    Then:
        - Ensure that the expected HTML is returned as expected
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'context', return_value={'OverallScore': '50'})
    expected_html = "<div style='color:#EF9700;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>50/100</div>"
    main()
    result = demisto.results.call_args[0][0]

    assert result['Contents'] == expected_html


def test_happy_path_score_90(mocker):
    """
    Given:
        - OverallScore 50
    When:
        - Calling the main function
    Then:
        - Ensure that the expected HTML is returned
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'context', return_value={'OverallScore': '90'})
    expected_html = "<div style='color:#b81d1d;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>90/100</div>"
    main()
    result = demisto.results.call_args[0][0]

    assert result['Contents'] == expected_html


def test_happy_path_score_100(mocker):
    """
    Given:
        - OverallScore 100
    When:
        - Calling the main function
    Then:
        - Ensure that the expected HTML is returned
    """
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'context', return_value={'OverallScore': '100'})
    expected_html = "<div style='color:#b81d1d;font-size:48px;padding: 60px; text-align:center;padding-left: 70px'>100/100</div>"
    main()
    result = demisto.results.call_args[0][0]

    assert result['Contents'] == expected_html
