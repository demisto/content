import demistomock as demisto
from LanguageDetect import main


def test_language_detect_english(mocker):
    """
    Given:
        - Text in English

    When:
        - Run the LanguageDetect script

    Then:
        - Verify the that english is returned.

    """
    mocker.patch.object(demisto, 'args', return_value={
        'text': 'This is some text'
    })

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args
    # Didn't test probability cause it changes every run.
    assert results[0][0]['Contents'][0].get('lang') == 'en'


def test_language_detect_hebrew(mocker):
    """
    Given:
        - Text in Hebrew

    When:
        - Run the LanguageDetect script

    Then:
        - Verify the that Hebrew is returned.

    """
    mocker.patch.object(demisto, 'args', return_value={
        'text': 'טקסט לבדיקה'
    })

    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args
    # Didn't test probability cause it changes every run.
    assert results[0][0]['Contents'][0].get('lang') == 'he'
