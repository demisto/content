import pytest

import demistomock as demisto  # noqa: F401
from HighlightWords import main


@pytest.mark.parametrize("args, expected_text",
                         [
                             ({'terms': "test", 'text': "This is a test"}, 'this is a **test**'),
                             ({'terms': "test", 'text': "Test upper case"}, '**test** upper case'),
                             ({'terms': "test", 'text': "test two test"}, '**test** two **test**')
                         ]
                         )
def test_highlight_as_expected(mocker, args, expected_text):
    """
        Scenario: Run the script

        Given:
        - args with one word and a text

        Then:
        - assert result is as expected
    """
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'results')
    main()
    assert demisto.results.call_args[0][0]['Contents'] == expected_text


def test_error_for_sentence_and_word(mocker):
    """
        Scenario: Args has word and a sentence containing the word

        Given:
        - args where there's a word and a sentence containing the word

        Then:
        - Make sure an error is printed
        """
    mocker.patch.object(demisto, 'args', return_value={'terms': "test, this is a test", "text": "testing test"})
    error_mock = mocker.patch('HighlightWords.return_error', return_value=None)
    main()
    assert error_mock.call_args.args[0] ==\
           'The word "test" is a substring of the sentance: "this is a test"'
