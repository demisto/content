import demistomock as demisto
import pytest


@pytest.mark.parametrize('str1, str2, expected_results', [
    ('aaa', 'aaa', 0),
    ('aba', 'baba', 1),
    ('kitten', 'sitting', 3)
])
def test_levenshtein(str1, str2, expected_results):
    """
        Given
        - Two strings.
        When
        - Calling levenshtein function.
        Then
        - Return the Levenshtein distance (int).
    """
    from CheckSenderDomainDistance import levenshtein

    assert levenshtein(str1, str2) == expected_results


def test_main(mocker):
    """
        Given
        - The commands args.
        When
        - Calling the main function.
        Then
        - Verify the result is as expected.
    """
    from CheckSenderDomainDistance import main

    mocker.patch('CheckSenderDomainDistance.levenshtein', return_value=1)
    mocker.patch.object(demisto, 'args', return_value={"domain": "example.com", "sender": "mail@example1.com"})
    results_mock = mocker.patch.object(demisto, 'results')
    expected_result = 'yes'

    main()

    assert results_mock.call_args[0][0][1] == expected_result
