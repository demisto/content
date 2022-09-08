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


@pytest.mark.parametrize('domain, sender, expected_results', [
    ('example.com', 'mail@example1.com', 'yes'),
    ('', 'mail@example1.com', 'no'),
    ('example.com', '', 'no'),
    ('example.com', 'mail@example.com', 'no')
])
def test_main(mocker, domain, sender, expected_results):
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
    mocker.patch.object(demisto, 'args', return_value={"domain": domain, "sender": sender})
    results_mock = mocker.patch.object(demisto, 'results')

    main()

    try:
        assert results_mock.call_args[0][0][1] == expected_results
    except IndexError:  # In the fourth case
        assert results_mock.call_args[0][0][0] == expected_results
