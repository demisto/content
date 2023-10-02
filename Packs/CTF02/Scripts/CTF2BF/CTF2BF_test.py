import pytest
import CTF2BF
import demistomock as demisto


@pytest.mark.parametrize("question_id, secret, expected", [
    ("01", "correct_secret", "no"),
    ("01", "incorrect_secret", "yes"),  # Error MSG
    ("04", "correct_secret", 2017),
    ("04", "incorrect_secret", 1990),
    ("07", "correct_secret", "blocked"),
    ("07", "incorrect_secret", "blocked"),
])
def test_main(mocker, question_id, secret, expected):
    args = {
        "question_ID": question_id,
        "secret": secret
    }

    m = mocker.patch.object(CTF2BF, 'return_results')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', return_value={'total': 'correct_secret'})

    CTF2BF.main()
    assert m.call_args[0][0]['Type'] == expected
