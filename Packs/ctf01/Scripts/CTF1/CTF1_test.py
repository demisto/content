import pytest
import CTF1
import demistomock as demisto


@pytest.mark.parametrize("question_id, secret, expected", [
    ("01", "correct_secret", 5),
    ("01", "wrong_secret", 3),  # Error MSG
    ("04", "correct_secret", "reportsarecool"),
    ("04", "incorrect_secret", "none"),
    ("05", "correct_secret", "monkey"),
    ("05", "incorrect_secret", "elephant"),
])
def test_main(mocker, question_id, secret, expected):
    args = {
        "question_ID": question_id,
        "secret": secret
    }

    m = mocker.patch.object(CTF1, 'return_results')
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(demisto, 'executeCommand', return_value={'total': 'correct_secret'})

    CTF1.main()
    assert m.call_args[0][0]['Type'] == expected
