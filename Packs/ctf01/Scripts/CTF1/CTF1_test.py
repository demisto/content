import pytest
import CTF1
import demistomock as demisto


@pytest.mark.parametrize("question_id, secret, expected", [
    ("01", "5", "Well Done!!!"),
    ("01", "3", "Nope!!! Try again"),  # Error MSG
    ("04", "reportsarecool", "Well Done!!!"),
    ("04", "none", "Nope!!! Try again"),
    ("05", "monkey", "Well Done!!!"),
    ("05", "elephant", "Nope!!! Try again"),
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
    assert expected in m.call_args[0][0]["Contents"]
