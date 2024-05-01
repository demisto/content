import pytest
import CTF2BF
import demistomock as demisto


@pytest.mark.parametrize("question_id, secret, expected", [
    ("01", "no", "Well Done!!!"),
    ("01", "yes", "Nope!!! Try again"),  # Error MSG
    ("04", "2017", "Well Done!!!"),
    ("04", "1990", "Nope!!! Try again"),
    ("07", "blocked", "Well Done!!!"),
    ("07", "done", "Nope!!! Try again"),
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
    assert expected in m.call_args[0][0]["Contents"]
