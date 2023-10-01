import pytest
import CTF2BF
from CommonServerPython import DemistoException
import demistomock as demisto


@pytest.mark.parametrize("question_id, secret, expected", [
    ("01", "correct_secret", 4),
    ("02", "wrong_secret", 4),  # Error MSG
    ("03", "correct_secret", 1),
    ("03", "incorrect_secret", 4),
    ("05", "correct_secret", 1),
    ("05", "incorrect_secret", 4),
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

