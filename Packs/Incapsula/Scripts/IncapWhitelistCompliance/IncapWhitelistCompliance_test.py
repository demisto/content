import IncapWhitelistCompliance
import pytest


@pytest.mark.parametrize('severity, expected_result', [(0, None), (4, "mail send successfully")])
def test_escalation(severity, expected_result, mocker):
    owner_mock_mail = 'mail'
    mock_url = 'url'
    mocker.patch.object(IncapWhitelistCompliance, "sendMail", return_value="mail send successfully")
    res = IncapWhitelistCompliance.escalation(mock_url, severity, owner_mock_mail)
    assert res == expected_result
