from EWSMailSender import prepare


def test_prepar():
    res = prepare()
    assert res.protocol.server == 'outlook.office365.com'
