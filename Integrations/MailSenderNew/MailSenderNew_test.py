# -*- coding: utf-8 -*-
import MailSenderNew
import demistomock as demisto
import pytest
import hmac

RETURN_ERROR_TARGET = 'MailSenderNew.return_error'


@pytest.mark.parametrize('subject,subj_include,headers', [
                        (u'testbefore\ntestafter', 'testafter', 'foo=baz'),
                        ('testbefore\ntestafter', 'testafter', 'foo=baz'),
                        ('\xd7\xa2\xd7\x91\xd7\xa8\xd7\x99\xd7\xaa', '=?utf-8?', 'foo=baz'),  # non-ascii char utf-8 encoded
                        (u'עברית', '=?utf-8?', 'foo=baz')
                        ])  # noqa: E124
def test_create_msg(mocker, subject, subj_include, headers):
    mocker.patch.object(demisto, 'args', return_value={
        'to': 'test@test.com,test1@test.com',  # disable-secrets-detection
        'from': 'test@test.com',
        'bcc': 'bcc@test.com',  # disable-secrets-detection
        'cc': 'cc@test.com',  # disable-secrets-detection
        'subject': subject,
        'body': 'this is the body',
        'additionalHeader': headers
    })
    mocker.patch.object(demisto, 'params', return_value={
        'from': 'test@test.com',
    })
    (msg, to, cc, bcc) = MailSenderNew.create_msg()
    assert to == ['test@test.com', 'test1@test.com']  # disable-secrets-detection
    assert cc == ['cc@test.com']  # disable-secrets-detection
    assert bcc == ['bcc@test.com']  # disable-secrets-detection
    lines = msg.splitlines()
    subj = [x for x in lines if 'Subject' in x][0]
    assert subj_include in subj
    assert 'foo' in msg


def test_debug_smtp(mocker):
    '''
    Test that when we do test-module and fail we collect the server debug log
    '''
    mocker.patch.object(demisto, 'params', return_value={
        'from': 'test@test.com',
        'host': 'localhost',
        'port': '2025'
    })
    mocker.patch.object(demisto, 'command', return_value='test-module')
    demisto_error = mocker.patch.object(demisto, 'error')
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    MailSenderNew.main()
    assert return_error_mock.call_count == 1
    assert demisto_error.call_count == 1
    # LOG should at least contain: "connect: " with port
    assert MailSenderNew.LOG.messages and '2025' in MailSenderNew.LOG.messages[0]


def test_hmac(mocker):
    '''
    Test that hmac is able to handle unicode user/pass
    '''
    mocker.patch.object(demisto, 'params', return_value={
        'credentials': {'identifier': unicode('user'), 'password': unicode('pass')}
    })
    user, password = MailSenderNew.get_user_pass()
    res = user + hmac.HMAC(password, 'test').hexdigest()
    assert len(res) > 0
