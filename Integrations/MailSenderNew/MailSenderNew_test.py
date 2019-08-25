# -*- coding: utf-8 -*-
from MailSenderNew import create_msg
import demistomock as demisto
import pytest


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
    (msg, to, cc, bcc) = create_msg()
    assert to == ['test@test.com', 'test1@test.com']  # disable-secrets-detection
    assert cc == ['cc@test.com']  # disable-secrets-detection
    assert bcc == ['bcc@test.com']  # disable-secrets-detection
    lines = msg.splitlines()
    subj = [x for x in lines if 'Subject' in x][0]
    assert subj_include in subj
    assert 'foo' in msg
