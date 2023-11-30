import base64
# -*- coding: iso-8859-1 -*-
import demistomock as demisto


def test_parse_mail_parts(mocker):
    """
    Given
    - Email data
    When
    - Email contains special characters
    Then
    - run parse_mail_parts method
    - Validate The result body.
    """

    from MailListener_POP3 import parse_mail_parts
    mocker.patch.object(demisto, 'params', return_value={'credentials_password': {'password': 'password'}})

    class MockEmailPart:
        pass

    part = MockEmailPart()
    part._headers = [['content-transfer-encoding', 'quoted-printable']]
    part._payload = "el Ni=C3=B1o"
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body.encode('utf-8') == b'el Ni\xc3\xb1o'


def test_base64_mail_decode(mocker):
    """
    Given
    - base64 email data which could not be decoded into utf-8
    When
    - Email contains special characters
    Then
    - run parse_mail_parts method
    - Validate that no exception is thrown
    - Validate The result body
    """
    from MailListener_POP3 import parse_mail_parts
    mocker.patch.object(demisto, 'params', return_value={'credentials_password': {'password': 'password'}})

    class MockEmailPart:
        pass

    test_payload = b'Foo\xbbBar=='
    base_64_encoded_test_payload = base64.b64encode(test_payload)

    part = MockEmailPart()
    part._headers = [['content-transfer-encoding', 'base64']]
    part._payload = base_64_encoded_test_payload
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body.replace('\uFFFD', '?') == 'Foo?Bar=='
