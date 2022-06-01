# -*- coding: iso-8859-1 -*-
import base64

from MailListener_POP3 import parse_mail_parts


def test_parse_mail_parts():
    """
    Given
    - Email data
    When
    - Email contains special characters
    Then
    - run parse_mail_parts method
    - Validate The result body.
    """

    class MockEmailPart:
        pass

    part = MockEmailPart()
    part._headers = [['content-transfer-encoding', 'quoted-printable']]
    part._payload = "El Ni\xc3\xb1o"
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body == 'El Nio'


def test_base64_mail_decode():
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
    class MockEmailPart:
        pass

    test_payload = 'Foo\xbbBar=='
    base_64_encoded_test_payload = base64.b64encode(test_payload)

    part = MockEmailPart()
    part._headers = [['content-transfer-encoding', 'base64']]
    part._payload = base_64_encoded_test_payload
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body.replace(u'\uFFFD', '?') == 'Foo?Bar=='
