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
