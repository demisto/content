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

    mocker.patch.object(demisto, "params", return_value={"credentials_password": {"password": "password"}})

    class MockEmailPart:
        pass

    part = MockEmailPart()
    part._headers = [["content-transfer-encoding", "quoted-printable"]]
    part._payload = "el Ni=C3=B1o"
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body.encode("utf-8") == b"el Ni\xc3\xb1o"


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

    mocker.patch.object(demisto, "params", return_value={"credentials_password": {"password": "password"}})

    class MockEmailPart:
        pass

    test_payload = b"Foo\xbbBar=="
    base_64_encoded_test_payload = base64.b64encode(test_payload)

    part = MockEmailPart()
    part._headers = [["content-transfer-encoding", "base64"]]
    part._payload = base_64_encoded_test_payload
    parts = [part]

    body, html, attachments = parse_mail_parts(parts)
    assert body.replace("\ufffd", "?") == "Foo?Bar=="


def test_parse_header_empty_input():
    """
    Given
    - Empty string input to parse_header function
    When
    - parse_header is called
    Then
    - Ensure empty string is returned
    """
    from MailListener_POP3 import parse_header

    result = parse_header("")
    assert result == ""

    result = parse_header(None)
    assert result == ""


def test_parse_header_plain_text():
    """
    Given
    - Plain text input (not encoded)
    When
    - parse_header is called
    Then
    - Ensure the original text is returned unchanged
    """
    from MailListener_POP3 import parse_header

    plain_text = "This is a normal subject"
    result = parse_header(plain_text)
    assert result == plain_text


def test_parse_header_utf8_encoded():
    """
    Given
    - UTF-8 base64 encoded text (common for international characters)
    When
    - parse_header is called
    Then
    - Ensure the text is properly decoded
    """
    from MailListener_POP3 import parse_header

    # "Café" encoded in base64 with UTF-8
    encoded_text = "=?UTF-8?B?Q2Fmw6k=?="
    result = parse_header(encoded_text)
    assert result == "Café"


def test_parse_header_iso_encoded():
    """
    Given
    - ISO-8859-1 encoded text (common in European languages)
    When
    - parse_header is called
    Then
    - Ensure the text is properly decoded
    """
    from MailListener_POP3 import parse_header

    # "Niño" encoded with ISO-8859-1
    encoded_text = "=?ISO-8859-1?Q?Ni=F1o?="
    result = parse_header(encoded_text)
    assert result == "Niño"


def test_parse_header_quoted_printable():
    """
    Given
    - Quoted-printable encoded text
    When
    - parse_header is called
    Then
    - Ensure the text is properly decoded
    """
    from MailListener_POP3 import parse_header

    # "Résumé" encoded as quoted-printable
    encoded_text = "=?UTF-8?Q?R=C3=A9sum=C3=A9?="
    result = parse_header(encoded_text)
    assert result == "Résumé"


def test_parse_header_multiple_parts():
    """
    Given
    - Text with multiple encoded parts
    When
    - parse_header is called
    Then
    - Ensure all parts are properly decoded and combined
    """
    from MailListener_POP3 import parse_header

    # "Hello Café" with the second word encoded
    encoded_text = "Hello =?UTF-8?B?Q2Fmw6k=?="
    result = parse_header(encoded_text)
    assert result == "Hello Café"


def test_parse_header_error_handling(mocker):
    """
    Given
    - Malformed encoded text that would cause decoding errors
    When
    - parse_header is called
    Then
    - Ensure errors are handled gracefully and original text is returned
    - Ensure debug message is logged
    """
    from MailListener_POP3 import parse_header

    # Mock demisto.debug to verify it's called
    debug_mock = mocker.patch.object(demisto, "debug")

    # Malformed base64 encoding
    malformed_text = "=?UTF-8?B?invalid@@base64==?="
    result = parse_header(malformed_text)

    # Original text should be returned
    assert result == malformed_text

    # Debug should have been called
    debug_mock.assert_called_once()
    assert "Failed to decode" in debug_mock.call_args[0][0]
