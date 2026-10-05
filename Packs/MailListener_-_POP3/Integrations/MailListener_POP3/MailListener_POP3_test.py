import base64

# -*- coding: iso-8859-1 -*-
import demistomock as demisto
import pytest


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


@pytest.mark.parametrize("transfer_encoding_header", ["Content-Transfer-Encoding: 8bit\n", ""])
def test_parse_mail_parts_utf8_body_with_bytes_undefined_in_cp1252(mocker, transfer_encoding_header):
    """
    Given
    - A multipart email whose text/plain part is raw UTF-8 (8bit or no Content-Transfer-Encoding)
    - The body contains "č" (U+010D), whose UTF-8 encoding is b"\\xc4\\x8d". Byte 0x8d is undefined in cp1252.
    When
    - parse_mail_parts is called on the parsed message parts (as done by fetch_incidents)
    Then
    - Ensure no UnicodeDecodeError ('charmap' codec can't decode byte 0x8d) is raised
    - Ensure the body is returned as the original text
    """
    from email.parser import Parser

    mocker.patch.object(demisto, "params", return_value={"credentials_password": {"password": "password"}})
    from MailListener_POP3 import parse_mail_parts

    body_text = "Dobrý den, děkuji za zprávu. Hezký večer."
    raw_email = (
        "From: sender@example.com\n"
        "To: receiver@example.com\n"
        "Subject: test\n"
        "Date: Tue, 29 Sep 2026 15:27:29 +0000\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="BOUNDARY"\n'
        "\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain; charset=utf-8\n"
        f"{transfer_encoding_header}"
        "\n"
        f"{body_text}\n"
        "--BOUNDARY--\n"
    )
    msg = Parser().parsestr(raw_email)

    body, html, attachments = parse_mail_parts(msg._payload)

    assert body.strip() == body_text
    assert html == ""
    assert attachments == []


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


@pytest.mark.parametrize(
    "date_header, expected",
    [
        ("Tue, 23 Sep 2025 08:18:52", "2025-09-23T08:18:52Z"),
        ("23 Sep 2025 08:18:52", "2025-09-23T08:18:52Z"),
        ("Tue, 23 Sep 2025 08:18:52 +0200", "2025-09-23T08:18:52Z"),
        ("23 Sep 2025 08:18:52 -0500", "2025-09-23T08:18:52Z"),
    ],
)
def test_parse_time_variants(mocker, date_header, expected):
    """
    Given
    - An email Date header, with or without a leading day-of-week and/or timezone
    When
    - parse_time is called
    Then
    - Ensure it returns a normalized ISO-8601 string with a trailing 'Z'
    """
    mocker.patch.object(demisto, "params", return_value={"credentials_password": {"password": "password"}})
    from MailListener_POP3 import parse_time

    assert parse_time(date_header) == expected


@pytest.mark.parametrize("date_header", ["not a valid date", ""])
def test_parse_time_invalid(mocker, date_header):
    """
    Given
    - A Date header that cannot be parsed by any supported format (including an empty string)
    When
    - parse_time is called
    Then
    - Ensure a ValueError is raised
    """
    mocker.patch.object(demisto, "params", return_value={"credentials_password": {"password": "password"}})
    from MailListener_POP3 import parse_time

    with pytest.raises(ValueError):
        parse_time(date_header)
