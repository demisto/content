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


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"content-disposition": "attachment"}, "attachment.txt"),
        ({"content-disposition": "attachment", "content-type": "weird"}, "attachment.txt"),
        ({"content-disposition": "attachment", "content-type": "application/pdf"}, "attachment.pdf"),
        ({"content-disposition": 'attachment; filename="report.docx"'}, "report.docx"),
        ({"content-description": "image.png"}, "image.png"),
    ],
)
def test_get_attachment_name(headers, expected):
    """
    Given
    - Attachment headers, including ones without a filename and without a (valid) Content-Type
    When
    - Running get_attachment_name
    Then
    - A name is returned and no exception is raised
    """
    from MailListener_POP3 import get_attachment_name

    assert get_attachment_name(headers) == expected


def _build_mail(index, minute, subject, attachment_part=None):
    from email.parser import Parser

    if attachment_part is None:
        body = "Content-Type: text/plain\r\n\r\nhello\r\n"
    else:
        body = attachment_part
    raw = (
        f"Date: Sun, 18 Oct 2026 09:0{minute}:00 +0000\r\n"
        "From: sender@example.test\r\n"
        "To: inbox@example.test\r\n"
        f"Subject: {subject}\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="x"\r\n'
        "\r\n"
        "--x\r\n"
        f"{body}"
        "--x--\r\n"
    )
    msg = Parser().parsestr(raw)
    msg["index"] = index
    return msg


def test_fetch_incidents_attachment_without_name_and_content_type(mocker):
    """
    Given
    - A mailbox with a normal email, an email whose attachment has no filename and no Content-Type, and another normal email
    When
    - Running fetch_incidents
    Then
    - All three emails become incidents (the attachment gets a default name) and last run advances
    """
    from MailListener_POP3 import fetch_incidents

    poison_part = "Content-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n"
    mails = [
        _build_mail(1, 1, "normal-1"),
        _build_mail(2, 2, "poison", poison_part),
        _build_mail(3, 3, "normal-2"),
    ]
    mocker.patch("MailListener_POP3.get_user_emails", return_value=mails)
    mocker.patch("MailListener_POP3.fileResult", return_value={"Type": 1, "FileID": "file-id"})
    mocker.patch.object(demisto, "getLastRun", return_value={"time": "2026-10-18T00:00:00Z"})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")

    fetch_incidents()

    incidents = incidents_mock.call_args[0][0]
    assert [inc["name"] for inc in incidents] == ["normal-1", "poison", "normal-2"]
    assert incidents[1]["attachment"] == [{"path": "file-id", "name": "attachment.txt"}]
    set_last_run.assert_called_once_with({"time": "2026-10-18T09:03:01Z"})


def test_fetch_incidents_skips_failing_email(mocker):
    """
    Given
    - A mailbox where converting one email to an incident raises an exception
    When
    - Running fetch_incidents
    Then
    - The failing email is skipped, the other emails become incidents and last run advances
    """
    from MailListener_POP3 import fetch_incidents, mail_to_incident as original_mail_to_incident

    mails = [_build_mail(1, 1, "normal-1"), _build_mail(2, 2, "broken"), _build_mail(3, 3, "normal-2")]

    def mail_to_incident(msg):
        if msg["subject"] == "broken":
            raise Exception("unexpected parsing error")
        return original_mail_to_incident(msg)

    mocker.patch("MailListener_POP3.get_user_emails", return_value=mails)
    mocker.patch("MailListener_POP3.mail_to_incident", side_effect=mail_to_incident)
    mocker.patch.object(demisto, "getLastRun", return_value={"time": "2026-10-18T00:00:00Z"})
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    incidents_mock = mocker.patch.object(demisto, "incidents")
    error_mock = mocker.patch.object(demisto, "error")

    fetch_incidents()

    assert [inc["name"] for inc in incidents_mock.call_args[0][0]] == ["normal-1", "normal-2"]
    set_last_run.assert_called_once_with({"time": "2026-10-18T09:03:01Z"})
    assert "broken" in error_mock.call_args[0][0]
