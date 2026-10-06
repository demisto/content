import base64
import copy
import tempfile
from email import message_from_bytes
from email.message import EmailMessage, Message
from pathlib import Path

import demistomock as demisto
import pytest
from CommonServerPython import *
from parse_emails.parse_emails import EmailParser
from ParseEmailFilesV2 import (
    data_to_md,
    extract_attached_eml_files,
    fix_attached_eml_outputs,
    get_decoded_file_data,
    get_file_name_key,
    main,
    match_attachments_to_files,
    parse_attached_eml_files,
    parse_nesting_level,
    remove_empty_unnamed_attachments,
)
from pytest_mock import MockerFixture


def exec_command_for_file(
    file_path,
    info="RFC 822 mail text, with CRLF line terminators",
    file_name=None,
    file_type="",
):
    """
    Return a executeCommand function which will return the passed path as an entry to the call 'getFilePath'

    Arguments:
        file_path {string} -- file name of file residing in test_data dir

    Raises:
        ValueError: if call with differed name from getFilePath or getEntry

    Returns:
        [function] -- function to be used for mocking
    """
    if not file_name:
        file_name = file_path
    path = "test_data/" + file_path

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [{"Type": entryTypes["note"], "Contents": {"path": path, "name": file_name}}]
        elif name == "getEntry":
            return [{"Type": entryTypes["file"], "FileMetadata": {"info": info, "type": file_type}}]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    return executeCommand


def test_eml_type(mocker):
    """
    Given:
        - A eml file
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [
                {"Type": entryTypes["note"], "Contents": {"path": "test_data/smtp_email_type.eml", "name": "smtp_email_type.eml"}}
            ]
        elif name == "getEntry":
            return [
                {"Type": entryTypes["file"], "FileMetadata": {"info": "SMTP mail, UTF-8 Unicode text, with CRLF terminators"}}
            ]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["SMTP mail, UTF-8 Unicode text, with CRLF terminators"])
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entryid"] == "test"
    # assert demisto.executeCommand('getFilePath', {})[0]['Type'] == entryTypes['note']
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Type"] == entryTypes["note"]
    assert results[0]["EntryContext"]["Email"]["Subject"] == "Test Smtp Email"


def test_eml_contains_eml(mocker):
    """
    Given:
        - A eml file contains eml
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure the was parsed successfully
        - Ensure both files was parsed
        - Ensure the attachments was returned
    """

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": {
                        "path": "test_data/Fwd_test-inner_attachment_eml.eml",
                        "name": "Fwd_test-inner_attachment_eml.eml",
                    },
                }
            ]
        elif name == "getEntry":
            return [{"Type": entryTypes["file"], "FileMetadata": {"info": "news or mail text, ASCII text"}}]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["news or mail text, ASCII text"])
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entryid"] == "test"

    main()
    assert demisto.results.call_count == 4
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == 4

    assert results[0].args[0]["File"] == "ArcSight_ESM_fixes.yml"

    assert results[1].args[0]["File"] == "test - inner attachment eml.eml"

    assert results[2].args[0]["EntryContext"]["Email"]["Subject"] == "Fwd: test - inner attachment eml"
    assert "ArcSight_ESM_fixes.yml" in results[2].args[0]["EntryContext"]["Email"]["Attachments"]
    assert "ArcSight_ESM_fixes.yml" in results[2].args[0]["EntryContext"]["Email"]["AttachmentsData"][0]["Name"]
    assert "test - inner attachment eml.eml" in results[2].args[0]["EntryContext"]["Email"]["Attachments"]
    assert "test - inner attachment eml.eml" in results[2].args[0]["EntryContext"]["Email"]["AttachmentsData"][1]["Name"]
    assert results[2].args[0]["EntryContext"]["Email"]["Depth"] == 0

    assert results[3].args[0]["EntryContext"]["Email"]["Subject"] == "test - inner attachment eml"
    assert results[3].args[0]["EntryContext"]["Email"]["Depth"] == 1


def test_eml_contains_msg(mocker):
    """
    Given:
        - A eml file contains msg
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure the was parsed successfully
        - Ensure both files was parsed
        - Ensure the attachments was returned
    """

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": {"path": "test_data/DONT_OPEN-MALICIOUS.eml", "name": "DONT_OPEN-MALICIOUS.eml"},
                }
            ]
        elif name == "getEntry":
            return [{"Type": entryTypes["file"], "FileMetadata": {"info": "news or mail text, ASCII text"}}]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["news or mail text, ASCII text"])
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entryid"] == "test"

    main()
    results = demisto.results.call_args_list

    assert demisto.results.call_count == 3

    assert len(results) == 3

    assert results[0].args[0]["File"] == "Attacker+email+.msg"

    assert results[1].args[0]["EntryContext"]["Email"]["Subject"] == "DONT OPEN - MALICIOS"
    assert "Attacker+email+.msg" in results[1].args[0]["EntryContext"]["Email"]["Attachments"]
    assert "Attacker+email+.msg" in results[1].args[0]["EntryContext"]["Email"]["AttachmentsData"][0]["Name"]
    assert results[1].args[0]["EntryContext"]["Email"]["Depth"] == 0

    assert results[2].args[0]["EntryContext"]["Email"]["Subject"] == "Attacker email"
    assert results[2].args[0]["EntryContext"]["Email"]["Depth"] == 1


def test_eml_contains_eml_depth(mocker):
    """
    Given:
        - A eml file contains eml
        - depth = 1
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure only the first mail is parsed
        - Ensure the attachments of the first mail was returned
    """

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": {
                        "path": "test_data/Fwd_test-inner_attachment_eml.eml",
                        "name": "Fwd_test-inner_attachment_eml.eml",
                    },
                }
            ]
        elif name == "getEntry":
            return [{"Type": entryTypes["file"], "FileMetadata": {"info": "news or mail text, ASCII text"}}]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    mocker.patch.object(demisto, "args", return_value={"entryid": "test", "max_depth": "1"})
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["news or mail text, ASCII text"])
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entryid"] == "test"

    main()
    assert demisto.results.call_count == 3
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == 3

    assert results[0].args[0]["File"] == "ArcSight_ESM_fixes.yml"

    assert results[1].args[0]["File"] == "test - inner attachment eml.eml"

    assert results[2].args[0]["EntryContext"]["Email"]["Depth"] == 0
    assert "ArcSight_ESM_fixes.yml" in results[2].args[0]["EntryContext"]["Email"]["Attachments"]
    assert "ArcSight_ESM_fixes.yml" in results[2].args[0]["EntryContext"]["Email"]["AttachmentsData"][0]["Name"]
    assert "test - inner attachment eml.eml" in results[2].args[0]["EntryContext"]["Email"]["Attachments"]
    assert "test - inner attachment eml.eml" in results[2].args[0]["EntryContext"]["Email"]["AttachmentsData"][1]["Name"]


def test_msg(mocker):
    """
    Given:
        - A msg file
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """
    info = "CDFV2 Microsoft Outlook Message"
    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=exec_command_for_file("smime-p7s.msg", info=info))
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["CDFV2 Microsoft Outlook Message"])
    mocker.patch.object(demisto, "results")
    # validate our mocks are good
    assert demisto.args()["entryid"] == "test"
    main()
    # assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Type"] == entryTypes["note"]
    assert results[0]["EntryContext"]["Email"]["Subject"] == "test"


def test_no_content_type_file(mocker):
    """
    Given:
        - A eml with no_content_type
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """
    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=exec_command_for_file("no_content_type.eml", info="ascii text"))
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["ascii text"])
    mocker.patch.object(demisto, "results")
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["Type"] == entryTypes["note"]
    assert results[0]["EntryContext"]["Email"]["Subject"] == "No content type"


def test_no_content_file(mocker):
    """
    Given:
        - A eml without content
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure a error is returned
    """
    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=exec_command_for_file("no_content.eml", info="ascii text"))
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["ascii text"])
    mocker.patch.object(demisto, "results")
    try:
        main()
    except SystemExit:
        gotexception = True
    assert gotexception
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert "Could not extract email from file" in results[0]["Contents"]


def test_md_output_empty_body_text():
    """
    Given:
     - The input email_data where the value of the 'Text' field is None.

    When:
     - Running the data_to_md command on this email_data.

    Then:
     - Validate that output the md doesn't contain a row for the 'Text' field.
    """
    email_data = {"To": "email1@paloaltonetworks.com", "From": "email2@paloaltonetworks.com", "Text": None}
    expected = (
        "### Results:\n"
        "* From:\temail2@paloaltonetworks.com\n"
        "* To:\temail1@paloaltonetworks.com\n"
        "* CC:\t\n"
        "* BCC:\t\n"
        "* Subject:\t\n"
        "* Attachments:\t\n\n\n"
        "### HeadersMap\n"
        "**No entries.**\n"
    )

    md = data_to_md(email_data)
    assert expected == md

    email_data = {
        "To": "email1@paloaltonetworks.com",
        "From": "email2@paloaltonetworks.com",
    }
    expected = (
        "### Results:\n"
        "* From:\temail2@paloaltonetworks.com\n"
        "* To:\temail1@paloaltonetworks.com\n"
        "* CC:\t\n"
        "* BCC:\t\n"
        "* Subject:\t\n"
        "* Attachments:\t\n\n\n"
        "### HeadersMap\n"
        "**No entries.**\n"
    )

    md = data_to_md(email_data)
    assert expected == md


def test_md_output_with_body_text():
    """
    Given:
     - The input email_data with a value in the 'Text' field.

    When:
     - Running the data_to_md command on this email_data.

    Then:
     - Validate that the output md contains a row for the 'Text' field.
    """
    email_data = {"To": "email1@paloaltonetworks.com", "From": "email2@paloaltonetworks.com", "Text": "<email text>"}
    expected = (
        "### Results:\n"
        "* From:\temail2@paloaltonetworks.com\n"
        "* To:\temail1@paloaltonetworks.com\n"
        "* CC:\t\n"
        "* BCC:\t\n"
        "* Subject:\t\n"
        "* Body/Text:\t[email text]\n"
        "* Attachments:\t\n\n\n"
        "### HeadersMap\n"
        "**No entries.**\n"
    )

    md = data_to_md(email_data)
    assert expected == md


@pytest.mark.parametrize(
    "nesting_level_to_return, output, res",
    [
        ("All files", ["output1", "output2", "output3"], ["output1", "output2", "output3"]),
        ("Outer file", ["output1", "output2", "output3"], ["output1"]),
        ("Inner file", ["output1", "output2", "output3"], ["output3"]),
    ],
)
def test_parse_nesting_level(nesting_level_to_return, output, res):
    """
    Given:
    - parsed email output, nesting_level_to_return param - All files.
    - parsed email output, nesting_level_to_return param - Outer file.
    - parsed email output, nesting_level_to_return param - Inner file.

    When:
    calling the parse_nesting_level function.

    Then:
    - Validating the that all outputs are returned.
    - Validating the that only output1 is returned.
    - Validating the that only output3 is returned.
    """
    assert parse_nesting_level(nesting_level_to_return, output) == res


@pytest.mark.parametrize(
    "nesting_level_to_return, results_len, depth, results_index",
    [("All files", 4, 0, 2), ("Outer file", 3, 0, 2), ("Inner file", 1, 1, 0)],
)
def test_eml_contains_eml_nesting_level(mocker, nesting_level_to_return, results_len, depth, results_index):
    """
    Given:
    - A eml file contains eml, nesting_level_to_return param - All files.
    - A eml file contains eml, nesting_level_to_return param - Outer file.
    - A eml file contains eml, nesting_level_to_return param - Inner file.

    When: parsing the eml file.

    Then:
    - Validating the that call_args_list length is 4 (2 parsed eml files and 2 attachments).
    - Validating the that call_args_list length is 3 (the outer parsed eml file and is 2 attachments).
    - Validating the that call_args_list length is 1 ( the Inner parsed eml file).
    """

    def executeCommand(name, args=None):
        if name == "getFilePath":
            return [
                {
                    "Type": entryTypes["note"],
                    "Contents": {
                        "path": "test_data/Fwd_test-inner_attachment_eml.eml",
                        "name": "Fwd_test-inner_attachment_eml.eml",
                    },
                }
            ]
        elif name == "getEntry":
            return [{"Type": entryTypes["file"], "FileMetadata": {"info": "news or mail text, ASCII text"}}]
        else:
            raise ValueError(f"Unimplemented command called: {name}")

    mocker.patch.object(demisto, "args", return_value={"entryid": "test", "nesting_level_to_return": nesting_level_to_return})
    mocker.patch.object(demisto, "context")
    mocker.patch.object(demisto, "dt", return_value=["news or mail text, ASCII text"])
    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    mocker.patch.object(demisto, "results")
    main()
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == results_len
    assert results[results_index].args[0]["EntryContext"]["Email"]["Depth"] == depth


def test_eml_contains_empty_htm_not_containing_file_data(mocker):
    """
    Given: A root attachment-disposition envelope with an unnamed empty body and a named HTML attachment.
    When: Parsing a valid email file with default parameters.
    Then: The HTML attachment has a FilePath, not FileData; the empty body is not emitted as a file.
    """
    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(demisto, "executeCommand", side_effect=exec_command_for_file("eml_contains_emptytxt_htm_file.eml"))
    mocker.patch.object(demisto, "results")

    assert demisto.args()["entryid"] == "test"
    main()

    results = demisto.results.call_args[0]

    attachments = results[0]["EntryContext"]["Email"]["AttachmentsData"]
    assert len(attachments) == 1
    assert attachments[0]["Name"] == "SomeTest.HTM"
    assert attachments[0]["FilePath"]
    assert "FileData" not in attachments[0]


def test_smime_without_to_from_subject(mocker):
    """
    Given:
        multipart/signed p7m file without "To"/"From"/"Subject" fields contains an eml attachment
    When:
        Parsing the file
    Then:
        The attachment files are saved to the war-room
    """
    save_file = mocker.patch("ParseEmailFilesV2.save_file", return_value="mocked_file_path")
    mocker.patch.object(demisto, "args", return_value={"entryid": "test"})
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=exec_command_for_file(
            "smime_without_fields.p7m",
            info="ascii text",
            file_type='multipart/signed; protocol="application/pkcs7-signature";, ASCII text',
        ),
    )
    mocker.patch.object(demisto, "results")
    expected_email_content = (
        "Return-Path: <testing@gmail.com>\n"
        "Received: from [172.31.255.255] ([172.31.255.255])\n"
        "        by smtp.gmail.com with ESMTPSA id t6sm46056484wmb.29.2019.07.23.05.38.26\n"
        "        for <testing@gmail.com>\n"
        "        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);\n"
        "        Tue, 23 Jul 2019 05:38:26 -0700 (PDT)\n"
        "To: testing@gmail.com\n"
        "From: test ing <testing@gmail.com>\n"
        "Subject: Testing Email Attachment\n"
        "Message-ID: <a853a1b0-1ffe-4e37-d9a9-a27c6bc0bd5b@gmail.com>\n"
        "Date: Tue, 23 Jul 2019 15:38:25 +0300\n"
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:60.0)\n"
        " Gecko/20100101 Thunderbird/60.8.0\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8; format=flowed\n"
        "Content-Transfer-Encoding: 7bit\n"
        "Content-Language: en-US\n"
        "\n"
        "This is the body of the attachment."
    )

    main()

    # Assert that save_file was called with the expected arguments
    save_file.assert_called_once_with("Attachment.eml", expected_email_content)
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]["EntryContext"]["Email"]["FileName"] == "Attachment.eml"


def test_remove_bom():
    """
    Given:
        an eml file which contains BOM
    When:
        executing the remove_bom function
    Then:
        - Ensure the new file does not contain BOM
        - Ensure the new file content is as expected
    """
    from ParseEmailFilesV2 import remove_bom

    # Create a temporary file with BOM
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"\xef\xbb\xbfThis is a test file with BOM.")
        temp_file_path = temp_file.name

    # Call the remove_bom function
    cleaned_file_path, file_type, file_name = remove_bom(temp_file_path, "message/rfc822", temp_file_path)

    # Read the content of the cleaned file
    with open(cleaned_file_path, "rb") as cleaned_file:
        cleaned_content = cleaned_file.read()

    # Assert that the BOM has been removed
    assert not cleaned_content.startswith(b"\xef\xbb\xbf")
    assert cleaned_content == b"This is a test file with BOM."

    # Clean up temporary files
    Path(temp_file_path).unlink()
    Path(cleaned_file_path).unlink()


def test_remove_bom_no_bom():
    """
    Given:
        an eml file which does not contain BOM
    When:
        executing the remove_bom function
    Then:
        - Ensure the all arguments were sent to remove_bom, remained as they are (file_path, file_type, file_name)
    """
    from ParseEmailFilesV2 import remove_bom

    # Create a temporary file with BOM
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"This is a test file with BOM.")
        temp_file_path = temp_file.name

    # Call the remove_bom function
    cleaned_file_path, file_type, file_name = remove_bom(temp_file_path, "message/rfc822", temp_file_path)

    # Assert all arguments remained as they are
    assert cleaned_file_path == temp_file_path
    assert file_type == "message/rfc822"
    assert temp_file_path == file_name

    # Clean up temporary files
    Path(temp_file_path).unlink()


def test_html_unescape_decodes_entities():
    """
    Given:
        - An HTML string containing HTML-encoded entities (e.g. '&amp;' in href attributes)
    When:
        - Calling html_unescape()
    Then:
        - All HTML entities are decoded (e.g. '&amp;' becomes '&')
        - URLs in href attributes are properly formed for indicator extraction
    """
    from ParseEmailFilesV2 import html_unescape

    raw_html = '<a href="https://example.com/page?foo=bar&amp;baz=1">link</a>'
    result = html_unescape(raw_html)

    assert "&amp;" not in result
    assert "https://example.com/page?foo=bar&baz=1" in result


def test_html_unescape_populated_in_context(mocker):
    """
    Given:
        - An EML file whose HTML body contains HTML-encoded entities (e.g. '&amp;' in href URLs)
    When:
        - Running the ParseEmailFilesV2 script
    Then:
        - The Email context contains an 'HTMLUnescape' key
        - The 'HTMLUnescape' value has HTML entities decoded (e.g. '&amp;' → '&')
        - The original 'HTML' key is unchanged
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"entryid": "test"},
    )
    mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=exec_command_for_file(
            "html_with_entities.eml",
            info="RFC 822 mail text, with CRLF line terminators",
        ),
    )
    mocker.patch.object(demisto, "context")
    mocker.patch.object(
        demisto,
        "dt",
        return_value=["RFC 822 mail text, with CRLF line terminators"],
    )
    mocker.patch.object(demisto, "results")

    main()

    results = demisto.results.call_args[0]
    assert len(results) == 1
    email_context = results[0]["EntryContext"]["Email"]

    # HTMLUnescape must be present and have entities decoded
    assert "HTMLUnescape" in email_context
    html_text = email_context["HTMLUnescape"]
    assert "&amp;" not in html_text, "HTML entities were not decoded in HTMLUnescape"
    assert "https://example.com/page?foo=bar&baz=1" in html_text

    # Original HTML key must still be present (unchanged)
    assert "HTML" in email_context


@pytest.mark.parametrize("content_type", ["message/rfc822", "text/plain", "application/octet-stream"])
@pytest.mark.parametrize(
    "max_depth, nesting_level, expected_depths, expected_names",
    [
        ("3", "All files", [0, 1], ["original_message.eml", "pixel.png"]),
        ("3", "Outer file", [0], ["original_message.eml"]),
        ("3", "Inner file", [1], ["pixel.png"]),
        ("1", "All files", [0], ["original_message.eml"]),
    ],
)
def test_root_attachment_envelope_without_preprocessing(
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    content_type: str,
    max_depth: str,
    nesting_level: str,
    expected_depths: list[int],
    expected_names: list[str],
) -> None:
    """Run the real parser, file writer, and context conversion, mocking only platform boundaries."""
    test_data = Path(__file__).parent / "test_data"
    original_bytes = (test_data / "original_message.eml").read_bytes()
    original = message_from_bytes(original_bytes)
    pixel_bytes = next(part.get_payload(decode=True) for part in original.walk() if part.get_content_type() == "image/png")
    expected_files = {"original_message.eml": original_bytes, "pixel.png": pixel_bytes}
    report = (test_data / "reported_message_root_attachment.eml").read_bytes()
    report = report.replace(b"Content-Type: message/rfc822;", f"Content-Type: {content_type};".encode(), 1)
    input_path = tmp_path / "reported_message_root_attachment.eml"
    input_path.write_bytes(report)
    monkeypatch.chdir(tmp_path)
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "entryid": "sample-entry",
            "default_encoding": "utf-8",
            "max_depth": max_depth,
            "nesting_level_to_return": nesting_level,
        },
    )
    execute_command = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": entryTypes["note"], "Contents": {"path": str(input_path), "name": input_path.name}}],
    )
    mocker.patch.object(demisto, "context", return_value={})
    mocker.patch.object(demisto, "dt", return_value="RFC 822 mail text")
    mocker.patch.object(demisto, "investigation", return_value={"id": "sample-case"})
    mocker.patch.object(demisto, "uniqueFile", side_effect=["file-1", "file-2"])
    result_writer = mocker.patch.object(demisto, "results")

    main()

    execute_command.assert_called_once_with("getFilePath", {"id": "sample-entry"})
    entries = [call.args[0] for call in result_writer.call_args_list]
    files = {entry["File"]: entry for entry in entries if entry["Type"] == entryTypes["file"]}
    emails = [entry["EntryContext"]["Email"] for entry in entries if "Email" in entry.get("EntryContext", {})]
    assert sorted(files) == sorted(expected_names)
    assert [item["Depth"] for item in emails] == expected_depths
    for name, file_entry in files.items():
        assert (tmp_path / f"sample-case_{file_entry['FileID']}").read_bytes() == expected_files[name]
    for parsed_email in emails:
        if parsed_email["Depth"] == 0:
            assert parsed_email["HeadersMap"]["Content-Disposition"] == "attachment"
        else:
            assert parsed_email["ParentFileName"] == input_path.name
        for attachment in parsed_email["AttachmentsData"]:
            assert "FileData" not in attachment
            assert attachment["FilePath"] == f"sample-case_{files[attachment['Name']]['FileID']}"


RFC822_FILE_TYPE = "RFC 822 mail text"


def build_email(subject: str, body: str = "Harmless body.") -> EmailMessage:
    """Build a small synthetic email."""
    message = EmailMessage()
    message["From"] = "Example Sender <sender@example.com>"
    message["To"] = "Example Recipient <recipient@example.org>"
    message["Subject"] = subject
    message.set_content(body)
    return message


def build_report_with_root_attachment(
    attached_emails: list[tuple[str, bytes]], content_type: str = "message/rfc822", transfer_encoding: str = "base64"
) -> bytes:
    """
    Build a report whose top level part is marked as an attachment, like test_data/reported_message_root_attachment.eml,
    carrying the given emails as attachments, which are base64 encoded unless the transfer encoding is 7bit.
    """
    lines = [
        "From: Example Reporter <reporter@example.org>",
        "To: Example Reports <reports@example.org>",
        "Subject: Reported message",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="report-boundary"',
        "Content-Disposition: attachment",
        "",
    ]
    for attachment_name, attachment_data in attached_emails:
        lines += [
            "--report-boundary",
            f'Content-Type: {content_type}; name="{attachment_name}"',
            f'Content-Disposition: attachment; filename="{attachment_name}"',
            f"Content-Transfer-Encoding: {transfer_encoding}",
            "",
            base64.encodebytes(attachment_data).decode() if transfer_encoding == "base64" else attachment_data.decode(),
        ]
    lines += ["--report-boundary--", ""]
    return "\n".join(lines).encode()


def build_email_with_attached_message(disposition_parameters: str) -> bytes:
    """Build an ordinary email with an attached message/rfc822, whose Content-Disposition has the given parameters."""
    lines = [
        "From: Example Sender <sender@example.com>",
        "To: Example Recipient <recipient@example.org>",
        "Subject: Outer",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="outer-boundary"',
        "",
        "--outer-boundary",
        "Content-Type: text/plain",
        "",
        "Outer body.",
        "--outer-boundary",
        "Content-Type: message/rfc822",
        f"Content-Disposition: attachment; {disposition_parameters}",
        "Content-Transfer-Encoding: 7bit",
        "",
        build_email("Attached").as_string(),
        "--outer-boundary--",
        "",
    ]
    return "\n".join(lines).encode()


def get_attachment_parts(email_bytes: bytes) -> list[Message]:
    return [part for part in message_from_bytes(email_bytes).walk() if part.get_filename()]


def parse_with_email_parser(file_path: Path, max_depth: int = 3, parse_only_headers: bool = False) -> list[dict]:
    """Parse an email file with the parser only, the way the script does before it fixes the attached emails."""
    output = EmailParser(
        file_path=str(file_path),
        max_depth=max_depth,
        parse_only_headers=parse_only_headers,
        file_info=RFC822_FILE_TYPE,
        default_encoding="utf-8",
        file_name=file_path.name,
    ).parse()
    return [output] if isinstance(output, dict) else output


def fix_outputs(file_path: Path, output: list[dict], max_depth: int = 3, parse_only_headers: bool = False) -> list[dict]:
    return fix_attached_eml_outputs(
        output, str(file_path), file_path.name, max_depth, parse_only_headers, RFC822_FILE_TYPE, None, "utf-8"
    )


def run_main_with_email(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, email_bytes: bytes, file_name: str = "email.eml"
) -> list[dict]:
    """Run the script on an email, mocking only the platform boundaries, and return the entries sent to the war room."""
    input_path = tmp_path / file_name
    input_path.write_bytes(email_bytes)
    monkeypatch.chdir(tmp_path)
    mocker.patch.object(demisto, "args", return_value={"entryid": "sample-entry", "default_encoding": "utf-8"})
    mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=[{"Type": entryTypes["note"], "Contents": {"path": str(input_path), "name": file_name}}],
    )
    mocker.patch.object(demisto, "context", return_value={})
    mocker.patch.object(demisto, "dt", return_value=RFC822_FILE_TYPE)
    mocker.patch.object(demisto, "investigation", return_value={"id": "sample-case"})
    mocker.patch.object(demisto, "uniqueFile", side_effect=[f"file-{index}" for index in range(10)])
    result_writer = mocker.patch.object(demisto, "results")

    main()

    return [call.args[0] for call in result_writer.call_args_list]


def test_get_decoded_file_data_base64_message_returns_original_bytes():
    """
    Given: An attached message/rfc822 part which is base64 encoded, with the base64 text wrapped to lines.
    When: Getting the decoded file data.
    Then: The original bytes of the attached message are returned.
    """
    original_bytes = build_email("Original", "Line. " * 100).as_bytes()
    report = build_report_with_root_attachment([("original.eml", original_bytes)])

    (attachment_part,) = get_attachment_parts(report)

    assert get_decoded_file_data(attachment_part) == original_bytes


def test_get_decoded_file_data_invalid_base64_message_returns_none():
    """
    Given: An attached message/rfc822 part declared as base64, whose content is not base64 but is accepted by a lenient decoder.
    When: Getting the decoded file data.
    Then: None is returned, instead of garbage that was decoded from non-base64 data.
    """
    not_base64 = b"abcd efgh!"
    assert base64.b64decode(not_base64)  # a lenient decoder silently returns bytes for it
    email_bytes = (
        b"Content-Type: multipart/mixed; boundary=b\n\n"
        b"--b\n"
        b'Content-Type: message/rfc822; name="invalid.eml"\n'
        b'Content-Disposition: attachment; filename="invalid.eml"\n'
        b"Content-Transfer-Encoding: base64\n\n" + not_base64 + b"\n--b--\n"
    )

    (attachment_part,) = get_attachment_parts(email_bytes)

    assert get_decoded_file_data(attachment_part) is None


def test_get_decoded_file_data_plain_attached_message_keeps_headers():
    """
    Given: An attached message/rfc822 part which is not encoded, and its message has a single part.
    When: Getting the decoded file data.
    Then: The whole attached message is returned, and not only its body.
    """
    outer = build_email("Outer")
    outer.add_attachment(build_email("Inner", "Inner body."), filename="inner.eml")

    (attachment_part,) = get_attachment_parts(outer.as_bytes())
    file_data = get_decoded_file_data(attachment_part)

    assert file_data
    attached_message = message_from_bytes(file_data)
    assert attached_message["Subject"] == "Inner"
    assert "Inner body." in attached_message.get_payload()


def test_get_decoded_file_data_base64_file_returns_decoded_bytes():
    """
    Given: An .eml file attached as a base64 encoded application/octet-stream.
    When: Getting the decoded file data.
    Then: The decoded bytes are returned.
    """
    original_bytes = build_email("Original").as_bytes()
    outer = build_email("Outer")
    outer.add_attachment(original_bytes, maintype="application", subtype="octet-stream", filename="original.eml")

    (attachment_part,) = get_attachment_parts(outer.as_bytes())

    assert get_decoded_file_data(attachment_part) == original_bytes


def test_get_decoded_file_data_empty_file_returns_none():
    """
    Given: An empty .eml file attachment.
    When: Getting the decoded file data.
    Then: None is returned.
    """
    outer = build_email("Outer")
    outer.add_attachment(b"", maintype="application", subtype="octet-stream", filename="empty.eml")

    (attachment_part,) = get_attachment_parts(outer.as_bytes())

    assert get_decoded_file_data(attachment_part) is None


def test_extract_attached_eml_files_keeps_files_with_the_same_name(tmp_path: Path):
    """
    Given: A report with two attached emails which have the same file name and different content.
    When: Extracting the attached .eml files.
    Then: Both files are returned in the order in which they appear, none overwrites the other.
    """
    first = build_email("First").as_bytes()
    second = build_email("Second").as_bytes()
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(build_report_with_root_attachment([("original.eml", first), ("original.eml", second)]))

    assert extract_attached_eml_files(str(report_path)) == [("original.eml", first), ("original.eml", second)]


def test_extract_attached_eml_files_ignores_other_files_and_inner_attachments(tmp_path: Path):
    """
    Given: An email with a text attachment, and an attached email which has an .eml attachment of its own.
    When: Extracting the attached .eml files.
    Then: Only the .eml file attached to the email itself is returned.
    """
    inner = build_email("Inner")
    inner.add_attachment(build_email("Deep"), filename="deep.eml")
    outer = build_email("Outer")
    outer.add_attachment(b"notes", maintype="text", subtype="plain", filename="notes.txt")
    outer.add_attachment(inner, filename="inner.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())

    assert [name for name, _ in extract_attached_eml_files(str(outer_path))] == ["inner.eml"]


def test_extract_attached_eml_files_ignores_empty_files(tmp_path: Path):
    """
    Given: An email with an empty .eml attachment.
    When: Extracting the attached .eml files.
    Then: No file is returned.
    """
    outer = build_email("Outer")
    outer.add_attachment(b"", maintype="application", subtype="octet-stream", filename="empty.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())

    assert extract_attached_eml_files(str(outer_path)) == []


def test_match_attachments_to_files_attachment_without_a_file_is_not_matched():
    """
    Given: An attachment that the parser returned, and attached files none of which has its name.
    When: Matching the attachments to the files.
    Then: Nothing is matched, an attachment is never matched to a file of another name.
    """
    assert match_attachments_to_files([{"Name": "missing.eml"}], [("other.eml", b"data")]) == []


def test_fix_attached_eml_outputs_files_with_the_same_name_are_all_parsed(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, with two attached emails which have the same file name.
    When: Fixing the attached emails of the parser output.
    Then: Both emails are parsed as nested emails of the report, and each attachment gets the content of its own file.
    """
    first = build_email("First").as_bytes()
    second = build_email("Second").as_bytes()
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(build_report_with_root_attachment([("original.eml", first), ("original.eml", second)]))

    fixed_output = fix_outputs(report_path, parse_with_email_parser(report_path))

    assert [(email["Depth"], email["Subject"]) for email in fixed_output] == [
        (0, "Reported message"),
        (1, "First"),
        (1, "Second"),
    ]
    assert {(email["FileName"], email["ParentFileName"]) for email in fixed_output[1:]} == {("original.eml", "report.eml")}
    assert [attachment["FileData"] for attachment in fixed_output[0]["AttachmentsData"]] == [first, second]


def test_fix_attached_eml_outputs_parses_only_attachments_the_parser_did_not_parse(tmp_path: Path):
    """
    Given: An email with an attached message/rfc822 that the parser parses, and an .eml file labeled text/plain that it doesn't.
    When: Fixing the attached emails of the parser output.
    Then: Only the file the parser skipped is parsed, the decision is made for each attachment,
        and the data of the attachments is what the parser returned.
    """
    outer = build_email("Outer")
    outer.add_attachment(build_email("Native"), filename="native.eml")
    outer.add_attachment(build_email("Labeled").as_bytes(), maintype="text", subtype="plain", filename="labeled.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())
    parser_output = parse_with_email_parser(outer_path)
    assert [email["FileName"] for email in parser_output] == ["outer.eml", "native.eml"]
    attachments_data = copy.deepcopy(parser_output[0]["AttachmentsData"])

    fixed_output = fix_outputs(outer_path, parser_output)

    assert [(email["Depth"], email["FileName"], email.get("ParentFileName")) for email in fixed_output] == [
        (0, "outer.eml", None),
        (1, "native.eml", "outer.eml"),
        (1, "labeled.eml", "outer.eml"),
    ]
    assert fixed_output[0]["AttachmentsData"] == attachments_data


def test_fix_attached_eml_outputs_email_the_parser_handled_is_not_changed(tmp_path: Path):
    """
    Given: An ordinary email with an attached message/rfc822 that has a single part, which the parser handles correctly.
    When: Fixing the attached emails of the parser output.
    Then: The output is exactly what the parser returned, including the whole attached message as the attachment data.
    """
    outer = build_email("Outer")
    outer.add_attachment(build_email("Inner", "Inner body."), filename="inner.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())
    parser_output = parse_with_email_parser(outer_path)

    fixed_output = fix_outputs(outer_path, copy.deepcopy(parser_output))

    assert fixed_output == parser_output
    assert "Subject: Inner" in parser_output[0]["AttachmentsData"][0]["FileData"]


def test_fix_attached_eml_outputs_file_is_not_read_again_when_the_parser_handled_everything(
    mocker: MockerFixture, tmp_path: Path
):
    """
    Given: An ordinary email whose attached .eml file was parsed by the parser, with valid data.
    When: Fixing the attached emails of the parser output.
    Then: The email file is not read again, so emails the parser handled don't pay for the fix.
    """
    extract_files = mocker.patch("ParseEmailFilesV2.extract_attached_eml_files")
    outer = build_email("Outer")
    outer.add_attachment(build_email("Inner"), filename="inner.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())
    parser_output = parse_with_email_parser(outer_path)

    assert fix_outputs(outer_path, copy.deepcopy(parser_output)) == parser_output
    extract_files.assert_not_called()


def test_fix_attached_eml_outputs_file_which_is_not_an_email_is_skipped(tmp_path: Path):
    """
    Given: An email with a text file that is named as an .eml file.
    When: Fixing the attached emails of the parser output.
    Then: No error is raised, and the output is what the parser returned.
    """
    outer = build_email("Outer")
    outer.add_attachment(b"just some notes, not an email", maintype="text", subtype="plain", filename="notes.eml")
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(outer.as_bytes())
    parser_output = parse_with_email_parser(outer_path)

    assert fix_outputs(outer_path, copy.deepcopy(parser_output)) == parser_output


def test_fix_attached_eml_outputs_file_which_is_not_an_email_does_not_stop_the_other_files(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, with an attached file that is not an email and a valid attached email.
    When: Fixing the attached emails of the parser output.
    Then: The valid email is parsed as a nested email, and the invalid one is skipped.
    """
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(
        build_report_with_root_attachment(
            [("invalid.eml", b"not an email at all"), ("valid.eml", build_email("Valid").as_bytes())]
        )
    )

    fixed_output = fix_outputs(report_path, parse_with_email_parser(report_path))

    assert [(email["Depth"], email["FileName"], email["Subject"]) for email in fixed_output][1:] == [(1, "valid.eml", "Valid")]


def test_fix_attached_eml_outputs_only_headers_are_not_changed(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, which is parsed with parse_only_headers.
    When: Fixing the attached emails of the parser output.
    Then: Only the headers of the outer email are returned, no nested email is added.
    """
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(build_report_with_root_attachment([("original.eml", build_email("Original").as_bytes())]))
    parser_output = parse_with_email_parser(report_path, parse_only_headers=True)

    fixed_output = fix_outputs(report_path, copy.deepcopy(parser_output), parse_only_headers=True)

    assert fixed_output == parser_output
    assert list(fixed_output[0]) == ["HeadersMap"]


def test_get_decoded_file_data_empty_attached_message_returns_none():
    """
    Given: An attached message/rfc822 part which has no headers and no content.
    When: Getting the decoded file data.
    Then: None is returned, an empty message is not turned into a file.
    """
    email_bytes = (
        b"Content-Type: multipart/mixed; boundary=b\n\n"
        b"--b\n"
        b'Content-Type: message/rfc822; name="empty.eml"\n'
        b'Content-Disposition: attachment; filename="empty.eml"\n\n'
        b"--b--\n"
    )

    (attachment_part,) = get_attachment_parts(email_bytes)

    assert get_decoded_file_data(attachment_part) is None


def test_get_decoded_file_data_base64_message_without_content_returns_none():
    """
    Given: An attached message/rfc822 part declared as base64, which has no content.
    When: Getting the decoded file data.
    Then: None is returned.
    """
    email_bytes = (
        b"Content-Type: multipart/mixed; boundary=b\n\n"
        b"--b\n"
        b'Content-Type: message/rfc822; name="empty.eml"\n'
        b'Content-Disposition: attachment; filename="empty.eml"\n'
        b"Content-Transfer-Encoding: base64\n\n"
        b"--b--\n"
    )

    (attachment_part,) = get_attachment_parts(email_bytes)

    assert get_decoded_file_data(attachment_part) is None


def test_get_file_name_key_unknown_charset_does_not_raise():
    """
    Given: A file name with an encoded word in a charset which is not known.
    When: Getting the key of the name.
    Then: The name is used as it is, and the file extension is kept.
    """
    assert get_file_name_key("=?no-such-charset?q?abc?=.eml").lower().endswith(".eml")


@pytest.mark.parametrize(
    "file_name, same_file_name_as_the_parser_reports",
    [
        pytest.param("=?utf-8?q?caf=C3=A9?=.eml", "caf\u00e9 .eml", id="encoded_word_followed_by_extension"),
        pytest.param("=?UTF-8?B?Y2Fmw6kuZW1s?=", "caf\u00e9.eml", id="whole_name_is_an_encoded_word"),
        pytest.param(
            "Re:\ufffd\ufffdYour account.eml", "Re:\xa0Your account.eml", id="undecodable_bytes_replaced_by_the_mime_parser"
        ),
        pytest.param("report.eml", "report.eml", id="plain_name"),
    ],
)
def test_get_file_name_key_names_which_were_read_differently_are_equal(file_name: str, same_file_name_as_the_parser_reports: str):
    """
    Given: A file name as the MIME parser reads it, and the same name as the email parser reports it.
    When: Getting the key of each name.
    Then: The keys are equal, and they keep the file extension.
    """
    key = get_file_name_key(file_name)

    assert key == get_file_name_key(same_file_name_as_the_parser_reports)
    assert key.lower().endswith(".eml")


def test_get_file_name_key_different_names_have_different_keys():
    assert get_file_name_key("first.eml") != get_file_name_key("second.eml")


@pytest.mark.parametrize(
    "disposition_parameters",
    [
        pytest.param('filename="inner.eml"', id="plain_name"),
        pytest.param('filename="INNER.EML"', id="upper_case_extension"),
        pytest.param('filename="=?utf-8?q?caf=C3=A9?=.eml"', id="encoded_word_followed_by_extension"),
        pytest.param('filename="=?UTF-8?B?Y2Fmw6kuZW1s?="', id="whole_name_is_an_encoded_word"),
        pytest.param("filename*=UTF-8''caf%C3%A9.eml", id="rfc_2231_name"),
        pytest.param('filename="Re:\u00a0Your account.eml"', id="non_ascii_name_which_is_not_encoded"),
    ],
)
def test_fix_attached_eml_outputs_attached_message_the_parser_parsed_is_not_parsed_again(
    tmp_path: Path, disposition_parameters: str
):
    """
    Given: An ordinary email with an attached message/rfc822 which the parser parses, with a file name written in any form.
    When: Fixing the attached emails of the parser output.
    Then: The output is what the parser returned, the attached email is not parsed a second time.
    """
    outer_path = tmp_path / "outer.eml"
    outer_path.write_bytes(build_email_with_attached_message(disposition_parameters))
    parser_output = parse_with_email_parser(outer_path)
    assert [email["Depth"] for email in parser_output] == [0, 1]

    assert fix_outputs(outer_path, copy.deepcopy(parser_output)) == parser_output


def test_fix_attached_eml_outputs_attached_message_which_is_not_encoded_is_restored_and_parsed(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, with an attached message/rfc822 that is not base64 encoded.
    When: Fixing the attached emails of the parser output.
    Then: The attachment data is the whole attached message, and the attached email is parsed as a nested email.
    """
    attached_email = build_email("Seven bit", "Seven bit body.").as_bytes()
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(build_report_with_root_attachment([("seven.eml", attached_email)], transfer_encoding="7bit"))

    fixed_output = fix_outputs(report_path, parse_with_email_parser(report_path))

    assert [(email["Depth"], email["Subject"]) for email in fixed_output] == [(0, "Reported message"), (1, "Seven bit")]
    (attachment,) = fixed_output[0]["AttachmentsData"]
    attached_message = message_from_bytes(attachment["FileData"])
    assert (attached_message["Subject"], attached_message.get_payload().strip()) == ("Seven bit", "Seven bit body.")


def test_fix_attached_eml_outputs_non_ascii_file_name_is_reported_as_the_parser_reports_it(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, with an attached email whose file name is not ASCII and not encoded.
    When: Fixing the attached emails of the parser output.
    Then: The attached email is parsed, and it is named as the parser names the attachment.
    """
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(
        build_report_with_root_attachment([("\u043e\u0442\u0447\u0451\u0442.eml", build_email("Cyrillic").as_bytes())])
    )
    parser_output = parse_with_email_parser(report_path)
    (attachment_name,) = parser_output[0]["AttachmentNames"]

    fixed_output = fix_outputs(report_path, parser_output)

    assert [(email["Depth"], email["FileName"], email["Subject"]) for email in fixed_output][1:] == [
        (1, attachment_name, "Cyrillic")
    ]
    assert attachment_name == "\u043e\u0442\u0447\u0451\u0442.eml"


def test_fix_attached_eml_outputs_attachment_the_parser_did_not_report_is_ignored(tmp_path: Path):
    """
    Given: A report whose top level part is an attachment, with an email attached inside a nested multipart that the parser
        reports only as an unnamed attachment.
    When: Fixing the attached emails of the parser output.
    Then: The output is what the parser returned, only attachments that the parser reported are handled.
    """
    nested_part = "\n".join(
        [
            'Content-Type: multipart/mixed; boundary="inner-boundary"',
            "",
            "--inner-boundary",
            'Content-Type: message/rfc822; name="hidden.eml"',
            'Content-Disposition: attachment; filename="hidden.eml"',
            "Content-Transfer-Encoding: base64",
            "",
            base64.encodebytes(build_email("Hidden").as_bytes()).decode(),
            "--inner-boundary--",
        ]
    )
    report_path = tmp_path / "report.eml"
    report_path.write_bytes(
        "\n".join(
            [
                "From: Example Reporter <reporter@example.org>",
                "Subject: Reported message",
                "MIME-Version: 1.0",
                'Content-Type: multipart/mixed; boundary="report-boundary"',
                "Content-Disposition: attachment",
                "",
                "--report-boundary",
                nested_part,
                "--report-boundary--",
                "",
            ]
        ).encode()
    )
    parser_output = parse_with_email_parser(report_path)
    assert not any(attachment["Name"] == "hidden.eml" for attachment in parser_output[0]["AttachmentsData"])

    assert fix_outputs(report_path, copy.deepcopy(parser_output)) == parser_output


@pytest.mark.parametrize(
    "attachment_name",
    [
        "../escaped.eml",
        "../../escaped.eml",
        "{tmp_path}/absolute_escaped.eml",
        "nested/dir/escaped.eml",
        "..\\escaped.eml",
        "a" * 300 + ".eml",
        "null\x00byte.eml",
    ],
    ids=["parent_dir", "grandparent_dir", "absolute_path", "sub_dir", "backslash", "too_long", "null_byte"],
)
def test_parse_attached_eml_files_unsafe_file_name_is_not_used_as_a_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, attachment_name: str
):
    """
    Given: An attached email whose file name is a path traversal attempt, or can't be a file name.
    When: Parsing the attached email.
    Then: The email is parsed under its original name, and no file is created outside of the temporary directory.
    """
    attachment_name = attachment_name.replace("{tmp_path}", str(tmp_path))
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(sandbox))

    parsed_emails = parse_attached_eml_files(
        [(attachment_name, build_email("Nested").as_bytes())], "parent.eml", 3, False, RFC822_FILE_TYPE, None, "utf-8"
    )

    assert [(email["Subject"], email["FileName"], email["ParentFileName"], email["Depth"]) for email in parsed_emails] == [
        ("Nested", attachment_name, "parent.eml", 1)
    ]
    assert list(tmp_path.iterdir()) == [sandbox]
    assert not list(sandbox.iterdir())


def test_parse_attached_eml_files_nested_emails_keep_their_own_parent_file_name():
    """
    Given: An attached email which has an attached email of its own.
    When: Parsing the attached email.
    Then: The depth is relative to the parent email, and each email is linked to the file name of the email containing it.
    """
    inner = build_email("Inner")
    inner.add_attachment(build_email("Deep"), filename="deep.eml")

    parsed_emails = parse_attached_eml_files(
        [("inner.eml", inner.as_bytes())], "outer.eml", 3, False, RFC822_FILE_TYPE, None, "utf-8"
    )

    assert [(email["Depth"], email["FileName"], email["ParentFileName"]) for email in parsed_emails] == [
        (1, "inner.eml", "outer.eml"),
        (2, "deep.eml", "inner.eml"),
    ]


@pytest.mark.parametrize(
    "attachments_data, expected_names",
    [
        pytest.param([{"Name": "unknown_file_name0", "FileData": b""}], [], id="unnamed_empty_placeholder_is_removed"),
        pytest.param([{"Name": "unknown_file_name0", "FileData": None}], [], id="unnamed_placeholder_without_data_is_removed"),
        pytest.param([{"Name": "unknown_file_name", "FileData": b"data"}], ["unknown_file_name"], id="unnamed_with_data_is_kept"),
        pytest.param([{"Name": "empty.txt", "FileData": None}], ["empty.txt"], id="named_empty_file_is_kept"),
        pytest.param([{"Name": None, "FileData": b"data"}], [], id="attachment_without_a_name_is_removed"),
        pytest.param(
            [{"Name": "unknown_file_name0", "FileData": b""}, {"Name": "report.eml", "FileData": b"data"}],
            ["report.eml"],
            id="other_attachments_are_kept",
        ),
    ],
)
def test_remove_empty_unnamed_attachments(attachments_data: list[dict], expected_names: list):
    """
    Given: Attachments returned by the parser, including placeholders for parts which have neither a name nor content.
    When: Removing the empty unnamed attachments.
    Then: Only the placeholders are removed, and the attachment names of the email are updated accordingly.
    """
    email_data = {"AttachmentsData": attachments_data, "AttachmentNames": ["old"], "Attachments": "old"}

    remove_empty_unnamed_attachments(email_data)

    assert [attachment["Name"] for attachment in email_data["AttachmentsData"]] == expected_names
    assert email_data["AttachmentNames"] == expected_names
    assert email_data["Attachments"] == ",".join(expected_names)


def test_named_empty_attachment_is_returned_without_file_data(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """
    Given: An email with a named attachment that has no content.
    When: Running the script.
    Then: The attachment is returned with no file data and nothing is saved for it, so an empty file doesn't fail the script.
    """
    outer = build_email("Outer")
    outer.add_attachment(b"", maintype="application", subtype="octet-stream", filename="empty.txt")

    entries = run_main_with_email(mocker, monkeypatch, tmp_path, outer.as_bytes())

    assert not [entry for entry in entries if entry["Type"] == entryTypes["file"]]
    (email_entry,) = entries
    (attachment,) = email_entry["EntryContext"]["Email"]["AttachmentsData"]
    assert attachment["Name"] == "empty.txt"
    assert attachment["FileData"] is None
    assert "FilePath" not in attachment
