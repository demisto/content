import base64
import binascii
import html
import mimetypes
import re
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesHeaderParser, BytesParser
from pathlib import Path

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from parse_emails.parse_emails import EmailParser

logger = logging.getLogger("parse-email")  # type: ignore[assignment]
logger.addHandler(DemistoHandler)  # type: ignore[attr-defined]

EML_EXTENSION = ".eml"
UNKNOWN_FILE_NAME_PREFIX = "unknown_file_name"  # the name the parser gives to attachments which have no name
NON_ASCII_CHARACTERS = re.compile(r"[^\x00-\x7f]+")
HEADERS_SAMPLE_SIZE = 64 * 1024  # enough to tell if data starts with email headers, without reading all of a large email
AttachedEml = tuple[str, bytes]  # the file name, and the file content
AttachmentMatch = tuple[dict, bytes]  # an attachment returned by the parser, and the content of its file


def get_decoded_file_data(attachment_part: Message) -> bytes | None:
    """
    Get the content of an attached file, as it was written in the email.

    The MIME parser doesn't decode attached messages (`message/*` parts), it exposes the inner message instead.
    If such a part is also base64 encoded (RFC 2046 doesn't allow it, but some mail clients do it),
    the inner "message" is just the still encoded text.

    Args:
        attachment_part (Message): The MIME part of the attachment.

    Returns:
        bytes | None: The attachment content, or None if it can't be extracted reliably.
    """
    file_data = attachment_part.get_payload(decode=True)
    if isinstance(file_data, bytes) and file_data:
        return file_data

    payload = attachment_part.get_payload()
    nested_message = payload[0] if isinstance(payload, list) and len(payload) == 1 else None
    if not isinstance(nested_message, Message):
        return None

    if str(attachment_part.get("Content-Transfer-Encoding", "")).strip().lower() != "base64":
        return nested_message.as_bytes() if nested_message.keys() or nested_message.get_payload() else None

    encoded_data = nested_message.get_payload(decode=True)
    if not isinstance(encoded_data, bytes) or not encoded_data:
        return None

    try:
        # MIME base64 is wrapped to lines, so the whitespaces are removed to allow a strict validation of the rest
        return base64.b64decode(b"".join(encoded_data.split()), validate=True)
    except binascii.Error:
        demisto.debug(f"Failed to base64 decode attached email payload: {traceback.format_exc()}")
        return None


def get_file_name_key(file_name: str) -> str:
    """
    Get a key for comparing file names which were read from the same email by different readers.

    The email parser and the MIME parser decode RFC 2047 encoded words and non-ASCII characters differently,
    so the encoded words are decoded and every run of non-ASCII characters is replaced by a placeholder.
    """
    try:
        file_name = str(make_header(decode_header(file_name)))
    except (LookupError, UnicodeError, HeaderParseError):
        pass  # not an encoded name, it is compared as it is
    return NON_ASCII_CHARACTERS.sub("?", file_name)


def iter_email_parts(message: Message) -> Iterator[Message]:
    """
    Iterate over the MIME parts of an email, without going into the emails attached to it,
    so only the parts that belong to the email itself are returned.
    """
    pending_parts = [message]
    while pending_parts:
        part = pending_parts.pop()
        yield part
        payload = part.get_payload()
        if isinstance(payload, list) and (part is message or part.get_content_maintype() != "message"):
            pending_parts.extend(sub_part for sub_part in reversed(payload) if isinstance(sub_part, Message))


def extract_attached_eml_files(file_path: str) -> list[AttachedEml]:
    """
    Extract the files attached to an email, whose name ends with `.eml`.
    Attachments which share a name are all returned, in the order in which they appear in the email.

    Args:
        file_path (str): The path of the email file.

    Returns:
        list[AttachedEml]: The name and the content of each attached `.eml` file.
    """
    message = BytesParser().parsebytes(Path(file_path).read_bytes())
    attached_files: list[AttachedEml] = []

    for part in iter_email_parts(message):
        attachment_name = part.get_filename() or ""
        if not get_file_name_key(attachment_name).lower().endswith(EML_EXTENSION):
            continue

        if file_data := get_decoded_file_data(part):
            attached_files.append((attachment_name, file_data))

    return attached_files


def is_email_data(file_data: bytes | str | None) -> bool:
    """
    Check if the data starts with email headers, as opposed to a placeholder
    such as the string representation of Message objects.
    """
    if not file_data:
        return False

    file_data_sample = file_data[:HEADERS_SAMPLE_SIZE]
    if isinstance(file_data_sample, str):
        file_data_sample = file_data_sample.encode("utf-8", errors="ignore")
    return bool(BytesHeaderParser().parsebytes(file_data_sample).keys())


def get_eml_attachments(email_data: dict) -> list[dict]:
    return [
        attachment
        for attachment in email_data.get("AttachmentsData") or []
        if get_file_name_key(attachment.get("Name") or "").lower().endswith(EML_EXTENSION)
    ]


def match_attachments_to_files(attachments: list[dict], attached_files: list[AttachedEml]) -> list[AttachmentMatch]:
    """
    Match each attachment that the parser returned to the content of its file.
    Only attachments that the parser returned are matched, and attachments that share a name are matched by their order.

    Args:
        attachments (list[dict]): The attachments of the parsed email.
        attached_files (list[AttachedEml]): The attached `.eml` files, as extracted from the email file.

    Returns:
        list[AttachmentMatch]: Each attachment which has a file, with the content of the file.
    """
    files_by_name: dict[str, list[bytes]] = defaultdict(list)
    for attachment_name, file_data in attached_files:
        files_by_name[get_file_name_key(attachment_name)].append(file_data)

    matches = []
    for attachment in attachments:
        remaining_files = files_by_name.get(get_file_name_key(attachment.get("Name") or ""))
        if remaining_files:
            matches.append((attachment, remaining_files.pop(0)))

    return matches


def restore_attached_eml_file_data(matches: list[AttachmentMatch]) -> None:
    """
    Set the content of the attachments whose data the parser did not return as an email.
    Data which is already a valid email is never replaced.
    """
    for attachment, file_data in matches:
        if not is_email_data(attachment.get("FileData")):
            attachment["FileData"] = file_data


def get_unparsed_attachments(output: list[dict], attachments: list[dict]) -> list[dict]:
    """
    Get the attachments which the parser did not parse to a nested email.
    The decision is made for each attachment, nested emails are matched to attachments by their file name.

    Args:
        output (list[dict]): The emails returned by the parser.
        attachments (list[dict]): The attachments of the parsed email which are `.eml` files.

    Returns:
        list[dict]: The attachments which have no matching nested email.
    """
    parsed_file_names = Counter(
        get_file_name_key(email_data.get("FileName") or "") for email_data in output if email_data.get("Depth")
    )
    unparsed_attachments = []

    for attachment in attachments:
        file_name_key = get_file_name_key(attachment.get("Name") or "")
        if parsed_file_names[file_name_key] > 0:
            parsed_file_names[file_name_key] -= 1
        else:
            unparsed_attachments.append(attachment)

    return unparsed_attachments


def set_nested_email_metadata(emails: list[dict], parent_file_name: str) -> None:
    """
    Convert emails that were parsed as a standalone file to the nested emails of their parent email:
    the depth is increased, and the top email is linked to the file name of its parent, as the parser does.

    Args:
        emails (list[dict]): The emails to update in place.
        parent_file_name (str): The file name of the email which the top email is attached to.
    """
    for email_data in emails:
        depth = email_data.get("Depth", 0)
        if not depth:
            email_data["ParentFileName"] = parent_file_name
        email_data["Depth"] = depth + 1


def parse_attached_eml_files(
    attached_files: list[AttachedEml],
    parent_file_name: str,
    max_depth: int,
    parse_only_headers: bool,
    file_type: str | None,
    forced_encoding: str | None,
    default_encoding: str | None,
) -> list[dict]:
    """
    Parse attached emails as the nested emails of the email which they are attached to.
    An attached file that can't be parsed is skipped, it must not fail the parsing of the email that contains it.

    Args:
        attached_files (list[AttachedEml]): The attached `.eml` files to parse.
        parent_file_name (str): The name of the email file which the files are attached to.
        max_depth (int): The max depth of the parent email, the attached emails are parsed with one level less.
        parse_only_headers (bool): Whether only the headers are parsed.
        file_type (str | None): The type of the parent email file.
        forced_encoding (str | None): The encoding to force when parsing.
        default_encoding (str | None): The encoding to use when the detected encoding fails.

    Returns:
        list[dict]: The parsed emails, including the emails which are attached to the attached emails.
    """
    if max_depth <= 1 or not attached_files:
        return []

    parsed_emails: list[dict] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        for index, (attachment_name, file_data) in enumerate(attached_files):
            # The attachment name is controlled by the sender of the email, so it is never used to build a path
            attached_file_path = Path(temp_dir) / f"attached_email_{index}{EML_EXTENSION}"
            attached_file_path.write_bytes(file_data)
            try:
                child_output = EmailParser(
                    file_path=str(attached_file_path),
                    max_depth=max_depth - 1,
                    parse_only_headers=parse_only_headers,
                    file_info=file_type,
                    forced_encoding=forced_encoding,
                    default_encoding=default_encoding,
                    file_name=attachment_name,
                ).parse()
            except Exception:  # the parser raises a generic Exception for every failure
                demisto.debug(f"Failed to parse the attached email {attachment_name}: {traceback.format_exc()}")
                continue

            child_emails = [child_output] if isinstance(child_output, dict) else child_output
            set_nested_email_metadata(child_emails, parent_file_name)
            parsed_emails.extend(child_emails)

    return parsed_emails


def is_empty_unnamed_attachment(attachment: dict) -> bool:
    name = attachment.get("Name")
    return not name or (name.startswith(UNKNOWN_FILE_NAME_PREFIX) and not attachment.get("FileData"))


def remove_empty_unnamed_attachments(email_data: dict) -> None:
    """
    Remove the placeholder attachments that the parser creates for MIME parts which have neither a name nor content,
    for example the empty body of an email whose top level part is marked as an attachment.
    Attachments which have a name, or have content, are kept.
    """
    attachments_data = email_data.get("AttachmentsData")
    if not attachments_data:
        return

    attachments_data = [attachment for attachment in attachments_data if not is_empty_unnamed_attachment(attachment)]
    attachment_names = [attachment.get("Name") for attachment in attachments_data]
    email_data["AttachmentsData"] = attachments_data
    email_data["AttachmentNames"] = attachment_names
    email_data["Attachments"] = ",".join(attachment_names)


def fix_attached_eml_outputs(
    output: list[dict],
    file_path: str,
    file_name: str,
    max_depth: int,
    parse_only_headers: bool,
    file_type: str | None,
    forced_encoding: str | None,
    default_encoding: str | None,
) -> list[dict]:
    """
    Complete the attached `.eml` files which the email parser did not handle, for example when the top level part
    of the email is marked as an attachment: their content is restored, and they are parsed as nested emails.
    Only attachments that the parser reported and did not parse are handled, everything else is left as the parser returned it.

    Args:
        output (list[dict]): The emails returned by the parser.
        file_path (str): The path of the parsed email file.
        file_name (str): The name of the parsed email file.
        max_depth (int): How many levels of attached emails to parse.
        parse_only_headers (bool): Whether only the headers are parsed.
        file_type (str | None): The type of the parsed email file.
        forced_encoding (str | None): The encoding to force when parsing.
        default_encoding (str | None): The encoding to use when the detected encoding fails.

    Returns:
        list[dict]: The emails returned by the parser, followed by the attached emails that were parsed here.
    """
    if not file_name.lower().endswith(EML_EXTENSION):
        return output

    root_email = next((email_data for email_data in output if not email_data.get("Depth")), None)
    eml_attachments = get_eml_attachments(root_email) if root_email else []
    unparsed_attachments = get_unparsed_attachments(output, eml_attachments) if max_depth > 1 else []
    if not unparsed_attachments and all(is_email_data(attachment.get("FileData")) for attachment in eml_attachments):
        return output  # the parser handled everything, so the email file is not read again

    matches = match_attachments_to_files(eml_attachments, extract_attached_eml_files(file_path))
    restore_attached_eml_file_data(matches)
    unparsed_attachment_ids = {id(attachment) for attachment in unparsed_attachments}  # equal attachments are still different
    unparsed_files = [
        (attachment.get("Name") or "", file_data)
        for attachment, file_data in matches
        if id(attachment) in unparsed_attachment_ids
    ]

    return output + parse_attached_eml_files(
        unparsed_files,
        file_name,
        max_depth,
        parse_only_headers,
        file_type,
        forced_encoding,
        default_encoding,
    )


def html_unescape(html_body: str) -> str:
    """
    Unescape HTML entities in the raw HTML string returned by the email parser.

    The ``parse_emails`` library returns the HTML body verbatim from the email
    source, which means HTML entities such as ``&amp;`` (used inside attribute
    values like ``href``) are **not** decoded.  When indicator-extraction runs
    against this raw HTML it sees ``https://example.com?a=1&amp;b=2`` instead
    of the real URL ``https://example.com?a=1&b=2``, causing missed or broken
    indicators.

    This function applies a single ``html.unescape()`` pass so that all named
    and numeric character references are replaced with their Unicode equivalents
    before the HTML is stored in context and consumed by downstream automations.

    Args:
        html_body (str): Raw HTML content as returned by the email parser.

    Returns:
        str: HTML string with all character references decoded.
    """
    return html.unescape(html_body)


def remove_bom(file_path: str, file_type: str, file_name: str) -> tuple[str, Optional[str], str]:
    """
    Removes the Byte Order Mark (BOM) from a file, saves the cleaned content,
    and returns the path to the cleaned file, its MIME type, and its file name.
    If no BOM, keep the previous behaviour.
    """
    path = Path(file_path)
    content = path.read_bytes()
    if content.startswith(b"\xef\xbb\xbf"):
        content = content[3:]
        # Write the cleaned content to a new file or overwrite the original file
        cleaned_file_path = path.with_name("cleaned_" + path.name)
        cleaned_file_path.write_bytes(content)
        # Get the MIME type
        mime_type, _ = mimetypes.guess_type(cleaned_file_path)
        # Get the file name
        file_name = cleaned_file_path.name
        return str(cleaned_file_path), mime_type, file_name
    else:  # keep the exists behaviour (without BOM)
        demisto.info(f"BOM not detected in file: {file_name}, {file_type=}")
        return file_path, file_type, file_name


def data_to_md(email_data, email_file_name=None, parent_email_file=None, print_only_headers=False) -> str:
    """
    create Markdown with the data.

    Args:
      email_data (dict): all the email data.
      email_file_name (str): the email file name.
      parent_email_file (str): the parent email file name (for attachment mail).
      print_only_headers (bool): Whether to only the headers.

    Returns:
      str: the parsed Markdown

    """
    if email_data is None:
        return "No data extracted from email"

    md = "### Results:\n"
    if email_file_name:
        md = f"### {email_file_name}\n"

    if print_only_headers:
        return tableToMarkdown(f"Email Headers: {email_file_name}", email_data.get("HeadersMap"))

    if parent_email_file:
        md += f"### Containing email: {parent_email_file}\n"

    md += f"""* From:\t{email_data.get("From") or ""}\n"""
    md += f"""* To:\t{email_data.get("To") or ""}\n"""
    md += f"""* CC:\t{email_data.get("CC") or ""}\n"""
    md += f"""* BCC:\t{email_data.get("BCC") or ""}\n"""
    md += f"""* Subject:\t{email_data.get("Subject") or ""}\n"""
    if email_data.get("Text"):
        text = email_data["Text"].replace("<", "[").replace(">", "]")
        md += f"* Body/Text:\t{text or ''}\n"
    if email_data.get("HTML"):
        md += f"""* Body/HTML:\t{email_data["HTML"] or ""}\n"""

    md += f"""* Attachments:\t{email_data.get("Attachments") or ""}\n"""
    md += "\n\n" + tableToMarkdown("HeadersMap", email_data.get("HeadersMap"))
    return md


def save_file(file_name, file_content) -> str:
    """
    save attachment to the war room and return the file internal path.

    Args:
      file_name (str): The name of the file to be created.
      file_content (str/bytes): the file data.

    Returns:
      str: the file internal path

    """
    created_file = fileResult(file_name, file_content)
    file_id = created_file.get("FileID")
    attachment_internal_path = demisto.investigation().get("id") + "_" + file_id
    return_results(created_file)

    return attachment_internal_path


def extract_file_info(entry_id: str) -> tuple:
    """
    extract from the entry id the file_type, file_path and file_name.

    Args:
      entry_id (str): The entry id.

    Returns:
        file_type(str): the file mime type.
        file_path(str): the file path.
        file_name(str):the file name.
    """
    file_type = ""
    file_path = ""
    file_name = ""
    try:
        result = demisto.executeCommand("getFilePath", {"id": entry_id})
        if is_error(result):
            return_error(get_error(result))

        file_path = result[0]["Contents"]["path"]
        file_name = result[0]["Contents"]["name"]

        dt_file_type = demisto.dt(demisto.context(), f"File(val.EntryID=='{entry_id}').Type")
        file_type = dt_file_type[0] if isinstance(dt_file_type, list) else dt_file_type

        dt_file_info = demisto.dt(demisto.context(), f"File(val.EntryID=='{entry_id}').Info")
        file_info = dt_file_info[0] if isinstance(dt_file_info, list) else dt_file_info
        demisto.debug(f"Context values: {dt_file_type=}, {file_type=}, {dt_file_info=}, {file_info=}, {file_name=}")

        if file_type in ("eml", "txt") and file_info and ("rfc" in file_info.lower() or "ascii" in file_info.lower()):
            demisto.debug(f"{file_type=} seems wrong, changing it to {file_info=}")
            file_type = file_info

        if (
            file_name
            and file_name.lower().endswith(".eml")
            and file_type
            and ("iso-8859" in file_type.lower() or "mime entity" in file_type.lower())
        ):
            demisto.debug(f"Detected EML file misclassified as text ({file_type}). Forcing RFC822 parsing.")
            file_type = "RFC 822 mail text"

    except Exception as ex:
        return_error(
            "Failed to load file entry with entry id: {}. Error: {}".format(
                entry_id, str(ex) + "\n\nTrace:\n" + traceback.format_exc()
            )
        )

    demisto.debug(f"extract_file_info returning {file_type=}, {file_path=}, {file_name=}")
    return file_type, file_path, file_name


def parse_nesting_level(nesting_level_to_return, output):
    if nesting_level_to_return == "Outer file":
        # return only the outer email info
        return [output[0]]

    elif nesting_level_to_return == "Inner file":
        # the last file in list it is the inner attached file
        return [output[-1]]
    return output


def main():
    args = demisto.args()
    entry_id = args.get("entryid")
    max_depth = arg_to_number(args.get("max_depth", "3")) or 0
    if max_depth < 1:
        return_error("Minimum max_depth is 1, the script will parse just the top email")
    parse_only_headers = argToBoolean(args.get("parse_only_headers", "false"))
    forced_encoding = args.get("forced_encoding")
    default_encoding = args.get("default_encoding")
    nesting_level_to_return = args.get("nesting_level_to_return", "All files")

    file_type, file_path, file_name = extract_file_info(entry_id)
    demisto.debug(f"{file_type=}, {file_path=}, {file_name=}")

    # Remove BOM and parse the email
    cleaned_file_path, file_type, file_name = remove_bom(file_path, file_type, file_name)

    try:
        email_parser = EmailParser(
            file_path=cleaned_file_path,
            max_depth=max_depth,
            parse_only_headers=parse_only_headers,
            file_info=file_type,
            forced_encoding=forced_encoding,
            default_encoding=default_encoding,
            file_name=file_name,
        )
        output = email_parser.parse()
        demisto.debug(f"{output=}")

        results = []
        if isinstance(output, dict):
            output = [output]

        output = fix_attached_eml_outputs(
            output,
            cleaned_file_path,
            file_name,
            max_depth,
            parse_only_headers,
            file_type,
            forced_encoding,
            default_encoding,
        )

        if output and nesting_level_to_return != "All files":
            output = parse_nesting_level(nesting_level_to_return, output)

        for email in output:
            remove_empty_unnamed_attachments(email)
            if email.get("AttachmentsData"):
                for attachment in email.get("AttachmentsData"):
                    if name := attachment.get("Name"):
                        if content := attachment.get("FileData"):
                            attachment["FilePath"] = save_file(name, content)
                            del attachment["FileData"]
                        else:
                            attachment["FileData"] = None

            # probably a wrapper and we can ignore the outer "email"
            if email.get("Format") == "multipart/signed" and all(not email.get(field) for field in ["To", "From", "Subject"]):
                continue

            if isinstance(email.get("HTML"), bytes):
                email["HTML"] = email.get("HTML").decode("utf-8")

            if html_body := email.get("HTML"):
                email["HTMLUnescape"] = html_unescape(html_body)

            results.append(
                CommandResults(
                    outputs_prefix="Email",
                    outputs=email,
                    readable_output=data_to_md(
                        email, file_name, email.get("ParentFileName", None), print_only_headers=parse_only_headers
                    ),
                    raw_response=email,
                )
            )

        return_results(results)

    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
