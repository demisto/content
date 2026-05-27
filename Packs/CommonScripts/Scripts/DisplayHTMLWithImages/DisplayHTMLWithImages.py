import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

IMG_FORMATS = ["jpeg", "gif", "bmp", "png", "jfif", "tiff", "eps", "indd", "jpg"]

# Define allowed tags for email body rendering (preserve formatting, strip dangerous tags)
ALLOWED_EMAIL_TAGS = {
    "p",
    "br",
    "div",
    "span",
    "b",
    "i",
    "u",
    "a",
    "img",
    "table",
    "tr",
    "td",
    "th",
    "thead",
    "tbody",
    "ul",
    "ol",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "pre",
    "code",
    "blockquote",
    "strong",
    "em",
    "hr",
    "font",
    "center",
    "small",
    "big",
    "sub",
    "sup",
    "dl",
    "dt",
    "dd",
    "caption",
    "col",
    "colgroup",
}


def is_image(file_name: str):
    return file_name and file_name.split(".")[-1] in IMG_FORMATS


def create_html_with_images(email_html="", entry_id_list=None):
    if not entry_id_list:
        return email_html

    account_name = get_tenant_account_name()
    xsoar_prefix = "/xsoar" if is_xsiam_or_xsoar_saas() else ""
    for file_name, attach_content_id, file_entry_id in entry_id_list:
        # Escape user-controlled values before interpolating into regex patterns
        safe_content_id = re.escape(attach_content_id)
        safe_file_name = re.escape(file_name)
        # Handling inline attachments from Gmail mailboxes
        if re.search(f'src="[^>]+{safe_content_id}"(?=[^>]+alt="{safe_file_name}")', email_html):
            email_html = re.sub(
                f'src="[^>]+{safe_content_id}"(?=[^>]+alt="{safe_file_name}")',
                f"src={account_name}{xsoar_prefix}/entry/download/{file_entry_id}",
                email_html,
            )
        # Handling inline attachments from Outlook mailboxes
        # Note: the format of an image src are like this src="cid:THE CONTENT ID"
        else:
            email_html = re.sub(
                f'(src="cid(.*?{safe_content_id}.*?"))',
                f"src={account_name}{xsoar_prefix}/entry/download/{file_entry_id}",
                email_html,
                count=1,
            )
    return email_html


# for backwards compatible
def get_entry_id_list_by_incident_attachments(attachments, files):
    """Get the incident attachments and create entry id list.
    Args:
        attachments (list): The incident attachments.
        files (list): The uploaded files in the context.
    Returns:
        list. List ou tuples, in the format (file name, attachment id, file EntryID).
    """
    if not (attachments and files):
        return []

    img_data_list = []
    entry_ids = set()
    for attachment in attachments:
        attachment_name = attachment.get("name", "")
        if is_image(attachment_name):
            for file in files:
                if attachment_name == file.get("Name") and file.get("EntryID") not in entry_ids:
                    entry_ids.add(file.get("EntryID"))
                    img_data_list.append((attachment_name, "", file.get("EntryID")))
                    break

    demisto.info(f"\n\n idlist by incident attachments \n\n{img_data_list}")
    return img_data_list


def get_entry_id_list_by_parsed_email_attachments(attachments, files):
    """Get the email attachments and create entry id list.
    Args:
        attachments (list): The parsed email attachments.
        files (list): The uploaded files in the context.
    Returns:
        list. List ou tuples, in the format (file name, attachment id, file EntryID).
    """
    if not (attachments and files):
        return []

    img_data_list = []
    entry_ids = set()
    for attachment in attachments:
        attach_name = attachment.get("Name", "")
        attach_id = (attachment.get("Content-ID") or "").replace("<", "").replace(">", "")
        if is_image(attach_name) and attach_id:
            for file in files:
                # we use the entry_ids set to avoid taking the wrong file in case there is two different images with same name
                if attach_name == file.get("Name") and file.get("EntryID") not in entry_ids:
                    entry_ids.add(file.get("EntryID"))
                    img_data_list.append((attach_name, attach_id, file.get("EntryID")))
                    break
    demisto.info(f"\n\n idlist by parsed email attachments\n\n{img_data_list}")
    return img_data_list


def _sanitize_html(html_body: str) -> str:
    """Sanitize HTML body using an allowlist of safe tags.

    When bleach is available, strips disallowed tags while preserving safe ones.
    When bleach is not available, uses a basic tag-stripping fallback to remove
    potentially dangerous tags while preserving content.
    """
    try:
        import bleach  # type: ignore[import-untyped]

        html_body = bleach.clean(
            html_body,
            tags=ALLOWED_EMAIL_TAGS,
            strip=True,
            attributes={
                "a": ["href", "title"],
                "img": ["src", "alt", "width", "height"],
                "td": ["style", "colspan", "rowspan"],
                "th": ["style", "colspan", "rowspan"],
                "div": ["style"],
                "span": ["style"],
                "p": ["style"],
                "font": ["color", "size", "face"],
                "table": ["style", "border", "cellpadding", "cellspacing"],
            },
        )
    except ImportError:
        demisto.debug("bleach is not available; using basic tag-stripping fallback")
        # Remove script/iframe/object/embed tags and their content as a basic fallback
        # Use [^>]*> for end tags to handle whitespace/attributes like </script > or </script\t\nbar>
        html_body = re.sub(r"<\s*script[^>]*>.*?<\s*/\s*script[^>]*>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
        html_body = re.sub(r"<\s*iframe[^>]*>.*?<\s*/\s*iframe[^>]*>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
        html_body = re.sub(r"<\s*object[^>]*>.*?<\s*/\s*object[^>]*>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
        html_body = re.sub(r"<\s*embed[^>]*>.*?<\s*/\s*embed[^>]*>", "", html_body, flags=re.DOTALL | re.IGNORECASE)
        # Also remove self-closing variants
        html_body = re.sub(r"<\s*(?:script|iframe|object|embed)[^>]*/\s*>", "", html_body, flags=re.IGNORECASE)
    return html_body


def main():
    incident = demisto.incident()
    html_body = demisto.get(incident, "CustomFields.emailhtml") or demisto.get(incident, "CustomFields.emailbody") or ""

    if 'src="cid' in html_body:
        context = demisto.context()
        files = argToList(context.get("File", []))
        attachments = argToList(demisto.get(context, "Email.AttachmentsData", []))
        entry_id_list = get_entry_id_list_by_parsed_email_attachments(attachments, files)

        if not entry_id_list:
            # for backwards compatible
            attachments = incident.get("attachment", {})
            entry_id_list = get_entry_id_list_by_incident_attachments(attachments, files)

        html_body = create_html_with_images(html_body, entry_id_list)

    # Sanitize after image replacement so cid: references are resolved first
    html_body = _sanitize_html(html_body)
    html_body = f'<div style="background-color: white; color:black;"> {html_body} </div>\n'

    return_results(
        {
            "ContentsFormat": formats["html"],
            "Type": entryTypes["note"],
            "Contents": html_body,
        }
    )


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
