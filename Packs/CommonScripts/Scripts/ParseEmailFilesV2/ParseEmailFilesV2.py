import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from parse_emails.parse_emails import EmailParser


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
        return 'No data extracted from email'

    md = u"### Results:\n"
    if email_file_name:
        md = f"### {email_file_name}\n"

    if print_only_headers:
        return tableToMarkdown(f"Email Headers: {email_file_name}", email_data.get('HeadersMap'))

    if parent_email_file:
        md += f"### Containing email: {parent_email_file}\n"

    md += u"* {0}:\t{1}\n".format('From', email_data.get('From') or "")
    md += u"* {0}:\t{1}\n".format('To', email_data.get('To') or "")
    md += u"* {0}:\t{1}\n".format('CC', email_data.get('CC') or "")
    md += u"* {0}:\t{1}\n".format('Subject', email_data.get('Subject') or "")
    if email_data.get('Text'):
        text = email_data['Text'].replace('<', '[').replace('>', ']')
        md += u"* {0}:\t{1}\n".format('Body/Text', text or "")
    if email_data.get('HTML'):
        md += u"* {0}:\t{1}\n".format('Body/HTML', email_data['HTML'] or "")

    md += u"* {0}:\t{1}\n".format('Attachments', email_data.get('Attachments') or "")
    md += u"\n\n" + tableToMarkdown('HeadersMap', email_data.get('HeadersMap'))
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
    file_id = created_file.get('FileID')
    attachment_internal_path = demisto.investigation().get('id') + '_' + file_id
    demisto.results(created_file)

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
    file_type = ''
    file_path = ''
    file_name = ''
    try:
        result = demisto.executeCommand('getFilePath', {'id': entry_id})
        if is_error(result):
            return_error(get_error(result))

        file_path = result[0]['Contents']['path']
        file_name = result[0]['Contents']['name']
        result = demisto.executeCommand('getEntry', {'id': entry_id})
        if is_error(result):
            return_error(get_error(result))

        file_metadata = result[0]['FileMetadata']
        file_type = file_metadata.get('info', '') or file_metadata.get('type', '')

    except Exception as ex:
        return_error(
            "Failed to load file entry with entry id: {}. Error: {}".format(
                entry_id, str(ex) + "\n\nTrace:\n" + traceback.format_exc()))

    return file_type, file_path, file_name


def parse_nesting_level(nesting_level_to_return, output):
    if nesting_level_to_return == 'Outer file':
        # return only the outer email info
        return [output[0]]

    elif nesting_level_to_return == 'Inner file':
        # the last file in list it is the inner attached file
        return [output[-1]]
    return output


def main():
    args = demisto.args()
    entry_id = args.get('entryid')
    max_depth = arg_to_number(args.get('max_depth', '3'))
    if not max_depth or max_depth < 1:
        return_error('Minimum max_depth is 1, the script will parse just the top email')
    parse_only_headers = argToBoolean(args.get('parse_only_headers', 'false'))
    forced_encoding = args.get('forced_encoding')
    default_encoding = args.get('default_encoding')
    nesting_level_to_return = args.get('nesting_level_to_return', 'All files')

    file_type, file_path, file_name = extract_file_info(entry_id)

    try:
        email_parser = EmailParser(file_path=file_path, max_depth=max_depth, parse_only_headers=parse_only_headers,
                                   file_info=file_type, forced_encoding=forced_encoding,
                                   default_encoding=default_encoding)
        output = email_parser.parse()

        results = []
        if isinstance(output, dict):
            output = [output]

        elif nesting_level_to_return != 'All files':
            output = parse_nesting_level(nesting_level_to_return, output)

        for email in output:
            if email.get('AttachmentsData'):
                for attachment in email.get('AttachmentsData'):
                    if (name := attachment.get('Name')) and (content := attachment.get('FileData')):
                        del attachment['FileData']
                        attachment['FilePath'] = save_file(name, content)
            results.append(CommandResults(
                outputs_prefix='Email',
                outputs=email,
                readable_output=data_to_md(email, file_name, email.get('ParentFileName', None),
                                           print_only_headers=parse_only_headers),
                raw_response=email))

        return_results(results)

    except Exception as e:
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
