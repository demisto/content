import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from parse_emails.parse_emails import EmailParser


def recursive_convert_to_unicode(replace_to_utf):
    """Converts object into UTF-8 characters
    ignores errors
    Args:
        replace_to_utf (object): any object

    Returns:
        object converted to UTF-8
    """
    try:
        if isinstance(replace_to_utf, dict):
            return {recursive_convert_to_unicode(k): recursive_convert_to_unicode(v) for k, v in replace_to_utf.items()}
        if isinstance(replace_to_utf, list):
            return [recursive_convert_to_unicode(i) for i in replace_to_utf if i]
        if not replace_to_utf:
            return replace_to_utf
        return replace_to_utf
    except TypeError:
        return replace_to_utf


def data_to_md(email_data, email_file_name=None, parent_email_file=None, print_only_headers=False):
    if email_data is None:
        return 'No data extracted from email'
    # email_data = recursive_convert_to_unicode(email_data)
    # email_file_name = recursive_convert_to_unicode(email_file_name)
    # parent_email_file = recursive_convert_to_unicode(parent_email_file)

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


def save_file(file_name, file_content):
    created_file = fileResult(file_name, file_content)
    file_id = created_file.get('FileID')
    attachment_internal_path = demisto.investigation().get('id') + '_' + file_id
    demisto.results(created_file)

    return attachment_internal_path


def main():
    file_type = ''
    entry_id = demisto.args()['entryid']
    max_depth = int(demisto.args().get('max_depth', '3'))

    if max_depth < 1:
        return_error('Minimum max_depth is 1, the script will parse just the top email')

    parse_only_headers = demisto.args().get('parse_only_headers', 'false').lower() == 'true'
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

    try:
        email_parser = EmailParser(file_path=file_path, max_depth=max_depth, parse_only_headers=parse_only_headers,
                                   file_info=file_type)
        output = email_parser.parse()

        resultss = []
        if isinstance(output, dict):
            output = [output]

        for email in output:
            if email.get('AttachmentsData'):
                for attachment in email.get('AttachmentsData'):
                    if attachment.get('Name') and attachment.get('FileData'):
                        content = attachment.get('FileData')
                        del attachment['FileData']
                        name = attachment.get('Name')
                        attachment['FilePath'] = save_file(name, content)
            resultss.append(CommandResults(outputs_prefix='Email',
                            outputs=email,
                            readable_output=data_to_md(email, file_name, email.get('ParentFileName', None),
                                                       print_only_headers=parse_only_headers),
                            raw_response=email,
                            entry_type=EntryType.NOTE))
        return_results(resultss)

    except Exception as e:
        demisto.error(str(e) + "\n\nTrace:\n" + traceback.format_exc())
        return_error(str(e) + "\n\nTrace:\n" + traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
