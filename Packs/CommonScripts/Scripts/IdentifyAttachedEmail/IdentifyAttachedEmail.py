import demistomock as demisto
from CommonServerPython import *


# file info types which identify emails
CONFIDENT_EMAIL_INFOS = {
    'cdfv2 microsoft outlook message',
    'rfc 822 mail',
    'smtp mail',
    'multipart/signed',
    'news or mail text',
}


# IMPORTANT: If you modify the logic here make sure to update ParseEmailFiles too
def is_email(file_metadata: dict, file_name: str):
    file_info = file_metadata.get('info', '')
    return any((
        file_metadata.get('type') == 'eml',
        CONFIDENT_EMAIL_INFOS.intersection(file_info),
        file_name.endswith('.eml') and ('text' in file_info or file_info == 'data'),
        file_name.endswith('.msg') and 'composite document file v2 document' in file_info
    ))


def is_entry_email(entry: dict):
    """
    Return entry ID if this is an email entry otherwise None

    Arguments:
        entry {dict} -- Entry object as returned from getEntries or getEntry
    """
    file_metadata = entry.get('FileMetadata', {})
    name = entry.get('File', '')
    if is_email(file_metadata, name):
        return entry.get('ID')
    return None


def identify_attached_mail(args):
    entry_ids = args.get('entryid')
    if entry_ids:
        if isinstance(entry_ids, STRING_TYPES):
            # playbook inputs may be in the form: [\"23@2\",\"24@2\"] if passed as a string and not array
            entry_ids = entry_ids.strip().replace(r'\"', '"')  # type:ignore
        entry_ids = argToList(entry_ids)
        entries = []  # type: List[str]

        if is_xsiam_or_xsoar_saas():
            entry_ids_str = ",".join(entry_ids)
            entries = demisto.executeCommand('getEntriesByIDs', {'entryIDs': entry_ids_str})
        else:
            for ent_id in entry_ids:
                res = demisto.executeCommand('getEntry', {'id': ent_id})
                if not is_error(res):
                    id = is_entry_email(res[0])
                    if id:
                        # return the first email entry that we find.
                        return 'yes', {'reportedemailentryid': id}
    else:
        entries = demisto.executeCommand('getEntries', {"filter": {"categories": ["attachments"]}})

    if not entries:
        return 'no', None

    for e in entries:
        id = is_entry_email(e)
        if id:
            # leave the following comment as server used it to detect the additional context path used beyond the condition values
            # demisto.setContext('reportedemailentryid', id)
            return 'yes', {'reportedemailentryid': id}

    return 'no', None


def main():
    args = demisto.args()
    result, outputs = identify_attached_mail(args)
    return_outputs(result, outputs, result)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
