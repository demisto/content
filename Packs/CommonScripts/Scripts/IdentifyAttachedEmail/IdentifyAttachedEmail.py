import demistomock as demisto
from CommonServerPython import *


# file info types which identify emails
CONFIDENT_EMAIL_INFOS = [
    'cdfv2 microsoft outlook message',
    'rfc 822 mail',
    'smtp mail',
    'multipart/signed',
    'news or mail text',
]


# IMPORTANT: If you modify the logic here make sure to update ParseEmailFiles too
def is_email(file_info, file_name):
    if not file_info:
        demisto.info("IdentifyAttachedEmail: No file info for file: {}. Returning false.".format(file_name))
        return False
    file_info = file_info.lower().strip()
    for info in CONFIDENT_EMAIL_INFOS:
        if info in file_info:
            return True
    file_name = file_name.lower().strip() if file_name else ''
    if file_name.endswith('.eml') and ('text' in file_info or 'data' == file_info):
        return True
    if file_name.endswith('.msg') and 'composite document file v2 document' in file_info:
        return True
    return False


def is_entry_email(entry):
    """
    Return entry ID if this is an email entry otherwise None

    Arguments:
        entry {dict} -- Entry object as returned from getEntries or getEntry
    """
    info = demisto.get(entry, 'FileMetadata.info')
    name = demisto.get(entry, 'File')
    if is_email(info, name):
        return demisto.get(entry, 'ID')
    return None


def identify_attached_mail(args):
    entry_ids = demisto.get(args, 'entryid')
    if entry_ids:
        if isinstance(entry_ids, STRING_TYPES):
            # playbook inputs may be in the form: [\"23@2\",\"24@2\"] if passed as a string and not array
            entry_ids = entry_ids.strip().replace(r'\"', '"')  # type:ignore
        entry_ids = argToList(entry_ids)
        entries = []  # type: List[str]
        for ent_id in entry_ids:
            res = demisto.executeCommand('getEntry', {'id': ent_id})
            entries.extend(res)
    else:
        entries = demisto.executeCommand('getEntries', {})
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
