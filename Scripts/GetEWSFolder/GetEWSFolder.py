from typing import List, Dict

from CommonServerPython import *


def convert_mail_to_json(item, folder, emailSubjectKey, emailTextKey, emailHtmlKey, emailTagKey):
    return {
        emailSubjectKey: item.get('subject', ''),
        emailTextKey: item.get('textBody', ''),
        emailHtmlKey: item.get('body', ''),
        emailTagKey: folder}


def main():
    folders_paths_str = demisto.args()['foldersPaths']
    folders_paths_list = [folder.strip() for folder in folders_paths_str.split(',')]
    path_to_mails = {folder: [] for folder in folders_paths_list}   # type: Dict[str, List[Dict[str,str]]]
    emailTagKey = demisto.args()['emailTagKey']
    emailTextKey = demisto.args()['emailTextKey']
    emailHtmlKey = demisto.args()['emailHtmlKey']
    emailSubjectKey = demisto.args()['emailSubjectKey']
    for folder in folders_paths_list:
        res = demisto.executeCommand('ews-get-items-from-folder', {
            'folder-path': folder,
            'limit': demisto.args().get('limit'),
            'target-mailbox': demisto.args().get('targetMailbox'),
            'is-public': 'False' if demisto.args().get('isPublic') == 'false' else 'True',
            'get-internal-item': 'yes' if demisto.args().get('getInternalItem') == 'true' else 'no'
        })
        if is_error(res):
            return_error(get_error(res))

        items = res[0]['Contents']
        path_to_mails[folder] = [convert_mail_to_json(i, folder, emailSubjectKey, emailTextKey,
                                                      emailHtmlKey, emailTagKey) for i in items]
    mails_from_all_folders_list = [mail_json for folder_mails in path_to_mails.values() for mail_json in folder_mails]
    return fileResult("all_mails.json", json.dumps(mails_from_all_folders_list))


if __name__ == "__builtin__" or __name__ == "builtins":
    entry = main()
    demisto.results(entry)