
from CommonServerPython import *


def convert_mail_to_json(item, folder):
    return {
        'subject': item.get('subject', ''),
        'textBody': item.get('textBody', ''),
        'body': item.get('body', ''),
        'folder': folder
    }


def main():
    folders_paths_str = demisto.args()['foldersPaths']
    folders_paths_list = [folder.strip() for folder in folders_paths_str.split(',')]
    path_to_mails = {folder: [] for folder in folders_paths_list}   # type: Dict[str, List[str]]
    for folder in folders_paths_list:

        res = demisto.executeCommand('ews-get-items-from-folder', {
            'folder-path': folder,
            'limit': demisto.args().get('limit'),
            'target-mailbox': demisto.args().get('targetMailbox'),
            'is-public': 'False' if demisto.args().get('isPublic') == 'false' else 'True'
        })
        if is_error(res):
            return_error(get_error(res))

        items = res[0]['Contents']
        if isinstance(items, str) and items == 'There is no output results':
            mails_at_folder = []
        else:
            mails_at_folder = [convert_mail_to_json(i, folder) for i in items]
        path_to_mails[folder] = mails_at_folder
    mails_from_all_folders_list = [mail_json for folder_mails in path_to_mails.values() for mail_json in folder_mails]
    return fileResult("all_mails.json", json.dumps(mails_from_all_folders_list))


if __name__ == "__builtin__" or __name__ == "builtins":
    entry = main()
    demisto.results(entry)
