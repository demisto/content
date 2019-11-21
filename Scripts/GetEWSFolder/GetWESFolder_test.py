import json

from GetEWSFolder import main, convert_mail_to_json

import demistomock as demisto


def mail(subject, body):
    return {'subject': subject, 'body': body}


mails_folder_1 = [mail(subject='subject 1', body='of folder 1'), mail(subject='subject 2', body='of folder 1')]
mails_folder_2 = [mail(subject='subject 1', body='of folder 2'), mail(subject='subject 2', body='of folder 2')]


def test_main(mocker):
    def executeCommand(name, args):
        if args['folder-path'] == 'folder1':
            return [{'Contents': mails_folder_1, 'Type': 'Content'}]
        if args['folder-path'] == 'folder2':
            return [{'Contents': mails_folder_2, 'Type': 'Content'}]
        else:
            raise ValueError('Unexist directory')

    mocker.patch.object(demisto, 'args', return_value={
        "foldersPaths": 'folder1,folder2'
    })
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')

    entry = main()
    file_name = '1_{}'.format(entry['FileID'])
    with open(file_name) as json_file:
        data = json.load(json_file)

    assert len(data) == len(mails_folder_1) + len(mails_folder_2)
    for mails_folder, folder in zip([mails_folder_1, mails_folder_2], ['folder1', 'folder2']):
        for mail in mails_folder:
            formatted_mail = convert_mail_to_json(mail, folder)
            assert sum(
                m['subject-body'] == formatted_mail['subject-body'] and m['folder'] == formatted_mail['folder'] for m in
                data) == 1
