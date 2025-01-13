import json

from GetEWSFolder import main, convert_mail_to_json

import demistomock as demisto


def create_mail(subject, body):
    return {'subject': subject, 'textBody': body, 'body': f'<body>{body}<\\body>'}


mails_folder_1 = [create_mail(subject='subject 1', body='body 1'), create_mail(subject='subject 2', body='body 2')]
mails_folder_2 = [create_mail(subject='subject 3', body='body 3'), create_mail(subject='subject 4', body='body 4')]


def identical_mail(mail1, mail2):
    if len(mail1) != len(mail2):
        return False
    return all(mail1[field] == mail2[field] for field in ['subject', 'body', 'textBody'])


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
        mails_from_file = json.load(json_file)

    assert len(mails_from_file) == len(mails_folder_1) + len(mails_folder_2)
    for mails_folder, folder in zip([mails_folder_1, mails_folder_2], ['folder1', 'folder2']):
        for mail in mails_folder:
            formatted_mail = convert_mail_to_json(mail, folder)
            assert sum(identical_mail(m, formatted_mail) for m in mails_from_file) == 1
