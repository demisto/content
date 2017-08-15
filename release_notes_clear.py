# remove all releaseNotes from files in: Itegrations, Playbooks, Reports and Scripts.
# Note: using yaml will destroy the file structures so filtering as regular text-file.
import os
import glob

def yml_remove_releaseNote_record(file_path):
    '''
    locate and remove release notes from a yaml file.
    :param file_path: path of the file
    :return: True if file was changed, otherwise False.
    '''
    with open(file_path, 'r') as f:
        lines = f.readlines()

    orig_size = len(lines)
    consider_multiline_notes = False
    new_lines = []
    for line in lines:
        if line.startswith('releaseNotes:'):
            # releaseNote title: ignore current line and consider following lines as part of it (multiline notes)
            consider_multiline_notes = True

        elif consider_multiline_notes:
            # not a releaseNote title (right after a releaseNote block (single or multi line)
            if not line[0].isspace():
                # regular line
                consider_multiline_notes = False
                new_lines.append(line)
            else:
                # line is part of a multiline releaseNote: ignore it
                pass
        else:
            # regular line
            new_lines.append(line)

    with open(file_path, 'w') as f:
        f.write(''.join(new_lines))

    return orig_size != len(new_lines)


def json_remove_releaseNote_record(file_path):
    '''
    locate and remove release notes from a json file.
    :param file_path: path of the file
    :return: True if file was changed, otherwise False.
    '''
    with open(file_path, 'r') as f:
        lines = f.readlines()

    orig_size = len(lines)
    consider_multiline_notes = False
    new_lines = []
    for line in lines:
        if line.strip().startswith('"releaseNotes"'):
            # releaseNote title: ignore current line and consider following lines as part of it (multiline notes)
            consider_multiline_notes = True

        elif consider_multiline_notes:
            # not a releaseNote title (right after a releaseNote block (single or multi line)
            if line.strip() and line.strip()[0] == '"':
                # line
                consider_multiline_notes = False
                new_lines.append(line)
            else:
                # line is part of a multiline releaseNote: ignore it
                pass
        else:
            # regular line
            new_lines.append(line)

    with open(file_path, 'w') as f:
        f.write(''.join(new_lines))

    return orig_size != len(new_lines)


FILE_EXTRACTER_DICT = {
    '*.yml' : yml_remove_releaseNote_record,
    '*.json' : json_remove_releaseNote_record,
}


def remove_releaseNotes_folder(folder_path, files_extension):
    '''
    scan folder and remove all references to release notes
    :param folder_path: path of the folder
    :param files_extension: type of file to look for (json or yml)
    :return:
    '''
    scan_files = glob.glob(os.path.join(folder_path, files_extension))

    count = 0
    for path in scan_files:
        if FILE_EXTRACTER_DICT[files_extension](path):
            count += 1

    return count


def main(root_dir):
    yml_folders_to_scan = ['Integrations', 'Playbooks', 'Scripts', ] # yml
    json_folders_to_scan = ['Reports', ] # json

    for folder in yml_folders_to_scan:
        print 'scanning directory: %s' % (folder, ),
        changed = remove_releaseNotes_folder(os.path.join(root_dir, folder), '*.yml')
        print 'Done: removed %d from files' % (changed, )

    for folder in json_folders_to_scan:
        print 'scanning directory: %s' % (folder, ),
        changed = remove_releaseNotes_folder(os.path.join(root_dir, folder), '*.json')
        print 'Done: removed %d from files' % (changed,)


if __name__ == '__main__':
    main(os.path.dirname(__file__))