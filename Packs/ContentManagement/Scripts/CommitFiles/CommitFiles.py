import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import traceback
import io
from contextlib import redirect_stderr, redirect_stdout
from demisto_sdk.commands.common.constants import FileType
from demisto_sdk.commands.common.tools import find_type
from demisto_sdk.commands.split.ymlsplitter import *
from ruamel.yaml.scalarstring import SingleQuotedScalarString
from demisto_sdk.commands.format.format_module import run_format_on_file


TYPE_TO_FOLDER = {'playbook': 'Playbooks',
                  'automation': 'Scripts',
                  'integration': 'Integrations',
                  'classifier': 'Classifiers',
                  'incidenttype': 'IncidentTypes',
                  'incidentfield': 'IncidentFields',
                  'layoutscontainer': 'Layouts',
                  'widget': 'Widgets',
                  'dashboard': 'Dashboards'
                  }

PR_TEMPLATE = '### Pull Request created in Cortex XSOAR\n' \
              '**Created by:** {}\n' \
              '**Pack:** {}\n' \
              '**Branch:** {}\n' \
              '**Link to incident in Cortex XSOAR:** {}\n\n' \
              '{}\n\n' \
              '---'

new_files = []
modified_files = []


def commit_content_item(branch_name, content_file):
    file_sha = ''

    commit_args = {'commit_message': f'Added {content_file.file_name}',
                   'path_to_file': f'{content_file.path_to_file}/{content_file.file_name}',
                   'branch_name': branch_name, 'file_text': content_file.file_text}

    # try to get the file from branch
    list_files_res = demisto.executeCommand('Github-list-files', {'branch': branch_name, 'path': content_file.path_to_file})

    if not is_error(list_files_res):
        for file in list_files_res[0]['Contents']:
            if file['name'] == content_file.file_name:
                # if the file already exists - take the file sha1 value
                file_sha = file['sha']

    # dont commit pack_metadata.json if already exists in the branch
    if file_sha and content_file.file_name == 'pack_metadata.json':
        return
    elif file_sha:
        # update existing file
        commit_args['file_sha'] = file_sha
        commit_args['commit_message'] = f'Updated {content_file.file_name}'
        modified_files.append(content_file.file_name)
    else:
        # new file added
        new_files.append(content_file.file_name)

    commit_res = demisto.executeCommand('Github-commit-file', commit_args)
    if is_error(commit_res):
        print(str(get_error(commit_res)))


def split_script_file(content_file):
    file_object = demisto.getFilePath(content_file.entry_id)
    base_name = content_file.file_name.replace('automation-', '').replace('.yml', '')

    # create the yml file from entry id
    with open(file_object['path'], 'r') as f:
        file_contents = f.read()

    with open(content_file.file_name, "w") as f:
        f.write(file_contents)

    # split the yml file
    yml_splitter = YmlSplitter(no_readme=True, base_name=base_name, input=content_file.file_name,
                               output=base_name, file_type='script', no_pipenv=True, no_basic_fmt=True)

    output_capture = io.StringIO()
    with redirect_stdout(output_capture):
        with redirect_stderr(output_capture):
            yml_splitter.extract_to_package_format()

    yml_file_path = f'{base_name}/{base_name}.yml'
    script_file_path = f'{base_name}/{base_name}.py'
    path_to_file = f'{content_file.path_to_file}/{base_name}'

    # read the py and yml files content
    with open(yml_file_path, 'r') as f:
        yml_txt = f.read()

    with open(script_file_path, 'r') as f:
        script_txt = f.read()

    # create the yml and script files
    yml_file = ContentFile()
    yml_file.file_text = yml_txt
    yml_file.file_name = f'{base_name}.yml'
    yml_file.path_to_file = path_to_file

    py_file = ContentFile()
    py_file.file_text = script_txt
    py_file.file_name = f'{base_name}.py'
    py_file.path_to_file = path_to_file

    return yml_file, py_file


class ContentFile:
    path_to_file: str = ''
    file_name: str = ''
    content_type: str = ''
    file_text: str = ''
    entry_id: str = ''

    def __init__(self, pack_name=None, file=None):
        if not pack_name and not file:
            return

        # read the file from entry id
        file_object = demisto.getFilePath(file['EntryID'])
        with open(file_object['path'], 'r') as f:
            file_contents = f.read()

        self.file_text = file_contents
        self.file_name = file['Name']
        self.entry_id = file['EntryID']

        if self.file_name == 'metadata.json':
            self.file_name = 'pack_metadata.json'
            self.path_to_file = f'Packs/{pack_name}'
            self.content_type = 'packmetadata'
        else:
            content_type = self.file_name.split('-')[0].lower()
            folder = TYPE_TO_FOLDER[content_type]
            self.path_to_file = f'Packs/{pack_name}/{folder}'
            self.content_type = content_type


''' MAIN FUNCTION '''


def main():
    try:
        files = demisto.getArg('files')
        branch_name = demisto.getArg('branch')
        pack_name = demisto.getArg('pack')
        user = demisto.getArg('user')
        comment = demisto.getArg('comment', '')

        username = user.get('username')
        if user.get('email'):
            username = f'{username} ({user.get("email")})'

        # commit the files from the input
        for file in files:
            if file.get('Unzipped') == True:
                continue

            content_file = ContentFile(pack_name=pack_name, file=file)

            if content_file.content_type == 'automation':
                # split automation file to yml and python files
                yml_file, py_file = split_script_file(content_file)
                commit_content_item(branch_name, yml_file)
                commit_content_item(branch_name, py_file)
            else:
                commit_content_item(branch_name, content_file)

        inciden_url = demisto.demistoUrls().get('investigation')

        # create the PR text
        pr_body = PR_TEMPLATE.format(username, pack_name, branch_name, inciden_url, comment)
        if new_files:
            pr_body = f'{pr_body}\n\n### New files\n- '
            pr_body = pr_body + '\n- '.join(new_files)

        if modified_files:
            pr_body = f'{pr_body}\n\n### Modified files\n- '
            pr_body = pr_body + '\n- '.join(modified_files)

        return_results(CommandResults(
            readable_output=pr_body,
            outputs_prefix='PR_text',
            outputs=pr_body
        ))

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CommitFiles script. Error: {str(traceback.format_exc())}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
