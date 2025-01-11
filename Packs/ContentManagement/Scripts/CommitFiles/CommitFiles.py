from pathlib import Path

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import os
import io
from os.path import exists
from contextlib import redirect_stderr, redirect_stdout
from demisto_sdk.commands.split.ymlsplitter import YmlSplitter
from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR
from demisto_sdk.commands.common.tools import find_type

PR_TEMPLATE = '### Pull Request created in Cortex XSOAR\n' \
              '**Created by:** {}\n' \
              '**Pack:** {}\n' \
              '**Branch:** {}\n' \
              '**Link to incident in Cortex XSOAR:** {}\n\n' \
              '{}\n\n' \
              '---'

file_path_to_sha: dict[str, str] = {}

files_path = []


class ContentFile:  # pragma: no cover
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
        with open(file_object['path']) as f:
            file_contents = f.read()

        self.file_text = file_contents
        self.file_name = file['Name']
        self.entry_id = file['EntryID']

        if self.file_name == 'metadata.json':
            self.file_name = 'pack_metadata.json'
            self.path_to_file = os.path.join('Packs', pack_name)
            self.content_type = 'metadata'
        else:
            with open(file_object['name'], "w") as f:
                f.write(file_contents)

            file_type = find_type(file_object['name'])
            os.remove(file_object['name'])
            self.content_type = file_type.value if file_type else file_type
            folder = ENTITY_TYPE_TO_DIR.get(self.content_type, '')
            self.path_to_file = os.path.join('Packs', pack_name, folder)


def get_file_sha(branch_name: str, content_file: ContentFile, get_files_command: str):
    full_path = os.path.join(content_file.path_to_file, content_file.file_name)

    sha = file_path_to_sha.get(full_path)
    if sha:
        return sha

    # try to get the file from branch
    status, list_files_res = execute_command(get_files_command, {'branch': branch_name,
                                                                 'path': content_file.path_to_file},
                                             fail_on_error=False)
    if status:
        for file in list_files_res:
            file_path_to_sha[file['path']] = file['sha']

    return file_path_to_sha.get(full_path)


def commit_content_item(branch_name: str, content_file: ContentFile, new_files: List, modified_files: List):
    commit_args = {'commit_message': f'Added {content_file.file_name}',
                   'path_to_file': f'{content_file.path_to_file}/{content_file.file_name}',
                   'branch_name': branch_name, 'file_text': content_file.file_text}

    file_sha = get_file_sha(branch_name, content_file, 'Github-list-files')

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

    status, commit_res = execute_command('Github-commit-file', commit_args, fail_on_error=False)
    if not status:
        raise DemistoException(commit_res)


def commit_content_item_gitlab(branch_name: str, content_file: ContentFile, new_files: List, modified_files: List):
    commit_args = {'commit_message': f'Added {content_file.file_name}',
                   'file_path': f'{content_file.path_to_file}/{content_file.file_name}',
                   'branch': branch_name, 'file_content': content_file.file_text}
    status, commit_res = execute_command('gitlab-file-create', commit_args, fail_on_error=False)
    if isinstance(commit_res, dict):
        new_files.append(content_file.file_name)
    elif isinstance(commit_res, str) and "already exists" in commit_res:
        demisto.debug(f'The file {content_file.file_name} already exist, running update command')
        if content_file.file_name == 'pack_metadata.json':
            return
        commit_args['commit_message'] = f'Updated {content_file.file_name}'
        modified_files.append(content_file.file_name)
        status, commit_res = execute_command('gitlab-file-update', commit_args, fail_on_error=False)
    if not status:
        raise DemistoException(commit_res)


def does_file_exist(branch_name: str, content_file: ContentFile) -> bool:
    full_path = os.path.join(content_file.path_to_file, content_file.file_name)

    if full_path in files_path:
        return True
    # try to get the file from branch
    status, list_commit_res = execute_command('bitbucket-commit-list', {'included_branches': branch_name,
                                                                        'file_path': full_path},
                                              fail_on_error=False)
    if list_commit_res and len(list_commit_res) > 0:
        files_path.append(full_path)
        return True
    return False


def searched_file_path(branch_name: str, content_file: ContentFile) -> bool:
    full_path = Path(content_file.path_to_file, content_file.file_name)

    if str(full_path) in files_path:  # the files list, check if the file already exists in the list
        return True
    # try to get the file from branch
    response = execute_command('azure-devops-file-list',
                               args={'branch_name': branch_name.split('/')[-1], 'recursion_level': 'Full'})
    files_set = {file["path"] for file in response.get("value", [])}
    for file in files_set:
        if str(full_path) in file:
            files_path.append(str(full_path))
            return True
    return False


def commit_content_item_bitbucket(branch_name: str, content_file: ContentFile, new_files: List, modified_files: List):
    commit_args = {"message": f"Added {content_file.file_name}",
                   "file_name": f"{content_file.path_to_file}/{content_file.file_name}",
                   "branch": f"{branch_name}",
                   "file_content": f"{content_file.file_text}"}
    file_status = does_file_exist(branch_name, content_file)
    # dont commit pack_metadata.json if already exists in the branch
    if file_status and content_file.file_name == 'pack_metadata.json':
        return
    elif file_status:
        # update existing file
        commit_args['message'] = f'Updated {content_file.file_name}'
        modified_files.append(content_file.file_name)
    else:
        # new file added
        new_files.append(content_file.file_name)
    try:
        demisto.executeCommand('bitbucket-commit-create', args=commit_args)
    except DemistoException as e:
        raise DemistoException(f'Failed to execute bitbucket-commit-create command. Error: {e}, '
                               f'{traceback.format_exc()}')


def commit_content_item_azure_devops(branch_name: str, content_file: ContentFile, new_files: List, modified_files: List):
    file_args = {"commit_comment": f"{content_file.file_name} was added.",
                 "file_path": f"{content_file.path_to_file}/{content_file.file_name}",
                 "branch_name": f"{branch_name}",
                 "file_content": f"{content_file.file_text}"}

    file_exists = searched_file_path(branch_name, content_file)

    # don't commit pack_metadata.json if already exists in the branch
    if file_exists and content_file.file_name == 'pack_metadata.json':
        return
    response = demisto.executeCommand('azure-devops-branch-list', args={})
    branches_list = response[0].get("Contents", {}).get("value", []) if response and isinstance(response, list) else []
    for branch in branches_list:
        if branch["name"] == branch_name:
            branch_id = branch["objectId"]
            break
    else:
        raise DemistoException('Failed to find a corresponding branch id to the given branch name.')
    file_args["branch_id"] = branch_id

    if file_exists:
        # update existing file
        file_args['commit_comment'] = f'{content_file.file_name} was updated.'
        modified_files.append(content_file.file_name)
        command_to_execute = 'azure-devops-file-update'
    else:
        # new file added
        new_files.append(content_file.file_name)
        command_to_execute = 'azure-devops-file-create'

    try:
        demisto.executeCommand(command_to_execute, args=file_args)
    except DemistoException as e:
        raise DemistoException(
            f'Failed to execute azure-devops-file-update or azure-devops-file-create commands. Error: {e}, '
        ) from e


def split_yml_file(content_file: ContentFile):  # pragma: no cover
    content_files = []

    if content_file.content_type == 'script':
        base_name = content_file.file_name.replace('automation-', '').replace('.yml', '')
    else:
        base_name = content_file.file_name.replace('integration-', '').replace('.yml', '')

    # create the yml file from entry id
    with open(content_file.file_name, "w") as f:
        f.write(content_file.file_text)

    output_capture = io.StringIO()

    # split the yml file
    yml_splitter = YmlSplitter(content_file.file_name, base_name=base_name, output=base_name,  # pylint: disable=E1123
                               file_type=content_file.content_type, no_pipenv=True, no_code_formatting=True,
                               no_logging=True, no_readme=True)

    script_type = yml_splitter.yml_data.get('type')
    if not script_type:
        script_type = yml_splitter.yml_data.get('script', {}).get('type')

    if script_type == 'python':
        script_extention = 'py'
    elif script_type == 'javascript':
        script_extention = 'js'
    elif script_type == 'powershell':
        script_extention = 'ps1'
    else:
        script_extention = ''
        demisto.debug(f"{script_type=} didn't match any condition. {script_extention=}")

    with redirect_stdout(output_capture), redirect_stderr(output_capture):
        yml_splitter.extract_to_package_format()

    yml_file_path = f'{base_name}/{base_name}.yml'
    script_file_path = f'{base_name}/{base_name}.{script_extention}'
    path_to_file = os.path.join(content_file.path_to_file, base_name)

    # read the py and yml files content
    with open(yml_file_path) as f:
        yml_txt = f.read()

    with open(script_file_path) as f:
        script_txt = f.read()

    # create the yml file
    yml_file = ContentFile()
    yml_file.file_text = yml_txt
    yml_file.file_name = f'{base_name}.yml'
    yml_file.path_to_file = path_to_file
    content_files.append(yml_file)

    # create the script file
    script_file = ContentFile()
    script_file.file_text = script_txt
    script_file.file_name = f'{base_name}.{script_extention}'
    script_file.path_to_file = path_to_file
    content_files.append(script_file)

    # create the description file
    description_file_path = f'{base_name}/{base_name}_description.md'
    if exists(description_file_path):
        with open(description_file_path) as f:
            description_txt = f.read()

        description_file = ContentFile()
        description_file.file_text = description_txt
        description_file.file_name = f'{base_name}_description.md'
        description_file.path_to_file = path_to_file
        content_files.append(description_file)

    return content_files


def commit_git(git_integration: str, branch_name: str, content_file: ContentFile,
               new_files: List, modified_files: List):
    if git_integration == 'Gitlab':
        commit_content_item_gitlab(branch_name, content_file, new_files, modified_files)
    elif git_integration == 'GitHub':
        commit_content_item(branch_name, content_file, new_files, modified_files)
    elif git_integration == 'Bitbucket':
        commit_content_item_bitbucket(branch_name, content_file, new_files, modified_files)
    elif git_integration == 'AzureDevOps':
        commit_content_item_azure_devops(branch_name, content_file, new_files, modified_files)
    else:
        raise DemistoException(f"Unexpected {git_integration=}. Possible values: Gitlab, GitHub, Bitbucket and AzureDevOps.")


''' MAIN FUNCTION '''


def main():
    try:
        files = demisto.getArg('files')
        branch_name = demisto.getArg('branch')
        pack_name = demisto.getArg('pack')
        user = demisto.getArg('user')
        comment = demisto.getArg('comment')
        template = demisto.getArg('template')
        git_integration = demisto.getArg('git_integration')
        new_files: List[str] = []
        modified_files: List[str] = []

        if not template:
            template = PR_TEMPLATE

        if not comment:
            comment = ''

        username = user.get('username')
        if user.get('email'):
            username = f'{username} ({user.get("email")})'

        # commit the files from the input
        for file in files:
            if file.get('Unzipped'):
                continue

            # create ContentFile item
            content_file = ContentFile(pack_name=pack_name, file=file)

            if content_file.content_type in ('script', 'integration'):
                # split automation file to yml and script files
                content_files = split_yml_file(content_file)
                for file_to_commit in content_files:
                    commit_git(git_integration, branch_name, file_to_commit, new_files, modified_files)

            else:
                commit_git(git_integration, branch_name, content_file, new_files, modified_files)
        incident_url = demisto.demistoUrls().get('investigation')

        # create the PR text
        pr_body = template.format(f'{username}\n', f'{pack_name}\n', f'{branch_name}\n', f'{incident_url}\n',
                                  f'{comment}\n')
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
        return_error(f'Failed to execute CommitFiles script. Error: {ex}', error=ex)


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
