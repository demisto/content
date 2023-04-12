import argparse
import json5

from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging
from pathlib import Path
import pathlib
import yaml


def get_git_diff(branch_name, repo):
    changed_files: list[str] = []
    packs_files_were_removed_from: set[str] = set()

    previous_commit = 'origin/master'
    current_commit = branch_name

    # if os.getenv('IFRA_ENV_TYPE') == 'Bucket-Upload':
    #     # logger.info('bucket upload: getting last commit from index')
    #     previous_commit = get_last_commit_from_index(self.service_account)
    #     if self.branch_name == 'master':
    #         current_commit = 'origin/master'

    if branch_name == 'master':
        current_commit, previous_commit = tuple(repo.iter_commits(max_count=2))

    # elif os.getenv('CONTRIB_BRANCH'):
    #     # gets files of unknown status
    #     contrib_diff: tuple[str, ...] = tuple(filter(lambda f: f.startswith('Packs/'), repo.untracked_files))
    #     # logger.info('contribution branch found, contrib-diff:\n' + '\n'.join(contrib_diff))
    #     changed_files.extend(contrib_diff)

    # elif os.getenv('EXTRACT_PRIVATE_TESTDATA'):
    #     logger.info('considering extracted private test data')
    #     private_test_data = tuple(filter(lambda f: f.startswith('Packs/'), repo.untracked_files))
    #     changed_files.extend(private_test_data)

    diff = repo.git.diff(f'{previous_commit}...{current_commit}', '--name-status')
    # logger.debug(f'raw changed files string:\n{diff}')

    # diff is formatted as `M  foo.json\n A  bar.py\n ...`, turning it into ('foo.json', 'bar.py', ...).
    for line in diff.splitlines():
        match len(parts := line.split('\t')):
            case 2:
                git_status, file_path = parts
            case 3:
                git_status, old_file_path, file_path = parts  # R <old location> <new location>

                if git_status.startswith('R'):
                    print(f'{git_status=} for {file_path=}, considering it as <M>odified')
                    git_status = 'M'

                # if pack_file_removed_from := find_pack_file_removed_from(Path(old_file_path), Path(file_path)):
                #     packs_files_were_removed_from.add(pack_file_removed_from)

            case _:
                raise ValueError(f'unexpected line format '
                                 f'(expected `<modifier>\t<file>` or `<modifier>\t<old_location>\t<new_location>`'
                                 f', got {line}')

        if git_status not in {'A', 'M', 'D', }:
            print(f'unexpected {git_status=}, considering it as <M>odified')

        # if git_status == 'D':  # git-deleted file
        #     if pack_file_removed_from := find_pack_file_removed_from(Path(file_path), None):
        #         packs_files_were_removed_from.add(pack_file_removed_from)
        #     continue  # not adding to changed files list

        changed_files.append(file_path)  # non-deleted files (added, modified)
        # return FilesToCollect(changed_files=tuple(changed_files),
        #                       pack_ids_files_were_removed_from=tuple(packs_files_were_removed_from))
    return changed_files


def run(options):
    paths = PathManager(Path(__file__).absolute().parents[2])
    branch_name = paths.content_repo.active_branch.name
    root_dir = Path(__file__).absolute().parents[2]
    root_dir_instance = pathlib.Path(root_dir)
    filesindir = [item.name for item in root_dir_instance.glob("*")]
    # TODO: Add Ddup
    changed_files = get_git_diff(branch_name, paths.content_repo)
    changed_packs = []
    yml_ids = []
    for f in changed_files:
        if 'Packs' in f:
            pack_path = f'{Path(__file__).absolute().parents[2]}/{f}'
            pack_path = '/'.join(pack_path.split('/')[:-1])
            changed_packs.append(pack_path)
    print(f'{changed_packs=}')
    for changed_pack in changed_packs:
        print(f'changed_pack: {changed_pack}')
        pack_dir = changed_pack
        print(f'pack_dir: {pack_dir}')
        pack_dir_instance = pathlib.Path(pack_dir)
        pack_files = [item.name for item in pack_dir_instance.glob("*")]
        print(branch_name)  # the branch name
        print('******************************')
        print(f'{filesindir=}')  # the files in content
        print('******************************')
        print(f'{changed_files=}')  # the array of changed files
        print('******************************')
        print(f'{changed_pack=}')  # the path of the changed integration
        print('******************************')
        print(f'{pack_files=}')  # the content of the paath location
        root_dir = Path(changed_pack)
        root_dir_instance = pathlib.Path(root_dir)
        filesindir = [item.name for item in root_dir_instance.glob("*") if str(item.name).endswith('yml')]
        print(f'{filesindir=}')
        for yml_file in filesindir:
            with open(f'{changed_pack}/{yml_file}', "r") as stream:
                try:
                    yml_obj = yaml.safe_load(stream)
                    print(yml_obj['commonfields']['id'])
                    yml_ids.append(yml_obj['commonfields']['id'])
                except yaml.YAMLError as exc:
                    print(exc)
    print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
    print(yml_ids)
    secret_conf = GoogleSecreteManagerModule(options.service_account)
    secrets = secret_conf.list_secrets(options.gsm_project_id, name_filter=yml_ids, with_secret=True, ignore_dev=True)
    secrets_dev = secret_conf.list_secrets(options.gsm_project_id, with_secret=True, branch_name=branch_name,
                                           ignore_dev=False)
    print(f'secrets pre merge: {secrets}')
    print(f'secrets_dev: {secrets_dev}')
    if secrets_dev:
        for dev_secret in secrets_dev:
            replaced = False
            for i in range(len(secrets)):
                if dev_secret['secret_name'] == secrets[i]['secret_name']:
                    dev_secret['test'] = 'test secret'
                    secrets[i] = dev_secret
                    replaced = True
            if not replaced:
                secrets.append(dev_secret)
    print('************************')
    print(f'secrets: {secrets}')
    secret_file = {
        "username": options.user,
        "userPassword": options.password,
        "integrations": secrets
    }
    with open(options.json_path_file, 'w') as secrets_out_file:
        try:
            secrets_out_file.write(json5.dumps(secret_file, quote_keys=True))
        except Exception as e:
            logging.error(f'Could not save secrets file, malformed json5 format, the error is: {e}')
    logging.info(f'saved the json file to: {options.json_path_file}')


def options_handler(args=None):
    parser = argparse.ArgumentParser(description='Utility for Importing secrets from Google Secret Manager.')
    parser.add_argument('-gpid', '--gsm_project_id', help='The project id for the GSM.')
    parser.add_argument('-u', '--user', help='the user for Demisto.')
    parser.add_argument('-p', '--password', help='The password for Demisto.')
    parser.add_argument('-sf', '--json_path_file', help='Path to the secret json file.')
    # disable-secrets-detection-start
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information see: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    options = parser.parse_args(args)

    return options


if __name__ == '__main__':
    options = options_handler()
    run(options)
