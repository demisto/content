import argparse
import json5

from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging
from pathlib import Path


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
    # raise Exception(f'ppppaaaaattttthhhh: {Path(__file__).absolute()},ppppaaaaattttthhhh: {Path(__file__).absolute().parents[3]},ppppaaaaattttthhhh: {Path(__file__).absolute().parents[2]}')
    PATHS = PathManager(Path(__file__).absolute().parents[2])
    branch_name = PATHS.content_repo.active_branch.name
    import pathlib
    root_dir = Path(__file__).absolute().parents[2]
    root_dir_instance = pathlib.Path(root_dir)
    filesindir = [item.name for item in root_dir_instance.glob("*")]
    changed_files = get_git_diff(branch_name, PATHS.content_repo)
    paath = ''
    for p in changed_files:
        if 'Packs' in p:
            paath = f'{Path(__file__).absolute().parents[2]}/{p}'
            paath = '/'.join(paath.split('/')[:-1])
    root_dir1 = paath
    root_dir_instance1 = pathlib.Path(root_dir1)
    filesindir1 = [item.name for item in root_dir_instance1.glob("*")]
    print(branch_name)
    print('******************************')
    print(filesindir)
    print('******************************')
    print(changed_files)
    print('******************************')
    print(paath)
    print('******************************')
    print(filesindir1)
    secret_conf = GoogleSecreteManagerModule(options.service_account)
    secrets = secret_conf.list_secrets(options.gsm_project_id, with_secret=True, attr_validation=('name', 'params'))
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
