import argparse
import json5
import pathlib
import yaml

from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging
from pathlib import Path


def get_git_diff(branch_name: str, repo) -> list[str]:
    changed_files: list[str] = []

    previous_commit = 'origin/master'
    current_commit = branch_name

    if branch_name == 'master':
        current_commit, previous_commit = tuple(repo.iter_commits(max_count=2))

    diff = repo.git.diff(f'{previous_commit}...{current_commit}', '--name-status')

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

            case _:
                logging.error(f'unexpected line format '
                                 f'(expected `<modifier>\t<file>` or `<modifier>\t<old_location>\t<new_location>`'
                                 f', got {line}')

        if git_status not in {'A', 'M', 'D', }:
            print(f'unexpected {git_status=}, considering it as <M>odified')

        changed_files.append(file_path)

    return changed_files


def get_secrets_from_gsm(branch_name: str, options, yml_pack_ids: list[str]) -> dict:
    secret_conf = GoogleSecreteManagerModule(options.service_account)
    secrets = secret_conf.list_secrets(options.gsm_project_id, name_filter=yml_pack_ids, with_secret=True, ignore_dev=True)
    secrets_dev = secret_conf.list_secrets(options.gsm_project_id, with_secret=True, branch_name=branch_name,
                                           ignore_dev=False)
    print('==============================')
    print(f'secrets pre merge: {secrets}')
    print('==============================')
    print(f'secrets_dev: {secrets_dev}')
    if secrets_dev:
        for dev_secret in secrets_dev:
            replaced = False
            for i in range(len(secrets)):
                if dev_secret['name'] == secrets[i]['name']:
                    secrets[i] = dev_secret
                    replaced = True
            # If the dev secret is not in the changed packs it's a new secret
            if not replaced:
                secrets.append(dev_secret)
    print('++++++++++++++++++++++++++++++++++')
    print(f'secrets post merge: {secrets}')
    secret_file = {
        "username": options.user,
        "userPassword": options.password,
        "integrations": secrets
    }
    return secret_file


def write_secrets_to_file(options, secrets_file: dict):
    with open(options.json_path_file, 'w') as secrets_out_file:
        try:
            secrets_out_file.write(json5.dumps(secrets_file, quote_keys=True))
        except Exception as e:
            logging.error(f'Could not save secrets file, malformed json5 format, the error is: {e}')
    logging.info(f'saved the json file to: {options.json_path_file}')


def get_yml_pack_ids(changed_packs):
    yml_ids = []
    for changed_pack in changed_packs:
        root_dir = Path(changed_pack)
        root_dir_instance = pathlib.Path(root_dir)
        yml_files = [item.name for item in root_dir_instance.glob("*") if str(item.name).endswith('yml')]
        print(f'{yml_files=}')
        for yml_file in yml_files:
            with open(f'{changed_pack}/{yml_file}', "r") as stream:
                try:
                    yml_obj = yaml.safe_load(stream)
                    yml_ids.append(yml_obj['commonfields']['id'])
                except yaml.YAMLError as exc:
                    logging.error(f'Could not convert {yml_file} to YML: {exc}')
    return yml_ids


def get_changed_packs(changed_files: list[str]) -> list[str]:
    """

    """
    changed_packs = []
    for f in changed_files:
        if 'Packs' in f:
            pack_path = f'{Path(__file__).absolute().parents[2]}/{f}'
            pack_path = '/'.join(pack_path.split('/')[:-1])
            changed_packs.append(pack_path)
    return changed_packs


def run(options):
    paths = PathManager(Path(__file__).absolute().parents[2])
    branch_name = paths.content_repo.active_branch.name
    changed_packs = []
    yml_pack_ids = []
    # TODO: Add Ddup
    changed_files = get_git_diff(branch_name, paths.content_repo)
    changed_packs.extend(get_changed_packs(changed_files))
    print(f'{changed_packs=}')
    yml_pack_ids.extend(get_yml_pack_ids(changed_packs))
    print(f'{yml_pack_ids=}')
    print('^^^^^^^^^^^^^^^^^^^^m^^^^^^^^^^')
    secrets_file = get_secrets_from_gsm(branch_name, options, yml_pack_ids)
    write_secrets_to_file(options, secrets_file)


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
