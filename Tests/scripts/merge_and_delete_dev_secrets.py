import argparse
import json5
import requests
from isort.profiles import google
from Tests.scripts.add_secrets_file_to_build import FilterLabels, FilterOperators
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging

CONTENT_REPO_URL = 'https://api.github.com/repos/demisto/content'
# The max limit for the PRs API is 100, we use this variable to get more if it's 5 for example will get the last 500 PRs
LATEST_MERGED_PR = 3


def get_latest_merged() -> list[dict]:
    """
    Get the 500 latest merged PR's
    """
    latest_prs = []
    url = f'{CONTENT_REPO_URL}/pulls'

    for i in range(1, LATEST_MERGED_PR + 1):
        params = {'sort': 'created', 'direction': 'desc', 'per_page': 100, 'page': i, 'state': 'closed'}
        try:
            response = requests.request("GET", url, params=params, verify=False)
            response.raise_for_status()
        except Exception as exc:
            raise Exception(f'Could not get merged PRs from Git API, error: {exc}')
        latest_prs.extend(response.json())
    return latest_prs


def merge_dev_secrets(dev_secrets_to_merge, gsm_project_id: str, secret_conf: GoogleSecreteManagerModule):
    merged_dev_secrets_names = []
    for dev_secret in dev_secrets_to_merge:
        dev_secret_name = dev_secret.get('secret_name')
        merged_dev_secrets_names.append(dev_secret_name)
        main_secret_name = dev_secret_name.split('__')[1]
        try:
            # Checks if the main secret exist in our store
            secret_conf.get_secret(gsm_project_id, main_secret_name)

        except google.api_core.exceptions.NotFound:
            # Adding new secret to main store
            secret_conf.create_secret(gsm_project_id, main_secret_name)
            logging.debug(f'Adding new secret: {main_secret_name}')

        # Remove build properties from secret
        del dev_secret['secret_name']
        del dev_secret['labels']
        # Add a new version to master secret
        # secret_conf.add_secret_version(gsm_project_id, main_secret_name, json5.dumps(dev_secret, quote_keys=True))
        logging.debug(f'dev secret {dev_secret_name} was merged to {main_secret_name} on main store')
        print(f'dev secret {dev_secret_name} was merged to {main_secret_name} on main store')
    return merged_dev_secrets_names


def get_dev_secrets_to_merge(latest_pr_merges, secrets):
    secrets_to_update = []
    merged_branches = [p.get('head').get('ref') for p in latest_pr_merges]
    for secret in secrets:
        if secret.get('labels', {}).get('branch') in merged_branches:
            secrets_to_update.append(secret)
    return secrets_to_update


def delete_dev_secrets(secrets_to_delete: list[str], secret_conf: GoogleSecreteManagerModule, project_id: str):
    for secret_name in secrets_to_delete:
        # secret_conf.delete_secret(project_id, secret_name)
        print(f'would delete {secret_name}')

def run(options: argparse.Namespace):
    secret_conf = GoogleSecreteManagerModule(options.service_account)
    latest_pr_merges = get_latest_merged()
    secrets_filter = {FilterLabels.PACK_ID.value: FilterOperators.NOT_NONE.value,
                      FilterLabels.IGNORE_SECRET.value: FilterOperators.NONE.value,
                      FilterLabels.SECRET_MERGE_TIME.value: FilterOperators.NONE.value,
                      FilterLabels.IS_DEV_BRANCH.value: FilterOperators.NOT_NONE.value}
    secrets = secret_conf.list_secrets(options.gsm_project_id, secrets_filter, with_secrets=True)
    dev_secrets_to_merge = get_dev_secrets_to_merge(latest_pr_merges, secrets)
    secrets_to_delete = merge_dev_secrets(dev_secrets_to_merge, options.gsm_project_id, secret_conf)
    delete_dev_secrets(secrets_to_delete, secret_conf, options.gsm_project_id)


def options_handler(args=None) -> argparse.Namespace:
    """
    Parse the passed parameters for the script
    :param args: a list of arguments to add
    :return: the parsed arguments that were passed to the script
    """
    parser = argparse.ArgumentParser(description='Utility for Importing secrets from Google Secret Manager.')
    parser.add_argument('-gpid', '--gsm_project_id', help='The project id for the GSM.')
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
