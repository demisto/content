import argparse
import json5
import requests
from isort.profiles import google

from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging
from datetime import datetime

CONTENT_REPO_URL = 'https://api.github.com/repos/demisto/content'


def get_latest_merged() -> list[dict]:
    url = f'{CONTENT_REPO_URL}/pulls'
    params = {'sort': 'created', 'direction': 'desc', 'per_page': 100, 'state': 'closed'}

    try:
        response = requests.request("GET", url, params=params, verify=False)
    except Exception as exc:
        raise Exception(f'Could not get merged PRs from Git API, error: {exc}')
    return response.json()


def run(options: argparse.Namespace):
    secret_conf = GoogleSecreteManagerModule('options.service_account')
    # secret_conf = GoogleSecreteManagerModule(options.service_account)
    latest_pr_merges = get_latest_merged()
    secrets = secret_conf.list_secrets(options.gsm_project_id, with_secrets=True, ignore_dev=False, ignore_merged=True)
    dev_secrets_to_merge = get_dev_secrets_to_merge(latest_pr_merges, secrets)
    for dev_secret_name in dev_secrets_to_merge:

        # Get dev secret value(we use list to get more info for the secret)
        dev_secret_value = secret_conf.list_secrets(options.gsm_project_id, with_secrets=True, name_filter=[dev_secret_name],
                                                    ignore_dev=False)
        labels = dev_secret_value[0].get('labels', {})
        labels['merged'] = str(int(datetime.timestamp(datetime.now())))
        main_secret_name = dev_secret_name.split('__')[1]
        try:
            # Checks if the main secret exist in our store
            secret_conf.get_secret(options.gsm_project_id, main_secret_name)

        except google.api_core.exceptions.NotFound:
            # Adding new main secret to store
            secret_conf.create_secret(options.gsm_project_id, main_secret_name)
            logging.debug(f'Adding new secret: {main_secret_name}')

        # Add a new version to master secret
        secret_conf.add_secret_version(options.gsm_project_id, main_secret_name, json5.dumps(dev_secret_value, quote_keys=True))
        # Add the merged label to dev secret
        secret_conf.update_secret(options.gsm_project_id, dev_secret_name, labels)
        logging.debug(f'dev secret {dev_secret_name} was merged to main store')


def get_dev_secrets_to_merge(latest_pr_merges, secrets):
    secrets_to_update = []
    for secret in secrets:
        if secret.get('labels', {}).get('force') or secret.get('labels', {}).get('branch') in [p.get('head').get('ref') for p in
                                                                                               latest_pr_merges]:
            secrets_to_update.append(secret.get('secret_name'))
    return secrets_to_update


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
