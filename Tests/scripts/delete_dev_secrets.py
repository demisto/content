import argparse
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils import logging_wrapper as logging
from datetime import datetime, timedelta


def get_secrets_to_delete(options: argparse.Namespace, secret_conf: GoogleSecreteManagerModule) -> list[str]:
    """
    Gets the ID of the dev secrets we need to delete
    :param options: the parsed parameter for the script
    :param secret_conf: the GSM object
    :return: a list of secret IDs to delete
    """

    secrets = secret_conf.list_secrets(options.gsm_project_id, with_secrets=False, ignore_dev=False)
    print(f'{secrets=}')
    secrets_to_delete = []
    ttl = int(options.secret_ttl)
    for secret in secrets:
        if 'merged' in secret.labels:
            timestamp = datetime.fromtimestamp(int(secret.labels.get('merged')))
            now = datetime.now()
            delta = timedelta(days=ttl)
            print(f'{ttl=}')
            print(f'{now=}')
            print(f'{delta=}')
            print(f'{timestamp=}')
            if now >= timestamp + delta:
                secret_conf.delete_secret(options.gsm_project_id, secret.name)
        else:
            continue
    print(f'{secrets_to_delete=}')
    return secrets_to_delete


def delete_secrets(gsm_project_id, secret_conf, secrets_to_delete):
    for secret in secrets_to_delete:
        secret_conf.delete_secret(gsm_project_id, secret)


def run(options: argparse.Namespace):
    secret_conf = GoogleSecreteManagerModule(options.service_account)
    secrets_to_delete = get_secrets_to_delete(options, secret_conf)
    # logging.debug(f'Deleting the secrets: {secrets_to_delete}')
    print(f'Deleting the secrets: {secrets_to_delete}')
    # delete_secrets(options.gsm_project_id, secret_conf, secrets_to_delete)


def options_handler(args=None) -> argparse.Namespace:
    """
    Parse the passed parameters for the script
    :param args: a list of arguments to add
    :return: the parsed arguments that were passed to the script
    """
    parser = argparse.ArgumentParser(description='Utility for Importing secrets from Google Secret Manager.')
    parser.add_argument('-gpid', '--gsm_project_id', help='The project id for the GSM.')
    parser.add_argument('-ttl', '--secret_ttl', help='The amount of time we want to keep a dev secret(in days).')
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
