import argparse
import json5
from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging


def run(options):
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
    install_logging('add_secrets_file_to_build.log', logger=logging)
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