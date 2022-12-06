import argparse
import json

from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule


def run(options):
    json_path_file = options.service_account
    print(f'******************conf file location: {json_path_file}')
    print(options.service_account)
    print(options.user)
    print(options.password)
    secret_conf = GoogleSecreteManagerModule(get_secret_service_account_config(options.service_account))
    project_id = options.gsm_project_id
    secrets = secret_conf.list_secrets(project_id, with_secret=True)
    secret_file = {
        "username": options.user,
        "userPassword": options.password,
        "integrations": secrets
    }

    print(f'secrets from API: {secret_file[0:10]}')
    print(f'json_path_file: {json_path_file}')
    with open(json_path_file, 'w') as secrets_out_file:
        secrets_out_file.write(json.dumps(secret_file))
    print(json_path_file)


def options_handler(args=None):
    parser = argparse.ArgumentParser(description='Utility for Importing secrets from Google Secret Manager.')
    parser.add_argument('-pid', '--gsm_project_id', help='The project id for the GSM.')
    parser.add_argument('-u', '--user', help='Path to secret xsiam server metadata file.')
    parser.add_argument('-p', '--password', help='Path to file with XSIAM Servers api keys.')
    # disable-secrets-detection-start
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    options = parser.parse_args(args)

    return options


def get_secret_service_account_config(json_path_file: str) -> str:
    print('##################################')
    print('##################################')
    print('##################################')
    print(f'GSM_SERVICE_ACCOUNT: {json_path_file[0:5]}')
    with open(json_path_file) as f:
        creds = json.load(f)
        return json.dumps(creds)


if __name__ == '__main__':
    options = options_handler()
    run(options)
