import json
import os
import sys

from Tests.scripts.utils.GoogleSecretManagerModule import GoogleSecreteManagerModule


def run(json_path_file):
    print(f'******************conf file location: {json_path_file}')
    secret_conf = GoogleSecreteManagerModule(get_secret_service_account_config())
    project_id = os.environ['GSM_PROJECT_ID']
    secrets = secret_conf.list_secrets(project_id, with_secret=True)
    secret_file = {
        "username": os.environ["DEMISTO_USERNAME"],
        "userPassword": os.environ["DEMISTO_PASSWORD"],
        "integrations": secrets
    }

    print(f'secrets from API: {secret_file[0:20]}')
    with open(json_path_file, 'w') as secrets_out_file:
        secrets_out_file.write(json.dumps(secret_file))
    print(json_path_file)


def get_secret_service_account_config() -> str:
    print('##################################')
    print('##################################')
    print('##################################')
    print(f'GSM_SERVICE_ACCOUNT: {os.environ["GSM_SERVICE_ACCOUNT"][0:5]}')
    with open(os.environ['GSM_SERVICE_ACCOUNT']) as f:
        creds = json.load(f)
        return json.dumps(creds)


if __name__ == '__main__':
    run(sys.argv[1])
