import google
from google.cloud import secretmanager
import json
from datetime import datetime
import os
from Tests.scripts.utils import logging_wrapper as logging


class GoogleSecreteManagerModule:
    def __init__(self, service_account_file: str):
        self.client = self.init_secret_manager_client(service_account_file)

    def get_secret(self, project_id: str, secret_id: str, version_id: str = 'latest') -> dict:
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = self.client.access_secret_version(request={"name": name})
        return json.loads(response.payload.data.decode("UTF-8"))

    def list_secrets(self, project_id: str, name_filter: str = '', with_secret=False) -> list:
        secrets = []
        parent = f"projects/{project_id}"
        print(f'parent: {parent}')
        logging.info(f'parent: {parent}')
        try:
            a = self.client.list_secrets(request={"parent": parent})
            print(a)
            logging.info(f'secrets: {a}')
        except Exception as e:
            print(e)
            logging.info(f'error: {e}')

        for secret in self.client.list_secrets(request={"parent": parent}):
            secret.name = str(secret.name).split('/')[-1]
            if name_filter and name_filter not in secret.name:
                continue
            if with_secret:
                try:
                    secret_value = self.get_secret(project_id, secret.name)
                    secrets.append(secret_value)
                except google.api_core.exceptions.NotFound:
                    logging.error(f'Could not find the secret: {secret.name}')
            else:
                secrets.append(secret)

        return secrets

    @staticmethod
    def init_secret_manager_client(service_account: str) -> secretmanager.SecretManagerServiceClient:
        try:
            service_account = service_account.replace('\r', '').replace('\n', '')
            cur_directory_path = os.getcwd()
            credentials_file_name = f'{datetime.now().strftime("%m-%d-%Y,%H:%M:%S:%f")}.json'
            credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)
            json_object = json.loads(service_account)
            with open(credentials_file_path, 'w') as f:
                f.write(json.dumps(json_object))
            client = secretmanager.SecretManagerServiceClient.from_service_account_json(credentials_file_path)# type: ignore # noqa
            return client
        finally:
            try:
                os.remove(credentials_file_path)
            except:
                pass