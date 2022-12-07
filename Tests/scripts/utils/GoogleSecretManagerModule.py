import google
from google.cloud import secretmanager
import json
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

        try:
            for secret in self.client.list_secrets(request={"parent": parent}):
                secret.name = str(secret.name).split('/')[-1]
                print(f'_____________________{secret.name}_____________________')
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

        except Exception as e:
            print(e)
        return secrets

    @staticmethod
    def init_secret_manager_client(service_account: str) -> secretmanager.SecretManagerServiceClient:
        try:
            client = secretmanager.SecretManagerServiceClient.from_service_account_json(
                service_account)  # type: ignore # noqa
            return client
        except Exception as e:
            print('EEEEEERRRRRRRRRRRROOOOOOORRRRR')
            print(e)
