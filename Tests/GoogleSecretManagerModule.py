import google
from google.cloud import secretmanager
import json5
from datetime import datetime
import os


class GoogleSecreteManagerModule:
    def __init__(self, service_account_file=None):
        self.client = self.init_secret_manager_client(service_account_file)

    def get_secret(self, project_id: str, secret_id: str, version_id: str = 'latest') -> dict:
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = self.client.access_secret_version(request={"name": name})
        return json5.loads(response.payload.data.decode("UTF-8"))

    def list_secrets(self, project_id: str, name_filter='', with_secret=False) -> list:
        secrets = []
        parent = f"projects/{project_id}"
        # response = self.client.access_secret_version(request={"name": name})
        # return json5.loads(response.payload.data.decode("UTF-8"))
        for secret in self.client.list_secrets(request={"parent": parent}):
            secret.name = str(secret.name).split('/')[-1]
            if name_filter in secret.name:
                if with_secret:
                    try:
                        secretfg = self.get_secret(project_id, secret.name)
                    except google.api_core.exceptions.NotFound:
                        secretfg = None
                        # TODO: add log telling the secrete couldn't be found
                secrets.append({'name': secret.name, 'secretValue': secretfg})
        return secrets

    @staticmethod
    def init_secret_manager_client(service_account: str) -> secretmanager.SecretManagerServiceClient:
        if not service_account:
            return secretmanager.SecretManagerServiceClient()
        try:
            service_account = service_account.replace('\r', '').replace('\n', '')
            cur_directory_path = os.getcwd()
            credentials_file_name = f'{datetime.now().strftime("%m-%d-%Y,%H:%M:%S:%f")}.json'
            credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)
            json_object = json5.loads(service_account)
            f = open(credentials_file_path, "w")
            f.write(json5.dumps(json_object))
            f.close()
            client = secretmanager.SecretManagerServiceClient.from_service_account_json(credentials_file_path)
            return client
        finally:
            os.remove(credentials_file_path)
