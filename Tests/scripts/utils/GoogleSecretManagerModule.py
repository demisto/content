from google.cloud import secretmanager
import json5
from Tests.scripts.utils import logging_wrapper as logging


class GoogleSecreteManagerModule:
    def __init__(self, service_account_file: str):
        self.client = self.init_secret_manager_client(service_account_file)

    def get_secret(self, project_id: str, secret_id: str, version_id: str = 'latest') -> dict:
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = self.client.access_secret_version(request={"name": name})
        try:
            return json5.loads(response.payload.data.decode("UTF-8"))
        except Exception as e:
            logging.warning(
                f'Secret json is malformed for: {secret_id} version: {response.name.split("/")[-1]}, '
                f'got error: {e}')
            return {}

    def list_secrets(self, project_id: str, name_filter: list = [], with_secret=False, attr_validation=tuple()) -> list:
        secrets = []
        parent = f"projects/{project_id}"
        for secret in self.client.list_secrets(request={"parent": parent}):
            secret.name = str(secret.name).split('/')[-1]
            logging.debug(f'Getting the secret: {secret.name}')
            if secret.name in name_filter:
                continue
            if with_secret:
                try:
                    secret_value = self.get_secret(project_id, secret.name)
                    # We make sure that the keys we want in the dict are present
                    missing_attrs = [attr for attr in attr_validation if attr not in secret_value]
                    if missing_attrs:
                        missing_attrs_str = ','.join(missing_attrs)
                        logging.warning(
                            f'Error getting the secret: {secret.name}, it\'s missing the following required attributes: {missing_attrs_str}')  # noqa: E501
                        continue
                    secrets.append(secret_value)
                except Exception as e:
                    logging.error(f'Error getting the secret: {secret.name}, got the error: {e}')
            else:
                secrets.append(secret)

        return secrets

    @staticmethod
    def init_secret_manager_client(service_account: str) -> secretmanager.SecretManagerServiceClient:
        try:
            client = secretmanager.SecretManagerServiceClient.from_service_account_json(
                service_account)  # type: ignore # noqa
            return client
        except Exception as e:
            logging.error(f'Could not create GSM client, error: {e}')
            raise