import json5

from google.cloud import secretmanager
from Tests.scripts.utils import logging_wrapper as logging

SPECIAL_CHARS = [' ', '(', '(', ')', '.', '']


class GoogleSecreteManagerModule:

    def __init__(self, service_account_file: str):
        self.client = self.init_secret_manager_client(service_account_file)

    @staticmethod
    def convert_to_gsm_format(name: str) -> str:
        """
        Convert a string to comply with GSM labels formatting(A-Z, a-z, 0-9, -, _)
        param name: the name to transform
        return: the name after it's been transformed to a GSM supported format
        """

        for char in SPECIAL_CHARS:
            name = name.replace(char, '')
        return name

    def get_secret(self, project_id: str, secret_id: str, version_id: str = 'latest') -> dict:
        """
        Gets a secret from GSM
        :param project_id: the ID of the GCP project
        :param secret_id: the ID of the secret we want to get
        :param version_id: the version of the secret we want to get
        :return: the secret as json5 object
        """
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = self.client.access_secret_version(request={"name": name})
        try:
            return json5.loads(response.payload.data.decode("UTF-8"))
        except Exception as e:
            logging.error(
                f'Secret json is malformed for: {secret_id} version: {response.name.split("/")[-1]}, got error: {e}')
            return {}

    def list_secrets(self, project_id: str, labels_filter: dict, name_filter=None, with_secrets: bool = False) -> list:
        """
        Lists secrets from GSM
        :param project_id: the ID of the GCP project
        :param name_filter: a secret name to filter results by
        :param with_secrets: indicates if we want to bring the secret value(will need another API call per scret or just metadata)
        :param labels_filter: indicates how we want to filer secrets according to labels
        :return: the secret as json5 object
        """
        if name_filter is None:
            name_filter = []
        secrets = []
        parent = f"projects/{project_id}"
        for secret in self.client.list_secrets(request={"parent": parent}):
            secret.name = str(secret.name).split('/')[-1]
            labels = {}
            try:
                labels = dict(secret.labels)
            except Exception as e:
                logging.error(f'Error the secret {secret.name} has no labels, got the error: {e}')
            secret_pack_id = labels.get('pack_id')
            logging.debug(f'Getting the secret: {secret.name}')
            search_ids = [self.convert_to_gsm_format(s.lower()) for s in name_filter]
            # Check if the secret comply to the function filter params
            filter = [eval(f'{labels}.get("{k}"){v}') for k, v in labels_filter.items()]
            if not all(filter) or (search_ids and secret_pack_id not in search_ids):
                continue
            if with_secrets:
                try:
                    secret_value = self.get_secret(project_id, secret.name)
                    secret_value['secret_name'] = secret.name
                    secrets.append(secret_value)
                except Exception as e:
                    logging.error(f'Error getting the secret: {secret.name}, got the error: {e}')
            else:
                secrets.append(secret)

        return secrets

    @staticmethod
    def init_secret_manager_client(service_account: str) -> secretmanager.SecretManagerServiceClient:
        """
        Creates GSM object using a service account
        :param service_account: the service account json as a string
        :return: the GSM object
        """
        try:
            client = secretmanager.SecretManagerServiceClient.from_service_account_json(
                service_account)  # type: ignore # noqa
            return client
        except Exception as e:
            logging.error(f'Could not create GSM client, error: {e}')
            raise
