from google.cloud import secretmanager
import json5
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

    def delete_secret(self, project_id: str, secret_id: str) -> None:
        """
        Delete a secret from GSM
        :param project_id: The project ID for GCP
        :param secret_id: The name of the secret in GSM

        """

        name = self.client.secret_path(project_id, secret_id)
        self.client.delete_secret(request={"name": name})

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

    def update_secret(self, project_id: str, secret_id: str, labels=None) -> None:
        """

        :param project_id: The project ID for GCP
        :param secret_id: The name of the secret in GSM
        :param labels: A dict with the labels we want to add to th secret

        """
        if labels is None:
            labels = {}
        name = self.client.secret_path(project_id, secret_id)
        secret = {"name": name, "labels": labels}
        update_mask = {"paths": ["labels"]}
        self.client.update_secret(
            request={"secret": secret, "update_mask": update_mask}
        )

    def add_secret_version(self, project_id: str, secret_id: str, payload: dict) -> None:
        """
        Add a new secret version to the given secret with the provided payload.
        """

        parent = self.client.secret_path(project_id, secret_id)

        payload = payload.encode("UTF-8")

        self.client.add_secret_version(
            request={
                "parent": parent,
                "payload": {"data": payload},
            }
        )

    def list_secrets(self, project_id: str, name_filter=None, with_secrets: bool = False, branch_name='',
                     ignore_dev: bool = True, ignore_merged: bool = True) -> list:
        """
        Lists secrets from GSM
        :param project_id: the ID of the GCP project
        :param name_filter: a secret name to filter results by
        :param with_secrets: indicates if we want to bring the secret value(will need another API call per scret or just metadata)
        :param branch_name: filter results according to the label 'branch'
        :param ignore_dev: indicates whether we ignore secrets with the 'dev' label
        :param ignore_merged: indicates whether we ignore secrets with the 'merged' label
        :return: the secret as json5 object
        """
        if name_filter is None:
            name_filter = []
        secrets = []
        parent = f"projects/{project_id}"
        for secret in self.client.list_secrets(request={"parent": parent}):
            secret.name = str(secret.name).split('/')[-1]

            try:
                labels = dict(secret.labels)
            except Exception as e:
                labels = {}
                logging.error(f'Error the secret: {secret.name} has no labels, got the error: {e}')
            search_ids = [s for s in name_filter]
            logging.debug(f'Getting the secret: {secret.name}')
            if not labels.get('pack_id') or labels.get('ignore') or (ignore_dev and labels.get('dev')) or (
                ignore_merged and labels.get('merged')) or (not ignore_dev and not labels.get('dev')) or (
                branch_name and labels.get('branch', '') != branch_name) or (
                    search_ids and secret.name not in search_ids):
                continue
            if with_secrets:
                try:
                    secret_value = self.get_secret(project_id, secret.name)
                    secret_value['secret_name'] = secret.name
                    secret_value['labels'] = labels
                    secrets.append(secret_value)
                except Exception as e:
                    logging.error(f'Error getting the secret: {secret.name}, got the error: {e}')
            else:
                secret.labels = labels
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
            # client = secretmanager.SecretManagerServiceClient.from_service_account_json(
            #     service_account)  # type: ignore # noqa
            client = secretmanager.SecretManagerServiceClient()
            return client
        except Exception as e:
            logging.error(f'Could not create GSM client, error: {e}')
            raise
