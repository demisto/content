import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Keeper Secrets Manager Integration for Cortex XSOAR (aka Demisto)

Manage Secrets and Protect Sensitive Data through Keeper Vault.

"""

from CommonServerUserPython import *  # noqa

import urllib3
import traceback
from typing import Any
from keeper_secrets_manager_core import SecretsManager
from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage


# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

APP_NAME = 'keeper-secrets-manager'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

metadata_collector = YMLMetadataCollector(integration_name="KeeperSecretsManager",
                                          description="Use the Keeper Secrets Manager integration to manage secrets and protect"
                                          " sensitive data through Keeper Vault.",
                                          detailed_description="<p>Keeper Secrets Manager API is available for administrators"
                                          " and developers to integrate Keeper Vault data into their applications."
                                          " This integration fetches credentials. For more information,"
                                          " see <a href=\"https://xsoar.pan.dev/docs/reference/articles/managing-credentials\">"
                                          "Managing Credentials</a>.</p>"
                                          " <p>This integration was integrated and tested with"
                                          " version 16.3.5 of Keeper Secrets Manager.</p>",
                                          display="Keeper Secrets Manager",
                                          category="Authentication",
                                          default_classifier=None,
                                          default_mapper_in=None,
                                          deprecated=None,
                                          docker_image="demisto/keeper-ksm:1.0.0.33394",
                                          fromversion="6.5.0",
                                          is_runonce=False,
                                          integration_subtype="python3",
                                          integration_type="python",
                                          is_feed=False,
                                          is_fetch=False,
                                          long_running=False,
                                          long_running_port=False,
                                          tests=["No tests"],
                                          conf=[ConfKey(name="credentials",
                                                        display="KSM Configuration",
                                                        additional_info="The KSM config to use for connection.",
                                                        required=True,
                                                        key_type=ParameterTypes.TEXT_AREA_ENCRYPTED),
                                                ConfKey(name="insecure",
                                                        display="Trust any certificate (not secure)",
                                                        additional_info="When 'trust any certificate' is selected,"
                                                        " the integration ignores TLS/SSL certificate validation errors."
                                                        " Use to test connection issues or connect to a server without a valid"
                                                        " certificate.",
                                                        required=False,
                                                        key_type=ParameterTypes.BOOLEAN),
                                                ConfKey(name="isFetchCredentials",
                                                        display="Fetches credentials",
                                                        additional_info="Fetches credentials from login records.",
                                                        default_value=False,
                                                        required=False,
                                                        key_type=ParameterTypes.BOOLEAN),
                                                ConfKey(name="concat_username_to_cred_name",
                                                        display="Concat username to credential object name",
                                                        additional_info="Use to make the credential object unique"
                                                        " in case of duplicate names in different folders/secrets.",
                                                        required=False,
                                                        key_type=ParameterTypes.BOOLEAN),
                                                ConfKey(name="credential_names",
                                                        display="A comma-separated list of credential names to fetch.",
                                                        additional_info="Partial names are not supported. If left empty,"
                                                        " all credentials will be fetched.",
                                                        required=False,
                                                        key_type=ParameterTypes.TEXT_AREA),
                                                # ConfKey(name="proxy",
                                                #         display="Use system proxy settings",
                                                #         required=False,
                                                #         key_type=ParameterTypes.BOOLEAN),
                                                ])

''' CLIENT CLASS '''


class Client:
    """Client class to interact with the service API
    """

    def __init__(self, credentials: str, insecure: bool):
        self.credentials = credentials
        self.verify_ssl_certs = False if insecure else True
        try:
            config = InMemoryKeyValueStorage(credentials)
        except Exception:
            demisto.debug("Failed to initialize KSM configuration. Invalid credentials.")
            raise ValueError("Failed to initialize KSM configuration. Invalid credentials.")
        try:
            self.secrets_manager = SecretsManager(
                config=config,
                verify_ssl_certs=self.verify_ssl_certs
            )
        except Exception as e:
            demisto.debug("Failed to initialize KSM Client. " + str(e))
            raise

    def ksm_get_field(self, notation: str) -> str:
        """Returns a simple python dict with the information provided
        in the input (notation).

        :type notation: ``str``
        :param notation: Keeper URI notation to select desired field

        :return: field value
        :rtype: ``dict``
        """

        result = self.secrets_manager.get_notation(notation)

        return result or ''

    def ksm_list_records(self) -> list[dict[str, str]]:
        result = []
        records = self.secrets_manager.get_secrets()
        if records:
            for r in records:
                result.append({'uid': r.uid,
                               'type': r.type,
                               'title': r.title})
        return result

    def ksm_find_records(self, title: str, partial_match: bool = True) -> list[dict[str, str]]:
        result = []
        title = title.lower()
        records = self.secrets_manager.get_secrets() or []
        for r in records:
            record_title: str = str(r.title).lower() if r.title else ''
            if record_title == title or (partial_match and title and record_title.__contains__(title)):
                result.append({'uid': r.uid,
                               'type': r.type,
                               'title': r.title})
        return result

    def ksm_fetch_credentials(self) -> list[dict[str, str]]:
        result = []
        records = self.secrets_manager.get_secrets()
        if records:
            for r in records:
                if r.type == "login":
                    result.append({'user': r.get_standard_field_value("login", True),
                                   'password': r.password,
                                   'name': r.title})
        return result

    def list_credentials(self) -> list[dict[str, str]]:
        result = []
        records = self.secrets_manager.get_secrets()
        if records:
            for r in records:
                if r.type == 'login':
                    result.append({'name': r.title,
                                   'user': r.get_standard_field_value('login', True),
                                   'uid': r.uid})
        return result

    def ksm_list_files(self, record_uids: list[str]) -> list[dict[str, str]]:
        result = []
        records = self.secrets_manager.get_secrets(record_uids) or []
        for r in records:
            files = r.files or []
            for f in files:
                result.append({'record_uid': r.uid,
                               'file_uid': f.f.get('fileUid', ''),
                               'file_name': f.name or f.title,
                               'file_size': f.size})
        return result

    def ksm_find_files(self, file_name: str, partial_match: bool = True) -> list[dict[str, str]]:
        result = []
        file_name = file_name.lower()
        records = self.secrets_manager.get_secrets() or []
        for r in records:
            files = r.files or []
            for f in files:
                fname: str = str(f.name).lower() if f.name else ''
                if fname == file_name or (partial_match and file_name and fname.__contains__(file_name)):
                    result.append({'record_uid': r.uid,
                                   'file_uid': f.f.get('fileUid', ''),
                                   'file_name': f.name,
                                   'file_size': f.size})
        return result

    def ksm_get_file(self, record_uid: str, file_uid: str) -> list[tuple[str, bytes]]:
        result = []
        record_filter = [record_uid] if record_uid else []
        records = self.secrets_manager.get_secrets(record_filter) or []
        for r in records:
            files = r.files or []
            for f in files:
                if file_uid == f.f.get('fileUid', ''):
                    result.append((f.name or f.title, f.get_file_data()))
        return result


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def fetch_credentials(client: Client):
    params: dict = demisto.params()
    args: dict = demisto.args()
    credentials_str = params.get('credential_names')
    credentials_names_from_configuration = argToList(credentials_str)
    credentials_name = args.get('identifier')
    concat_username_to_cred_name = argToBoolean(params.get('concat_username_to_cred_name') or 'false')
    demisto.debug('Name of credential used: ', credentials_name)
    demisto.debug('Name of credentials used: ', credentials_names_from_configuration)
    credentials = []

    try:
        credentials = client.ksm_fetch_credentials()
    except Exception as e:
        demisto.debug(f"Could not fetch credentials. Error: {e}")
        credentials = []

    if concat_username_to_cred_name:
        for i in range(len(credentials)):
            credentials[i]['name'] = '{0}_{1}'.format(credentials[i].get('name', ''), credentials[i].get('user', ''))

    if credentials_name:
        credentials = list(filter(lambda c: c.get('name', '') == credentials_name, credentials))
        if len(credentials) > 1:
            credentials = credentials[:1]
        # Important - always return a list containing up to one set of credentials.
        # If no list or a list with more than one element will be returned,
        # the credentials tab will fail to load.
    elif credentials_names_from_configuration:
        credentials = list(filter(lambda c: c.get('name', '') in credentials_names_from_configuration, credentials))

    demisto.credentials(credentials)


LIST_CREDENTIALS_OUTPUTS = [OutputArgument(name='uid', output_type=str, description='Record UID.'),
                            OutputArgument(name='title', output_type=str, description='Record Title.'),
                            OutputArgument(name='name', output_type=str, description='Username.')]


@metadata_collector.command(command_name="ksm-list-credentials",
                            outputs_prefix="KeeperSecretsManager.Creds",
                            outputs_list=LIST_CREDENTIALS_OUTPUTS, restore=True,
                            description="Use this command to list all credentials in your Keeper Vault"
                                        " that are shared to the KSM application.")
def list_credentials_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """Lists all credentials available to the KSM application.
    :param client: the client object with the given params
    :return: the credentials info without the explicit password
    """
    demisto.debug('list_credentials_command - command_name: ' + str(kwargs.get('command_name', '')))
    creds_list = client.list_credentials()
    markdown = '### Credentials\n'
    markdown += tableToMarkdown('Credential Details', creds_list)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='KeeperSecretsManager.Creds',
        outputs_key_field='name',
        outputs=creds_list,
        raw_response=creds_list
    )
    return results


@metadata_collector.command(command_name="ksm-get-field",
                            outputs_prefix="KeeperSecretsManager.Field",
                            inputs_list=[InputArgument(name="notation",
                                                       required=True,
                                                       description="Keeper KSM notation URI.")],
                            description="Use this command to get field value from Keeper record.")
def get_field_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """Get field command - returns field value.

    Args:
        client (Client): KeeperSecretsManager client to use.
        notation (str):  The Keeper notation URI used to find the field in the record. required.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the field value.

    Context Outputs:
        field (str): Extracted field value.
    """

    demisto.debug('get_field_command - command_name: ' + str(kwargs.get('command_name', '')))
    notation = args.get('notation', None)
    if not notation:
        raise ValueError('notation URI not specified')

    result = client.ksm_get_field(notation)
    readable_output = f'## {result}'

    results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='KeeperSecretsManager.Field',
        outputs_key_field='',
        outputs=result
    )
    return results


GET_RECORDS_OUTPUTS = [OutputArgument(name='uid', output_type=str, description='Record UID.'),
                       OutputArgument(name='type', output_type=str, description='Record Type.'),
                       OutputArgument(name='title', output_type=str, description='Record Title.')]


@metadata_collector.command(command_name="ksm-list-records",
                            outputs_prefix="KeeperSecretsManager.Records",
                            outputs_list=GET_RECORDS_OUTPUTS, restore=True,
                            description="Use this command to list all records from your Keeper Vault"
                                        " that are shared to the application.")
def list_records_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """List records command - returns list of record info.

    Args:
        client (Client): KeeperSecretsManager client to use.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records info.

    :rtype: ``CommandResults``
    """

    demisto.debug('list_records_command - command_name: ' + str(kwargs.get('command_name', '')))
    records = client.ksm_list_records()
    markdown = '### Records\n'
    markdown += tableToMarkdown('Record Details', records)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='KeeperSecretsManager.Records',
        outputs_key_field='uid',
        outputs=records
    )
    return results


@metadata_collector.command(command_name="ksm-find-records",
                            outputs_prefix="KeeperSecretsManager.Records",
                            outputs_list=GET_RECORDS_OUTPUTS, restore=True,
                            inputs_list=[InputArgument(name="title",
                                                       required=True,
                                                       description="Title text to search for."),
                                         InputArgument(name="partial_match",
                                                       required=False,
                                                       default=False,
                                                       description="Search for partial title match.")],
                            description="Search for records by full or partial title match.")
def find_records_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """Find records command - returns list of record info.

    Args:
        client (Client): KeeperSecretsManager client to use.
        title (str): Title text to search for.
        partial_match (bool): Flag for partial title match.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records info.

    :rtype: ``CommandResults``
    """

    demisto.debug('find_records_command - command_name: ' + str(kwargs.get('command_name', '')))

    title = args.get('title') or ''
    partial_match = args.get('partial_match', None)
    partial_match = True if partial_match else False
    demisto.debug(f'Find records with title={title} and partial_match={partial_match}')

    records = client.ksm_find_records(title, partial_match)
    markdown = '### Records\n'
    markdown += tableToMarkdown('Record Details', records)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='KeeperSecretsManager.Records',
        outputs_key_field='uid',
        outputs=records
    )
    return results


GET_FILES_OUTPUTS = [OutputArgument(name='record_uid', output_type=str, description='Record UID.'),
                     OutputArgument(name='file_uid', output_type=str, description='File UID.'),
                     OutputArgument(name='file_name', output_type=str, description='File Name.'),
                     OutputArgument(name='file_size', output_type=str, description='File Size.')]


@metadata_collector.command(command_name="ksm-list-files",
                            outputs_prefix="KeeperSecretsManager.Files",
                            outputs_list=GET_FILES_OUTPUTS, restore=True,
                            inputs_list=[InputArgument(name="record_uids",
                                                       required=False,
                                                       default="",
                                                       description="A comma-separated list of record UIDs to search."
                                                       " If left empty all records with file attachments will be listed.")],
                            description="Use this command to list all records that have file attachments.")
def list_files_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """List files command - returns list of record and file info.

    Args:
        client (Client): KeeperSecretsManager client to use.
        record_uids (str):  The CSV list of record UIDs to search for files.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records and files info.

    :rtype: ``CommandResults``
    """

    demisto.debug('list_files_command - command_name: ' + str(kwargs.get('command_name', '')))
    record_uids_str = args.get('record_uids') or ''
    record_uids = argToList(record_uids_str)
    demisto.debug('List files for record UIDs: ', record_uids_str)

    records = client.ksm_list_files(record_uids)
    markdown = '### Records with attachments\n'
    markdown += tableToMarkdown('Record Details', records)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='KeeperSecretsManager.Files',
        outputs_key_field='file_uid',
        outputs=records
    )
    return results


@metadata_collector.command(command_name="ksm-find-files",
                            outputs_prefix="KeeperSecretsManager.Files",
                            outputs_list=GET_FILES_OUTPUTS, restore=True,
                            inputs_list=[InputArgument(name="file_name",
                                                       required=True,
                                                       description="File name text to search for."),
                                         InputArgument(name="partial_match",
                                                       required=False,
                                                       default=False,
                                                       description="Search for partial file name match.")],
                            description="Search for records by full or partial file name match.")
def find_files_command(client: Client, args: dict[str, Any], **kwargs) -> CommandResults:
    """Find files command - returns list of record and file info.

    Args:
        client (Client): KeeperSecretsManager client to use.
        file_name (str): The file name text to search for.
        partial_match (bool): Flag for partial file name match.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records and files info.

    :rtype: ``CommandResults``
    """

    demisto.debug('find_files_command - command_name: ' + str(kwargs.get('command_name', '')))

    file_name = args.get('file_name') or ''
    partial_match = args.get('partial_match', None)
    partial_match = True if partial_match else False
    demisto.debug(f'Find records with file_name={file_name} and partial_match={partial_match}')

    records = client.ksm_find_files(file_name, partial_match)
    markdown = '### Records with attachments\n'
    markdown += tableToMarkdown('Record Details', records)

    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='KeeperSecretsManager.Files',
        outputs_key_field='file_uid',
        outputs=records
    )
    return results


@metadata_collector.command(command_name="ksm-get-file",
                            inputs_list=[InputArgument(name="file_uid",
                                                       required=True,
                                                       description="File UID to search for."),
                                         InputArgument(name="record_uid",
                                                       required=False,
                                                       default="",
                                                       description="Record UID to search for files."
                                                       " Search all records if empty.")],
                            description="Use this command to fetch the file attachment as a File.")
def get_file_command(client: Client, args: dict[str, Any], **kwargs) -> dict | None:
    """Get file command - returns the file attachment as a File.

    Args:
        client (Client): KeeperSecretsManager client to use.
        file_uid (str):  The file UID to search for. required.
        record_uid (str):  The record UID to search for files. Searches all records if record UID is empty.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records and files info.

    :rtype: ``CommandResults``
    """

    demisto.debug('get_file_command - command_name: ' + str(kwargs.get('command_name', '')))
    record_uid = args.get('record_uid') or ''
    file_uid = args.get('file_uid', None)
    if not file_uid:
        raise ValueError('file_uid not specified')
    demisto.debug(f'Get file UID: "{file_uid}" from record UID:"{record_uid}"')

    files = client.ksm_get_file(record_uid, file_uid)
    if files:
        file_result = fileResult(filename=files[0][0], data=files[0][1])
        # file_result["Contents"] = files[0][1]
        return file_result
    return None


@metadata_collector.command(command_name="ksm-get-infofile",
                            inputs_list=[InputArgument(name="file_uid",
                                                       required=True,
                                                       description="File UID to search for."),
                                         InputArgument(name="record_uid",
                                                       required=False,
                                                       default="",
                                                       description="Record UID to search for files."
                                                       " Search all records if empty.")],
                            description="Use this command to fetch the file attachment as an Info File.")
def get_infofile_command(client: Client, args: dict[str, Any], **kwargs) -> dict | None:
    """Get info file command - returns the file attachment as an Info File.

    Args:
        client (Client): KeeperSecretsManager client to use.
        file_uid (str):  The file UID to search for. required.
        record_uid (str):  The record UID to search for files. Searches all records if record UID is empty.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains the list with records and files info.

    :rtype: ``CommandResults``
    """

    demisto.debug('get_infofile_command - command_name: ' + str(kwargs.get('command_name', '')))
    record_uid = args.get('record_uid') or ''
    file_uid = args.get('file_uid', None)
    if not file_uid:
        raise ValueError('file_uid not specified')
    demisto.debug(f'Get file UID: "{file_uid}" from record UID:"{record_uid}"')

    files = client.ksm_get_file(record_uid, file_uid)
    if files:
        file_result = fileResult(filename=files[0][0], data=files[0][1], file_type=EntryType.ENTRY_INFO_FILE)
        # file_result["Contents"] = files[0][1]
        return file_result
    return None


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # Tests connectivity and authentication to KSM service.
        # This validates all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        client.secrets_manager.get_secrets(["AAAAAAAAAAAAAAAAAAAAA"])
        message = 'ok'
    except Exception as e:
        message = str(e)
    return message


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    credentials = demisto.params().get('credentials')
    insecure = demisto.params().get('insecure', False)
    command = demisto.command()

    try:
        demisto.debug(f'Command being called in KSM is: {command}')
        client = Client(credentials=credentials, insecure=insecure)

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-credentials':
            fetch_credentials(client)
        elif command == 'ksm-list-credentials':
            return_results(list_credentials_command(client, demisto.args()))
        elif command == 'ksm-list-records':
            return_results(list_records_command(client, demisto.args()))
        elif command == 'ksm-get-field':
            return_results(get_field_command(client, demisto.args()))
        elif command == 'ksm-list-files':
            return_results(list_files_command(client, demisto.args()))
        elif command == 'ksm-get-file':
            return_results(get_file_command(client, demisto.args()))
        elif command == 'ksm-get-infofile':
            return_results(get_infofile_command(client, demisto.args()))
        elif command == 'ksm-find-records':
            return_results(find_records_command(client, demisto.args()))
        elif command == 'ksm-find-files':
            return_results(find_files_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
