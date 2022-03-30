import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import hashlib
import time
from datetime import datetime

import dateparser
import requests
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%d/%m/%Y, %H:%M:%S'


class Client(BaseClient):
    """
    Trustwave API Client
    """

    def __init__(self, host: str, config_port: str, api_port: str,
                 username: str, password: str, proxy: bool,
                 verify: bool):
        """initializing a client instance with authentication header

        Args:
            host (str): The host, should be an IP or localhost
            config_port (str): Trustwave config port, used for getting the token
            api_port (str): Trustwave API port
            username (str): The username for the Trustwave console
            password (str): The password for the Trustwave console
            proxy (bool): Proxy settings
            verify (bool): Verify settings
        """
        base_url = f'https://{host}:{api_port}/seg/api'
        token = Client.retrieve_token(
            host, config_port, username, password, verify)
        headers = {'Authorization': f'Bearer {token}'}
        super().__init__(base_url, verify, proxy, headers=headers)

    @staticmethod
    def retrieve_token(host: str, config_port: str, username: str,
                       password: str, verify: bool) -> str:
        """Retrieving the token from the integration context or from the API

        Args:
            host (str): The host, should be an IP or localhost
            config_port (str): Trustwave config port, used for getting the token
            username (str): The username for the Trustwave console
            password (str): The password for the Trustwave console
            verify (bool): Verify settings

        Raises:
            ValueError: Problem with connection

        Returns:
            str: The token for the session
        """
        integration_context = get_integration_context()
        now = int(time.time())
        if integration_context.get('token') and integration_context.get('expires_in'):
            if now < integration_context['expires_in']:
                return integration_context['token']

        try:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            response = requests.post(url=f'https://{host}:{config_port}/token',
                                     verify=verify,
                                     data={
                                         'grant_type': 'password',
                                         'username': username,
                                         'password': hashed_password
                                     }).json()
            integration_context = {
                'token': response.get('access_token'),
                'expires_in': now + int(response.get('expires_in'))
            }
            set_integration_context(integration_context)
            return response.get('access_token')
        except Exception as exception:
            raise ValueError(
                'Check the ports and Host or IP Address.') from exception

    def get_version(self) -> dict:
        """Retrieve Trustwave version information

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/version')

    def get_statistics(self, start_time: int, end_time: int) -> dict:
        """Retrieve Statistics from Trustwave console

        Args:
            start_time (int): Start time for the statistics.
            end_time (int): End time for the statistics.

        Returns:
            dict: Response JSON
        """
        params = {
            'fromtime': start_time,
            'totime': end_time,
        }
        return self._http_request(method='GET',
                                  url_suffix='/console/array/stats',
                                  params=params)

    def get_classifications(self) -> dict:
        """List information about the classification in the console

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/quarantine/classifications')

    def list_automatic_config_backups(self) -> dict:
        """Retrieve automatic config backup list

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/services/config/autobackups')

    def run_automatic_config_backups(self, timeout: int = 30, include_dkim: bool = False,
                                     dkim_password: str = None) -> dict:
        """Run an automatic config backup on Trustwave console.

        Args:
            timeout (int): The timeout of the request.
            include_dkim (bool): Should the backup be protected by a DKIM
            dkim_password (str, optional): The DKIM password, only if include_skim is True.

        Returns:
            dict: Response JSON
        """
        data = {
            'includeDkim': include_dkim,
            'dkimPassword': dkim_password
        }
        return self._http_request(method='PUT',
                                  url_suffix='/services/config/autobackups/backup',
                                  data=data,
                                  timeout=timeout)

    def restore_automatic_config_backups(self, name: str, timeout: int = 30, include_dkim: bool = False,
                                         dkim_password: str = None) -> dict:
        """Restore an automatic config backup based on params

        Args:
            name (str): The name of the backup to restore
            timeout (int): The timeout of the request.
            include_dkim (bool): If the backup is protected by DKIM
            dkim_password (str, optional): The DKIM, only if include_dkim is True.

        Returns:
            dict: Response JSON
        """
        data = {
            'name': name,
            'includeDkim': include_dkim,
            'dkimPassword': dkim_password
        }
        return self._http_request(method='PUT',
                                  url_suffix='/services/config/autobackups/restore',
                                  json_data=data,
                                  timeout=timeout)

    def list_alerts(self, active_only: bool) -> dict:
        """Retrieve a list of alerts from Trustwave

        Args:
            active_only (bool): Retrieve only active alerts

        Returns:
            dict: Response JSON
        """
        params = {
            'activeonly': active_only
        }
        return self._http_request(method='GET',
                                  url_suffix='/console/alerts',
                                  params=params)

    def get_server(self, server_id: str) -> dict:
        """Retrieve specific server information

        Args:
            server_id (str): The ID of the server to retrieve its information

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/services/servers/{server_id}')

    def list_servers(self) -> dict:
        """Retrieve the list of servers

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/services/servers/')

    def list_quarantine_folders(self) -> dict:
        """List quarantine folders information

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/quarantine/folders/')

    def list_folders_with_day_info(self) -> dict:
        """List quarantine folder with day's information

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix='/quarantine/folderswithdayinfo/')

    def list_day_info_from_folder(self, folder_id: str) -> dict:
        """Retrieve only the day information from a quarantine folder

        Args:
            folder_id (str): The ID of the folder

        Returns:
            dict: Response JSON
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/quarantine/folders/{folder_id}/dayinfo')

    def find_message(self, max_rows: int, start_time: int, end_time: int,
                     folder_id: str = None, message_name: str = None,
                     classification: str = None, from_user: str = None,
                     to_user: str = None, to_domain: str = None,
                     min_size: str = None, max_size: str = None, subject: str = None,
                     search_history: str = None, forwards: str = None,
                     block_number: str = None, search_blank_subject: str = None) -> dict:
        """Find a message or messages by params

        Args:
            max_rows (int): The maximum messages to return from the search
            start_time (int): Start time for the search.
            end_time (int): End time for the search.
            folder_id (str, optional): The ID of the folder to search in.
            message_name (str, optional): The name of the message to search for.
            classification (str, optional): The classification of the message to find.
            from_user (str, optional): Find messages from a specific user.
            to_user (str, optional): Find message that were send to a specific user.
            to_domain (str, optional): Find messages that were sent to specific domain.
            min_size (str, optional): Minimum size of the message.
            max_size (str, optional): Maximum size of the message.
            subject (str, optional): The subject of the message to search.
            search_history (str, optional): Should the search include search history.
            forwards (str, optional): Should the search include forwarded messages.
            block_number (str, optional): The block number to search in.
            search_blank_subject (str, optional): Should the search include blank subject messages.
        Returns:
            dict: Response JSON
        """
        params = {
            'maxRows': max_rows
        }
        data = {
            "startTime": start_time,
            "endTime": end_time,
            "folderId": folder_id,
            "messageName": message_name,
            "classification": classification,
            "fromUser": from_user,
            "toUser": to_user,
            "toDomain": to_domain,
            "minSize": min_size,
            "maxSize": max_size,
            "subject": subject,
            "searchHistory": search_history,
            "forwards": forwards,
            "blockNumber": block_number,
            "searchBlankSubject": search_blank_subject,
        }
        return self._http_request(method='POST',
                                  url_suffix='/quarantine/findmessage/',
                                  json_data=remove_empty_elements(data),
                                  params=params)

    def forward_spam(self, block_number: int, edition: str, folder_id: int,
                     message_name: str, recipient: str, server_id: int, time_logged: int,
                     is_spam: bool,
                     spam_report_message: str) -> requests.Response:
        """Forward a message to Trustwave Spiderlabs to confirm a message is a spam

        Args:
            block_number (int): Block number of the message to forward from find message command
            edition (int): Edition of the message to forward from find message command
            folder_id (int): Folder ID of the message to forward from find message command
            message_name (str): Message name of the message to forward from find message command
            recipient (str): Recipeient of the message to forward from find message command
            server_id (int): Server ID of the message to forward from find message command
            time_logged (int): Time logged of the message to forward from find message command
            spam_report_message (str): The reason for the report
            is_spam (bool): Should it be reported as spam

        Returns:
            requests.Response: The response from the API
        """
        data = {
            "messages": [
                {
                    "blockNumber": block_number,
                    "edition": edition,
                    "folderId": folder_id,
                    "messageName": message_name,
                    "recipient": recipient,
                    "serverId": server_id,
                    "timeLogged": time_logged
                },
            ],
            "isSpam": is_spam,
            "spamReportNotificationFromAddress": spam_report_message
        }
        return self._http_request(method='POST',
                                  url_suffix='/quarantine/forwardspam/',
                                  json_data=data,
                                  resp_type='response')


def trustwave_seg_get_version_command(client: Client) -> CommandResults:
    """Retrieve Trustwave version information

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.get_version()

    readable_output = tableToMarkdown('Version Information', response,
                                      ['configVersion', 'productVersion'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Version',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_automatic_config_backup_list_command(client: Client) -> CommandResults:
    """Retrieve automatic config backup list

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_automatic_config_backups()

    outputs = []
    for output in response:
        outputs.append({**output.copy().pop('info'), **output.copy()})

    readable_output = tableToMarkdown('Automatic Configured Backups',
                                      outputs,
                                      ['filename', 'containsDkimKeys',
                                       'backupUser', 'productVersion',
                                       'configVersion', 'commitDescription', 'backupType'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.AutomaticBackupConfig',
        outputs_key_field='filename',
        raw_response=response,
        outputs=outputs,
        readable_output=readable_output
    )


def trustwave_seg_automatic_config_backup_restore_command(client: Client, name: str, timeout: int = 30,
                                                          include_dkim: bool = False,
                                                          dkim_password: str = None
                                                          ) -> CommandResults:
    """Restore an automatic config backup based on params

    Args:
        client (Client): Trustwave SEG API Client
        name (str): The name of the backup to restore
        timeout (int): The timeout of the request.
        include_dkim (bool): If the backup is protected by DKIM
        dkim_password (str, optional): The DKIM, only if include_dkim is True.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """

    response = client.restore_automatic_config_backups(name, int(timeout),
                                                       argToBoolean(include_dkim), dkim_password)

    readable_outputs = response.copy()
    readable_outputs['name'] = name

    readable_output = tableToMarkdown('Automatic Configuration Backup Restore Completed',
                                      readable_outputs,
                                      ['name', 'reason', 'warnings', 'errors'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.AutomaticBackupRestore',
        outputs_key_field='name',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_automatic_config_backup_run_command(client: Client, timeout: int = 30,
                                                      include_dkim: bool = False,
                                                      dkim_password: str = None
                                                      ) -> CommandResults:
    """Run an automatic config backup on Trustwave console.

    Args:
        client (Client): Trustwave SEG API Client
        timeout (int): The timeout of the request.
        include_dkim (bool): Should the backup be protected by a DKIM
        dkim_password (str, optional): The DKIM password, only if include_skim is True.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.run_automatic_config_backups(
        int(timeout), include_dkim, dkim_password)

    readable_output = tableToMarkdown('Automatic Configuration Backup Run Completed',
                                      response,
                                      ['backupName', 'reason'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.AutomaticBackupRun',
        outputs_key_field='backupName',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_list_alerts_command(client: Client, active_only: bool) -> CommandResults:
    """Retrieve a list of alerts from Trustwave

    Args:
        client (Client): Trustwave SEG API Client
        active_only (bool): Retrieve only active alerts

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_alerts(argToBoolean(active_only))
    readable_outputs = []
    for data in response:
        data = data.copy()
        readable_outputs.append({
            'triggered': datetime.fromtimestamp(data.pop('triggered')).strftime(DATE_FORMAT),
            **data
        })

    readable_output = tableToMarkdown('Alerts', readable_outputs,
                                      ['description', 'active', 'node',
                                          'source', 'triggered'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Alert',
        outputs_key_field=['triggered', 'source'],
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_statistics_command(client: Client, start_time: str = None, end_time: str = None,
                                     time_range: str = None) -> CommandResults:
    """Get Statistics from Trustwave console. time_range has priority over start_time.

    Args:
        client (Client): Trustwave SEG API Client
        start_time (str, optional): Start time for the statistics.
        end_time (str, optional): End time for the statistics.
        time_range (str, optional): Time range for the statistics.

    Raises:
        Exception: Start time or time range is mandatory.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    if not start_time and not time_range:
        raise Exception(
            'Invalid time format. Must provide start_time or time_range.')

    start_time = dateparser.parse(time_range if time_range else start_time)  # type: ignore

    # if end time not provided - set it to current date
    end_time = dateparser.parse("now" if not end_time else end_time)
    assert start_time is not None and end_time is not None
    start_info = start_time.strftime(DATE_FORMAT)
    end_info = end_time.strftime(DATE_FORMAT)

    start_time = int(datetime.timestamp(
        datetime.utcfromtimestamp(datetime.timestamp(start_time))))
    end_time = int(datetime.timestamp(
        datetime.utcfromtimestamp(datetime.timestamp(end_time))))

    response = client.get_statistics(start_time, end_time)

    readable_output = tableToMarkdown(f"Statistics Information between {start_info} to {end_info}",
                                      response,
                                      ['msgsIn', 'msgsOut', 'maliciousUrls',
                                       'msgsBlendedThreats', 'msgsSpam',
                                       'msgsVirus', 'numQuarantined', 'unsafeClicks',
                                       'unsafeUrls', 'virusDetected'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Statistics',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_list_servers_command(client: Client) -> CommandResults:
    """Retrieve the list of servers

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_servers()

    readable_outputs = []
    for data in response:
        data = data.copy()
        services_list = [server.get('name')
                         for server in data.pop('pServiceStatus')]
        readable_outputs.append({'Services': ', '.join(services_list), **data})

    readable_output = tableToMarkdown('Servers Details', readable_outputs,
                                      ['serverName', 'serverId', 'productVersion',
                                       'isActive', 'serverLocation',
                                       'serverDescription', 'Services'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Server',
        outputs_key_field='serverId',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_get_server_command(client: Client, server_id: str) -> CommandResults:
    """Retrieve specific server information

    Args:
        client (Client): Trustwave SEG API Client
        server_id (str): The ID of the server to retrieve its information

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.get_server(server_id)

    readable_outputs = []
    server = response.copy()
    services_list = [services.get('name')
                     for services in server.pop('pServiceStatus')]
    readable_outputs.append({'Services': ', '.join(services_list), **server})

    readable_output = tableToMarkdown(f"Server Details. ID: {server_id}", readable_outputs,
                                      ['serverName', 'serverId', 'productVersion',
                                       'isActive', 'serverLocation',
                                       'serverDescription', 'Services'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Server',
        outputs_key_field='serverId',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_list_classifications_command(client: Client) -> CommandResults:
    """List information about the classification in the console

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.get_classifications()

    outputs = sorted(response.copy(), key=lambda x: x.get('id'))

    readable_output = tableToMarkdown('Classifications', outputs,
                                      ['id', 'name'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Classification',
        outputs_key_field='id',
        raw_response=response,
        outputs=outputs,
        readable_output=readable_output
    )


def trustwave_seg_list_quarantine_folders_command(client: Client) -> CommandResults:
    """List quarantine folders information

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_quarantine_folders()

    outputs = sorted(response.copy(), key=lambda x: x.get('folderId'))

    readable_output = tableToMarkdown('Quarantine Folders', outputs,
                                      ['folderId', 'name', 'description', 'isDeleted', 'isReadOnly',
                                       'numFiles', 'retention'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Folder',
        outputs_key_field='folderId',
        raw_response=response,
        outputs=outputs,
        readable_output=readable_output
    )


def trustwave_seg_list_quarantine_folders_with_day_info_command(client: Client) -> CommandResults:
    """List quarantine folder with day's information

    Args:
        client (Client): Trustwave SEG API Client

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_folders_with_day_info()
    readable_outputs = []
    for output in response:
        if output.get('dayItems'):
            readable_outputs.append(
                {**output.copy().pop('dayItems')[0], **output.copy()})

    readable_output = tableToMarkdown('Quarantine Folders with Day Info', readable_outputs,
                                      ['folderId', 'name', 'description', 'numFiles', 'isDeleted',
                                       'isReadOnly', 'retention'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Folder',
        outputs_key_field='folderId',
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_list_day_info_by_quarantine_folder_command(client: Client,
                                                             folder_id: str) -> CommandResults:
    """Retrieve only the day information (number of mails in the folder, time ranges...) from a quarantine folder

    Args:
        client (Client): Trustwave SEG API Client
        folder_id (str): The ID of the folder

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    response = client.list_day_info_from_folder(folder_id)

    outputs = []
    for output in response:
        output = output.copy()
        output['startTime'] = datetime.fromtimestamp(
            output['startTime']).strftime(DATE_FORMAT)
        output['endTime'] = datetime.fromtimestamp(
            output['endTime']).strftime(DATE_FORMAT)
        outputs.append(output)

    readable_output = tableToMarkdown(f'Quarantine Folder with Day Info. ID: {folder_id}', outputs,
                                      ['numFiles', 'startTime', 'endTime'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.DayInfo',
        outputs_key_field=['startTime', 'endTime'],
        raw_response=response,
        outputs=outputs,
        readable_output=readable_output
    )


def trustwave_seg_find_quarantine_message_command(client: Client, max_rows: str,
                                                  time_range: str = None,
                                                  start_time: str = None, end_time: str = None,
                                                  folder_id: str = None, message_name: str = None,
                                                  classification: str = None,
                                                  from_user: str = None,
                                                  to_user: str = None, to_domain: str = None,
                                                  min_size: str = None, max_size: str = None,
                                                  subject: str = None, search_history: str = None,
                                                  forwards: str = None, block_number: str = None,
                                                  search_blank_subject: str = None
                                                  ) -> CommandResults:
    """Find a message or messages by params. time_range has priority over start_time.

    Args:
        client (Client): Trustwave SEG API Client
        max_rows (str): The maximum messages to return from the search
        time_range (str, optional): Time range for the search.
        start_time (str, optional): Start time for the search.
        end_time (str, optional): End time for the search.
        folder_id (str, optional): The ID of the folder to search in.
        message_name (str, optional): The name of the message to search for.
        classification (str, optional): The classification of the message to find.
        from_user (str, optional): Find messages from a specific user.
        to_user (str, optional): Find message that were send to a specific user.
        to_domain (str, optional): Find messages that were sent to specific domain.
        min_size (str, optional): Minimum size of the message.
        max_size (str, optional): Maximum size of the message.
        subject (str, optional): The subject of the message to search.
        search_history (str, optional): Should the search include search history.
        forwards (str, optional): Should the search include forwarded messages.
        block_number (str, optional): The block number to search in.
        search_blank_subject (str, optional): Should the search include blank subject messages.

    Raises:
        Exception: Start time or time range is mandatory.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.
    """
    if not start_time and not time_range:
        raise Exception(
            'Invalid time format. Must provide start_time or time_range.')

    start_time = dateparser.parse(time_range if time_range else start_time)  # type: ignore

    # if end time not provided - set it to current date
    end_time = dateparser.parse("now" if not end_time else end_time)
    assert start_time is not None and end_time is not None
    start_time = int(datetime.timestamp(start_time))
    end_time = int(datetime.timestamp(end_time))

    response = client.find_message(int(max_rows), start_time, end_time, folder_id,
                                   message_name, classification, from_user, to_user,
                                   to_domain, min_size, max_size, subject, search_history,
                                   forwards, block_number, search_blank_subject)

    readable_output = tableToMarkdown('Find Quarantine Messages Results', response,
                                      ['subject', 'description', 'blockNumber',
                                       'edition', 'folderId', 'messageName',
                                       'recipient', 'serverId', 'timeLogged'],
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(
        outputs_prefix='TrustwaveSEG.Message',
        outputs_key_field=['edition', 'blockNumber'],
        raw_response=response,
        outputs=response,
        readable_output=readable_output
    )


def trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command(client: Client,
                                                                        block_number: str,
                                                                        edition: str,
                                                                        folder_id: str,
                                                                        message_name: str,
                                                                        recipient: str,
                                                                        server_id: str,
                                                                        time_logged: str,
                                                                        spam_report_message: str,
                                                                        is_spam: str) -> str:
    """Forward a message to Trustwave Spiderlabs to confirm a message is a spam

    Args:
        client (Client): Trustwave SEG API Client
        block_number (str): Block number of the message to forward from find message command
        edition (str): Edition of the message to forward from find message command
        folder_id (str): Folder ID of the message to forward from find message command
        message_name (str): Message name of the message to forward from find message command
        recipient (str): Recipeient of the message to forward from find message command
        server_id (str): Server ID of the message to forward from find message command
        time_logged (str): Time logged of the message to forward from find message command
        spam_report_message (str): The reason for the report
        is_spam (str): Should it be reported as spam

    Returns:
        str: An informative string about the action
    """
    client.forward_spam(int(block_number), edition, int(folder_id),
                        message_name, recipient, int(
        server_id), int(time_logged),
        argToBoolean(is_spam), spam_report_message)
    return "The message was forwarded to Spiderlabs."


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication

    Args:
        client (Client): Trustwave SEG API client

    Returns: 'ok' if test passed, anything else will fail the test.

    """
    try:
        client.get_version()

    except Exception as exception:
        if 'Host or IP Address' in str(exception):
            return f'Connection Error: {str(exception)}'

        if 'Access is denied' in str(exception):
            return 'Authorization Error: Make sure User Credentials is correctly set'

        raise exception

    return 'ok'


def main() -> None:
    params = demisto.params()

    host = params.get('host')
    config_port = params.get('config_port')
    api_port = params.get('api_port')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(host, config_port, api_port, username,
                        password, proxy, verify_certificate)

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'trustwave-seg-get-version':
            return_results(trustwave_seg_get_version_command(client))

        elif command == 'trustwave-seg-automatic-config-backup-list':
            return_results(
                trustwave_seg_automatic_config_backup_list_command(client))

        elif command == 'trustwave-seg-automatic-config-backup-restore':
            return_results(
                trustwave_seg_automatic_config_backup_restore_command(client, **args))

        elif command == 'trustwave-seg-automatic-config-backup-run':
            return_results(
                trustwave_seg_automatic_config_backup_run_command(client, **args))

        elif command == 'trustwave-seg-list-alerts':
            return_results(trustwave_seg_list_alerts_command(client, **args))

        elif command == 'trustwave-seg-statistics':
            return_results(trustwave_seg_statistics_command(client, **args))

        elif command == 'trustwave-seg-list-servers':
            return_results(trustwave_seg_list_servers_command(client))

        elif command == 'trustwave-seg-get-server':
            return_results(trustwave_seg_get_server_command(client, **args))

        elif command == 'trustwave-seg-list-classifications':
            return_results(trustwave_seg_list_classifications_command(client))

        elif command == 'trustwave-seg-list-quarantine-folders':
            return_results(
                trustwave_seg_list_quarantine_folders_command(client))

        elif command == 'trustwave-seg-list-quarantine-folders-with-day-info':
            return_results(
                trustwave_seg_list_quarantine_folders_with_day_info_command(client))

        elif command == 'trustwave-seg-list-day-info-by-quarantine-folder':
            return_results(
                trustwave_seg_list_day_info_by_quarantine_folder_command(client, **args))

        elif command == 'trustwave-seg-find-quarantine-message':
            return_results(
                trustwave_seg_find_quarantine_message_command(client, **args))

        elif command == 'trustwave-seg-spiderlabs-forward-quarantine-message-as-spam':
            return_results(
                trustwave_seg_spiderlabs_forward_quarantine_message_as_spam_command(client, **args))

    # Log exceptions and return errors
    except Exception as exception:
        if command == 'test-module':
            error_msg = (str(exception))
        else:
            error_msg = f'Failed to execute {command} command. Error: {str(exception)}'
        return_error(error_msg)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
