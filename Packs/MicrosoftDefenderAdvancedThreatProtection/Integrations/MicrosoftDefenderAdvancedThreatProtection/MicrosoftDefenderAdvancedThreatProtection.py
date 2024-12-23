import copy
from itertools import product
from json import JSONDecodeError
from typing import Any
from collections.abc import Callable
from CommonServerPython import *
import urllib3
import dataclasses
from dateutil.parser import parse
from requests import Response
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
APP_NAME = 'ms-defender-atp'
TIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

''' HELPER FUNCTIONS '''

SEVERITY_TO_NUMBER = {
    'Informational': 0,
    'Low': 1,
    'MediumLow': 2,
    'MediumHigh': 3,
    'High': 4
}

NUMBER_TO_SEVERITY = {
    0: 'Informational',
    1: 'Low',
    2: 'MediumLow',
    3: 'MediumHigh',
    4: 'High',
    5: 'Informational'
}
SC_INDICATORS_HEADERS = (
    'id',
    'action',
    'indicatorValue',
    'indicatorType',
    'severity',
    'title',
    'description',
)

INDICATOR_TYPE_TO_DBOT_TYPE = {
    'FileSha256': DBotScoreType.FILE,
    'FileSha1': DBotScoreType.FILE,
    'FileMd5': DBotScoreType.FILE,
    'Url': DBotScoreType.URL,
    'DomainName': DBotScoreType.DOMAIN,
    'IpAddress': DBotScoreType.IP,
    'CertificateThumbprint': None,
}

HEALTH_STATUS_TO_ENDPOINT_STATUS = {
    "Active": "Online",
    "Inactive": "Offline",
    "ImpairedCommunication": "Online",
    "NoSensorData": "Online",
    "NoSensorDataImpairedCommunication": "Online",
    "Unknown": None,
}

DETECTION_SOURCE_TO_API_VALUE = {  # https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/alerts-queue
    "Third-party sensors": "ThirdPartySensors",
    "Antivirus": "WindowsDefenderAv",
    "Automated investigation": "AutomatedInvestigation",
    "Custom detection": "CustomDetection",
    "Custom TI": "CustomerTI",
    "EDR": "WindowsDefenderAtp",
    "Microsoft 365 Defender": "MTP",
    "Microsoft Defender for Office 365": "OfficeATP",
    "Microsoft Defender Experts": "ThreatExperts",
    "SmartScreen": "WindowsDefenderSmartScreen",
}

INTEGRATION_NAME = 'Microsoft Defender ATP'


@dataclasses.dataclass
class FileStatisticsAPIParser:
    sha1: str
    org_prevalence: str
    organization_prevalence: int
    org_first_seen: str | None    # same as 'org_prevalence', but as integer
    org_last_seen: str | None
    global_prevalence: str
    globally_prevalence: int    # same as 'global_prevalence', but as integer
    global_first_observed: str
    global_last_observed: str
    top_file_names: list[str]

    @classmethod
    def from_raw_response(cls, raw_response: dict):
        """Creates an instance from the file stats API raw response body (ignores extra fields, if any).

        Args:
            raw_response (dict): File stats API response

        Returns:
            FileStatisticsAPIParser
        """
        dataclass_field_names = {field.name for field in dataclasses.fields(cls)}
        snake_case_response = snakify(raw_response)
        return cls(**{key: value for key, value in snake_case_response.items() if key in dataclass_field_names})

    def to_context_output(self) -> dict:
        """Generates context output from an instance of FileStatisticsAPIParser.

        Returns:
            dict: context output
        """
        return {
            'Sha1': self.sha1,
            'Statistics': assign_params(
                **{camelize_string(key): value for key, value in dataclasses.asdict(self).items() if key != 'sha1'}
            )
        }

    def to_human_readable(self, file_hash: str) -> str:
        """Generates a human readable table from an instance of FileStatisticsAPIParser.

        Args:
            file_hash (str): The hash of the file

        Returns:
            str: human readable markdown table
        """
        table_data = {self.format_for_table(key): value for key, value in dataclasses.asdict(self).items() if key != 'sha1'}
        return tableToMarkdown(f'Statistics on {file_hash} file:', table_data, removeNull=True)

    def to_file_indicator(self, file_hash: str) -> Common.File:
        """Generates a File indicator object from an instance of FileStatisticsAPIParser.

        Args:
            file_hash (str): The hash of the file

        Returns:
            Common.File
        """
        return Common.File(
            dbot_score=Common.DBotScore(file_hash, DBotScoreType.FILE, INTEGRATION_NAME, Common.DBotScore.NONE),
            sha1=self.sha1,
            organization_prevalence=self.organization_prevalence,
            global_prevalence=self.globally_prevalence,
            organization_first_seen=self.org_first_seen,
            organization_last_seen=self.org_last_seen,
            first_seen_by_source=self.global_first_observed,
            last_seen_by_source=self.global_last_observed,
        )

    @staticmethod
    def format_for_table(field_name: str) -> str:
        """Replaces certain words and formats fields from 'snake_case' to 'Space Case'.

        Args:
            field_name (str): Name of field in snake_case.

        Returns:
            str: Formatted in Space Case with replacements.
        """
        replacements = {'globally_': 'global_', 'org_': 'organization_'}
        for old_value, new_value in replacements.items():
            field_name = field_name.replace(old_value, new_value)
        return pascalToSpace(camelize_string(field_name))


class HuntingQueryBuilder:
    """ERROR MESSAGES"""
    FILE_ARGS_ERR = 'Please provide at least one file arguments: "file_name", "sha1", "sha256" or "md5".'
    DEVICES_ARGS_ERR = 'Please provide at least one devices arguments: "device_id" or "device_name".'
    ANY_ARGS_ERR = 'Please provide at least one of the query args: "device_name", "file_name", "sha1, "sha256", "md5"' \
                   ' or "device_id".'

    @staticmethod
    def get_time_range_query(time_range: str | None) -> str:
        """
        Given a human readable time_range returns the time_range query
        """
        if not time_range:
            return ''
        parsed_time = dateparser.parse(time_range)
        if parsed_time:
            time_in_minutes = int((datetime.now() - parsed_time).total_seconds() // 60)
            return f'Timestamp > ago({time_in_minutes}m)'
        else:
            return ''

    @staticmethod
    def rebuild_query_with_time_range(query: str, time_range: str) -> str:
        """
        Given a query and human readable time_range returns the query with a time_range query
        """
        time_range_query = HuntingQueryBuilder.get_time_range_query(time_range)
        insert_pos = query.find('|')
        if insert_pos == -1:
            return f'{query} | where {time_range_query}'
        return f'{query[:insert_pos - 1]} | where {time_range_query} {query[insert_pos:]}'

    @staticmethod
    def get_filter_values(list_values: list | str | None) -> str | None:
        """
        creates a string of CSV values wrapped by parenthesis and brackets
        """
        if isinstance(list_values, str):
            list_values = argToList(list_values)
        if not list_values or not isinstance(list_values, list):
            return None
        return '("' + '","'.join(list_values) + '")'

    @staticmethod
    def remove_last_expression(query, expression):
        """
        Removes the last expression from the given query
        """
        return query.rsplit(expression, 1)[0]

    @staticmethod
    def build_generic_query(
            query_prefix: str,
            query_suffix: str,
            query_dict: dict,
            query_operation: str,
            operator: str = 'has_any'
    ):
        if not query_dict:
            return query_prefix + query_suffix
        query = query_prefix + ' ('
        for key, val in query_dict.items():
            if isinstance(val, tuple):
                # dict_val with special operator
                query += f' {key} {val[0]} {val[1]} {query_operation}'
            else:
                query += f' ({key} {operator} {val}) {query_operation}'
        query = HuntingQueryBuilder.remove_last_expression(query, query_operation)
        query += ')'
        if query_suffix:
            return query + query_suffix
        return query

    class LateralMovementEvidence:
        """QUERY PREFIX"""
        NETWORK_CONNECTIONS_QUERY_PREFIX = 'DeviceNetworkEvents\n| where (RemoteIP startswith "172.16" or RemoteIP startswith "192.168" or RemoteIP startswith "10.") and'  # noqa: E501
        SMB_CONNECTIONS_QUERY_PREFIX = 'DeviceNetworkEvents\n| where RemotePort == 445 and InitiatingProcessId !in (0, 4) and'  # noqa: E501
        CREDENTIAL_DUMPING_QUERY_PREFIX = 'DeviceProcessEvents\n| where ((FileName has_any ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass") or (ProcessCommandLine has "lsass.exe" and (ProcessCommandLine has "-accepteula" or ProcessCommandLine contains "-ma")) ) and'  # noqa: E501
        MANAGEMENT_CONNECTION_QUERY_PREFIX = 'DeviceNetworkEvents\n| where RemotePort in (22,3389,139,135,23,1433) and'

        """QUERY SUFFIX"""
        NETWORK_CONNECTIONS_QUERY_SUFFIX = '\n| summarize TotalConnections = count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName\n| order by TotalConnections\n| limit {}'  # noqa: E501
        SMB_CONNECTIONS_QUERY_SUFFIX = '\n| summarize RemoteIPCount=dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime\n|{} limit {}'  # noqa: E501
        CREDENTIAL_DUMPING_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, AccountName, InitiatingProcessIntegrityLevel, InitiatingProcessTokenElevation\n| limit {}'  # noqa: E501
        MANAGEMENT_CONNECTION_QUERY_SUFFIX = '\n| summarize TotalCount=count() by DeviceName,LocalIP,RemoteIP,RemotePort\n| order by TotalCount\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     remote_ip_count: str | None = None,
                     ):
            if not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                raise DemistoException(HuntingQueryBuilder.ANY_ARGS_ERR)

            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)
            self._remote_ip_count = remote_ip_count

        def build_network_connections_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.NETWORK_CONNECTIONS_QUERY_PREFIX,
                query_suffix=self.NETWORK_CONNECTIONS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation,
            )

            return query

        def build_smb_connections_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            remote_ip_count_query = '' if not self._remote_ip_count else ' where RemoteIPCount > ' \
                                                                         f'{self._remote_ip_count} |'

            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.SMB_CONNECTIONS_QUERY_PREFIX,
                query_suffix=self.SMB_CONNECTIONS_QUERY_SUFFIX.format(remote_ip_count_query, self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation,
            )

            return query

        def build_credential_dumping_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.CREDENTIAL_DUMPING_QUERY_PREFIX,
                query_suffix=self.CREDENTIAL_DUMPING_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation,
            )

            return query

        def build_management_connection_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.MANAGEMENT_CONNECTION_QUERY_PREFIX,
                query_suffix=self.MANAGEMENT_CONNECTION_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation,
            )

            return query

    class PersistenceEvidence:
        """QUERY PREFIX"""
        SCHEDULE_JOB_QUERY_PREFIX = 'DeviceEvents | where ActionType == "ScheduledTaskCreated" and InitiatingProcessAccountSid != "S-1-5-18" and'  # noqa: E501
        REGISTRY_ENTRY_QUERY_PREFIX = 'DeviceRegistryEvents | where ActionType == "RegistryValueSet" and'
        STARTUP_FOLDER_CHANGES_QUERY_PREFIX = 'DeviceFileEvents | where FolderPath contains @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" and ActionType == "FileCreated" and'  # noqa: E501
        NEW_SERVICE_CREATED_QUERY_PREFIX = 'DeviceRegistryEvents | where RegistryKey contains @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\" and ActionType == "RegistryKeyCreated" and'  # noqa: E501
        SERVICE_UPDATED_QUERY_PREFIX = 'DeviceRegistryEvents | where RegistryKey contains @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\" and ActionType has_any ("RegistryValueSet","RegistryKeyCreated") and'  # noqa: E501
        FILE_REPLACED_QUERY_PREFIX = 'DeviceFileEvents | where FolderPath contains @"C:\Program Files" and ActionType == "FileModified" and'  # noqa: E501
        NEW_USER_QUERY_PREFIX = 'DeviceEvents | where ActionType == "UserAccountCreated" and'
        NEW_GROUP_QUERY_PREFIX = 'DeviceEvents | where ActionType == "SecurityGroupCreated" and'
        GROUP_USER_CHANGE_QUERY_PREFIX = 'DeviceEvents | where ActionType == "UserAccountAddedToLocalGroup" and'
        LOCAL_FIREWALL_CHANGE_QUERY_PREFIX = 'DeviceRegistryEvents | where RegistryKey contains @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" and'  # noqa: E501
        HOST_FILE_CHANGE_QUERY_PREFIX = 'DeviceFileEvents | where FolderPath contains @"C:\Windows\System32\drivers\etc\hosts" and ActionType == "FileModified" and'  # noqa: E501

        """QUERY SUFFIX"""
        SCHEDULE_JOB_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, InitiatingProcessAccountDomain, InitiatingProcessAccountName, AdditionalFields\n| limit {}'  # noqa: E501
        REGISTRY_ENTRY_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, RegistryKey, RegistryValueType, PreviousRegistryValueData, RegistryValueName, PreviousRegistryValueName, PreviousRegistryKey, InitiatingProcessFileName\n| limit {}'  # noqa: E501
        STARTUP_FOLDER_CHANGES_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        NEW_SERVICE_CREATED_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        SERVICE_UPDATED_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, ActionType, RegistryKey, PreviousRegistryKey, RegistryValueName, PreviousRegistryValueName, RegistryValueType, RegistryValueData, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        FILE_REPLACED_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        NEW_USER_QUERY_SUFFIX = '\n| project AccountName,DeviceName,Timestamp,AccountSid,AccountDomain,InitiatingProcessAccountName,InitiatingProcessLogonId\n| limit {}'  # noqa: E501
        NEW_GROUP_QUERY_SUFFIX = '\n| project AccountName,DeviceName,Timestamp,AccountSid,AccountDomain,InitiatingProcessAccountName,InitiatingProcessLogonId,AdditionalFields\n| limit {}'  # noqa: E501
        GROUP_USER_CHANGE_QUERY_SUFFIX = '\n| summarize by AccountSid\n| limit {}'
        LOCAL_FIREWALL_CHANGE_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, ActionType, RegistryKey, PreviousRegistryKey, RegistryValueName, PreviousRegistryValueName, RegistryValueType, RegistryValueData, PreviousRegistryValueData, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        HOST_FILE_CHANGE_QUERY_SUFFIX = '\n| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     query_purpose: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     process_cmd: str | None = None,
                     ):
            if query_purpose == 'registry_entry' and not process_cmd:
                raise DemistoException('Cannot initiate "registry_entry" query without "process_cmd" argument.')
            elif not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                raise DemistoException(HuntingQueryBuilder.ANY_ARGS_ERR)

            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)
            self._process_cmd = ('contains', f'"{process_cmd}"') if process_cmd else None

        def build_scheduled_job_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.SCHEDULE_JOB_QUERY_PREFIX,
                query_suffix=self.SCHEDULE_JOB_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_registry_entry_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
                InitiatingProcessCommandLine=self._process_cmd
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.REGISTRY_ENTRY_QUERY_PREFIX,
                query_suffix=self.REGISTRY_ENTRY_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_startup_folder_changes_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.STARTUP_FOLDER_CHANGES_QUERY_PREFIX,
                query_suffix=self.STARTUP_FOLDER_CHANGES_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_new_service_created_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
                InitiatingProcessCommandLine=self._process_cmd
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.NEW_SERVICE_CREATED_QUERY_PREFIX,
                query_suffix=self.NEW_SERVICE_CREATED_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_service_updated_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
                InitiatingProcessCommandLine=self._process_cmd
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.SERVICE_UPDATED_QUERY_PREFIX,
                query_suffix=self.SERVICE_UPDATED_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_file_replaced_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.FILE_REPLACED_QUERY_PREFIX,
                query_suffix=self.FILE_REPLACED_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_new_user_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.NEW_USER_QUERY_PREFIX,
                query_suffix=self.NEW_USER_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_new_group_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.NEW_GROUP_QUERY_PREFIX,
                query_suffix=self.NEW_GROUP_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_group_user_change_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.GROUP_USER_CHANGE_QUERY_PREFIX,
                query_suffix=self.GROUP_USER_CHANGE_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_local_firewall_change_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
                InitiatingProcessCommandLine=self._process_cmd
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.LOCAL_FIREWALL_CHANGE_QUERY_PREFIX,
                query_suffix=self.LOCAL_FIREWALL_CHANGE_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_host_file_change_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id,
                InitiatingProcessCommandLine=self._process_cmd
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.HOST_FILE_CHANGE_QUERY_PREFIX,
                query_suffix=self.HOST_FILE_CHANGE_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

    class FileOrigin:
        """QUERY PREFIX"""
        FILE_ORIGIN_QUERY_PREFIX = 'DeviceFileEvents | where'

        """QUERY SUFFIX"""
        FILE_ORIGIN_QUERY_SUFFIX = '\n| project Timestamp,FileName,FolderPath, ActionType,DeviceName,MD5,SHA1,SHA256,FileSize,FileOriginUrl,FileOriginIP,InitiatingProcessCommandLine,InitiatingProcessFileName,InitiatingProcessParentFileName\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     ):
            if not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                raise DemistoException(
                    'Please provide at least one of the query args: "device_name", "file_name", "sha1, '
                    '"sha256", "md5" or "device_id".')

            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)

        def build_file_origin_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.FILE_ORIGIN_QUERY_PREFIX,
                query_suffix=self.FILE_ORIGIN_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

    class ProcessDetails:
        """QUERY PREFIX"""
        GENERIC_PROCESS_DETAILS_QUERY_PREFIX = 'DeviceProcessEvents | where'
        BECAONING_QUERY_PREFIX = 'DeviceNetworkEvents | where'
        POWERSHELL_EXECUTION_PROCESS_QUERY_PREFIX = 'DeviceProcessEvents | where FileName in~ ("powershell.exe", "powershell_ise.exe",".ps") and'  # noqa: E501
        POWERSHELL_EXECUTION_PROCESS_UNSIGNED_QUERY_PREFIX = 'DeviceProcessEvents | where FileName in~ ("powershell.exe", "powershell_ise.exe",".ps") and ( InitiatingProcessFileName != "SenerIR.exe" and InitiatingProcessParentFileName != "MsSense.exe" and InitiatingProcessSignatureStatus != "Valid" ) and (InitiatingProcessFileName != "CompatTelRunner.exe" and InitiatingProcessParentFileName != "CompatTelRunner.exe")'  # noqa: E501

        """QUERY SUFFIX"""
        PARENT_PROCESS_QUERY_SUFFIX = '\n| project Timestamp, DeviceId, DeviceName, ActionType, ProcessId, ProcessCommandLine, ProcessCreationTime, AccountSid, AccountName, AccountDomain,InitiatingProcessAccountDomain, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountSid, InitiatingProcessAccountSid, InitiatingProcessAccountUpn, InitiatingProcessAccountObjectId, InitiatingProcessLogonId, InitiatingProcessIntegrityLevel, InitiatingProcessTokenElevation, InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5, InitiatingProcessFileName, InitiatingProcessFileSize, InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessVersionInfoInternalFileName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoFileDescription, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessCreationTime, InitiatingProcessFolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountSid\n| limit {}'  # noqa: E501
        GRANDPARENT_PROCESS_QUERY_SUFFIX = '\n| project Timestamp, DeviceId, DeviceName, ActionType, ProcessId, ProcessCommandLine, ProcessIntegrityLevel, ProcessCreationTime, AccountSid, AccountName, AccountDomain, AccountObjectId, AccountUpn, InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessParentId, InitiatingProcessParentCreationTime\n| limit {}'  # noqa: E501
        PROCESS_DETAILS_QUERY_SUFFIX = '\n| summarize by SHA1,FileName,SHA256,MD5 | join DeviceFileCertificateInfo on SHA1 | summarize by FileName,SHA1,SHA256,IsSigned,Signer,SignatureType,Issuer,CertificateExpirationTime,IsTrusted,IsRootSignerMicrosoft\n| limit {}'  # noqa: E501
        BEACONING_EVIDENCE_QUERY_SUFFIX = '\n| project Timestamp, DeviceId, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol, LocalIPType, RemoteIPType, InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5, InitiatingProcessFileName\n| limit {}'  # noqa: E501
        POWERSHELL_EXECUTION_PROCESS_QUERY_SUFFIX = '| project Timestamp, FileName, FolderPath, ProcessVersionInfoProductName, ProcessCommandLine, ProcessCreationTime, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessSignerType, InitiatingProcessSignatureStatus,DeviceId,DeviceName\n| limit {}'  # noqa: E501
        POWERSHELL_EXECUTION_PROCESS_UNSIGNED_QUERY_SUFFIX = '\n| summarize by InitiatingProcessFolderPath,InitiatingProcessFileName,InitiatingProcessParentFileName,InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessVersionInfoProductName,InitiatingProcessCommandLine,InitiatingProcessSignerType,InitiatingProcessSignatureStatus'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     query_purpose: str | None = None,
                     ):
            if query_purpose == 'process_excecution_powershell':
                if not (file_name or sha1 or sha256 or md5):
                    raise DemistoException(HuntingQueryBuilder.FILE_ARGS_ERR)
                if not (device_id or device_name):
                    raise DemistoException(HuntingQueryBuilder.DEVICES_ARGS_ERR)

            elif query_purpose != 'powershell_execution_unsigned_files' \
                    and not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                raise DemistoException(HuntingQueryBuilder.ANY_ARGS_ERR)

            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)

        def build_parent_process_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.GENERIC_PROCESS_DETAILS_QUERY_PREFIX,
                query_suffix=self.PARENT_PROCESS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_grandparent_process_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.GENERIC_PROCESS_DETAILS_QUERY_PREFIX,
                query_suffix=self.GRANDPARENT_PROCESS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_process_details_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.GENERIC_PROCESS_DETAILS_QUERY_PREFIX,
                query_suffix=self.PROCESS_DETAILS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_beaconing_evidence_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.BECAONING_QUERY_PREFIX,
                query_suffix=self.BEACONING_EVIDENCE_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_process_excecution_powershell_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.POWERSHELL_EXECUTION_PROCESS_QUERY_PREFIX,
                query_suffix=self.POWERSHELL_EXECUTION_PROCESS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_powershell_execution_unsigned_files_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = self.POWERSHELL_EXECUTION_PROCESS_UNSIGNED_QUERY_PREFIX
            if query_dict:
                query += ' and'

            return HuntingQueryBuilder.build_generic_query(
                query_prefix=query,
                query_suffix=self.POWERSHELL_EXECUTION_PROCESS_UNSIGNED_QUERY_SUFFIX,
                query_dict=query_dict,
                query_operation=self._query_operation
            )

    class NetworkConnections:
        """QUERY PREFIX"""
        EXTERNAL_ADDRESSES_QUERY_PREFIX = 'DeviceNetworkEvents | where not(RemoteIP matches regex "(^10\\\\.)|(^172\\\\.1[6-9]\\\\.)|(^172\\\\.2[0-9]\\\\.)|(^172\\\\.3[0-1]\\\\.)|(^192\\\\.168\\\\.)") and'  # noqa: E501
        DNS_QUERY_PREFIX = 'DeviceNetworkEvents | where RemotePort == 53 and'
        ENCODED_COMMANDS_QUERY_PREFIX = 'DeviceProcessEvents | where FileName in ("powershell.exe","powershell_ise.exe") and ProcessCommandLine contains "-encoded" and'  # noqa: E501

        """QUERY SUFFIX"""
        EXTERNAL_ADDRESSES_QUERY_SUFFIX = '\n| summarize TotalConnections = count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName,InitiatingProcessFolderPath | order by TotalConnections\n| limit {}'  # noqa: E501
        DNS_QUERY_SUFFIX = '| project Timestamp,DeviceName,ActionType,RemoteIP,Packetinfo = url_decode(AdditionalFields)\n| limit {}'  # noqa: E501
        ENCODED_COMMANDS_QUERY_SUFFIX = '\n| limit {}'

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     query_purpose: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     ):
            if query_purpose == 'encoded_commands':
                if not (device_id or device_name):
                    raise DemistoException(HuntingQueryBuilder.DEVICES_ARGS_ERR)
            else:
                if not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                    raise DemistoException(HuntingQueryBuilder.ANY_ARGS_ERR)
            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)

        def build_external_addresses_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.EXTERNAL_ADDRESSES_QUERY_PREFIX,
                query_suffix=self.EXTERNAL_ADDRESSES_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_dns_query(self):
            query_dict = assign_params(
                InitiatingProcessFileName=self._file_name,
                InitiatingProcessSHA1=self._sha1,
                InitiatingProcessSHA256=self._sha256,
                InitiatingProcessMD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.DNS_QUERY_PREFIX,
                query_suffix=self.DNS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_encoded_commands_query(self):
            query_dict = assign_params(
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.ENCODED_COMMANDS_QUERY_PREFIX,
                query_suffix=self.ENCODED_COMMANDS_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

    class PrivilegeEscalation:
        QUERY_PREFIX = 'DeviceLogonEvents | where IsLocalAdmin == 1 and'
        QUERY_SUFFIX = ' and AccountDomain == DeviceName | project Timestamp, DeviceId, DeviceName, ActionType, LogonType, AccountDomain, AccountName, IsLocalAdmin, InitiatingProcessFileName\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     page: str,
                     device_name: str | None = None,
                     device_id: str | None = None,
                     ):
            if not (device_name or device_id):
                raise DemistoException(HuntingQueryBuilder.DEVICES_ARGS_ERR)
            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)

        def build_query(self):
            query_dict = assign_params(
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.QUERY_PREFIX,
                query_suffix=self.QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

    class Tampering:
        QUERY_PREFIX = 'let includeProc = dynamic(["sc.exe","net1.exe","net.exe", "taskkill.exe", "cmd.exe", "powershell.exe"]); let action = dynamic(["stop","disable", "delete"]); let service1 = dynamic([\'sense\', \'windefend\', \'mssecflt\']); let service2 = dynamic([\'sense\', \'windefend\', \'mssecflt\', \'healthservice\']); let params1 = dynamic(["-DisableRealtimeMonitoring", "-DisableBehaviorMonitoring" ,"-DisableIOAVProtection"]); let params2 = dynamic(["sgrmbroker.exe", "mssense.exe"]); let regparams1 = dynamic([\'reg add "HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Defender"\', \'reg add "HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows Advanced Threat Protection"\']); let regparams2 = dynamic([\'ForceDefenderPassiveMode\', \'DisableAntiSpyware\']); let regparams3 = dynamic([\'sense\', \'windefend\']); let regparams4 = dynamic([\'demand\', \'disabled\']); let timeframe = 1d; DeviceProcessEvents'  # noqa: E501
        QUERY_SUFFIX = '\n| where InitiatingProcessFileName in~ (includeProc) | where (InitiatingProcessCommandLine has_any(action) and InitiatingProcessCommandLine has_any (service2) and InitiatingProcessParentFileName != \'cscript.exe\') or (InitiatingProcessCommandLine has_any (params1) and InitiatingProcessCommandLine has \'Set-MpPreference\' and InitiatingProcessCommandLine has \'$true\') or (InitiatingProcessCommandLine has_any (params2) and InitiatingProcessCommandLine has "/IM") or (InitiatingProcessCommandLine has_any (regparams1) and InitiatingProcessCommandLine has_any (regparams2) and InitiatingProcessCommandLine has \'/d 1\') or (InitiatingProcessCommandLine has_any("start") and InitiatingProcessCommandLine has "config" and InitiatingProcessCommandLine has_any (regparams3) and InitiatingProcessCommandLine has_any (regparams4))| extend Account = iff(isnotempty(InitiatingProcessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName), Computer = DeviceName| project Timestamp, Computer, Account, AccountDomain, ProcessName = InitiatingProcessFileName, ProcessNameFullPath = FolderPath, Activity = ActionType, CommandLine = InitiatingProcessCommandLine, InitiatingProcessParentFileName\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     page: str,
                     device_name: str | None = None,
                     device_id: str | None = None,
                     ):
            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)

        def build_query(self):
            query_dict = assign_params(
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=f'{self.QUERY_PREFIX}{"| where" if query_dict else ""}',
                query_suffix=self.QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

    class CoverUp:
        """ERRORS"""
        USERNAME_ERROR = 'Please provide the "username" argument.'

        """QUERY PREFIX"""
        FILE_DELETED_QUERY_PREFIX = 'DeviceFileEvents | where ActionType == "FileDeleted" and'
        EVENT_LOG_CLEARED_QUERY_PREFIX = 'DeviceProcessEvents | where (ProcessCommandLine has "WEVTUTIL" and ProcessCommandLine has_any ("CL","clear-log")) or (ProcessCommandLine contains "Clear-EventLog") and'  # noqa: E501
        ACCOUNT_QUERY_PREFIX = 'union Device* | where'

        """QUERY SUFFIX"""
        FILE_DELETED_QUERY_SUFFIX = '\n| project Timestamp, DeviceId, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessVersionInfoProductName, InitiatingProcessCommandLine\n| limit {}'  # noqa: E501
        EVENT_LOG_CLEARED_QUERY_SUFFIX = '\n| summarize LogClearCount = dcount(ProcessCommandLine), ClearedLogList = make_set(ProcessCommandLine) by DeviceId,DeviceName, bin(Timestamp, 5m),FileName,InitiatingProcessFileName\n| limit {}'  # noqa: E501
        COMPROMISED_INFORMATION_QUERY_SUFFIX = '\n| project Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessFileName\n| limit {}'  # noqa: E501
        CONNECTED_DEVICES_QUERY_SUFFIX = '\n| summarize by DeviceName\n| limit {}'
        ACTION_TYPES_QUERY_SUFFIX = '\n| summarize Number_of_actions=count(ActionType) by ActionType,DeviceName | order by Number_of_actions\n| limit {}'  # noqa: E501
        COMMON_FILES_QUERY_SUFFIX = '\n| summarize Number_of_accoiated_events=count(FileName) by FileName, MD5, SHA1, SHA256 | order by Number_of_accoiated_events\n| limit {}'  # noqa: E501

        def __init__(self,
                     limit: str,
                     query_operation: str,
                     query_purpose: str,
                     page: str,
                     device_name: str | None = None,
                     file_name: str | None = None,
                     sha1: str | None = None,
                     sha256: str | None = None,
                     md5: str | None = None,
                     device_id: str | None = None,
                     username: str | None = None,
                     ):
            if query_purpose in ('compromised_information', 'connected_devices', 'action_types', 'common_files'):
                if not username:
                    raise DemistoException(self.USERNAME_ERROR)
            elif query_purpose == 'event_log_cleared' and not (device_name or device_id):
                raise DemistoException(HuntingQueryBuilder.DEVICES_ARGS_ERR)
            elif not (device_name or file_name or sha1 or sha256 or md5 or device_id):
                raise DemistoException(HuntingQueryBuilder.ANY_ARGS_ERR)
            self._limit = limit * (int(page))
            self._query_operation = query_operation
            self._device_name = HuntingQueryBuilder.get_filter_values(device_name)
            self._file_name = HuntingQueryBuilder.get_filter_values(file_name)
            self._sha1 = HuntingQueryBuilder.get_filter_values(sha1)
            self._sha256 = HuntingQueryBuilder.get_filter_values(sha256)
            self._md5 = HuntingQueryBuilder.get_filter_values(md5)
            self._device_id = HuntingQueryBuilder.get_filter_values(device_id)
            self._username = HuntingQueryBuilder.get_filter_values(username)

        def build_file_deleted_query(self):
            query_dict = assign_params(
                FileName=self._file_name,
                SHA1=self._sha1,
                SHA256=self._sha256,
                MD5=self._md5,
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.FILE_DELETED_QUERY_PREFIX,
                query_suffix=self.FILE_DELETED_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_event_log_cleared_query(self):
            query_dict = assign_params(
                DeviceName=self._device_name,
                DeviceId=self._device_id
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.EVENT_LOG_CLEARED_QUERY_PREFIX,
                query_suffix=self.EVENT_LOG_CLEARED_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_compromised_information_query(self):
            query_dict = assign_params(
                AccountName=self._username
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.ACCOUNT_QUERY_PREFIX,
                query_suffix=self.COMPROMISED_INFORMATION_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_connected_devices_query(self):
            query_dict = assign_params(
                AccountName=self._username
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.ACCOUNT_QUERY_PREFIX,
                query_suffix=self.CONNECTED_DEVICES_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_action_types_query(self):
            query_dict = assign_params(
                AccountName=self._username
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.ACCOUNT_QUERY_PREFIX,
                query_suffix=self.ACTION_TYPES_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query

        def build_common_files_query(self):
            query_dict = assign_params(
                AccountName=self._username
            )
            query = HuntingQueryBuilder.build_generic_query(
                query_prefix=self.ACCOUNT_QUERY_PREFIX,
                query_suffix=self.COMMON_FILES_QUERY_SUFFIX.format(self._limit),
                query_dict=query_dict,
                query_operation=self._query_operation)

            return query


def file_standard(observable: dict) -> Common.File:
    """Gets a file observable and returns a context key

    Args:
        observable: APT's file observable

    Returns:
        Context standard
    """
    file_obj = Common.File(
        Common.DBotScore.NONE,
        name=observable.get('fileName'),
        size=observable.get('fileSize'),
        path=observable.get('filePath')
    )
    hash_type = observable.get('fileHashType', '').lower()
    if hash_type and hash_type in INDICATOR_TYPE_TO_CONTEXT_KEY:
        hash_value = observable.get('fileHashValue')
        if hash_type == 'md5':
            file_obj.md5 = hash_value
        elif hash_type == 'sha256':
            file_obj.sha256 = hash_value
        elif hash_type == 'sha1':
            file_obj.sha1 = hash_value
    return file_obj


def network_standard(observable: dict) -> Common.Domain | Common.IP | Common.URL | None:
    """Gets a network observable and returns a context key

    Args:
        observable: APT's network observable

    Returns:
        Context standard or None of not supported
    """
    domain_name = observable.get('domainName')
    url = observable.get('url')
    ip = observable.get('networkIPv4', observable.get('networkIPv6'))
    if domain_name:
        return Common.Domain(domain_name, Common.DBotScore.NONE)
    elif ip:
        return Common.IP(ip, Common.DBotScore(ip, DBotScoreType.IP, 'Microsoft Defender Advanced Threat Protection', 0))
    elif url:
        return Common.URL(url, Common.DBotScore.NONE)
    return None


def standard_output(observable: dict) -> Common.Domain | Common.IP | Common.URL | Common.File | None:
    """Gets an observable and returns a context standard object.

    Args:
        observable: File or network observable from API.

    Links:
        File observable: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---file
        Network observable: https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---network

    Returns:
        File, IP, URL or Domain object. If observable is not supported, will return None.
    """  # noqa: E501
    file_keys = {
        'fileHashType', 'fileHashValue', 'fileName', 'filePath', 'fileSize', 'fileType'
    }
    # Must be file key
    if any(key in observable for key in file_keys):
        return file_standard(observable)
    # Else it's a network
    return network_standard(observable)


def build_std_output(indicators: dict | list) -> dict:
    """

    Args:
        indicators: Network or File observable

    Returns:
        Dict of standard outputs.
    """
    if isinstance(indicators, dict):
        indicators = [indicators]
    outputs = {}
    for indicator in indicators:
        output = standard_output(indicator)
        if output:
            for key, value in output.to_context().items():
                if key not in outputs:
                    outputs[key] = [value]
                else:
                    outputs[key].append(value)
    return outputs


def get_future_time(expiration_time: str) -> str:
    """ Gets a time and returns a string of the future time of it.

    Args:
        expiration_time: (3 days, 1 hour etc)

    Returns:
        time now + the expiration time

    Examples:
        time now: 20:00
        function get expiration_time=1 hour
        returns: 21:00 (format '%Y-%m-%dT%H:%M:%SZ')
    """
    start, end = parse_date_range(
        expiration_time
    )
    future_time: datetime = end + (end - start)
    return future_time.strftime('%Y-%m-%dT%H:%M:%SZ')


def alert_to_incident(alert, alert_creation_time):
    incident = {
        'rawJSON': json.dumps(alert),
        'name': 'Microsoft Defender ATP Alert ' + alert['id'],
        'occurred': alert_creation_time.isoformat() + 'Z'
    }

    return incident


class MsClient:
    """
     Microsoft  Client enables authorized access to Microsoft Defender Advanced Threat Protection (ATP)
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy, self_deployed,
                 alert_severities_to_fetch, alert_status_to_fetch, alert_time_to_fetch, max_fetch,
                 auth_type, endpoint_type, redirect_uri, auth_code, certificate_thumbprint: str | None = None,
                 private_key: str | None = None, managed_identities_client_id: str | None = None,
                 alert_detectionsource_to_fetch: str | None = None):

        self.endpoint_type = endpoint_type
        if auth_type == 'Authorization Code':
            token_retrieval_url = urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_TOKEN_RETRIVAL_ENDPOINTS.get(endpoint_type),
                                          '/organizations/oauth2/v2.0/token')
            grant_type = AUTHORIZATION_CODE
        else:
            token_retrieval_url = None
            grant_type = None

        client_args = assign_params(
            self_deployed=self_deployed,
            auth_id=auth_id,
            endpoint=endpoint_type,
            token_retrieval_url=token_retrieval_url,
            grant_type=grant_type,
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            scope=urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_APT_SERVICE_ENDPOINTS[self.endpoint_type],
                          "/windowsatpservice/.default"),
            ok_codes=(200, 201, 202, 204),
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            tenant_id=tenant_id,
            app_name=app_name,
            enc_key=enc_key,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            retry_on_rate_limit=True,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=MICROSOFT_DEFENDER_FOR_ENDPOINT_API[self.endpoint_type],
            command_prefix="microsoft-atp"
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.alert_detectionsource_to_fetch = alert_detectionsource_to_fetch
        self.alert_severities_to_fetch = alert_severities_to_fetch
        self.alert_status_to_fetch = alert_status_to_fetch
        self.alert_time_to_fetch = alert_time_to_fetch
        self.max_alerts_to_fetch = max_fetch

    def indicators_http_request(self, *args, **kwargs):
        """ Wraps the ms_client.http_request with scope=Scopes.graph
            should_use_security_center (bool): whether to use the security center's scope and resource
        """
        if kwargs.pop('should_use_security_center', None):
            kwargs['scope'] = urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_APT_SERVICE_ENDPOINTS[self.endpoint_type],
                                      "/windowsatpservice/.default")
            kwargs['resource'] = MICROSOFT_DEFENDER_FOR_ENDPOINT_API[self.endpoint_type]
        else:
            kwargs['scope'] = self.get_graph_scope()
        return self.ms_client.http_request(*args, **kwargs)

    def get_graph_scope(self):
        return "graph" if self.ms_client.auth_type == OPROXY_AUTH_TYPE else \
            urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_GRAPH_ENDPOINTS[self.endpoint_type], "/.default")

    def get_graph_indicator_endpoint(self):
        return urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_GRAPH_ENDPOINTS[self.endpoint_type],
                       "/beta/security/tiIndicators")

    def get_security_center_indicator_endpoint(self):
        return urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_API[self.endpoint_type],
                       '/api/indicators')

    def get_security_center_indicator_endpoint_batch(self):
        return urljoin(MICROSOFT_DEFENDER_FOR_ENDPOINT_API[self.endpoint_type],
                       '/api/indicators/import')

    def offboard_machine(self, machine_id, comment):
        """ Offboard machine from defender.

         Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the
        """
        cmd_url = f'/machines/{machine_id}/offboard'
        json_data = {
            "Comment": comment
        }
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)
        return response

    def isolate_machine(self, machine_id, comment, isolation_type):
        """Isolates a machine from accessing external network.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action.
            isolation_type (str): Type of the isolation.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/isolate'
        json_data = {
            "Comment": comment,
            "IsolationType": isolation_type
        }
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)
        return response

    def unisolate_machine(self, machine_id, comment):
        """Undo isolation of a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/unisolate'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_machines(self, filter_req, page_size='', page_num=''):
        """Retrieves a collection of Machines that have communicated with Microsoft Defender ATP cloud on the last 30 days.

        Returns:
            dict. Machine's info
        """
        cmd_url = '/machines'
        params = {'$filter': filter_req} if filter_req else {}

        if page_size and page_num:
            page_size = arg_to_number(page_size)
            page_size = min(page_size, 10000)
            page_num = arg_to_number(page_num)
            page_num = 0 if not page_num else (page_num - 1)
            skip = page_num * page_size
            params['$skip'] = str(skip)
            params['$top'] = str(page_size)

        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_machines_for_get_machine_by_ip_command(self, filter_req):
        """

        Args:
            filter_req string: a query request to use to filter machines,
            for example: "(ip='8.8.8.8',timestamp=2024-05-19T01:00:05Z)".
            Link to documentation: https://learn.microsoft.com/en-us/defender-endpoint/api/find-machines-by-ip?view=o365-worldwide
        Returns:
            dict: Machines info
        """
        demisto.debug(f'current request is: api/machines/findbyip{filter_req}')
        cmd_url = 'machines/findbyip' + filter_req
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_file_related_machines(self, file):
        """Retrieves a collection of Machines related to a given file hash.

        Args:
            file (str): File's hash

        Returns:
            dict. Related machines
        """
        cmd_url = f'/files/{file}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_machine_details(self, machine_id):
        """Retrieves specific Machine by its machine ID.

        Args:
            machine_id (str): Machine ID

        Returns:
            dict. Machine's info
        """
        cmd_url = f'/machines/{machine_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_list_machines_by_vulnerability(self, cve_id):
        """Retrieves a list of devices affected by a vulnerability.
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machines-by-vulnerability?view=o365-worldwide#http-request

        Args:
            cve_id (str): Vulnerability ID

        Returns:
            dict. Machine's info
        """
        cmd_url = f'/vulnerabilities/{cve_id}/machineReferences'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def run_antivirus_scan(self, machine_id, comment, scan_type):
        """Initiate Windows Defender Antivirus scan on a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): 	Comment to associate with the action
            scan_type (str): Defines the type of the Scan (Quick, Full)

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/runAntiVirusScan'
        json_data = {
            'Comment': comment,
            'ScanType': scan_type
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def list_alerts_by_params(self, filter_req=None, params=None, overwrite_rate_limit_retry=False):
        """Retrieves a collection of Alerts.
            overwrite_rate_limit_retry - Skip retry mechanism, True for fetch incidents
        Returns:
            dict. Alerts info
        """
        cmd_url = '/alerts'
        if not params:
            params = {'$filter': filter_req} if filter_req else None

        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params,
                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def list_alerts(self, filter_req=None, limit=None, evidence=False, creation_time=None):
        """Retrieves a collection of Alerts.

        Returns:
            dict. Alerts info
        """
        cmd_url = '/alerts'
        params = {}
        if evidence:
            params['$expand'] = 'evidence'
        if filter_req:
            if creation_time:
                filter_req += f"and {create_filter_alerts_creation_time(creation_time)}"
            params['$filter'] = filter_req
        if limit:
            params['$top'] = limit
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def update_alert(self, alert_id, json_data):
        """Updates properties of existing Alert.

        Returns:
            dict. Alerts info
        """
        cmd_url = f'/alerts/{alert_id}'
        return self.ms_client.http_request(method='PATCH', url_suffix=cmd_url, json_data=json_data)

    def get_advanced_hunting(self, query: str, timeout: int, time_range: str | None = None) -> dict[str, Any]:
        """Retrieves results according to query.

        Args:
            query (str): Query to do advanced hunting on
            timeout (int): Connection timeout
            time_range (Optional[int]): Time range in minutes given in timespan format

        Returns:
            dict. Advanced hunting results
        """
        cmd_url = '/advancedqueries/run'
        if time_range:
            query = HuntingQueryBuilder.rebuild_query_with_time_range(query, time_range)
        json_data = {
            'Query': query
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data, timeout=timeout)

    def create_alert(self, machine_id, severity, title, description, event_time, report_id, rec_action, category):
        """Creates new Alert on top of Event.

        Args:
            machine_id (str): ID of the machine on which the event was identified
            severity (str): Severity of the alert
            title (str): Title for the alert
            description (str): Description of the alert
            event_time (str): The precise time of the event as string
            report_id (str): The reportId of the event
            rec_action (str): Action that is recommended to be taken by security officer when analyzing the alert
            category (Str): Category of the alert

        Returns:
            dict. Related domains
        """
        cmd_url = '/alerts/CreateAlertByReference'
        json_data = {
            'machineId': machine_id,
            'severity': severity,
            'title': title,
            'description': description,
            'eventTime': event_time,
            'reportId': report_id,
            'recommendedAction': rec_action,
            'category': category
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def get_alert_related_domains(self, alert_id):
        """Retrieves all domains related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related domains
        """
        cmd_url = f'/alerts/{alert_id}/domains'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_files(self, alert_id):
        """Retrieves all files related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related files
        """
        cmd_url = f'/alerts/{alert_id}/files'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_ips(self, alert_id):
        """Retrieves all IPs related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related IPs
        """
        cmd_url = f'/alerts/{alert_id}/ips'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_related_user(self, alert_id):
        """Retrieves the User related to a specific alert.

        Args:
            alert_id (str): Alert ID

        Returns:
            dict. Related user
        """
        cmd_url = f'/alerts/{alert_id}/user'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_machine_action_by_id(self, action_id, overwrite_rate_limit_retry=False):
        """Retrieves specific Machine Action by its ID.

        Args:
            action_id (str): Action ID

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine Action entity
        """
        cmd_url = f'/machineactions/{action_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url,
                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def get_machine_actions(self, filter_req, limit):
        """Retrieves all Machine Actions.

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine Action entity
        """
        cmd_url = '/machineactions'
        params = {'$top': limit}
        if filter_req:
            params['$filter'] = filter_req
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_investigation_package(self, machine_id, comment, overwrite_rate_limit_retry=False):
        """Collect investigation package from a machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action
        Returns:

            dict. Machine's investigation_package
        """
        cmd_url = f'/machines/{machine_id}/collectInvestigationPackage'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data,
                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def get_investigation_package_sas_uri(self, action_id, overwrite_rate_limit_retry=False):
        """Get a URI that allows downloading of an Investigation package.

        Args:
            action_id (str): Action ID

        Returns:
            dict. An object that holds the link for the package
        """
        cmd_url = f'/machineactions/{action_id}/getPackageUri'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url,
                                           overwrite_rate_limit_retry=overwrite_rate_limit_retry)

    def restrict_app_execution(self, machine_id, comment):
        """Restrict execution of all applications on the machine except a predefined set.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/restrictCodeExecution'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data)

    def remove_app_restriction(self, machine_id, comment):
        """Enable execution of any application on the machine.

        Args:
            machine_id (str): Machine ID
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/unrestrictCodeExecution'
        json_data = {
            'Comment': comment
        }
        return self.ms_client.http_request('POST', cmd_url, json_data=json_data)

    def stop_and_quarantine_file(self, machine_id, file_sha1, comment):
        """Stop execution of a file on a machine and delete it.

        Args:
            machine_id (str): Machine ID
            file_sha1: (str): File's hash
            comment (str): Comment to associate with the action

        Notes:
            Machine action is a collection of actions you can apply on the machine, for more info
            https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

        Returns:
            dict. Machine action
        """
        cmd_url = f'/machines/{machine_id}/stopAndQuarantineFile'
        json_data = {
            'Comment': comment,
            'Sha1': file_sha1
        }
        return self.ms_client.http_request('POST', cmd_url, json_data=json_data)

    def get_investigation_by_id(self, investigation_id):
        """Get the investigation ID and return the investigation details.

        Args:
            investigation_id (str): The investigation ID

        Returns:
            dict. Investigations entity
        """
        cmd_url = f'/investigations/{investigation_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_alert_by_id(self, alert_id):
        """Get the alert ID and return the alert details.

        Args:
            alert_id (str): The alert ID

        Returns:
            dict. Alert's entity
        """
        cmd_url = f'/alerts/{alert_id}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_investigation_list(self, ):
        """Retrieves a collection of Investigations.

        Returns:
            dict. A collection of Investigations entities.
        """
        cmd_url = '/investigations'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def start_investigation(self, machine_id, comment, timeout):
        """Start automated investigation on a machine.

        Args:
            machine_id (str): The Machine ID
            comment (str): Comment to associate with the action
            timeout (int): Connection timeout

        Returns:
            dict. Investigation's entity
        """
        cmd_url = f'/machines/{machine_id}/startInvestigation'
        json_data = {
            'Comment': comment,
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=json_data, timeout=timeout)

    def get_domain_statistics(self, domain):
        """Retrieves the statistics on the given domain.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Domain's statistics
        """
        cmd_url = f'/domains/{domain}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_file_statistics(self, file_sha1):
        """Retrieves the statistics on the given file.

        Args:
            file_sha1 (str): The file's hash

        Returns:
            dict. File's statistics
        """
        cmd_url = f'/files/{file_sha1}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_ip_statistics(self, ip):
        """Retrieves the statistics on the given IP.

        Args:
            ip (str): The IP address

        Returns:
            dict. IP's statistics
        """
        cmd_url = f'/ips/{ip}/stats'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_domain_alerts(self, domain):
        """Retrieves a collection of Alerts related to a given domain address.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/domains/{domain}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_file_alerts(self, file_sha1):
        """Retrieves a collection of Alerts related to a given file hash.

        Args:
            file_sha1 (str): The file's hash

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/files/{file_sha1}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_ip_alerts(self, ip):
        """Retrieves a collection of Alerts related to a given IP.

        Args:
            ip (str): The IP address

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/ips/{ip}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_user_alerts(self, username):
        """Retrieves a collection of Alerts related to a given  user ID.

        Args:
            username (str): The user ID

        Returns:
            dict. Alerts entities
        """
        cmd_url = f'/users/{username}/alerts'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_domain_machines(self, domain):
        """Retrieves a collection of Machines that have communicated to or from a given domain address.

        Args:
            domain (str): The Domain's address

        Returns:
            dict. Machines entities
        """
        cmd_url = f'/domains/{domain}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_user_machines(self, username):
        """Retrieves a collection of machines related to a given user ID.

        Args:
            username (str): The user name

        Returns:
            dict. Machines entities
        """
        cmd_url = f'/users/{username}/machines'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def add_remove_machine_tag(self, machine_id, action, tag):
        """Retrieves a collection of machines related to a given user ID.

        Args:
            machine_id (str): The machine ID
            action (str): Add or Remove action
            tag (str): The tag name

        Returns:
            dict. Updated machine's entity
        """
        cmd_url = f'/machines/{machine_id}/tags'
        new_tags = {
            "Value": tag,
            "Action": action
        }
        return self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=new_tags)

    def get_file_data(self, file_hash):
        """Retrieves a File by identifier SHA1 or SHA256.
        For more details, see the docs:
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-file-information?view=o365-worldwide#http-request
        Args:
            file_hash(str): The file hash.

        Returns:
            dict. File entities
        """
        cmd_url = f'/files/{file_hash}'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def sc_list_indicators(self, indicator_id: str | None = None, limit: int = 50, skip: int = 0, indicator_title:
                           str | None = None, indicator_value: str | None = None, indicator_type: str | None = None) -> list:
        """Lists indicators. if indicator_id supplied, will get only that indicator.

                Args:
                    indicator_id: if provided, will get only this specific id.
                    limit: Limit the returned results.
                    skip: The number of indicators that are to be skipped and not included in the result.
                    indicator_title: The title of the indicator to get.
                    indicator_value: The value of the indicator to get.
                    indicator_type: The type of the indicator to get.

                Returns:
                    List of responses.
                """
        cmd_url = urljoin(self.get_security_center_indicator_endpoint(),
                          indicator_id) if indicator_id else self.get_security_center_indicator_endpoint()
        params: dict = {'$top': limit, '$skip': skip}
        if indicator_title:
            params.setdefault("$filter", []).append(f"contains(title,'{indicator_title}')")
        if indicator_value:
            params.setdefault("$filter", []).append(f"contains(indicatorValue,'{indicator_value}')")
        if indicator_type:
            params.setdefault("$filter", []).append(f"indicatorType eq '{indicator_type}'")
        if params.get("$filter"):
            params["$filter"] = " and ".join(params["$filter"])
        resp = self.indicators_http_request(
            'GET', full_url=cmd_url, url_suffix=None, params=params, timeout=1000,
            ok_codes=(200, 204, 206, 404), resp_type='response', should_use_security_center=True)
        # 404 - No indicators found, an empty list.
        if resp.status_code == 404:
            return []

        resp = resp.json()
        values_list = resp.get('value', [])  # value list appears only when requesting indicators list
        return [assign_params(**item) for item in values_list] if values_list else [resp]

    def list_indicators(self,
                        indicator_id: str | None = None, page_size: str = '50', limit: int = 50,
                        should_use_security_center: bool = False) -> list:
        """Lists indicators. if indicator_id supplied, will get only that indicator.

        Args:
            indicator_id: if provided, will get only this specific id.
            page_size: specify the page size of the result set.
            limit: Limit the returned results.
            should_use_security_center: whether to use the security center's scope and resource.

        Returns:
            List of responses.
        """
        results = {}
        cmd_url = urljoin(self.get_graph_indicator_endpoint(), indicator_id) \
            if indicator_id else self.get_graph_indicator_endpoint()
        # For getting one indicator
        # TODO: check in the future if the filter is working. Then remove the filter function.
        # params = {'$filter': 'targetProduct=\'Microsoft Defender ATP\''}
        params = {'$top': page_size}
        resp = self.indicators_http_request(
            'GET', full_url=cmd_url, url_suffix=None, params=params, timeout=1000,
            ok_codes=(200, 204, 206, 404), resp_type='response', should_use_security_center=should_use_security_center)
        # 404 - No indicators found, an empty list.
        if resp.status_code == 404:
            return []
        resp = resp.json()
        results.update(resp)

        while next_link := resp.get('@odata.nextLink'):
            resp = self.indicators_http_request('GET', full_url=next_link, url_suffix=None,
                                                timeout=1000, should_use_security_center=should_use_security_center)
            results['value'].extend(resp.get('value'))
            if len(results['value']) >= limit:
                break

        # If 'value' is in the response, should filter and limit. The '@odata.context' key is in the root which we're
        # not returning
        if 'value' in results:
            results['value'] = list(
                filter(lambda item: item.get('targetProduct') == 'Microsoft Defender ATP', results.get('value', []))
            )
            results = results['value']
        # If a single object - should remove the '@odata.context' key.
        elif not isinstance(results, list):
            results.pop('@odata.context')
            results = [results]  # type: ignore
        return [assign_params(values_to_ignore=[None], **item) for item in results]

    def create_indicator(self, body: dict) -> dict:
        """Creates indicator from the given body.

        Args:
            body: Body represents an indicator.

        Returns:
            A response from the API.
        """
        resp = self.indicators_http_request('POST', full_url=self.get_graph_indicator_endpoint(), json_data=body,
                                            url_suffix=None, should_use_security_center=False)
        # A single object - should remove the '@odata.context' key.
        resp.pop('@odata.context')
        return assign_params(values_to_ignore=[None], **resp)

    def create_update_indicator_security_center_api(self, indicator_value: str,
                                                    indicator_type: str,
                                                    action: str,
                                                    indicator_title: str,
                                                    description: str,
                                                    expiration_date_time: str | None = None,
                                                    severity: str | None = None,
                                                    indicator_application: str | None = None,
                                                    recommended_actions: str | None = None,
                                                    rbac_group_names: list | None = None,
                                                    generate_alert: bool | None = True
                                                    ) -> dict:
        """creates or updates (if already exists) a given indicator

        Args:
            indicator_value: Value of the indicator to update.
            expiration_date_time: Expiration time of the indicator.
            description: A Brief description of the indicator.
            severity: The severity of the indicator.
            indicator_type: The type of the indicator.
            action: The action that will be taken if the indicator will be discovered.
            indicator_title: Indicator alert title.
            indicator_application: The application associated with the indicator.
            recommended_actions: TI indicator alert recommended actions.
            rbac_group_names: Comma-separated list of RBAC group names the indicator would be.
            generate_alert: Whether to generate an alert for the indicator.

        Returns:
            A response from the API.
        """
        body = {  # required params
            'indicatorValue': indicator_value,
            'indicatorType': indicator_type,
            'action': action,
            'title': indicator_title,
            'description': description,
            'generateAlert': generate_alert,
        }
        body.update(assign_params(  # optional params
            severity=severity,
            application=indicator_application,
            expirationTime=expiration_date_time,
            recommendedActions=recommended_actions,
            rbacGroupNames=rbac_group_names
        ))
        resp = self.indicators_http_request('POST', full_url=self.get_security_center_indicator_endpoint(),
                                            json_data=body, url_suffix=None, should_use_security_center=True)
        return assign_params(values_to_ignore=[None], **resp)

    def create_update_indicator_batch_security_center_api(self, body):
        """
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/import-ti-indicators?view=o365-worldwide
        """
        resp = self.indicators_http_request('POST', full_url=self.get_security_center_indicator_endpoint_batch(),
                                            json_data=body, url_suffix=None, should_use_security_center=True)
        return resp

    def update_indicator(
            self, indicator_id: str, expiration_date_time: str,
            description: str | None, severity: int | None
    ) -> dict:
        """Updates a given indicator

        Args:
            indicator_id: ID of the indicator to update.
            expiration_date_time: Expiration time of the indicator.
            description: A Brief description of the indicator.
            severity: The severity of the indicator.

        Returns:
            A response from the API.
        """
        cmd_url = urljoin(self.get_graph_indicator_endpoint(), indicator_id)
        header = {'Prefer': 'return=representation'}
        body = {
            'targetProduct': 'Microsoft Defender ATP',
            'expirationDateTime': expiration_date_time
        }
        body.update(assign_params(
            description=description,
            severity=severity
        ))
        resp = self.indicators_http_request('PATCH', full_url=cmd_url,
                                            json_data=body, url_suffix=None, headers=header,
                                            should_use_security_center=False)
        # A single object - should remove the '@odata.context' key.
        resp.pop('@odata.context')
        return assign_params(values_to_ignore=[None], **resp)

    def delete_indicator(self, indicator_id: str, indicators_endpoint: str,
                         use_security_center: bool = False) -> Response:
        """Deletes a given indicator

        Args:
            indicator_id: ID of the indicator to delete.
            indicators_endpoint: The indicator endpoint to use.
            use_security_center: whether to use the security center's scope and resource.

        Returns:
            A response from the API.
        """
        cmd_url = urljoin(indicators_endpoint, indicator_id)
        return self.indicators_http_request('DELETE', None, full_url=cmd_url,
                                            resp_type='response', should_use_security_center=use_security_center)

    def get_live_response_result(self, machine_action_id, command_index=0, overwrite_rate_limit_retry=False):
        cmd_url = f'machineactions/{machine_action_id}/GetLiveResponseResultDownloadLink(index={command_index})'
        response = self.ms_client.http_request(method='GET', url_suffix=cmd_url,
                                               overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        return response

    def create_action(self, machine_id, request_body, overwrite_rate_limit_retry=False):
        cmd_url = f'machines/{machine_id}/runliveresponse'
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=request_body,
                                               overwrite_rate_limit_retry=overwrite_rate_limit_retry)
        return response

    def download_file(self, url_link):
        try:
            response = requests.get(url=url_link, verify=self.ms_client.verify, timeout=300)
        except Exception as e:
            raise Exception(f'Could not download file. {url_link=}. error: {str(e)}')
        return response

    def cancel_action(self, action_id, request_body):
        cmd_url = f'machineactions/{action_id}/cancel'
        response = self.ms_client.http_request(method='POST', url_suffix=cmd_url, json_data=request_body)
        return response

    def get_machine_users(self, machine_id):
        """Retrieves a collection of users related to a given machine ID (logon users).
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machine-log-on-users?view=o365-worldwide

        Args:
            machine_id (str): The machine ID

        Returns:
            dict. User entities
        """
        cmd_url = f"/machines/{machine_id}/logonusers"
        try:
            response = self.ms_client.http_request(method="GET", url_suffix=cmd_url)
        except Exception:
            raise Exception(f"Machine {machine_id} was not found")
        return response

    def get_machine_alerts(self, machine_id):
        """Retrieves a collection of alerts related to a given machine ID.
        https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-machine-related-alerts?view=o365-worldwide

        Args:
            machine_id (str): The machine ID

        Returns:
            dict. Alert entities
        """
        cmd_url = f"/machines/{machine_id}/alerts"
        try:
            response = self.ms_client.http_request(method="GET", url_suffix=cmd_url)
        except Exception:
            raise Exception(f"Machine {machine_id} not found")
        return response

    def get_list_machines_by_software(self, software_id: str) -> dict:
        """Retrieve a list of device references that has this software installed.
            Args:
                software_id (str): Software ID.
            Returns:
                dict: Machines list.
        """
        cmd_url = f'/Software/{software_id}/machineReferences'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_list_software_version_distribution(self, software_id: str) -> dict:
        """Retrieves a list of your organization's software version distribution.
            Args:
                software_id (str): Software ID.
            Returns:
                dict: Version distribution list.
        """
        cmd_url = f'/Software/{software_id}/distributions'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_list_missing_kb_by_software(self, software_id: str) -> dict:
        """Retrieves missing KBs (security updates) by software ID.
            Args:
                software_id (str): Software ID.
            Returns:
                dict:  Missing kb by software list.
        """
        cmd_url = f'/Software/{software_id}/getmissingkbs'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_list_vulnerabilities_by_software(self, software_id: str) -> dict:
        """Retrieve a list of vulnerabilities in the installed software.
            Args:
                software_id (str): Software ID.
            Returns:
                dict: list vulnerabilities by software.
        """
        cmd_url = f'/Software/{software_id}/vulnerabilities'
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url)

    def get_list_software(self, filter_req: str, limit: str, offset: str) -> dict:
        """Retrieves the organization software inventory.

        Returns:
            dict. software inventory.
        """
        cmd_url = '/Software'
        params = {'$top': limit, '$skip': offset}
        if filter_req:
            params['$filter'] = filter_req

        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_list_vulnerabilities_by_machine(self, filter_req: str, limit: str, offset: str) -> dict:
        """Retrieves a list of all the vulnerabilities affecting the organization per machine.

        Returns:
            dict: list of all the vulnerabilities affecting the organization per machine.
        """
        cmd_url = '/vulnerabilities/machinesVulnerabilities'
        params = {'$top': limit, '$skip': offset}
        if filter_req:
            params['$filter'] = filter_req
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)

    def get_list_vulnerabilities(self, filter_req: str, limit: str, offset: str) -> dict:
        """Retrieves a list of all vulnerabilities.

        Returns:
            dict: list of all the vulnerabilities.
        """
        cmd_url = '/vulnerabilities'
        params = {'$top': limit, '$skip': offset}
        if filter_req:
            params['$filter'] = filter_req
        return self.ms_client.http_request(method='GET', url_suffix=cmd_url, params=params)


''' Commands '''


def get_alert_related_user_command(client: MsClient, args: dict):
    """Retrieves the User related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    response = client.get_alert_related_user(alert_id)

    user_data = get_user_data(response)
    context_output = {
        'AlertID': alert_id,
        'User': user_data
    }
    ec = {
        'MicrosoftATP.AlertUser(val.AlertID === obj.AlertID)': context_output
    }

    hr = tableToMarkdown('Alert Related User:', user_data, removeNull=True)
    return hr, ec, response


def get_user_data(user_response):
    """Get the user raw response and returns the user info in context and human readable format

    Returns:
        dict. User data
    """
    user_data = {
        'ID': user_response.get('id'),
        'AccountName': user_response.get('accountName'),
        'AccountDomain': user_response.get('accountDomain'),
        'AccountSID': user_response.get('accountSid'),
        'FirstSeen': user_response.get('firstSeen'),
        'LastSeen': user_response.get('lastSeen'),
        'MostPrevalentMachineID': user_response.get('mostPrevalentMachineId'),
        'LeastPrevalentMachineID': user_response.get('leastPrevalentMachineId'),
        'LogonTypes': user_response.get('logonTypes'),
        'LogonCount': user_response.get('logOnMachinesCount'),
        'DomainAdmin': user_response.get('isDomainAdmin'),
        'NetworkUser': user_response.get('isOnlyNetworkUser')
    }
    return user_data


def offboard_machine_command(client: MsClient, args: dict):
    """Offboard machine from defender.

    Returns:
       CommandResults. Human readable, context, raw response
    """
    if not args.get('machine_id') or not args.get('comment'):
        raise ValueError("Not all mandatory arguments are provided. Provide both machine_id and comment.")
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_ids = remove_duplicates_from_list_arg(args, 'machine_id')
    comment = args.get('comment')
    machines_action_data = []
    raw_response = []
    failed_machines = {}  # if we got an error, we will return the machine ids that failed
    for machine_id in machine_ids:
        try:
            machine_action_response = client.offboard_machine(machine_id, comment)
            raw_response.append(machine_action_response)
            machines_action_data.append(get_machine_action_data(machine_action_response))
        except Exception as e:
            # if we got an error for a machine, we want to get result for the other ones
            failed_machines[machine_id] = e
            continue

    human_readable = tableToMarkdown("The offboard request has been submitted successfully:", machines_action_data,
                                     headers=headers, removeNull=True)
    human_readable += add_error_message(failed_machines, machine_ids)

    return CommandResults(
        outputs=machines_action_data,
        outputs_prefix="MicrosoftATP.OffboardMachine",
        outputs_key_field=["ID", "MachineID"],
        readable_output=human_readable,
        raw_response=raw_response
    )


def isolate_machine_command(client: MsClient, args: dict):
    """Isolates a machine from accessing external network.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_ids = remove_duplicates_from_list_arg(args, 'machine_id')
    comment = args.get('comment')
    isolation_type = args.get('isolation_type')
    machines_action_data = []
    raw_response = []
    failed_machines = {}  # if we got an error, we will return the machine ids that failed
    for machine_id in machine_ids:
        try:
            machine_action_response = client.isolate_machine(machine_id, comment, isolation_type)
            raw_response.append(machine_action_response)
            machines_action_data.append(get_machine_action_data(machine_action_response))
        except Exception as e:
            # if we got an error for a machine, we want to get result for the other ones
            failed_machines[machine_id] = e
            continue
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machines_action_data
    }
    human_readable = tableToMarkdown("The isolation request has been submitted successfully:", machines_action_data,
                                     headers=headers, removeNull=True)
    human_readable += add_error_message(failed_machines, machine_ids)
    return human_readable, entry_context, raw_response


def unisolate_machine_command(client: MsClient, args: dict):
    """Undo isolation of a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_ids = remove_duplicates_from_list_arg(args, 'machine_id')
    comment = args.get('comment')
    machines_action_data = []
    raw_response = []
    failed_machines = {}  # if we got an error, we will return the machine ids that failed
    for machine_id in machine_ids:
        try:
            machine_action_response = client.unisolate_machine(machine_id, comment)
            raw_response.append(machine_action_response)
            machines_action_data.append(get_machine_action_data(machine_action_response))
        except Exception as e:
            # if we got an error for a machine, we want to get result for the other ones
            failed_machines[machine_id] = e
            continue
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machines_action_data
    }
    human_readable = tableToMarkdown("The request to stop the isolation has been submitted successfully.",
                                     machines_action_data, headers=headers, removeNull=True)
    human_readable += add_error_message(failed_machines, machine_ids)
    return human_readable, entry_context, raw_response


def add_error_message(failed_devices, all_requested_devices):
    human_readable = ""
    if failed_devices:
        if len(all_requested_devices) == len(failed_devices):
            raise DemistoException(f"{INTEGRATION_NAME} The command was failed with the errors: {failed_devices}")
        human_readable = "Note: you don't see the following IDs in the results as the request was failed " \
                         "for them. \n"
        for device_id in failed_devices:
            human_readable += f'ID {device_id} failed with the error: {failed_devices[device_id]} \n'
    return human_readable


def not_found_message(not_found_devices):
    human_readable = ""
    if not_found_devices:
        human_readable = f"\n You don't see the following IDs in the results as they were not found: " \
                         f"{not_found_devices}."
    return human_readable


def get_machines_command(client: MsClient, args: dict):
    """Retrieves a collection of machines that have communicated with WDATP cloud on the last 30 days
    New: now the hostname and ip args can be from type list, but only one can be given as a list (not both).

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    hostname = remove_duplicates_from_list_arg(args, 'hostname')
    ip = remove_duplicates_from_list_arg(args, 'ip')
    risk_score = args.get('risk_score', '')
    health_status = args.get('health_status', '')
    os_platform = args.get('os_platform', '')
    page_num = args.get('page_num', '')
    page_size = args.get('page_size', '')

    more_than_one_hostname = len(hostname) > 1
    more_than_one_ip = len(ip) > 1
    if more_than_one_hostname and more_than_one_ip:
        raise DemistoException("Error: only hostname or ip can be an array, not both.")
    if more_than_one_hostname:
        ip = '' if not ip else ip[0]
        field_with_multiple_values = 'computerDnsName'
    elif more_than_one_ip:
        hostname = '' if not hostname else hostname[0]
        field_with_multiple_values = 'lastIpAddress'
    else:
        # both hostname and ip are not lists (each one is empty or includes only one value)
        field_with_multiple_values = ''
        ip = '' if not ip else ip[0]
        hostname = '' if not hostname else hostname[0]

    fields_to_filter_by = {
        'computerDnsName': hostname,
        'lastIpAddress': ip,
        'riskScore': risk_score,
        'healthStatus': health_status,
        'osPlatform': os_platform
    }

    if field_with_multiple_values:
        filter_req = reformat_filter_with_list_arg(fields_to_filter_by, field_with_multiple_values)
    else:
        filter_req = reformat_filter(fields_to_filter_by)
    machines_response = client.get_machines(filter_req, page_num=page_num, page_size=page_size)
    machines_list = get_machines_list(machines_response)

    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machines_list
    }
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} Machines:', machines_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, machines_response


def get_machines_list(machines_response):
    """Get a raw response of machines list

    Args:
        machines_response (dict): The raw response with the machines list in it

    Returns:
        list. Machines list
    """
    machines_list = []
    for machine in machines_response['value']:
        machine_data = get_machine_data(machine)
        machines_list.append(machine_data)
    return machines_list


def get_machine_mac_address(machine):
    """
    return the machine MAC address where “ipAddresses[].ipAddress” = “lastIpAddress”
    """
    ip_addresses = machine.get('ipAddresses', [])
    last_ip_address = machine.get('lastIpAddress', '')
    for ip_object in ip_addresses:
        if last_ip_address and ip_object.get('ipAddress') == last_ip_address:
            return ip_object.get('macAddress', '')
    return None


def reformat_filter(fields_to_filter_by):
    """Get a dictionary with all of the fields to filter

    Args:
        fields_to_filter_by (dict): Dictionary with all the fields to filter

    Returns:
        string. Filter to send in the API request
    """
    filter_req = ' and '.join(
        f"{field_key} eq '{field_value}'" for field_key, field_value in fields_to_filter_by.items() if field_value)
    return filter_req


def reformat_filter_with_list_arg(fields_to_filter_by, field_key_from_type_list):
    """Get a dictionary with all of the fields to filter when one field is a list and create a DNF query.

    Args:
        fields_to_filter_by (dict): Dictionary with all the fields to filter
        field_key_from_type_list (str): The arg field name from type list

    Returns:
        string. Filter to send in the API request

    For example, when we get:
    fields_to_filter_by: {
                        'status': 'Succeeded',
                        'machineId': [100,200] ,
                        'type': 'RunAntiVirusScan',
                        'requestor': ''
                        }
    and
    field_key_from_type_list: 'machineId'

    we build a query looks like:
    " (machineId eq 100 and status eq Succeeded and type eq RunAntiVirusScan and requestor eq '') or
    (machineId eq 200 and status eq Succeeded and type eq RunAntiVirusScan and requestor eq '') "

    note: we have "or" operator between each clause in order to create a DNF query.
    """
    field_value_from_type_list = fields_to_filter_by.get(field_key_from_type_list)
    if not field_value_from_type_list:
        fields_to_filter_by[field_key_from_type_list] = ''
        return reformat_filter(fields_to_filter_by)
    elif len(field_value_from_type_list) == 1:
        # in case the list is empty or includes only one item
        fields_to_filter_by[field_key_from_type_list] = field_value_from_type_list[0]
        return reformat_filter(fields_to_filter_by)

    filter_conditions = []
    for item in field_value_from_type_list:
        current_fields_to_filter = {key: value for (key, value) in fields_to_filter_by.items() if
                                    key != field_key_from_type_list}
        current_fields_to_filter.update({field_key_from_type_list: item})
        filter_conditions.append(reformat_filter(current_fields_to_filter))

    return ' or '.join(f"({condition})" for condition in filter_conditions)


def get_file_related_machines_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves a collection of Machines related to a given file hash.

    Returns:
       CommandResults. Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    files = remove_duplicates_from_list_arg(args, 'file_hash')
    raw_response = []
    context_outputs = []
    all_machines_outputs = []
    failed_files = {}  # if we got an error, we will return the file that failed

    for file in files:
        try:
            machines_response = client.get_file_related_machines(file)
            raw_response.append(machines_response)
            for machine in machines_response['value']:
                all_machines_outputs.append(get_machine_data(machine))
            context_outputs.append({
                'File': file,
                'Machines': get_machines_list(machines_response)
            })
        except Exception as e:
            failed_files[file] = e
            continue

    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} machines related to files {files}', all_machines_outputs,
                                     headers=headers, removeNull=True)
    human_readable += add_error_message(failed_files, files)
    return CommandResults(readable_output=human_readable,
                          outputs=context_outputs,
                          outputs_prefix="MicrosoftATP.FileMachine",
                          raw_response=raw_response)


def parse_ip_addresses(ip_addresses: list[dict]) -> list[dict]:
    """
    Creates new dict with readable keys and concat all the ip addresses with the same MAC address.
    Args:
        ip_addresses (List[Dict]): List of ip addresses dictionaries as recieved from the api.

    Returns:
        List of dicts
    """
    mac_addresses = dict.fromkeys([item.get('macAddress') for item in ip_addresses])
    for item in ip_addresses:
        current_mac = item.get('macAddress')
        if not mac_addresses[current_mac]:
            mac_addresses[current_mac] = {
                'MACAddress': item['macAddress'],
                'IPAddresses': [item['ipAddress']],
                'Type': item['type'],
                'Status': item['operationalStatus']
            }
        else:
            mac_addresses[current_mac]['IPAddresses'].append(item['ipAddress'])  # type: ignore

    return list(mac_addresses.values())  # type: ignore


def print_ip_addresses(parsed_ip_addresses: list[dict]) -> str:
    """
    Converts the given list of ip addresses to ascii table.
    Args:
        parsed_ip_addresses (List[Dict]):

    Returns:
        ascii table without headers
    """

    rows = []
    for i, entry in enumerate(parsed_ip_addresses, start=1):
        rows.append([f"{i}.", f"MAC : {entry['MACAddress']}", f"IP Addresses : {','.join(entry['IPAddresses'])}",
                     f"Type : {entry['Type']}", f"Status : {entry['Status']}"])
    max_lengths = [len(max(col, key=lambda x: len(x))) for col in zip(*rows)]  # to make sure the table is pretty
    string_rows = [' | '.join([cell.ljust(max_len_col) for cell, max_len_col in zip(row, max_lengths)]) for row in rows]

    return '\n'.join(string_rows)


def get_machine_details_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves specific Machine by its machine ID or computer name.

    Returns:
        CommandResults. Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel', 'IPAddresses']
    machine_ids = remove_duplicates_from_list_arg(args, 'machine_id')
    raw_response = []
    machines_outputs = []
    machines_readable_outputs = []
    failed_machines = {}  # if we got an error, we will return the machine ids that failed
    for machine_id in machine_ids:
        try:
            machine_response = client.get_machine_details(machine_id)
            machine_data = get_machine_data(machine_response)

            machine_data_to_readable_outputs = copy.deepcopy(machine_data)
            raw_ip_addresses = machine_data_to_readable_outputs.get('IPAddresses', [])
            parsed_ip_address = parse_ip_addresses(raw_ip_addresses)
            human_readable_ip_addresses = print_ip_addresses(parsed_ip_address)
            machine_data_to_readable_outputs['IPAddresses'] = human_readable_ip_addresses

            machines_outputs.append(machine_data)
            machines_readable_outputs.append(machine_data_to_readable_outputs)
            raw_response.append(machine_response)
        except Exception as e:
            failed_machines[machine_id] = e
            continue

    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} machines {machine_ids} details:',
                                     machines_readable_outputs, headers=headers, removeNull=True)
    human_readable += add_error_message(failed_machines, machine_ids)
    return CommandResults(
        outputs_prefix='MicrosoftATP.Machine',
        outputs_key_field='ID',
        outputs=machines_outputs,
        readable_output=human_readable,
        raw_response=raw_response)


def run_antivirus_scan_command(client: MsClient, args: dict):
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_ids = remove_duplicates_from_list_arg(args, 'machine_id')
    scan_type = args.get('scan_type')
    comment = args.get('comment')
    machine_actions_data = []
    raw_response = []
    failed_machines = {}  # if we got an error, we will return the machine ids that failed
    for machine_id in machine_ids:
        try:
            machine_action_response = client.run_antivirus_scan(machine_id, comment, scan_type)
            machine_actions_data.append(get_machine_action_data(machine_action_response))
            raw_response.append(machine_action_response)
        except Exception as e:
            failed_machines[machine_id] = e
            continue

    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': machine_actions_data
    }
    human_readable = tableToMarkdown('Antivirus scan successfully triggered', machine_actions_data, headers=headers,
                                     removeNull=True)
    human_readable += add_error_message(failed_machines, machine_ids)
    return human_readable, entry_context, raw_response


def list_alerts_command(client: MsClient, args: dict):
    """Initiate Windows Defender Antivirus scan on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    severity = args.get('severity')
    status = args.get('status')
    category = args.get('category')
    limit = arg_to_number(args.get('limit', 50))
    creation_time = arg_to_datetime(args.get('creation_time'), required=False)
    fields_to_filter_by = {
        'severity': severity,
        'status': status,
        'category': category,
    }
    filter_req = reformat_filter(fields_to_filter_by)
    alerts_response = client.list_alerts(filter_req, limit, creation_time=creation_time, evidence=True)
    alerts_list = get_alerts_list(alerts_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alerts_list
    }
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} alerts with limit of {limit}:', alerts_list,
                                     headers=headers, removeNull=True)
    return human_readable, entry_context, alerts_response


def get_alerts_list(alerts_response):
    """Get a raw response of alerts list

    Args:
        alerts_response (dict): The raw response with the alerts list in it

    Returns:
        list. Alerts list
    """
    alerts_list = []
    for alert in alerts_response['value']:
        alert_data = get_alert_data(alert)
        alerts_list.append(alert_data)
    return alerts_list


def update_alert_command(client: MsClient, args: dict):
    """Updates properties of existing Alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('alert_id')
    assigned_to = args.get('assigned_to')
    status = args.get('status')
    classification = args.get('classification')
    determination = args.get('determination')
    comment = args.get('comment')

    args_list = [assigned_to, status, classification, determination, comment]
    check_given_args_update_alert(args_list)
    json_data, context = add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination,
                                                      comment)
    alert_response = client.update_alert(alert_id, json_data)
    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': context
    }
    human_readable = f'The alert {alert_id} has been updated successfully'
    return human_readable, entry_context, alert_response


def check_given_args_update_alert(args_list):
    """Gets an arguments list and returns an error if all of them are empty
    """
    if all(v is None for v in args_list):
        raise Exception('No arguments were given to update the alert')


def add_args_to_json_and_context(alert_id, assigned_to, status, classification, determination, comment):
    """Gets arguments and returns the json and context with the arguments inside
    """
    json_data = {}
    context = {
        'ID': alert_id
    }
    if assigned_to:
        json_data['assignedTo'] = assigned_to
        context['AssignedTo'] = assigned_to
    if status:
        json_data['status'] = status
        context['Status'] = status
    if classification:
        json_data['classification'] = classification
        context['Classification'] = classification
    if determination:
        json_data['determination'] = determination
        context['Determination'] = determination
    if comment:
        json_data['comment'] = comment
        context['Comment'] = comment
    return json_data, context


def get_advanced_hunting_command(client: MsClient, args: dict):
    """Get results of advanced hunting according to user query.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    query = args.get('query', '')
    query_batch = args.get('query_batch', '')
    if query and query_batch:
        raise DemistoException('Both query and query_batch were given, please provide just one')
    if not query and not query_batch:
        raise DemistoException('Both query and query_batch were not given, please provide one')

    queries: list[dict[str, str]] = []
    if query:
        queries.append({'timeout': args.get('timeout', '10'),
                        'time_range': args.get('time_range', ''),
                        'name': args.get('name', ''),
                        'query': query
                        })
    else:
        query = safe_load_json(query_batch)
        queries.extend(query)

    if len(queries) > 10:
        raise DemistoException('Please provide only up to 10 queries.')

    human_readable = ''
    outputs = []
    for query_details in queries:
        query = query_details.get('query')
        name = query_details.get('name')
        timeout = int(query_details.get('timeout', '') or args.get('timeout', 10))
        time_range = query_details.get('time_range') or args.get('time_range', '')

        response = client.get_advanced_hunting(query, timeout, time_range)
        results: dict[str, Any] = response.get('Results', {})
        if isinstance(results, list) and len(results) == 1:
            report_id = results[0].get('ReportId')
            if report_id:
                results[0]['ReportId'] = str(report_id)
        if name:
            outputs.append({name: results})
        else:
            outputs = [results]
        human_readable += tableToMarkdown(f'Hunt results for {name} query:', results, removeNull=True)

    if len(outputs) == 1:
        entry_context: dict[str, Any] = {
            'MicrosoftATP.Hunt.Result': outputs[0]
        }
    else:
        entry_context = {
            'MicrosoftATP.Hunt.Result': outputs
        }
    return human_readable, entry_context, response


def create_alert_command(client: MsClient, args: dict):
    """Creates new Alert on top of Event.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    alert_response = client.create_alert(
        args.get('machine_id'),
        args.get('severity'),
        args.get('title'),
        args.get('description'),
        args.get('event_time'),
        args.get('report_id'),
        args.get('recommended_action'),
        args.get('category')
    )
    alert_data = get_alert_data(alert_response)

    entry_context = {
        'MicrosoftATP.Alert(val.ID === obj.ID)': alert_data
    }
    human_readable = tableToMarkdown('Alert created:', alert_data, headers=headers, removeNull=True)
    return human_readable, entry_context, alert_response


def get_alert_related_files_command(client: MsClient, args: dict):
    """Retrieves all files related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['Sha1', 'Sha256', 'SizeInBytes', 'FileType', 'FilePublisher', 'FileProductName']
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = client.get_alert_related_files(alert_id)
    response_files_list = response['value']

    files_data_list = []
    from_index = min(offset, len(response_files_list))
    to_index = min(offset + limit, len(response_files_list))
    for file_obj in response_files_list[from_index:to_index]:
        files_data_list.append(get_file_data(file_obj))

    context_output = {
        'AlertID': alert_id,
        'Files': files_data_list
    }
    entry_context = {
        'MicrosoftATP.AlertFile(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = tableToMarkdown(f'Alert {alert_id} Related Files:', files_data_list, headers=headers,
                                     removeNull=True)
    return human_readable, entry_context, response_files_list


def check_limit_and_offset_values(limit, offset):
    """Gets the limit and offset values and return an error if the values are invalid
    """
    if not limit.isdigit():
        raise Exception("Error: You can only enter a positive integer or zero to limit argument.")
    elif not offset.isdigit():
        raise Exception("Error: You can only enter a positive integer to offset argument.")
    else:
        limit_int = int(limit)
        offset_int = int(offset)

        if limit_int == 0:
            raise Exception("Error: The value of the limit argument must be a positive integer.")

        return limit_int, offset_int


def get_file_data(file_response):
    """Get file raw response and returns the file's info for context and human readable.

    Returns:
        dict. File's info
    """
    file_data = assign_params(
        Sha1=file_response.get('sha1'),
        Size=file_response.get('size'),
        Sha256=file_response.get('sha256'),
        Md5=file_response.get('md5'),
        GlobalPrevalence=file_response.get('globalPrevalence'),
        GlobalFirstObserved=file_response.get('globalFirstObserved'),
        GlobalLastObserved=file_response.get('globalLastObserved'),
        SizeInBytes=file_response.get('size'),
        FileType=file_response.get('fileType'),
        IsPeFile=file_response.get('isPeFile'),
        FilePublisher=file_response.get('filePublisher'),
        FileProductName=file_response.get('fileProductName'),
        Signer=file_response.get('signer'),
        Issuer=file_response.get('issuer'),
        SignerHash=file_response.get('signerHash'),
        IsValidCertificate=file_response.get('isValidCertificate'),
        DeterminationType=file_response.get('determinationType'),
        DeterminationValue=file_response.get('determinationValue'),
    )
    return file_data


def get_alert_related_ips_command(client: MsClient, args: dict):
    """Retrieves all IPs related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    response = client.get_alert_related_ips(alert_id)
    response_ips_list = response['value']

    ips_list = []
    from_index = min(offset, len(response_ips_list))
    to_index = min(offset + limit, len(response_ips_list))

    for ip in response_ips_list[from_index:to_index]:
        ips_list.append(ip['id'])

    context_output = {
        'AlertID': alert_id,
        'IPs': ips_list
    }
    entry_context = {
        'MicrosoftATP.AlertIP(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related IPs: {ips_list}'
    return human_readable, entry_context, response_ips_list


def get_alert_related_domains_command(client: MsClient, args: dict):
    """Retrieves all domains related to a specific alert.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    alert_id = args.get('id')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)
    response = client.get_alert_related_domains(alert_id)
    response_domains_list = response['value']
    domains_list = []
    from_index = min(offset, len(response_domains_list))
    to_index = min(offset + limit, len(response_domains_list))
    for domain in response_domains_list[from_index:to_index]:
        domains_list.append(domain['host'])
    context_output = {
        'AlertID': alert_id,
        'Domains': domains_list
    }
    entry_context = {
        'MicrosoftATP.AlertDomain(val.AlertID === obj.AlertID)': context_output
    }
    human_readable = f'Alert {alert_id} Related Domains: {domains_list}'
    return human_readable, entry_context, response_domains_list


def get_machine_action_by_id_command(client: MsClient, args: dict):
    """Returns machine's actions, if action ID is None, return all actions.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    action_id = args.get('id', '')
    status = args.get('status', '')
    machine_id = remove_duplicates_from_list_arg(args, 'machine_id')
    type = args.get('type', '')
    requestor = args.get('requestor', '')
    filters = args.get('filters', '')
    limit = arg_to_number(args.get('limit', 50))
    if action_id:
        for index in range(3):
            try:
                response = client.get_machine_action_by_id(action_id)
                if response:
                    break
            except Exception as e:
                if 'ResourceNotFound' in str(e) and index < 3:
                    time.sleep(1)
                else:
                    raise Exception(f'Machine action {action_id} was not found')
        response = client.get_machine_action_by_id(action_id)
        action_data = get_machine_action_data(response)
        human_readable = tableToMarkdown(f'Action {action_id} Info:', action_data, headers=headers, removeNull=True)
        context_output = action_data
    else:
        # A dictionary that contains all of the fields the user want to filter results by.
        # It will be sent in the request so the requested filters are applied on the results
        fields_to_filter_by = {
            'status': status,
            'machineId': machine_id,
            'type': type,
            'requestor': requestor
        }
        filter_req = filters or reformat_filter_with_list_arg(fields_to_filter_by, "machineId")
        response = client.get_machine_actions(filter_req, limit)
        machine_actions_list = []
        for machine_action in response['value']:
            machine_actions_list.append(get_machine_action_data(machine_action))
        human_readable = tableToMarkdown(f'Machine actions Info with limit of {limit}:',
                                         machine_actions_list, headers=headers, removeNull=True)
        context_output = machine_actions_list
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_machine_investigation_package(client: MsClient, args: dict):

    machine_id = args.get('machine_id')
    comment = args.get('comment')
    res = client.get_investigation_package(machine_id, comment, overwrite_rate_limit_retry=True)
    human_readable = tableToMarkdown('Processing action. This may take a few minutes.', res['id'], headers=['id'])

    return CommandResults(outputs_prefix='MicrosoftATP.MachineAction',
                          readable_output=human_readable, outputs={'action_id': res['id']})


def request_download_investigation_package_command(client: MsClient, args: dict):
    return run_polling_command(client, args, 'microsoft-atp-request-and-download-investigation-package',
                               get_machine_investigation_package,
                               get_machine_action_command, download_file_after_successful_status)


def generate_login_url_command(client: MsClient):
    return generate_login_url(client.ms_client,
                              MICROSOFT_DEFENDER_FOR_ENDPOINT_TOKEN_RETRIVAL_ENDPOINTS[client.endpoint_type])


def download_file_after_successful_status(client, res):
    demisto.debug("post polling - download file")
    machine_action_id = res['id']

    # get file uri from action:
    file_uri = client.get_investigation_package_sas_uri(machine_action_id, overwrite_rate_limit_retry=True)['value']
    demisto.debug(f'Got file for downloading: {file_uri}')

    # download link, create file result. File comes back as compressed gz file.
    f_data = client.download_file(file_uri)
    md_results = {
        'Machine Action Id': res.get('id'),
        'MachineId': res.get('machineId'),
        'Status': res.get('status'),
    }
    return [fileResult('Response Result.gz', f_data.content),
            CommandResults(
                outputs_prefix='MicrosoftATP.MachineAction',
                outputs=res,
                readable_output=tableToMarkdown('Machine Action:', md_results)
    )]


def get_machine_action_data(machine_action_response):
    """Get machine raw response and returns the machine action info in context and human readable format.

    Notes:
         Machine action is a collection of actions you can apply on the machine, for more info
         https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/machineaction

    Returns:
        dict. Machine action's info
    """
    action_data = \
        {
            "ID": machine_action_response.get('id'),
            "Type": machine_action_response.get('type'),
            "Scope": machine_action_response.get('scope'),
            "Requestor": machine_action_response.get('requestor'),
            "RequestorComment": machine_action_response.get('requestorComment'),
            "Status": machine_action_response.get('status'),
            "MachineID": machine_action_response.get('machineId'),
            "ComputerDNSName": machine_action_response.get('computerDnsName'),
            "CreationDateTimeUtc": machine_action_response.get('creationDateTimeUtc'),
            "LastUpdateTimeUtc": machine_action_response.get('lastUpdateTimeUtc'),
            "RelatedFileInfo": {
                "FileIdentifier": machine_action_response.get('fileIdentifier'),
                "FileIdentifierType": machine_action_response.get('fileIdentifierType')
            },
            "Commands": machine_action_response.get('commands')
        }
    return action_data


def get_machine_investigation_package_command(client: MsClient, args: dict):
    """Collect investigation package from a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.get_investigation_package(machine_id, comment)
    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating collect investigation package from {machine_id} machine :',
                                     action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def get_investigation_package_sas_uri_command(client: MsClient, args: dict):
    """Returns a URI that allows downloading an Investigation package.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    action_id = args.get('action_id')
    response = client.get_investigation_package_sas_uri(action_id)
    link = {'Link': response['value']}
    human_readable = f'Success. This link is valid for a very short time and should be used immediately for' \
                     f' downloading the package to a local storage{link["Link"]}'
    entry_context = {
        'MicrosoftATP.InvestigationURI(val.Link === obj.Link)': link
    }
    return human_readable, entry_context, response


def restrict_app_execution_command(client: MsClient, args: dict):
    """Restrict execution of all applications on the machine except a predefined set.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.restrict_app_execution(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Initiating Restrict execution of all applications on the machine {machine_id} '
                                     f'except a predefined set:', action_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def remove_app_restriction_command(client: MsClient, args: dict):
    """Enable execution of any application on the machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    machine_action_response = client.remove_app_restriction(machine_id, comment)

    action_data = get_machine_action_data(machine_action_response)
    human_readable = tableToMarkdown(f'Removing applications restriction on the machine {machine_id}:', action_data,
                                     headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.MachineAction(val.ID === obj.ID)': action_data
    }
    return human_readable, entry_context, machine_action_response


def stop_and_quarantine_file_command(client: MsClient, args: dict):
    """Stop execution of a file on a machine and delete it.

    Returns:
         CommandResults
    """
    headers = ['ID', 'Type', 'Requestor', 'RequestorComment', 'Status', 'MachineID', 'ComputerDNSName']
    machine_ids = argToList(args.get('machine_id'))
    file_sha1s = argToList(args.get('file_hash'))
    comment = args.get('comment')
    command_results = []
    for machine_id, file_sha1 in product(machine_ids, file_sha1s):
        machine_action_response = client.stop_and_quarantine_file(machine_id, file_sha1, comment)
        action_data = get_machine_action_data(machine_action_response)
        human_readable = tableToMarkdown(f'Stopping the execution of a file on {machine_id} machine and deleting it:',
                                         action_data, headers=headers, removeNull=True)

        command_results.append(CommandResults(outputs_prefix='MicrosoftATP.MachineAction', outputs_key_field='id',
                                              readable_output=human_readable, outputs=action_data,
                                              raw_response=machine_action_response))
    return command_results


def get_investigations_by_id_command(client: MsClient, args: dict):
    """Returns the investigation info, if investigation ID is None, return all investigations.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    investigation_id = args.get('id', '')
    limit = args.get('limit')
    offset = args.get('offset')
    limit, offset = check_limit_and_offset_values(limit, offset)

    if investigation_id:
        response = client.get_investigation_by_id(investigation_id)
        investigation_data = get_investigation_data(response)
        human_readable = tableToMarkdown(f'Investigation {investigation_id} Info:', investigation_data, headers=headers,
                                         removeNull=True)
        context_output = investigation_data
    else:
        response = client.get_investigation_list()['value']
        investigations_list = []
        from_index = min(offset, len(response))
        to_index = min(offset + limit, len(response))
        for investigation in response[from_index:to_index]:
            investigations_list.append(get_investigation_data(investigation))
        human_readable = tableToMarkdown('Investigations Info:', investigations_list, headers=headers, removeNull=True)
        context_output = investigations_list
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': context_output
    }
    return human_readable, entry_context, response


def get_investigation_data(investigation_response):
    """Get investigation raw response and returns the investigation info for context and human readable.

    Args:
        investigation_response: The investigation raw response
    Returns:
        dict. Investigation's info
    """
    investigation_data = {
        "ID": investigation_response.get('id'),
        "StartTime": investigation_response.get('startTime'),
        "EndTime": investigation_response.get('endTime'),
        "InvestigationState": investigation_response.get('state'),
        "CancelledBy": investigation_response.get('cancelledBy'),
        "StatusDetails": investigation_response.get('statusDetails'),
        "MachineID": investigation_response.get('machineId'),
        "ComputerDNSName": investigation_response.get('computerDnsName'),
        "TriggeringAlertID": investigation_response.get('triggeringAlertId')
    }
    return investigation_data


def start_investigation_command(client: MsClient, args: dict):
    """Start automated investigation on a machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'StartTime', 'EndTime', 'CancelledBy', 'InvestigationState', 'StatusDetails', 'MachineID',
               'ComputerDNSName', 'TriggeringAlertID']
    machine_id = args.get('machine_id')
    comment = args.get('comment')
    timeout = int(args.get('timeout', 50))
    response = client.start_investigation(machine_id, comment, timeout)
    investigation_id = response['id']
    investigation_data = get_investigation_data(response)
    human_readable = tableToMarkdown(f'Starting investigation {investigation_id} on {machine_id} machine:',
                                     investigation_data, headers=headers, removeNull=True)
    entry_context = {
        'MicrosoftATP.Investigation(val.ID === obj.ID)': investigation_data
    }
    return human_readable, entry_context, response


def get_domain_statistics_command(client: MsClient, args: dict):
    """Retrieves the statistics on the given domain.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    domain = args.get('domain')
    response = client.get_domain_statistics(domain)
    domain_statistics = get_domain_statistics_context(response)
    human_readable = tableToMarkdown(f'Statistics on {domain} domain:', domain_statistics, removeNull=True)

    context_output = {
        'Domain': domain,
        'Statistics': domain_statistics
    }
    entry_context = {
        'MicrosoftATP.DomainStatistics(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_domain_statistics_context(domain_stat_response):
    """Gets the domain statistics response and returns it in context format.

    Returns:
        (dict). domain statistics context
    """
    domain_statistics = assign_params(
        Host=domain_stat_response.get('host'),
        OrgPrevalence=domain_stat_response.get('orgPrevalence'),
        OrgFirstSeen=domain_stat_response.get('orgFirstSeen'),
        OrgLastSeen=domain_stat_response.get('orgLastSeen'),
    )
    return domain_statistics


def get_domain_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    domain = args.get('domain')
    response = client.get_domain_alerts(domain)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'Domain {domain} related alerts Info:', alerts_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Domain': domain,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.DomainAlert(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_alert_data(alert_response):
    """Get alert raw response and returns the alert info in context and human readable format.

    Returns:
        dict. Alert info
    """
    alert_data = {
        "ID": alert_response.get('id'),
        "IncidentID": alert_response.get('incidentId'),
        "InvestigationID": alert_response.get('investigationId'),
        "InvestigationState": alert_response.get('investigationState'),
        "AssignedTo": alert_response.get('assignedTo'),
        "Severity": alert_response.get('severity'),
        "Status": alert_response.get('status'),
        "Classification": alert_response.get('classification'),
        "Determination": alert_response.get('determination'),
        "DetectionSource": alert_response.get('detectionSource'),
        "Category": alert_response.get('category'),
        "ThreatFamilyName": alert_response.get('threatFamilyName'),
        "Title": alert_response.get('title'),
        "Description": alert_response.get('description'),
        "AlertCreationTime": alert_response.get('alertCreationTime'),
        "FirstEventTime": alert_response.get('firstEventTime'),
        "LastEventTime": alert_response.get('lastEventTime'),
        "LastUpdateTime": alert_response.get('lastUpdateTime'),
        "ResolvedTime": alert_response.get('resolvedTime'),
        "MachineID": alert_response.get('machineId'),
        "ComputerDNSName": alert_response.get('computerDnsName'),
        "AADTenantID": alert_response.get('aadTenantId'),
        "Comments": [
            {
                "Comment": alert_response.get('comment'),
                "CreatedBy": alert_response.get('createdBy'),
                "CreatedTime": alert_response.get('createdTime')
            }
        ],
        "Evidence": alert_response.get('evidence'),
        "DetectorID": alert_response.get('detectorId'),
        "ThreatName": alert_response.get('threatName'),
        "RelatedUser": alert_response.get('relatedUser'),
        "MitreTechniques": alert_response.get('mitreTechniques'),
        "RBACGroupName": alert_response.get('rbacGroupName'),
    }
    return alert_data


def get_domain_machine_command(client: MsClient, args: dict):
    """Retrieves a collection of Machines that have communicated to or from a given domain address.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """

    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    domain = args.get('domain')
    response = client.get_domain_machines(domain)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that have communicated with {domain} domain:', machines_list,
                                     headers=headers, removeNull=True)
    context_output = {
        'Domain': domain,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.DomainMachine(val.Domain === obj.Domain)': context_output
    }
    return human_readable, entry_context, response


def get_machine_data(machine):
    """Get machine raw response and returns the machine's info in context and human readable format.

    Returns:
        dict. Machine's info
    """
    machine_data = assign_params(
        ID=machine.get('id'),
        ComputerDNSName=machine.get('computerDnsName'),
        FirstSeen=machine.get('firstSeen'),
        LastSeen=machine.get('lastSeen'),
        OSPlatform=machine.get('osPlatform'),
        OSVersion=machine.get('version'),
        OSProcessor=machine.get('osProcessor'),
        LastIPAddress=machine.get('lastIpAddress'),
        LastExternalIPAddress=machine.get('lastExternalIpAddress'),
        AgentVersion=machine.get('agentVersion'),
        OSBuild=machine.get('osBuild'),
        HealthStatus=machine.get('healthStatus'),
        RBACGroupID=machine.get('rbacGroupId'),
        RBACGroupName=machine.get('rbacGroupName'),
        RiskScore=machine.get('riskScore'),
        ExposureLevel=machine.get('exposureLevel'),
        AADDeviceID=machine.get('aadDeviceId'),
        IsAADJoined=machine.get('isAadJoined'),
        MachineTags=machine.get('machineTags'),
        IPAddresses=machine.get('ipAddresses'),
    )
    return machine_data


def get_file_statistics_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves the statistics on the given file.

    Returns:
        CommandResults.
    """
    file_hash = args.get('file_hash', '')
    response = client.get_file_statistics(file_hash)
    file_stats = FileStatisticsAPIParser.from_raw_response(response)

    return CommandResults(
        outputs_prefix='MicrosoftATP.FileStatistics',
        outputs_key_field='Sha1',
        indicator=file_stats.to_file_indicator(file_hash),
        readable_output=file_stats.to_human_readable(file_hash),
        outputs=file_stats.to_context_output(),
        raw_response=response,
    )


def get_file_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given file hash.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    file_sha1 = args.get('file_hash')
    response = client.get_file_alerts(file_sha1)
    alerts_list = get_alerts_list(response)
    hr = tableToMarkdown(f'File {file_sha1} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'Sha1': file_sha1,
        'Alerts': alerts_list
    }
    ec = {
        'MicrosoftATP.FileAlert(val.Sha1 === obj.Sha1)': context_output
    }
    return hr, ec, response


def get_ip_statistics_command(client: MsClient, args: dict):
    """Retrieves the statistics on the given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    ip = args.get('ip')
    response = client.get_ip_statistics(ip)
    ip_statistics = get_ip_statistics_context(response)
    hr = tableToMarkdown(f'Statistics on {ip} IP:', ip_statistics, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Statistics': ip_statistics
    }
    ec = {
        'MicrosoftATP.IPStatistics(val.IPAddress === obj.IPAddress)': context_output
    }
    return hr, ec, response


def get_ip_statistics_context(ip_statistics_response):
    """Gets the IP statistics response and returns it in context format.

    Returns:
        (dict). IP statistics context
    """
    ip_statistics = assign_params(
        OrgPrevalence=ip_statistics_response.get('orgPrevalence'),
        OrgFirstSeen=ip_statistics_response.get('orgFirstSeen'),
        OrgLastSeen=ip_statistics_response.get('orgLastSeen')
    )
    return ip_statistics


def get_ip_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given IP.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    ip = args.get('ip')
    response = client.get_ip_alerts(ip)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'IP {ip} related alerts Info:', alerts_list, headers=headers, removeNull=True)
    context_output = {
        'IPAddress': ip,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.IPAlert(val.IPAddress === obj.IPAddress)': context_output
    }
    return human_readable, entry_context, response


def get_user_alerts_command(client: MsClient, args: dict):
    """Retrieves a collection of Alerts related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    username = args.get('username')
    response = client.get_user_alerts(username)
    alerts_list = get_alerts_list(response)
    human_readable = tableToMarkdown(f'User {username} related alerts Info:', alerts_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Username': username,
        'Alerts': alerts_list
    }
    entry_context = {
        'MicrosoftATP.UserAlert(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def get_alert_by_id_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves a specific alert by the given ID.

    Returns:
        CommandResults.
    """
    headers = ['ID', 'Title', 'Description', 'IncidentID', 'Severity', 'Status', 'Classification', 'Category',
               'ThreatFamilyName', 'MachineID']
    alert_ids = remove_duplicates_from_list_arg(args, 'alert_ids')
    raw_response = []
    alert_outputs = []
    failed_alerts = {}  # if we got an error, we will return the machine ids that failed
    not_found_ids = []

    for alert in alert_ids:
        try:
            alert_response = client.get_alert_by_id(alert)
            alerts_data = get_alert_data(alert_response)
            raw_response.append(alert_response)
            alert_outputs.append(alerts_data)
        except NotFoundError:  # in case the error is not found alert id, we want to return "No entries"
            not_found_ids.append(alert)
            continue
        except Exception as e:
            failed_alerts[alert] = e
            continue

    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} Alerts Info for IDs {alert_ids}:', alert_outputs,
                                     headers=headers, removeNull=True)
    human_readable += add_error_message(failed_alerts, alert_ids)
    human_readable += not_found_message(not_found_ids)
    return CommandResults(outputs_prefix="MicrosoftATP.Alert", outputs=alert_outputs, readable_output=human_readable,
                          raw_response=raw_response, outputs_key_field="ID")


def get_user_machine_command(client: MsClient, args: dict):
    """Retrieves a collection of machines related to a given user ID.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIPAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel']
    username = args.get('username')
    response = client.get_user_machines(username)
    machines_list = get_machines_list(response)
    human_readable = tableToMarkdown(f'Machines that are related to user {username}:', machines_list, headers=headers,
                                     removeNull=True)
    context_output = {
        'Username': username,
        'Machines': machines_list
    }
    entry_context = {
        'MicrosoftATP.UserMachine(val.Username === obj.Username)': context_output
    }
    return human_readable, entry_context, response


def add_remove_machine_tag_command(client: MsClient, args: dict):
    """Adds or remove tag to a specific Machine.

    Returns:
        (str, dict, dict). Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'LastIpAddress', 'LastExternalIPAddress', 'HealthStatus',
               'RiskScore', 'ExposureLevel', 'MachineTags']
    machine_id = args.get('machine_id')
    action = args.get('action')
    tag = args.get('tag')
    response = client.add_remove_machine_tag(machine_id, action, tag)
    machine_data = get_machine_data(response)
    human_readable = tableToMarkdown(f'Succeed to {action} tag to {machine_id}:', machine_data, headers=headers,
                                     removeNull=True)
    entry_context = {
        'MicrosoftATP.Machine(val.ID === obj.ID)': machine_data
    }
    return human_readable, entry_context, response


def fetch_incidents(client: MsClient, last_run, fetch_evidence):

    demisto.debug("Microsoft-ATP - Start fetching")

    first_fetch_time = dateparser.parse(client.alert_time_to_fetch,
                                        settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'})
    demisto.debug(f'First fetch time: {first_fetch_time}')

    if last_run:
        demisto.debug(f"Microsoft-ATP - Last run: {json.dumps(last_run)}")
        last_fetch_time = last_run.get('last_alert_fetched_time')
        last_fetch_time = datetime.strftime(parse_date_string(last_fetch_time) + timedelta(milliseconds=1), TIME_FORMAT)
        # handling old version of time format:
        if not last_fetch_time.endswith('Z'):
            last_fetch_time = last_fetch_time + "Z"

    else:
        last_fetch_time = datetime.strftime(first_fetch_time, TIME_FORMAT)  # type: ignore
        demisto.debug(f"Microsoft-ATP - Last run: {last_fetch_time}")

    latest_created_time = dateparser.parse(last_fetch_time,
                                           settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'})
    demisto.debug(f'latest_created_time: {latest_created_time}')

    params = _get_incidents_query_params(client, fetch_evidence, last_fetch_time)
    demisto.debug(f"Microsoft-ATP - Query sent to the server: {params}")
    incidents = []
    # get_alerts:
    try:
        alerts = client.list_alerts_by_params(params=params, overwrite_rate_limit_retry=True)['value']
    except DemistoException as err:
        big_query_err_msg = 'Verify that the server URL parameter is correct and that you have access to the server' \
                            ' from your host.'
        if str(err).startswith(big_query_err_msg):
            demisto.debug(f'Query crashed API, probably due to a big response. Params sent to query: {params}')
            raise Exception(
                f'Failed to fetch {client.max_alerts_to_fetch} alerts. This may caused due to large amount of alert. '
                f'Try using a lower limit.')
        demisto.debug(f'Query crashed API. Params sent to query: {params}')
        raise err
    skipped_incidents = 0

    for alert in alerts:
        alert_time = dateparser.parse(alert['alertCreationTime'],
                                      settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'})
        # to prevent duplicates, adding incidents with creation_time > last fetched incident
        if last_fetch_time:
            parsed = dateparser.parse(last_fetch_time, settings={'RETURN_AS_TIMEZONE_AWARE': True, 'TIMEZONE': 'UTC'})
            demisto.debug(f'Checking alert {alert["id"]} with parsed time {parsed}. last alert time is {alert_time}')
            if alert_time <= parsed:  # type: ignore
                skipped_incidents += 1
                demisto.debug(f'Microsoft - ATP - Skipping incident with id={alert["id"]} with time {alert_time} because its'
                              ' creation time is smaller than the last fetch.')
                continue
        demisto.debug(f'Adding alert {alert["id"]}')
        incidents.append({
            'rawJSON': json.dumps(alert),
            'name': f'{INTEGRATION_NAME} Alert {alert["id"]}',
            'occurred': alert['alertCreationTime'],
            'dbotMirrorId': alert["id"]
        })

        # Update last run and add incident if the incident is newer than last fetch
        if alert_time > latest_created_time:  # type: ignore
            demisto.debug(f'Updating last created time to {alert_time}')
            latest_created_time = alert_time  # type: ignore

    # last alert is the newest as we ordered by it ascending
    demisto.debug(f'Microsoft-ATP - Next run after incidents fetching: {latest_created_time}')
    demisto.debug(f"Microsoft-ATP - Number of incidents before filtering: {len(alerts)}")
    demisto.debug(f"Microsoft-ATP - Number of incidents after filtering: {len(incidents)}")
    demisto.debug(f"Microsoft-ATP - Number of incidents skipped: {skipped_incidents}")
    last_run['last_alert_fetched_time'] = datetime.strftime(latest_created_time, TIME_FORMAT)  # type: ignore
    return incidents, last_run


def _get_incidents_query_params(client, fetch_evidence, last_fetch_time):
    filter_query = f'alertCreationTime+gt+{last_fetch_time}'
    if client.alert_detectionsource_to_fetch:
        sources = argToList(client.alert_detectionsource_to_fetch)
        source_filter_list = [f"detectionSource+eq+'{DETECTION_SOURCE_TO_API_VALUE[source]}'" for source in sources]
        if len(source_filter_list) > 1:
            source_filter_list = [f"({x})" for x in source_filter_list]
        filter_query = filter_query + " and (" + " or ".join(source_filter_list) + ")"
    if client.alert_status_to_fetch:
        statuses = argToList(client.alert_status_to_fetch)
        status_filter_list = [f"status+eq+'{status}'" for status in statuses]
        if len(status_filter_list) > 1:
            status_filter_list = [f'({x})' for x in status_filter_list]
        filter_query = filter_query + ' and (' + ' or '.join(status_filter_list) + ')'
    if client.alert_severities_to_fetch:
        severities = argToList(client.alert_severities_to_fetch)
        severities_filter_list = [f"severity+eq+'{severity}'" for severity in severities]
        if len(severities_filter_list) > 1:
            severities_filter_list = [f'({x})' for x in severities_filter_list]
        filter_query = filter_query + ' and (' + ' or '.join(severities_filter_list) + ')'
    params = {'$filter': filter_query}
    params['$orderby'] = 'alertCreationTime asc'
    if fetch_evidence:
        params['$expand'] = 'evidence'
    params['$top'] = client.max_alerts_to_fetch
    return params


def create_filter_alerts_creation_time(last_alert_fetched_time):
    """Create filter with the last alert fetched time to send in the request.

    Args:
        last_alert_fetched_time(date): Last date and time of alert that been fetched

    Returns:
        (str). The filter of alerts creation time that will be send in the  alerts list API request
    """
    filter_alerts_creation_time = f"alertCreationTime+gt+{last_alert_fetched_time.isoformat()}"

    if not filter_alerts_creation_time.endswith('Z'):
        filter_alerts_creation_time = filter_alerts_creation_time + "Z"

    return filter_alerts_creation_time


def all_alerts_to_incidents(alerts, latest_creation_time, existing_ids, alert_status_to_fetch,
                            alert_severities_to_fetch):
    """Gets the alerts list and convert it to incidents.

    Args:
        alerts(list): List of alerts filtered by the first_fetch_timestamp parameter
        latest_creation_time(date):  Last date and time of alert that been fetched
        existing_ids(list): List of alerts IDs that already been fetched
        alert_status_to_fetch(str): Status to filter out alerts for fetching as incidents.
        alert_severities_to_fetch(str): Severity to filter out alerts for fetching as incidents.

    Returns:(list, list, date). Incidents list, new alerts IDs list, latest alert creation time
    """
    incidents = []
    new_ids = []
    for alert in alerts:
        alert_creation_time_for_incident = parse(alert['alertCreationTime'])
        reformatted_alert_creation_time_for_incident = \
            aware_timestamp_to_naive_timestamp(alert_creation_time_for_incident)

        if should_fetch_alert(alert, existing_ids, alert_status_to_fetch, alert_severities_to_fetch):
            incident = alert_to_incident(alert, reformatted_alert_creation_time_for_incident)
            incidents.append(incident)

            if reformatted_alert_creation_time_for_incident == latest_creation_time:
                new_ids.append(alert["id"])
            if reformatted_alert_creation_time_for_incident > latest_creation_time:
                latest_creation_time = reformatted_alert_creation_time_for_incident
                new_ids = [alert['id']]

    if not new_ids:
        new_ids = existing_ids
    return incidents, new_ids, latest_creation_time


def aware_timestamp_to_naive_timestamp(aware_timestamp):
    """Gets aware timestamp and reformatting it to naive timestamp

    Args:
        aware_timestamp(date): The alert creation time after parse to aware timestamp

    Returns:(date). Naive timestamp for alert creation time
    """
    iso_aware = aware_timestamp.isoformat()
    # Deal with timestamp like: 2020-03-26T17:24:58.441093
    if '.' in iso_aware:
        iso_aware = iso_aware.split('.')[0]
    # Deal with timestamp like: 2020-03-14T22:11:20+0000
    elif '+' in iso_aware:
        iso_aware = iso_aware.split('+')[0]
    return datetime.strptime(iso_aware, '%Y-%m-%dT%H:%M:%S')


def should_fetch_alert(alert, existing_ids, alert_status_to_fetch, alert_severities_to_fetch):
    """ Check the alert to see if it's data stands by the conditions.

    Args:
        alert (dict): The alert data
        existing_ids (list): The existing alert's ids list
        alert_status_to_fetch(str): Status to filter out alerts for fetching as incidents.
        alert_severities_to_fetch(str): Severity to filter out alerts for fetching as incidents.


    Returns:
        True - if the alert is according to the conditions, else False
    """
    alert_status = alert['status']
    alert_severity = alert['severity']
    return (alert_status in alert_status_to_fetch
            and alert_severity in str(alert_severities_to_fetch) and alert['id'] not in existing_ids)


def get_last_alert_fetched_time(last_run, alert_time_to_fetch):
    """Gets fetch last run and returns the last alert fetch time.

    Returns:
        (date). The date and time of the last alert that been fetched
    """
    if last_run and last_run['last_alert_fetched_time']:
        last_alert_fetched_time = datetime.strptime(last_run['last_alert_fetched_time'], '%Y-%m-%dT%H:%M:%S')
    else:
        last_alert_fetched_time, _ = parse_date_range(date_range=alert_time_to_fetch, date_format='%Y-%m-%dT%H:%M:%S',
                                                      utc=False, to_timestamp=False)
        last_alert_fetched_time = datetime.strptime(str(last_alert_fetched_time), '%Y-%m-%dT%H:%M:%S')

    return last_alert_fetched_time


def list_indicators_command(client: MsClient, args: dict[str, str]) -> tuple[str, dict | None, list | None]:
    """

    Args:
        client: MsClient
        args: arguments from CortexSOAR. May include 'indicator_id' and 'page_size'

    Returns:
        human_readable, outputs.
    """
    limit = int(args.get('limit', 50))
    raw_response = client.list_indicators(args.get('indicator_id'), args.get('page_size', '50'), limit)
    raw_response = raw_response[:limit]
    if raw_response:
        indicators = []
        for item in raw_response:
            item['severity'] = NUMBER_TO_SEVERITY.get(item['severity'])
            indicators.append(item)

        human_readable = tableToMarkdown(
            'Microsoft Defender ATP Indicators:',
            indicators,
            headers=[
                'id',
                'action',
                'threatType',
                'severity',
                'fileName',
                'fileHashType',
                'fileHashValue',
                'domainName',
                'networkIPv4',
                'url'
            ],
            removeNull=True
        )

        outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicators}
        std_outputs = build_std_output(indicators)
        outputs.update(std_outputs)
        return human_readable, outputs, indicators
    else:
        return 'No indicators found', None, None


def create_indicator_command(client: MsClient, args: dict, specific_args: dict) -> dict:
    """Adds required arguments to indicator (arguments that must be in every create call).

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must include the following keys:
            - action
            - description
            - expiration_time
            - threat_type
        specific_args: file, email or network object.

    Returns:
        A response from API.

    Raises:
        AssertionError: For some arguments.

    Documentation:
    https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#properties
    """
    action = args.get('action', '')
    description = args.get('description', '')
    assert 1 <= len(description) <= 100, 'The description argument must contain at' \
                                         ' least 1 character and not more than 100'
    expiration_time = get_future_time(args.get('expiration_time', ''))
    threat_type = args.get('threat_type', '')
    tlp_level = args.get('tlp_level', '')
    confidence = args.get('confidence', None)
    try:
        if confidence is not None:
            confidence = int(confidence)
            assert 0 <= confidence <= 100, 'The confidence argument must be between 0 and 100'
    except ValueError:
        raise DemistoException('The confidence argument must be an integer.')
    severity = SEVERITY_TO_NUMBER.get(args.get('severity', 'Informational'))
    tags = argToList(args.get('tags'))
    body = assign_params(
        action=action,
        description=description,
        expirationDateTime=expiration_time,
        targetProduct='Microsoft Defender ATP',
        threatType=threat_type,
        tlpLevel=tlp_level,
        confidence=confidence,
        severity=severity,
        tags=tags
    )
    body.update(specific_args)
    return client.create_indicator(body)


def create_file_indicator_command(client: MsClient, args: dict) -> tuple[str, dict, dict]:
    """Creates a file indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Should contain a file observable:
            - https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-beta#indicator-observables---file

    Returns:
        human readable, outputs, raw response

    Raises:
        AssertionError: If no file arguments.
    """
    file_object = assign_params(
        fileCompileDateTime=args.get('file_compile_date_time'),
        fileCreatedDateTime=args.get('file_created_date_time'),
        fileHashType=args.get('file_hash_type'),
        fileHashValue=args.get('file_hash_value'),
        fileMutexName=args.get('file_mutex_name'),
        fileName=args.get('file_name'),
        filePacker=args.get('file_packer'),
        filePath=args.get('file_path'),
        fileSize=args.get('file_size'),
        fileType=args.get('file_type')
    )
    assert file_object, 'Must supply at least one file attribute.'
    raw_response = create_indicator_command(client, args, file_object)
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator {indicator.get("id")} was successfully created:',
        indicator,
        headers=[
            'id',
            'action',
            'threatType',
            'severity',
            'fileName',
            'fileHashType',
            'fileHashValue',
            'domainName',
            'networkIPv4',
            'url'
        ],
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def create_network_indicator_command(client, args) -> tuple[str, dict, dict]:
    """Creates a network indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Should contain a network observable:
            - https://docs.microsoft.com/en-us/graph/api/resources/tiindicator?view=graph-rest-betaindicator-observables---network
    Returns:
        human readable, outputs, raw response

    Raises:
        AssertionError: If no file arguments.
    """  # noqa: E501
    network_object = assign_params(
        domainName=args.get('domain_name'),
        networkCidrBlock=args.get('network_cidr_block'),
        networkDestinationAsn=args.get('network_destination_asn'),
        networkDestinationCidrBlock=args.get('network_destination_cidr_block'),
        networkDestinationIPv4=args.get('network_destination_ipv4'),
        networkDestinationIPv6=args.get('network_destination_ipv6'),
        networkDestinationPort=args.get('network_destination_port'),
        networkIPv4=args.get('network_ipv4'),
        networkIPv6=args.get('network_ipv6'),
        networkPort=args.get('network_port'),
        networkProtocol=args.get('network_protocol'),
        networkSourceAsn=args.get('network_source_asn'),
        networkSourceCidrBlock=args.get('network_source_cidr_block'),
        networkSourceIPv4=args.get('network_source_ipv4'),
        networkSourceIPv6=args.get('network_source_ipv6'),
        networkSourcePort=args.get('network_source_port'),
        userAgent=args.get('user_agent'),
        url=args.get('url')
    )
    assert network_object, 'Must supply at least one network attribute.'
    raw_response = create_indicator_command(client, args, network_object)
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator {indicator.get("id")} was successfully created:',
        indicator,
        headers=[
            'id',
            'action',
            'threatType',
            'severity',
            'fileName',
            'fileHashType',
            'fileHashValue',
            'domainName',
            'networkIPv4',
            'url'
        ],
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def update_indicator_command(client: MsClient, args: dict) -> tuple[str, dict, dict]:
    """Updates an indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must contains 'indicator_id' and 'expiration_time'
    Returns:
        human readable, outputs
    """
    indicator_id = args.get('indicator_id', '')
    severity = SEVERITY_TO_NUMBER.get(args.get('severity', 'Informational'))
    expiration_time = get_future_time(args.get('expiration_time', ''))
    description = args.get('description')
    if description is not None:
        assert 1 <= len(
            description) <= 100, 'The description argument must contain at least 1 character and not more than 100'

    raw_response = client.update_indicator(
        indicator_id=indicator_id, expiration_date_time=expiration_time, description=description, severity=severity)
    indicator = raw_response.copy()
    indicator['severity'] = NUMBER_TO_SEVERITY.get(indicator['severity'])
    human_readable = tableToMarkdown(
        f'Indicator ID: {indicator_id} was updated successfully.',
        indicator,
        removeNull=True
    )
    outputs = {'MicrosoftATP.Indicators(val.id == obj.id)': indicator}
    std_outputs = build_std_output(indicator)
    outputs.update(std_outputs)
    return human_readable, outputs, raw_response


def delete_indicator_command(client: MsClient, args: dict) -> str:
    """Deletes an indicator

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must contains 'indicator_id'
    Returns:
        human readable
    """
    indicator_id = args.get('indicator_id', '')
    client.delete_indicator(indicator_id, client.get_graph_indicator_endpoint())
    return f'Indicator ID: {indicator_id} was successfully deleted'


def sc_delete_indicator_command(client: MsClient, args: dict[str, str]) -> CommandResults:
    """Deletes an indicator
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/delete-ti-indicator-by-id?view=o365-worldwide
    Args:
        client: MsClient
        args: arguments from CortexSOAR.
            Must contains 'indicator_id'
    Returns:
          An indication of whether the indicator was deleted successfully.
    """
    indicator_id = args['indicator_id']
    client.delete_indicator(indicator_id, client.get_security_center_indicator_endpoint(), use_security_center=True)
    return CommandResults(readable_output=f'Indicator ID: {indicator_id} was successfully deleted')


def sc_create_update_indicator_command(client: MsClient, args: dict[str, str]) -> CommandResults:
    """Updates an indicator if exists, if does not exist, create new one
    Note: CIDR notation for IPs is not supported.

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
           Must contains 'indicator_value', 'indicator_type','indicator_description', 'indicator_title', and 'action'.

    """
    indicator_value = args['indicator_value']
    indicator_type = args['indicator_type']
    action = args['action']
    severity = args.get('severity')
    expiration_time = get_future_time(args.get('expiration_time', '1 day'))
    indicator_description = args['indicator_description']
    indicator_title = args['indicator_title']
    indicator_application = args.get('indicator_application', '')
    recommended_actions = args.get('recommended_actions', '')
    rbac_group_names = argToList(args.get('rbac_group_names', []))
    generate_alert = argToBoolean(args.get('generate_alert', True))

    indicator = client.create_update_indicator_security_center_api(
        indicator_value=indicator_value, expiration_date_time=expiration_time,
        description=indicator_description, severity=severity, indicator_type=indicator_type, action=action,
        indicator_title=indicator_title, indicator_application=indicator_application,
        recommended_actions=recommended_actions, rbac_group_names=rbac_group_names, generate_alert=generate_alert
    )
    if indicator:
        indicator_value = indicator.get('indicatorValue')  # type:ignore
        dbot_indicator = get_indicator_dbot_object(indicator)
        human_readable = tableToMarkdown(f'Indicator {indicator_value} was updated successfully.',
                                         indicator, headers=list(SC_INDICATORS_HEADERS), removeNull=True)
        return CommandResults(outputs=indicator, indicator=dbot_indicator,
                              readable_output=human_readable, outputs_key_field='id',
                              outputs_prefix='MicrosoftATP.Indicators')
    else:
        return CommandResults(readable_output=f'Indicator {indicator_value} was NOT updated.')


def sc_update_batch_indicators_command(client: MsClient, args: dict[str, str]):  # -> CommandResults:
    """Updates batch of indicators. If an indicator exists it will be updated. Otherwise, will create new one
    Note: CIDR notation for IPs is not supported.

    Args:
        client: MsClient
        args: arguments from CortexSOAR.
           Must contains 'indicator_batch' as a JSON file.

    """
    indicator_batch = args.get('indicator_batch', "")
    headers = ["ID", "Value", "IsFailed", "FailureReason"]
    try:
        batch_json = json.loads(indicator_batch)
    except JSONDecodeError as e:
        raise DemistoException(f'{INTEGRATION_NAME}: The `indicator_batch` argument is not a valid json, {e}.')

    all_indicators = client.create_update_indicator_batch_security_center_api({"Indicators": batch_json})
    outputs = parse_indicator_batch_response(all_indicators)
    if outputs:
        human_readable = tableToMarkdown('Indicators updated successfully.', outputs, headers=headers, removeNull=True)
        return CommandResults(outputs=outputs, readable_output=human_readable, outputs_key_field='id',
                              outputs_prefix='MicrosoftATP.Indicators')
    return CommandResults(readable_output='Indicators were not updated.')


def parse_indicator_batch_response(indicators_response):
    parsed_response = []
    if indicators_response and indicators_response.get('value'):
        indicators = indicators_response.get('value')
        for indicator in indicators:
            parsed_response.append({
                "ID": indicator.get("id"),
                "Value": indicator.get("indicator"),
                "IsFailed": indicator.get("isFailed"),
                "FailureReason": indicator.get("failureReason"),
            })
    return parsed_response


def sc_list_indicators_command(client: MsClient, args: dict[str, str]) -> CommandResults | list[CommandResults]:
    """
    https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/get-ti-indicators-collection?view=o365-worldwide
    Args:
        client: MsClient
        args: arguments from CortexSOAR. May include 'indicator_id' and 'page_size'

    Returns:
        human_readable, outputs.
    """
    limit = arg_to_number(args.get('limit', 50)) or 50
    skip = arg_to_number(args.get('skip', 0)) or 0
    raw_response = client.sc_list_indicators(args.get('indicator_id'), limit, skip, args.get('indicator_title'),
                                             args.get('indicator_value'), args.get('indicator_type'))
    if raw_response:
        command_results = []
        for indicator in raw_response:
            indicator_value = indicator.get('indicatorValue')
            dbot_indicator = get_indicator_dbot_object(indicator)
            human_readable = tableToMarkdown(f'Results found in {INTEGRATION_NAME} SC for value: {indicator_value}',
                                             indicator, headers=list(SC_INDICATORS_HEADERS), removeNull=True)
            command_results.append(CommandResults(outputs=indicator, indicator=dbot_indicator,
                                                  readable_output=human_readable, outputs_key_field='id',
                                                  outputs_prefix='MicrosoftATP.Indicators'))
        return command_results
    else:
        return CommandResults(readable_output='No indicators found')


def lateral_movement_evidence_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    query_purpose = args.pop('query_purpose')
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    query_args = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id'),
        remote_ip_count=args.get('remote_ip_count'))
    query_builder = HuntingQueryBuilder.LateralMovementEvidence(**query_args)
    query_options = {
        'network_connections': query_builder.build_network_connections_query,
        'smb_connections': query_builder.build_smb_connections_query,
        'credential_dumping': query_builder.build_credential_dumping_query,
        'management_connection': query_builder.build_management_connection_query
    }
    if query_purpose not in query_options:
        raise DemistoException(f'Unsupported query_purpose: {query_purpose}.')
    query = query_options[query_purpose]()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown(f'Lateral Movement Evidence Hunt ({query_purpose}) Results',
                                      results,
                                      removeNull=True
                                      )
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'MicrosoftATP.HuntLateralMovementEvidence.Result.{query_purpose}',
        outputs=results
    )


def persistence_evidence_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    query_purpose = args.get('query_purpose')
    show_query = argToBoolean(args.pop('show_query', False))
    quey_args = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        query_purpose=args.get('query_purpose'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id'),
        process_cmd=args.get('process_cmd'))
    query_builder = HuntingQueryBuilder.PersistenceEvidence(**quey_args)
    query_options = {
        'scheduled_job': query_builder.build_scheduled_job_query,
        'registry_entry': query_builder.build_registry_entry_query,
        'startup_folder_changes': query_builder.build_startup_folder_changes_query,
        'new_service_created': query_builder.build_new_service_created_query,
        'service_updated': query_builder.build_service_updated_query,
        'file_replaced': query_builder.build_file_replaced_query,
        'new_user': query_builder.build_new_user_query,
        'new_group': query_builder.build_new_group_query,
        'group_user_change': query_builder.build_group_user_change_query,
        'local_firewall_change': query_builder.build_local_firewall_change_query,
        'host_file_change': query_builder.build_host_file_change_query,
    }
    if query_purpose not in query_options:
        raise DemistoException(f'Unsupported query_purpose: {query_purpose}.')
    query = query_options[query_purpose]()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    readable_output = tableToMarkdown(f'Persistence EvidenceHunt Hunt ({query_purpose}) Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'MicrosoftATP.HuntPersistenceEvidence.Result.{query_purpose}',
        outputs=results
    )


def file_origin_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    quey_params = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id'))
    query_builder = HuntingQueryBuilder.FileOrigin(**quey_params)
    query = query_builder.build_file_origin_query()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown('File Origin Hunt Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='MicrosoftATP.HuntFileOrigin.Result',
        outputs=results
    )


def process_details_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    query_purpose = args.get('query_purpose')
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    query_params = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id'),
        query_purpose=args.get('query_purpose')
    )
    query_builder = HuntingQueryBuilder.ProcessDetails(**query_params)
    query_options = {
        'parent_process': query_builder.build_parent_process_query,
        'grandparent_process': query_builder.build_grandparent_process_query,
        'process_details': query_builder.build_process_details_query,
        'beaconing_evidence': query_builder.build_beaconing_evidence_query,
        'powershell_execution_unsigned_files': query_builder.build_powershell_execution_unsigned_files_query,
        'process_excecution_powershell': query_builder.build_process_excecution_powershell_query,
    }
    if query_purpose not in query_options:
        raise DemistoException(f'Unsupported query_purpose: {query_purpose}.')
    query = query_options[query_purpose]()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown(f'Process Details Hunt ({query_purpose}) Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'MicrosoftATP.HuntProcessDetails.Result.{query_purpose}',
        outputs=results
    )


def network_connections_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    query_purpose = args.get('query_purpose')
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    query_params = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        query_purpose=args.get('query_purpose'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id')
    )
    query_builder = HuntingQueryBuilder.NetworkConnections(**query_params)
    query_options = {
        'external_addresses': query_builder.build_external_addresses_query,
        'dns_query': query_builder.build_dns_query,
        'encoded_commands': query_builder.build_encoded_commands_query
    }
    if query_purpose not in query_options:
        raise DemistoException(f'Unsupported query_purpose: {query_purpose}.')
    query = query_options[query_purpose]()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown(f'Network Connections Hunt ({query_purpose}) Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'MicrosoftATP.HuntNetworkConnections.Result.{query_purpose}',
        outputs=results
    )


def privilege_escalation_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    quey_args = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        device_id=args.get('device_id'))
    query_builder = HuntingQueryBuilder.PrivilegeEscalation(**quey_args)
    query = query_builder.build_query()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown('Privilege Escalation Hunt Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='MicrosoftATP.HuntPrivilegeEscalation.Result',
        outputs=results
    )


def tampering_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    quey_args = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        device_id=args.get('device_id')
    )
    query_builder = HuntingQueryBuilder.Tampering(**quey_args)
    query = query_builder.build_query()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown('Tampering Hunt Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='MicrosoftATP.HuntTampering.Result',
        outputs=results
    )


def cover_up_command(client, args):  # pragma: no cover
    # prepare query
    timeout = int(args.pop('timeout', 10))
    time_range = args.pop('time_range', None)
    query_purpose = args.get('query_purpose')
    page = int(args.get('page', 1))
    limit = int(args.get('limit', 50))
    show_query = argToBoolean(args.pop('show_query', False))
    quey_args = assign_params(
        limit=args.get('limit'),
        query_operation=args.get('query_operation'),
        query_purpose=args.get('query_purpose'),
        page=args.get('page'),
        device_name=args.get('device_name'),
        file_name=args.get('file_name'),
        sha1=args.get('sha1'),
        sha256=args.get('sha256'),
        md5=args.get('md5'),
        device_id=args.get('device_id'),
        username=args.get('username')
    )
    query_builder = HuntingQueryBuilder.CoverUp(**quey_args)
    query_options = {
        'file_deleted': query_builder.build_file_deleted_query,
        'event_log_cleared': query_builder.build_event_log_cleared_query,
        'compromised_information': query_builder.build_compromised_information_query,
        'connected_devices': query_builder.build_connected_devices_query,
        'action_types': query_builder.build_action_types_query,
        'common_files': query_builder.build_common_files_query
    }
    if query_purpose not in query_options:
        raise DemistoException(f'Unsupported query_purpose: {query_purpose}.')
    query = query_options[query_purpose]()

    # send request + handle result
    response = client.get_advanced_hunting(query, timeout, time_range)
    results = response.get('Results')
    if isinstance(results, list) and page > 1:
        results = results[(page - 1) * limit:limit * page]
    readable_output = tableToMarkdown(f'Cover Up Hunt ({query_purpose}) Results', results, removeNull=True)
    if show_query:
        readable_output = f'### The Query:\n{query}\n{readable_output}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'MicrosoftATP.HuntCoverUp.Result.{query_purpose}',
        outputs=results
    )


def test_module(client: MsClient):
    client.ms_client.http_request(method='GET', url_suffix='/alerts', params={'$top': '1'}, overwrite_rate_limit_retry=True)


def get_dbot_indicator(dbot_type, dbot_score, value):
    if dbot_type == DBotScoreType.FILE:
        hash_type = get_hash_type(value)
        if hash_type == 'md5':
            return Common.File(dbot_score=dbot_score, md5=value)
        if hash_type == 'sha1':
            return Common.File(dbot_score=dbot_score, sha1=value)
        if hash_type == 'sha256':
            return Common.File(dbot_score=dbot_score, sha256=value)
    if dbot_type == DBotScoreType.IP:
        return Common.IP(ip=value, dbot_score=dbot_score)
    if dbot_type == DBotScoreType.DOMAIN:
        return Common.Domain(domain=value, dbot_score=dbot_score)
    if dbot_type == DBotScoreType.URL:
        return Common.URL(url=value, dbot_score=dbot_score)
    return None


def get_indicator_dbot_object(indicator):
    indicator_type = INDICATOR_TYPE_TO_DBOT_TYPE.get(indicator.get('indicatorType'))
    if indicator_type:
        indicator_value = indicator.get('indicatorValue')
        dbot = Common.DBotScore(indicator=indicator_value, indicator_type=indicator_type,
                                score=Common.DBotScore.NONE)  # type:ignore
        return get_dbot_indicator(indicator_type, dbot, indicator_value)
    else:
        return None


def list_machines_by_software_command(client: MsClient, args: dict) -> CommandResults:
    """ Retrieve a list of device references that has the given software installed.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object with a list of machines by software.
    """
    software_id = str(args.get('id'))
    headers = ['id', 'computerDnsName', 'osPlatform', 'rbacGroupName', 'rbacGroupId']
    machines_response = client.get_list_machines_by_software(software_id)
    machines_response_value = machines_response.get('value')
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} list machines by software: {software_id}',
                                     machines_response_value, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='MicrosoftATP.SoftwareMachine',
        outputs_key_field='id',
        outputs=machines_response_value,
        readable_output=human_readable,
        raw_response=machines_response)


def list_software_version_distribution_command(client: MsClient, args: dict) -> CommandResults:
    """ Retrieves a list of your organization's software version distribution.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object with a list of software version distribution.
    """
    software_id = str(args.get('id'))
    headers = ['version', 'installations', 'vulnerabilities']
    software_version_distribution_response = client.get_list_software_version_distribution(software_id)
    software_version_distribution_response_value = software_version_distribution_response.get('value')
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} software version distribution:',
                                     software_version_distribution_response_value, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='MicrosoftATP.SoftwareVersion',
        outputs=software_version_distribution_response_value,
        outputs_key_field=['version', 'installations', 'vulnerabilities'],
        readable_output=human_readable,
        raw_response=software_version_distribution_response)


def list_missing_kb_by_software_command(client: MsClient, args: dict) -> CommandResults:
    """ Retrieves missing KBs (security updates) by software ID
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object with a list of missing kb by software.
    """
    software_id = str(args.get('id'))
    headers = ['id', 'name', 'osBuild', 'productsNames', 'url', 'machineMissedOn', 'cveAddressed']
    missing_kb_by_software_response = client.get_list_missing_kb_by_software(software_id)
    missing_kb_by_software_response_value = missing_kb_by_software_response.get('value')
    mark_down_values = add_backslash_infront_of_underscore_list(missing_kb_by_software_response_value)
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} missing kb by software: {software_id}',
                                     mark_down_values, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='MicrosoftATP.SoftwareKB',
        outputs_key_field='id',
        outputs=missing_kb_by_software_response_value,
        readable_output=human_readable,
        raw_response=missing_kb_by_software_response)


def list_vulnerabilities_by_software_command(client: MsClient, args: dict) -> list[CommandResults]:
    """ Retrieves list of vulnerabilities by software.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResult list with a list of vulnerabilities by software.
    """
    results_list = []
    software_id = str(args.get('id'))
    headers = ['id', 'name', 'description', 'severity', 'cvssV3', 'publishedOn', 'updatedOn',
               'exposedMachines', 'exploitVerified',
               'publicExploit']
    vulnerabilities_response = client.get_list_vulnerabilities_by_software(software_id)
    vulnerabilities_response_value = vulnerabilities_response.get('value')
    demisto.debug(f'Vulnerabilities Response {vulnerabilities_response_value}')
    if vulnerabilities_response_value:
        for cve in vulnerabilities_response_value:
            cve_id = cve.get('id')
            cve_indicator = Common.CVE(id=cve_id,
                                       cvss=cve.get('cvssV3'),
                                       description=cve.get('description'),
                                       published=cve.get('publishedOn'),
                                       modified=cve.get('updatedOn')
                                       )
            human_readable = tableToMarkdown(f'{INTEGRATION_NAME} vulnerability {cve_id} by software: {software_id}',
                                             add_backslash_infront_of_underscore_list([cve]), headers=headers,
                                             removeNull=True)
            results_list.append(CommandResults(outputs_prefix='MicrosoftATP.SoftwareCVE',
                                               outputs_key_field='id',
                                               outputs=cve,
                                               readable_output=human_readable,
                                               raw_response=cve,
                                               indicator=cve_indicator))
    else:
        results_list.append(
            CommandResults(readable_output=f'No vulnerabilities were found for software: {software_id}.'))
    return results_list


def create_filters_conjunction(filters_arg_list: list[str], name: str) -> str:
    """ Create filter conjunction (added 'or' between args)
        example output: id eq 'id1' or id eq 'id2'
        Args:
            filters_arg_list: list[str].
            name: str.
        Returns:
            A str corresponding to the filter param in a qury.
    """
    query = ''
    filters_arg_list = list(filter(None, filters_arg_list))
    list_length = len(filters_arg_list)
    if filters_arg_list:
        for index, list_item in enumerate(filters_arg_list):
            if index == list_length - 1 or list_length == 1:
                query = f"{query}{name} eq '{list_item}'"
            else:
                query = f"{query}{name} eq '{list_item}' or "
        demisto.debug(f'Filter conjunction query results: {query} ')
    return query


def add_backslash_infront_of_underscore_list(markdown_data: list[dict] | None) -> list[dict]:
    """ Escape underscores with a backslash in order to show underscores after markdown parsing.
        Args:
            markdown_data: list[dict] - list of dicts.
        Returns:
            A list of dicts with a backslash before each underscore.
    """
    markdown_data_to_return = []
    if markdown_data:
        for dict_item in markdown_data:
            dict = {}
            for k, v in dict_item.items():
                if isinstance(v, str):
                    v = str(v.replace('_', '\_'))
                dict[k] = v
            markdown_data_to_return.append(dict)
    return markdown_data_to_return


def create_filters_disjunctions(filters_arg_list: list[str]) -> str:
    """ Create filter disjunctions (added 'and' between args)
        example output: id eq 'id1' and vendor eq 'vendor1'
        Args:
            filters_arg_list: list[str].
        Returns:
            A str corresponding to the filter param in a qury.
    """
    query = ''
    filters_arg_list = list(filter(None, filters_arg_list))
    list_length = len(filters_arg_list)
    if filters_arg_list:
        for index, list_item in enumerate(filters_arg_list):
            if list_length == 1 and list_item == '':
                continue
            if list_length == 1:
                query = f'{query}{list_item}'
                continue
            if index == list_length - 1:
                query = f'{query}({list_item})'
                continue
            else:
                query = f'{query}({list_item}) and '
        demisto.debug(f'Filter disjunctions query results: {query} ')
    return query


def create_filter(args_and_name_list: list[tuple[list[str], str]]) -> str:
    """ Create filter with disjunctions and conjunction according to the API requirements
        example output: id eq 'id1' and vendor eq 'vendor1' or  vendor eq 'vendor2'
        Args:
            filters_arg_list: list[str].
        Returns:
            A str corresponding to the filter param in a qury.
    """
    list_for_disjunctions = []
    for arg_and_name in args_and_name_list:
        list_for_disjunctions.append(create_filters_conjunction(arg_and_name[0], arg_and_name[1]))
    return create_filters_disjunctions(list_for_disjunctions)


def list_software_command(client: MsClient, args: dict) -> CommandResults:
    """ Retrieves the organization software inventory.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object.
    """
    software_id = argToList(args.get('id', ''))
    names = argToList(args.get('name', ''))
    vendors = argToList(args.get('vendor', ''))
    limit = args.get('limit', '50')
    offset = args.get('offset', '0')
    filter_req = create_filter([(software_id, 'id'), (names, 'name'), (vendors, 'vendor')])
    headers = ['id', 'name', 'vendor', 'weaknesses', 'activeAlert', 'exposedMachines', 'installedMachines', 'publicExploit']
    list_software_response = client.get_list_software(filter_req, limit, offset)
    list_software_response_value = list_software_response.get('value')
    mark_down_values = add_backslash_infront_of_underscore_list(list_software_response_value)
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} list software:',
                                     mark_down_values, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix='MicrosoftATP.Software',
        outputs_key_field='id',
        outputs=list_software_response_value,
        readable_output=human_readable,
        raw_response=list_software_response)


def list_vulnerabilities_by_machine_command(client: MsClient, args: dict) -> list[CommandResults]:
    """ Retrieves a list of all the vulnerabilities affecting the organization per machine.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object.
    """
    machine_id = argToList(args.get('machine_id'))
    software_id = argToList(args.get('software_id', ''))
    cve_id = argToList(args.get('cve_id', ''))
    product_name = argToList(args.get('product_name', ''))
    product_version = argToList(args.get('product_version', ''))
    severity = argToList(args.get('severity', ''))
    product_vendor = argToList(args.get('product_vendor', ''))
    limit = args.get('limit', '25')
    offset = args.get('offset', '0')
    results_list = []
    filter_req = create_filter([(machine_id, 'machineId'), (software_id, 'id'), (cve_id, 'cveId'),
                                (product_name, 'productName'), (product_version, 'productVersion'), (severity, 'severity'),
                                (product_vendor, 'productVendor')])
    headers = ['id', 'cveId', 'machineId', 'productName', 'productVendor', 'productVersion', 'severity']
    list_vulnerabilities_response = client.get_list_vulnerabilities_by_machine(filter_req, limit, offset)
    list_vulnerabilities_response_value = list_vulnerabilities_response.get('value')
    if list_vulnerabilities_response_value:
        for cve in list_vulnerabilities_response_value:
            cve_id = cve.get('cveId')
            cve_indicator = Common.CVE(id=cve_id,
                                       cvss='',
                                       description='',
                                       published='',
                                       modified=''
                                       )
            human_readable = tableToMarkdown(f'{INTEGRATION_NAME} vulnerability {cve_id}:',
                                             add_backslash_infront_of_underscore_list([cve]), headers=headers, removeNull=True)
            results_list.append(CommandResults(outputs_prefix='MicrosoftATP.MachineCVE',
                                               outputs_key_field='id',
                                               outputs=cve,
                                               readable_output=human_readable,
                                               raw_response=cve,
                                               indicator=cve_indicator))
    else:
        results_list.append(
            CommandResults(readable_output=f'No vulnerabilities were found for machine: {machine_id}.'))
    return results_list


def create_filter_list_vulnerabilities(id_and_severity: str, name_equal: str, name_contains: str, description: str,
                                       published_on: str, cvss: str, updated_on: str) -> str:
    """ Create a string filter.
        Args:
            id_and_severity: str - Id and severity of the vulnerability.
            name: str - Name of the vulnerability.
            description: str - Description of the vulnerability.
            published_on: str - Date when vulnerability was published.
            cvss: str - CVSS v3 score.
            updated_on: str - Date when vulnerability was updated.
        Returns:
            A string filter.
    """
    filter_query_list = []
    if id_and_severity:
        filter_query_list.append(id_and_severity)
    if name_contains:
        filter_query_list.append(f"contains(name, '{name_contains}')")
    if name_equal:
        filter_query_list.append(f"name eq '{name_equal}'")
    if description:
        filter_query_list.append(f"contains(description, '{description}')")
    if cvss:
        filter_query_list.append(f"cvssV3 ge {cvss}")
    if updated_on:
        filter_query_list.append(f"updatedOn ge {updated_on}")
    if published_on:
        filter_query_list.append(f"publishedOn ge {published_on}")

    return create_filters_disjunctions(filter_query_list)


def date_to_iso_format(date: str) -> str:
    """ Retrieves date string or relational expression to iso format date.
        Args:
            date: str - date or relational expression.
        Returns:
            A str in ISO format.
    """
    date = dateparser.parse(date)
    date = date.strftime("%Y-%m-%dT%H:%M:%SZ") if date else ''
    return date


def list_vulnerabilities_command(client: MsClient, args: dict) -> list[CommandResults]:
    """ Retrieves a list of all vulnerabilities.
        Args:
            client: MsClient.
            args: dict - arguments from CortexSOAR.
        Returns:
            A CommandResults object.
    """
    id = argToList(args.get('id', ''))
    severity = argToList(args.get('severity', ''))
    name_equal = args.get('name_equal', '')
    name_contains = args.get('name_contains', '')
    description = args.get('description_contains', '')
    published_on = date_to_iso_format(args.get('published_on', ''))
    updated_on = date_to_iso_format(args.get('updated_on', ''))
    cvss = args.get('cvss', '')
    limit = args.get('limit', '25')
    offset = args.get('offset', '0')
    filter_req_id_and_severity = create_filter([(id, 'id'), (severity, 'severity')])
    filter_req = create_filter_list_vulnerabilities(filter_req_id_and_severity, name_equal, name_contains, description,
                                                    published_on, cvss, updated_on)
    headers = ['id', 'name', 'description', 'severity', 'publishedOn', 'updatedOn', 'exposedMachines',
               'exploitVerified', 'publicExploit', 'cvssV3']
    list_vulnerabilities_response = client.get_list_vulnerabilities(filter_req, limit, offset)
    list_vulnerabilities_response_value = list_vulnerabilities_response.get('value')
    results_list = []
    if list_vulnerabilities_response_value:
        for cve in list_vulnerabilities_response_value:
            cve_id = cve.get('id')
            cve_indicator = Common.CVE(id=cve_id,
                                       cvss=cve.get('cvssV3'),
                                       description=cve.get('description'),
                                       published=cve.get('publishedOn'),
                                       modified=cve.get('updatedOn')
                                       )
            human_readable = tableToMarkdown(f'{INTEGRATION_NAME} vulnerabilities:',
                                             add_backslash_infront_of_underscore_list([cve]), headers=headers, removeNull=True)
            results_list.append(CommandResults(outputs_prefix='MicrosoftATP.Vulnerability',
                                               outputs_key_field='id',
                                               outputs=cve,
                                               readable_output=human_readable,
                                               raw_response=cve,
                                               indicator=cve_indicator))
    else:
        results_list.append(
            CommandResults(readable_output='No vulnerabilities were found.'))
    return results_list


def list_machines_by_vulnerability_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves a list of devices affected by a vulnerability (by the given CVE ID).

    Returns:
        CommandResults. Human readable, context, raw response
    """
    headers = ['ID', 'ComputerDNSName', 'OSPlatform', 'RBACGroupID', 'RBACGroupName', 'CVE']
    cve_ids = remove_duplicates_from_list_arg(args, 'cve_id')
    raw_response = []
    machines_outputs = []
    failed_cve = {}  # if we got an error, we will return the machine ids that failed

    for cve_id in cve_ids:
        try:
            machines_response = client.get_list_machines_by_vulnerability(cve_id)
            for machine in machines_response['value']:
                machine_data = get_machine_data(machine)
                machine_data.update({"CVE": cve_id})
                machines_outputs.append(machine_data)
            raw_response.append(machines_response)
        except Exception as e:
            failed_cve[cve_id] = e
            continue

    machines_outputs = create_related_cve_list_for_machine(machines_outputs)
    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} machines by vulnerabilities: {cve_ids}',
                                     machines_outputs, headers=headers, removeNull=True)
    human_readable += add_error_message(failed_cve, cve_ids)
    return CommandResults(
        outputs_prefix='MicrosoftATP.CveMachine',
        outputs_key_field='ID',
        outputs=machines_outputs,
        readable_output=human_readable,
        raw_response=raw_response)


def create_related_cve_list_for_machine(machines):
    """
    Parses the machines list to include a CVE list for each machine by ID.
    For example,
    machines = [{'ID': 1, 'CVE': 'CVE-1'},{'ID': 1, 'CVE': 'CVE-2'},{'ID': 2, 'CVE': 'CVE-1'}]

    the output after the for loop will be:
    machines = [{'ID': 1, ['CVE': 'CVE-1','CVE-2']},{'ID': 1, ['CVE': 'CVE-1','CVE-2']},{'ID': 2, 'CVE': ['CVE-1']}]

    and the output after remove duplicates will be:
    unique_machines = [{'ID': 1, 'CVE': ['CVE-1','CVE-2']},{'ID': 2, 'CVE': ['CVE-1']}]
    """
    machine_id_to_cve_list: dict[str, list[str]] = {}
    for machine in machines:
        machine_id = machine.get('ID')
        cve_id = machine.get('CVE')
        if not machine_id_to_cve_list.get(machine_id):
            machine_id_to_cve_list[machine_id] = [cve_id]
        else:
            machine_id_to_cve_list[machine_id].append(cve_id)
        machine.pop('CVE')
        machine['CVE'] = machine_id_to_cve_list[machine_id]

    # handle duplicates
    unique_machines = []
    for machine in machines:
        if machine not in unique_machines:
            unique_machines.append(machine)
    return unique_machines


def get_file_context(file_info_response: dict[str, str], headers: list):
    return {key.capitalize(): value for (key, value) in file_info_response.items() if key in headers}


def get_file_info_command(client: MsClient, args: dict):
    """ Retrieves file info by a file hash (Sha1 or Sha256).

    Returns:
        CommandResults. Human readable, context, raw response
    """
    headers = ['Sha1', 'Sha256', 'Size', 'FileType', 'Signer', 'IsValidCertificate']
    file_context_path = 'File(val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || ' \
                        'val.Type && val.Type == obj.Type || val.Size && val.Size == obj.Size )'
    file_hashes = remove_duplicates_from_list_arg(args, 'hash')
    raw_response = []
    file_outputs = []
    file_context_outputs = []
    failed_hashes = {}  # if we got an error, we will return the machine ids that failed
    sha1_value_in_files = []  # for not adding duplicates machines to the table
    not_found_ids = []

    for file_hash in file_hashes:
        try:
            file_info_response = client.get_file_data(file_hash)
            file_data = get_file_data(file_info_response)
            if file_data.get('Sha1', '') not in sha1_value_in_files:
                file_outputs.append(file_data)
                sha1_value_in_files.append(file_data.get('Sha1', ''))
            raw_response.append(file_info_response)
            file_context_outputs.append(get_file_context(file_info_response, ["sha1", "sha256", "filetype", "size"]))
        except NotFoundError:  # in case the error is not found hash, we want to return "No entries"
            not_found_ids.append(file_hash)
            continue
        except Exception as e:
            failed_hashes[file_hash] = e
            continue

    human_readable = tableToMarkdown(f'{INTEGRATION_NAME} file info by hashes: {file_hashes}',
                                     file_outputs, headers=headers, removeNull=True)
    human_readable += add_error_message(failed_hashes, file_hashes)
    human_readable += not_found_message(not_found_ids)
    if file_outputs:
        context = {
            'MicrosoftATP.File(val.Sha1 === obj.Sha1)': file_outputs,
            file_context_path: file_context_outputs
        }
        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': file_outputs,
            'EntryContext': context,
            'HumanReadable': human_readable,
            'raw_response': raw_response
        }
    else:
        return "No entries."


def create_endpoint_verdict(machine: dict):
    return Common.Endpoint(
        id=machine.get('ID'),
        hostname=machine.get('ComputerDNSName'),
        ip_address=machine.get('LastIPAddress'),
        mac_address=machine.get('MACAddress'),
        os=machine.get('OSPlatform'),
        status=HEALTH_STATUS_TO_ENDPOINT_STATUS[machine.get('HealthStatus', 'Unknown')],
        vendor=INTEGRATION_NAME,
        os_version=f"{machine.get('OSVersion')} {machine.get('OSProcessor')} bit",
    )


def create_filter_for_endpoint_command(hostnames, ips, ids):
    """
    Creates a filter query for getting the machines according to the given args.
    The query build is: "or" operator separetes the key and the value between each arg.

    For example,
    for fields_to_values: {'computerDnsName': ['b.com', 'a.com'], 'lastIpAddress': ['1.2.3.4'], 'id': ['1','2']}
    the result is: "computerDnsName eq 'b.com' or computerDnsName eq 'a.com' or lastIpAddress eq '1.2.3.4' or
    id eq '1' or id eq '2'"

    Args:
        hostnames (list): Comma-separated list of computerDnsName.
        ips (list): Comma-separated list of lastIpAddress.
        ids (list): Comma-separated list of id.

    Returns: A string that represents the filter query according the inputs.
    """
    fields_to_values = {'computerDnsName': hostnames, 'lastIpAddress': ips, 'id': ids}
    return ' or '.join(
        f"{field_key} eq '{field_value}'" for (field_key, field_value_list) in fields_to_values.items() if
        field_value_list for field_value in field_value_list)


def validate_args_endpoint_command(hostnames, ips, ids):
    no_hostname = len(hostnames) == 0
    no_ip = len(ips) == 0
    no_id = len(ids) == 0
    if no_hostname and no_ip and no_id:
        raise DemistoException(
            f'{INTEGRATION_NAME} - In order to run this command, please provide valid id, ip or hostname')


def handle_machines(machines_response: dict) -> list[CommandResults]:
    """Converts the raw response of the API to a CommandResults list with relevant keys.
    Args:
        The raw API response, a list of machines.
    Returns:
        CommandResults list.
    """

    headers = ['ID', 'Hostname', 'OS', 'OSVersion', 'IPAddress', 'Status', 'MACAddress', 'Vendor']

    machines_outputs = []

    for machine in machines_response.get("value", []):
        machine_data = get_machine_data(machine)
        machine_data['MACAddress'] = get_machine_mac_address(machine)
        endpoint_indicator = create_endpoint_verdict(machine_data)
        human_readable = tableToMarkdown(f'{INTEGRATION_NAME} Machine:',
                                         endpoint_indicator.to_context()[Common.Endpoint.CONTEXT_PATH], headers=headers,
                                         removeNull=True)
        machines_outputs.append(CommandResults(
            readable_output=human_readable,
            outputs_prefix='MicrosoftATP.Machine',
            raw_response=machines_response,
            outputs_key_field="ID",
            outputs=machine_data,
            indicator=endpoint_indicator,
        ))

    if not machines_outputs:
        machines_outputs.append(CommandResults(
            readable_output=f"{INTEGRATION_NAME} no device found.",
            raw_response=machines_response,
        ))
    return machines_outputs


def get_machine_by_ip_command(client: MsClient, args: dict) -> list[CommandResults]:
    """Retreives Machines that were seen with the requested internal IP
    in the time range of 15 minutes prior and aftera given timestamp.
    Args:
        client: MsClient
        args: dict
    Returns:
        CommandResults list.
    """
    ip = args['ip']
    timestamp = args['timestamp']
    limit = arg_to_number(args.get('limit', 50))
    should_limit_result = not argToBoolean(args.get('all_results', False))

    filter = f"(ip='{ip}',timestamp={timestamp})"

    raw_machines_response = client.get_machines_for_get_machine_by_ip_command(filter)
    machines_response = raw_machines_response.get('value', [])

    demisto.debug(f'limit is set to: {limit}')
    limited_machines_response = machines_response[:limit] if should_limit_result else machines_response
    raw_machines_response["value"] = limited_machines_response

    demisto.debug('Calling handle_machines function to convert raw response to CommandResults list')
    return handle_machines(raw_machines_response)


def endpoint_command(client: MsClient, args: dict) -> list[CommandResults]:
    """Retrieves a collection of machines that have communicated with WDATP cloud on the last 30 days

    Returns:
        CommandResults list.
    """
    hostnames = argToList(args.get('hostname', ''))
    ips = argToList(args.get('ip', ''))
    ids = argToList(args.get('id', ''))
    validate_args_endpoint_command(hostnames, ips, ids)
    machines_response = client.get_machines(create_filter_for_endpoint_command(hostnames, ips, ids))

    return handle_machines(machines_response)


def get_machine_users_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves a collection of logon users on a given machine

    Returns:
        CommandResults.
    """
    headers = ["ID", "AccountName", "AccountDomain", "FirstSeen", "LastSeen", "LogonTypes", "DomainAdmin", "NetworkUser"]
    machine_id = args.get("machine_id")
    response = client.get_machine_users(machine_id)
    users_list = [dict(**get_user_data(r), MachineID=machine_id) for r in response.get("value", [])]

    return CommandResults(
        outputs=users_list,
        outputs_key_field=["ID", "MachineID"],
        outputs_prefix="MicrosoftATP.MachineUser",
        readable_output=tableToMarkdown(
            f"Microsoft Defender ATP logon users for machine {machine_id}:",
            users_list,
            headers=headers,
            removeNull=True,
        ),
        raw_response=response,
    )


def get_machine_alerts_command(client: MsClient, args: dict) -> CommandResults:
    """Retrieves a collection of alerts related to specific device.

    Returns:
        CommandResults.
    """
    headers = [
        "ID",
        "Title",
        "Description",
        "IncidentID",
        "Severity",
        "Status",
        "Classification",
        "Category",
        "ThreatFamilyName",
        "MachineID"
    ]
    machine_id = args.get("machine_id")
    alerts_response = client.get_machine_alerts(machine_id)
    alert_list = get_alerts_list(alerts_response)

    return CommandResults(
        outputs=alert_list,
        outputs_key_field=["ID", "MachineID"],
        outputs_prefix="MicrosoftATP.MachineAlerts",
        readable_output=tableToMarkdown(
            f"Alerts that are related to machine {machine_id}:",
            alert_list,
            headers=headers,
            removeNull=True,
        ),
        raw_response=alerts_response,
    )


''' EXECUTION CODE '''
''' LIVE RESPONSE CODE '''


def run_polling_command(client: MsClient, args: dict, cmd: str, action_func: Callable,
                        results_function: Callable, post_polling_process: Callable):
    """
    This function is generically handling the polling flow. In the polling flow, there is always an initial call that
    starts the uploading to the API (referred here as the 'upload' function) and another call that retrieves the status
    of that upload (referred here as the 'results' function).
    The run_polling_command function runs the 'upload' function and returns a ScheduledCommand object that schedules
    the next 'results' function, until the polling is complete.
    Args:
        args: the arguments required to the command being called, under cmd
        cmd: the command to schedule by after the current command
        results_function: the function that retrieves the status of the previously initiated upload process
        client: a Microsoft Client object

    Returns:

    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 10))
    timeout_in_seconds = int(args.get('timeout_in_seconds', 600))

    # distinguish between the initial run, which is the upload run, and the results run
    is_first_run = 'machine_action_id' not in args
    if is_first_run:
        command_results = action_func(client, args)
        outputs = command_results.outputs
        # schedule next poll
        polling_args = {
            'machine_action_id': outputs.get('action_id'),
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args,
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds)
        command_results.scheduled_command = scheduled_command
        return command_results

    # not a first run
    command_result = results_function(client, args)
    action_status = command_result.outputs.get("status")
    demisto.debug(f"action status is: {action_status}")

    # In case command is one of the put/get file/ run script there is command section, otherwise there isnt.
    if command_result.outputs.get("commands", []):
        command_status = command_result.outputs.get("commands", [{}])[0].get("commandStatus")
    else:
        command_status = 'Completed' if action_status == "Succeeded" else None

    if action_status in ['Failed', 'Cancelled'] or command_status == 'Failed':
        error_msg = f"Command {action_status}."
        if command_result.outputs.get("commands", []):
            error_msg += f'{command_result.outputs.get("commands", [{}])[0].get("errors")}'
        raise Exception(error_msg)

    elif command_status != 'Completed' or action_status in ('InProgress', 'Pending'):
        demisto.debug("action status is not completed")
        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }

        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=timeout_in_seconds
        )

        command_result = CommandResults(scheduled_command=scheduled_command)
        return command_result

    # action was completed
    else:
        return post_polling_process(client, command_result.outputs)


def get_live_response_result_command(client, args):
    machine_action_id = args['machine_action_id']
    command_index = arg_to_number(args['command_index'])
    res = client.get_live_response_result(machine_action_id, command_index)
    file_link = res['value']

    # download link, create file result
    f_data = client.download_file(file_link)
    try:
        outputs = f_data.json()
    except Exception:
        outputs = {'value': file_link}

    return [fileResult('Response Result', f_data.content), CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseResult',
        outputs=outputs,
        readable_output=f'file_link: {file_link}'
    )]


def get_machine_action_command(client, args):
    id = args['machine_action_id']
    res = client.get_machine_action_by_id(id, overwrite_rate_limit_retry=True)

    return CommandResults(
        outputs_prefix='MicrosoftATP.MachineAction',
        outputs_key_field='action_id',
        outputs=res
    )


def cancel_action_command(client, args):
    action_id = args['machine_action_id']
    comment = args['comment']
    body = {
        "Comment": comment
    }
    # cancel action should return either 200 or 404.
    try:
        client.cancel_action(action_id, body)
    except Exception as e:
        if '404' in str(e):
            raise DemistoException(f'Action ID {action_id} could not be found. Make sure you entered the correct ID.')
        raise

    return CommandResults(
        readable_output='Action was cancelled successfully.'
    )


# -------------- Run Script ---------------

def run_live_response_script_with_polling(client, args):
    return run_polling_command(client, args, 'microsoft-atp-live-response-run-script', run_live_response_script_action,
                               get_machine_action_command, get_successfull_action_results_as_info)


def run_live_response_script_action(client, args):
    machine_id = args['machine_id']
    scriptName = args['scriptName']
    comment = args['comment']
    arguments = args.get('arguments')
    params = [{
        "key": "ScriptName",
        "value": scriptName
    }]
    if arguments:
        params.append(
            {
                "key": "Args",
                "value": arguments
            }
        )
    request_body = {
        "Commands": [
            {
                "type": "RunScript",
                "params": params
            },
        ],
        "Comment": comment
    }

    # create action:
    res = client.create_action(machine_id, request_body, overwrite_rate_limit_retry=True)

    md = tableToMarkdown('Processing action. This may take a few minutes.', res['id'], headers=['id'])
    return CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseAction',
        outputs={'action_id': res['id']},
        readable_output=md
    )


def get_successfull_action_results_as_info(client, res):
    machine_action_id = res['id']
    file_link = client.get_live_response_result(machine_action_id, 0, overwrite_rate_limit_retry=True)['value']

    f_data = client.download_file(file_link)
    try:
        script_result = f_data.json()
    except Exception as e:
        demisto.debug(f'Failed download script results from link {file_link}. Error: {str(e)}')
        script_result = None
    return [
        CommandResults(
            outputs_prefix='MicrosoftATP.LiveResponseAction',
            outputs=script_result if script_result else res,
            readable_output=tableToMarkdown('Script Results:', script_result, is_auto_json_transform=True)
            if script_result else 'Could not retrieve script results.'
        ),
        fileResult('Response Result', f_data.content, file_type=EntryType.ENTRY_INFO_FILE)]


# -------------- Get File ---------------
def get_live_response_file_with_polling(client, args):
    return run_polling_command(client, args, 'microsoft-atp-live-response-get-file', get_live_response_file_action,
                               get_machine_action_command, get_file_get_successfull_action_results)


def get_live_response_file_action(client, args):
    machine_id = args['machine_id']
    file_path = args['path']
    comment = args['comment']

    request_body = {
        "Commands": [
            {
                "type": "GetFile",
                "params": [{
                    "key": "Path",
                    "value": file_path
                }]
            },
        ],
        "Comment": comment
    }

    # create action:
    res = client.create_action(machine_id, request_body, overwrite_rate_limit_retry=True)
    md = tableToMarkdown('Processing action. This may take a few minutes.', res['id'], headers=['id'])

    return CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseAction',
        outputs={'action_id': res['id']},
        readable_output=md)


def get_file_get_successfull_action_results(client, res):
    machine_action_id = res['id']

    # get file link from action:
    file_link = client.get_live_response_result(machine_action_id, 0, overwrite_rate_limit_retry=True)['value']
    demisto.debug(f'Got file for downloading: {file_link}')

    # download link, create file result. File comes back as compressed gz file.
    f_data = client.download_file(file_link)
    md_results = {
        'Machine Action Id': res.get('id'),
        'MachineId': res.get('machineId'),
        'Hostname': res.get('computerDnsName'),
        'Status': res.get('status'),
        'Creation time': res.get('creationDateTimeUtc'),
        'Commands': res.get('commands')
    }
    return [fileResult('Response Result.gz', f_data.content), CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseAction',
        outputs=res,
        readable_output=tableToMarkdown('Machine Action:', md_results, is_auto_json_transform=True)

    )]


# -------------- Put File ---------------
def put_live_response_file_with_polling(client, args):
    return run_polling_command(client, args, 'microsoft-atp-live-response-put-file', put_live_response_file_action,
                               get_machine_action_command, put_file_get_successful_action_results)


def put_live_response_file_action(client, args):
    machine_id = args['machine_id']
    file_path = args['file_name']
    comment = args['comment']

    request_body = {
        "Commands": [
            {
                "type": "PutFile",
                "params": [{
                    "key": "FileName",
                    "value": file_path
                }]
            },
        ],
        "Comment": comment
    }

    # create action:
    res = client.create_action(machine_id, request_body, overwrite_rate_limit_retry=True)
    md = tableToMarkdown('Processing action. This may take a few minutes.', res['id'], headers=['id'])

    return CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseAction',
        outputs={'action_id': res['id']},
        readable_output=md)


def put_file_get_successful_action_results(client, res):
    md_results = {
        'Machine Action Id': res.get('id'),
        'MachineId': res.get('machineId'),
        'Hostname': res.get('computerDnsName'),
        'Status': res.get('status'),
        'Creation time': res.get('creationDateTimeUtc'),
        'Commands': res.get('commands')
    }

    return CommandResults(
        outputs_prefix='MicrosoftATP.LiveResponseAction',
        outputs=res,
        readable_output=tableToMarkdown('Machine Action:', md_results, is_auto_json_transform=True)
    )


def main():  # pragma: no cover
    params: dict = demisto.params()
    params_endpoint_type = params.get('endpoint_type') or 'Worldwide'
    params_url = params.get('url')
    is_gcc = params.get('is_gcc', False)
    tenant_id = params.get('tenant_id') or params.get('_tenant_id')
    auth_id = params.get('_auth_id') or params.get('auth_id')
    enc_key = (params.get('credentials') or {}).get('password') or params.get('enc_key')
    use_ssl: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)
    self_deployed: bool = params.get('self_deployed', False)
    certificate_thumbprint = params.get('creds_certificate', {}).get('identifier') or params.get('certificate_thumbprint')
    private_key = replace_spaces_in_credential(params.get('creds_certificate', {}).get('password')) or params.get('private_key')
    alert_detectionsource_to_fetch = params.get("fetch_detectionsource")
    alert_severities_to_fetch = params.get('fetch_severity')
    alert_status_to_fetch = params.get('fetch_status')
    alert_time_to_fetch = params.get('first_fetch_timestamp', '3 days')
    max_alert_to_fetch = arg_to_number(params.get('max_fetch', 50))
    fetch_evidence = argToBoolean(params.get('fetch_evidence', False))
    last_run = demisto.getLastRun()
    auth_type = params.get('auth_type', 'Client Credentials')
    auth_code = params.get('auth_code', {}).get('password', '')
    redirect_uri = params.get('redirect_uri', '')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed = self_deployed or managed_identities_client_id is not None

    endpoint_type, params_url = microsoft_defender_for_endpoint_get_base_url(params_endpoint_type, params_url, is_gcc)

    base_url: str = urljoin(params_url, '/api')

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif not enc_key and (not certificate_thumbprint or not private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')
        if not auth_id:
            raise Exception('Authentication ID must be provided.')
        if not tenant_id:
            raise Exception('Tenant ID must be provided.')
        if auth_code:
            if redirect_uri and not self_deployed:
                raise Exception('In order to use Authorization Code, set Self Deployed: True.')
            if not redirect_uri:
                raise Exception('In order to use Authorization Code auth flow, you should set: '
                                '"Application redirect URI", "Authorization code" and "Self Deployed=True".')

    command = demisto.command()
    args = demisto.args()
    LOG(f'command is {command}')
    try:

        client = MsClient(
            base_url=base_url, tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=APP_NAME, verify=use_ssl,
            proxy=proxy, self_deployed=self_deployed, alert_severities_to_fetch=alert_severities_to_fetch,
            alert_status_to_fetch=alert_status_to_fetch, alert_time_to_fetch=alert_time_to_fetch,
            max_fetch=max_alert_to_fetch, certificate_thumbprint=certificate_thumbprint, private_key=private_key,
            auth_type=auth_type, endpoint_type=endpoint_type,
            auth_code=auth_code, redirect_uri=redirect_uri,
            managed_identities_client_id=managed_identities_client_id,
            alert_detectionsource_to_fetch=alert_detectionsource_to_fetch
        )
        if command == 'test-module':
            if auth_type == 'Authorization Code':
                raise Exception('Test-module is not available when using Authentication-code auth flow. '
                                'Please use `!microsoft-atp-test` command to test the connection')
            test_module(client)
            demisto.results('ok')

        elif command == 'microsoft-atp-test':
            test_module(client)
            return_results('✅ Success!')

        elif command == 'fetch-incidents':
            incidents, last_run = fetch_incidents(client, last_run, fetch_evidence)
            demisto.setLastRun(last_run)
            demisto.incidents(incidents)

        elif command == 'microsoft-atp-get-machine-by-ip':
            return_results(get_machine_by_ip_command(client, args))

        elif command == 'microsoft-atp-isolate-machine':
            return_outputs(*isolate_machine_command(client, args))

        elif command == 'microsoft-atp-unisolate-machine':
            return_outputs(*unisolate_machine_command(client, args))

        elif command == 'microsoft-atp-get-machines':
            return_outputs(*get_machines_command(client, args))

        elif command == 'microsoft-atp-get-file-related-machines':
            return_results(get_file_related_machines_command(client, args))

        elif command == 'microsoft-atp-get-machine-details':
            return_results(get_machine_details_command(client, args))

        elif command == 'microsoft-atp-run-antivirus-scan':
            return_outputs(*run_antivirus_scan_command(client, args))

        elif command == 'microsoft-atp-list-alerts':
            return_outputs(*list_alerts_command(client, args))

        elif command == 'microsoft-atp-update-alert':
            return_outputs(*update_alert_command(client, args))

        elif command == 'microsoft-atp-advanced-hunting':
            return_outputs(*get_advanced_hunting_command(client, args))

        elif command == 'microsoft-atp-create-alert':
            return_outputs(*create_alert_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-user':
            return_outputs(*get_alert_related_user_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-files':
            return_outputs(*get_alert_related_files_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-ips':
            return_outputs(*get_alert_related_ips_command(client, args))

        elif command == 'microsoft-atp-get-alert-related-domains':
            return_outputs(*get_alert_related_domains_command(client, args))

        elif command == 'microsoft-atp-list-machine-actions-details':
            return_outputs(*get_machine_action_by_id_command(client, args))

        elif command == 'microsoft-atp-collect-investigation-package':
            return_outputs(*get_machine_investigation_package_command(client, args))

        elif command == 'microsoft-atp-get-investigation-package-sas-uri':
            return_outputs(*get_investigation_package_sas_uri_command(client, args))

        elif command == 'microsoft-atp-restrict-app-execution':
            return_outputs(*restrict_app_execution_command(client, args))

        elif command == 'microsoft-atp-remove-app-restriction':
            return_outputs(*remove_app_restriction_command(client, args))

        elif command == 'microsoft-atp-stop-and-quarantine-file':
            return_results(stop_and_quarantine_file_command(client, args))

        elif command == 'microsoft-atp-list-investigations':
            return_outputs(*get_investigations_by_id_command(client, args))

        elif command == 'microsoft-atp-start-investigation':
            return_outputs(*start_investigation_command(client, args))

        elif command == 'microsoft-atp-get-domain-statistics':
            return_outputs(*get_domain_statistics_command(client, args))

        elif command == 'microsoft-atp-get-domain-alerts':
            return_outputs(*get_domain_alerts_command(client, args))

        elif command == 'microsoft-atp-get-domain-machines':
            return_outputs(*get_domain_machine_command(client, args))

        elif command == 'microsoft-atp-get-file-statistics':
            return_results(get_file_statistics_command(client, args))

        elif command == 'microsoft-atp-get-file-alerts':
            return_outputs(*get_file_alerts_command(client, args))

        elif command == 'microsoft-atp-get-ip-statistics':
            return_outputs(*get_ip_statistics_command(client, args))

        elif command == 'microsoft-atp-get-ip-alerts':
            return_outputs(*get_ip_alerts_command(client, args))

        elif command == 'microsoft-atp-get-user-alerts':
            return_outputs(*get_user_alerts_command(client, args))

        elif command == 'microsoft-atp-get-alert-by-id':
            return_results(get_alert_by_id_command(client, args))

        elif command == 'microsoft-atp-get-user-machines':
            return_outputs(*get_user_machine_command(client, args))

        elif command == 'microsoft-atp-add-remove-machine-tag':
            return_outputs(*add_remove_machine_tag_command(client, args))

        elif command == 'microsoft-atp-list-machines-by-vulnerability':
            return_results(list_machines_by_vulnerability_command(client, args))

        elif command == 'microsoft-atp-list-software-version-distribution':
            return_results(list_software_version_distribution_command(client, args))

        elif command == 'microsoft-atp-list-machines-by-software':
            return_results(list_machines_by_software_command(client, args))

        elif command == 'microsoft-atp-list-missing-kb-by-software':
            return_results(list_missing_kb_by_software_command(client, args))

        elif command == 'microsoft-atp-list-vulnerabilities-by-software':
            return_results(list_vulnerabilities_by_software_command(client, args))

        elif command == 'microsoft-atp-list-software':
            return_results(list_software_command(client, args))

        elif command == 'microsoft-atp-list-vulnerabilities-by-machine':
            return_results(list_vulnerabilities_by_machine_command(client, args))

        elif command == 'microsoft-atp-list-vulnerabilities':
            return_results(list_vulnerabilities_command(client, args))

        elif command == 'microsoft-atp-get-file-info':
            demisto.results(get_file_info_command(client, args))

        elif command == 'endpoint':
            return_results(endpoint_command(client, args))

        elif command in ('microsoft-atp-indicator-list', 'microsoft-atp-indicator-get-by-id'):
            return_outputs(*list_indicators_command(client, args))
        elif command == 'microsoft-atp-indicator-create-file':
            return_outputs(*create_file_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-create-network':
            return_outputs(*create_network_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-update':
            return_outputs(*update_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-delete':
            return_outputs(delete_indicator_command(client, args))
        elif command in ('microsoft-atp-sc-indicator-list', 'microsoft-atp-sc-indicator-get-by-id'):
            return_results(sc_list_indicators_command(client, args))
        elif command in ('microsoft-atp-sc-indicator-update', 'microsoft-atp-sc-indicator-create'):
            return_results(sc_create_update_indicator_command(client, args))
        elif command == 'microsoft-atp-sc-indicator-delete':
            return_results(sc_delete_indicator_command(client, args))
        elif command == 'microsoft-atp-indicator-batch-update':
            return_results(sc_update_batch_indicators_command(client, args))
        elif command == 'microsoft-atp-live-response-put-file':
            return_results(put_live_response_file_with_polling(client, args))
        elif command == 'microsoft-atp-live-response-get-file':
            return_results(get_live_response_file_with_polling(client, args))
        elif command == 'microsoft-atp-live-response-run-script':
            return_results(run_live_response_script_with_polling(client, args))
        elif command == 'microsoft-atp-live-response-cancel-action':
            return_results(cancel_action_command(client, args))
        elif command == 'microsoft-atp-live-response-result':
            return_results(get_live_response_result_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-lateral-movement-evidence':
            return_results(lateral_movement_evidence_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-persistence-evidence':
            return_results(persistence_evidence_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-file-origin':
            return_results(file_origin_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-process-details':
            return_results(process_details_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-network-connections':
            return_results(network_connections_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-privilege-escalation':
            return_results(privilege_escalation_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-tampering':
            return_results(tampering_command(client, args))
        elif command == 'microsoft-atp-advanced-hunting-cover-up':
            return_results(cover_up_command(client, args))
        elif command == 'microsoft-atp-offboard-machine':
            return_results(offboard_machine_command(client, args))
        elif command == 'microsoft-atp-get-machine-users':
            return_results(get_machine_users_command(client, args))
        elif command == 'microsoft-atp-get-machine-alerts':
            return_results(get_machine_alerts_command(client, args))
        elif command == 'microsoft-atp-request-and-download-investigation-package':
            return_results(request_download_investigation_package_command(client, args))
        elif command == 'microsoft-atp-generate-login-url':
            return_results(generate_login_url_command(client))
        elif command == 'microsoft-atp-auth-reset':
            return_results(reset_auth())

    except Exception as err:
        # TODO Following the CIAC-12304 ticket, many commands, including fetch incidents, are deprecated.
        # In the future, if the deprecation reaches end-of-life, we may receive a unique error.
        # It would be worth handling that error and adding explanations if needed.
        return_error(str(err))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
