import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
from http import HTTPStatus
from typing import Any
from collections.abc import Callable
from dateutil import parser
from datetime import datetime
import json
import uuid
import socket
import ipaddress
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
REPOSITORY_STATE_INCIDENT_TYPE = 'Repository Capacity'
CONFIGURATION_BACKUP_INCIDENT_TYPE = 'Configuration Backup'
MAX_ATTEMPTS = 3
MAX_EVENTS_FOR_FETCH = 160
MAX_REPOSITORIES_FOR_FETCH = 39
GRANT_TYPE = 'password'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INT = 2147483647
CONFIGURATION_BACKUP_OLDER_THEN_DAYS = 30
REPOSITORY_FREE_SPACE_LESS_THEN = 200
EARLIEST_TIME = '1970-01-01T00:00:00Z'
NOT_APPLICABLE = 'N/A'
MODE_CUSTOMIZED = 'Customized'
MODE_ORIGINAL_LOCATION = 'OriginalLocation'
X_API_VERSION = '1.1-rev2'
CONTENT_TYPE = 'application/json'
ERROR_COUNT_IN_MALWARE_INCIDENTS = 'error_count_in_malware_incidents'
ERROR_COUNT_IN_FREE_SPACE_INCIDENTS = 'error_count_in_free_space_incidents'
ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS = 'error_count_in_configuration_backup'
REPOSITORY_STATE_REQUEST_PAGE_SIZE = 500
MALWARE_EVENTS_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_SIZE_LIMIT = 0  # Unlimited


DESIRED_TYPES = {
    'EncryptedData': 'Encrypted files',
    'RenamedFiles': 'Renamed files',
    'RansomwareNotes': 'Ransomware notes',
    'MalwareExtensions': 'Suspicious files and extensions',
    'YaraScan': 'YARA scan',
    'AntivirusScan': 'Antivirus scan',
    'DeletedUsefulFiles': 'Deleted files',
    'Unknown': 'Unknown'

}

DESIRED_SOURCE = {
    'External': 'Third-party malware detection software',
    'Manual': 'Added manually',
    'InternalVeeamDetector': 'Veeam malware detection'
}

SEVERITY_MAP = {
    'Suspicious': IncidentSeverity.HIGH,
    'Infected': IncidentSeverity.CRITICAL,

}


ERROR_COUNT_MAP = {
    2: IncidentSeverity.LOW,
    6: IncidentSeverity.MEDIUM,
    48: IncidentSeverity.CRITICAL,

}


''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth, timeout):
        super().__init__(
            base_url=server_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            auth=auth,
            timeout=timeout
        )

    def get_headers(self):
        """
        Gets headers required for requests.

        Returns:
            dict: The header dictionary.
        """
        return self._headers

    def set_headers(self, headers):
        """
        Sets headers required for requests.

        Args:
            headers (dict): The header dictionary to set.
        """
        self._headers = headers

    def get_access_token_request(
        self, grant_type, username=None, password=None, refresh_token=None, code=None,
        use_short_term_refresh=False, v__token=None
    ):
        """
        Gets an access token.

        Args:
            grant_type (str): The grant type.
            username (str): The username.
            password (str): The password.
            refresh_token (str): The refresh token.
            code (str): The code.
            use_short_term_refresh (bool): Flag indicating if a short-term refresh token should be used.
            v__token (str): The v__token.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            grant_type=grant_type,
            username=username,
            password=password,
            refresh_token=refresh_token,
            code=code,
            use_short_term_refresh=use_short_term_refresh,
            v__token=v__token
        )
        headers = self._headers
        headers['Content-Type'] = 'application/x-www-form-urlencoded'

        response = self._http_request(
            'post',
            'api/oauth2/token',
            data=data,
            headers=headers
        )

        return response

    def create_malware_event_request(self, detection_time_utc, machine, details, engine):
        """
        Creates a malware event.

        Args:
            detection_time_utc (str): Detection time in the UTC format.
            machine (dict): Machine that you want to mark with the malware event. Specify at least 2 parameters.
            details (str): Event details.
            engine (str): The detection engine.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            detectionTimeUtc=detection_time_utc,
            machine=machine,
            details=details,
            engine=engine
        )
        headers = self._headers

        response = self._http_request(
            'post',
            'api/v1/malwareDetection/events',
            json_data=data,
            headers=headers
        )

        return response

    def get_all_malware_events_request(
        self, skip=None, limit=None, orderColumn=None, orderAsc=None, typeFilter=None,
        detectedAfterTimeUtcFilter=None, detectedBeforeTimeUtcFilter=None,
        backupObjectIdFilter=None, stateFilter=None, sourceFilter=None, severityFilter=None,
        createdByFilter=None, engineFilter=None
    ):
        """
        Gets all malware events.

        Args:
            skip (int): The number of events to skip.
            limit (int): The maximum number of events to return.
            orderColumn (str): The column to order the events by.
            orderAsc (bool): Flag indicating if the order should be ascending.
            typeFilter (str): Filters events by event type.
            detectedAfterTimeUtcFilter (str): Returns events created after the specified time, in UTC.
            detectedBeforeTimeUtcFilter (str): Returns events created before the specified time, in UTC.
            backupObjectIdFilter (str): Filters events by backup object ID.
            stateFilter (str): Filters events by state.
            sourceFilter (str): Filters events by the source type.
            severityFilter (str): Filters events by severity.
            createdByFilter (str): Filters events by the createdBy pattern.
            engineFilter (str): Filters events by the engine pattern.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(
            skip=skip,
            limit=limit,
            orderColumn=orderColumn,
            orderAsc=orderAsc,
            typeFilter=typeFilter,
            detectedAfterTimeUtcFilter=detectedAfterTimeUtcFilter,
            detectedBeforeTimeUtcFilter=detectedBeforeTimeUtcFilter,
            backupObjectIdFilter=backupObjectIdFilter,
            stateFilter=stateFilter,
            sourceFilter=sourceFilter,
            severityFilter=severityFilter,
            createdByFilter=createdByFilter,
            engineFilter=engineFilter
        )
        headers = self._headers

        response = self._http_request(
            'get',
            'api/v1/malwareDetection/events',
            params=params,
            headers=headers
        )

        return response

    def get_all_repository_states_request(
        self, skip=None, limit=None, orderColumn=None, orderAsc=None, idFilter=None,
        nameFilter=None, typeFilter=None, capacityFilter=None, freeSpaceFilter=None,
        usedSpaceFilter=None
    ):
        """
        Gets all repository states.

        Args:
            skip (int): The number of repository states to skip.
            limit (int): The maximum number of repository states to return.
            orderColumn (str): Sorts repository states by one of the state parameters.
            orderAsc (bool): Sorts repository states in the ascending order by the orderColumn parameter.
            idFilter (str): Filters repository states by the repository ID.
            nameFilter (str): Filters repository states by the nameFilter pattern.
            typeFilter (str): Filters repository states by the repository type.
            capacityFilter (int): Filters repository states by repository capacity.
            freeSpaceFilter (int): Filters repository states by repository free space.
            usedSpaceFilter (int): Filters repository states by repository used space.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(
            skip=skip,
            limit=limit,
            orderColumn=orderColumn,
            orderAsc=orderAsc,
            idFilter=idFilter,
            nameFilter=nameFilter,
            typeFilter=typeFilter,
            capacityFilter=capacityFilter,
            freeSpaceFilter=freeSpaceFilter,
            usedSpaceFilter=usedSpaceFilter
        )
        headers = self._headers

        response = self._http_request(
            'get',
            'api/v1/backupInfrastructure/repositories/states',
            params=params,
            headers=headers
        )

        return response

    def get_all_restore_points_request(
        self, skip, limit, orderColumn, orderAsc, createdAfterFilter, createdBeforeFilter,
        nameFilter, platformNameFilter, platformIdFilter, backupIdFilter,
        backupObjectIdFilter, malwareStatusFilter
    ):
        """
        Gets all restore points.

        Args:
            skip (int): The number of restore points to skip.
            limit (int): The maximum number of restore points to return.
            orderColumn (str): Sorts restore points by one of the restore point parameters.
            orderAsc (bool): Sorts restore points in the ascending order by the orderColumn parameter.
            createdAfterFilter (str): Returns restore points that are created after the specified date and time.
            createdBeforeFilter (str): Returns restore points that are created before the specified date and time.
            nameFilter (str): Filters restore points by the nameFilter pattern.
            platformNameFilter (str): Filters restore points by name of the backup object platform.
            platformIdFilter (str): Filters restore points by ID of the backup object platform.
            backupIdFilter (str): Filters restore points by the backup ID.
            backupObjectIdFilter (str): Filters restore points by the backup object ID.
            malwareStatusFilter (str): Filters restore points by the malware status.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(
            skip=skip,
            limit=limit,
            orderColumn=orderColumn,
            orderAsc=orderAsc,
            createdAfterFilter=createdAfterFilter,
            createdBeforeFilter=createdBeforeFilter,
            nameFilter=nameFilter,
            platformNameFilter=platformNameFilter,
            platformIdFilter=platformIdFilter,
            backupIdFilter=backupIdFilter,
            backupObjectIdFilter=backupObjectIdFilter,
            malwareStatusFilter=malwareStatusFilter
        )
        headers = self._headers

        response = self._http_request(
            'get',
            'api/v1/restorePoints',
            params=params,
            headers=headers
        )

        return response

    def get_backup_object_request(self, id_):
        """
        Gets backup object.

        Args:
            id_ (str): The backup object ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers

        response = self._http_request(
            'get',
            f'api/v1/backupObjects/{id_}',
            headers=headers
        )

        return response

    def get_backup_server_information_request(self):
        """
        Gets backup server information.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers

        response = self._http_request('get', 'api/v1/serverInfo', headers=headers)

        return response

    def get_configuration_backup_request(self):
        """
        Gets configuration backup.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers

        response = self._http_request('get', 'api/v1/configBackup', headers=headers)

        return response

    def get_inventory_objects_request(self, resetCache, hostname, pagination, filter, sorting, hierarchyType):
        """
        Gets inventory objects.

        Args:
            resetCache (bool): Flag indicating if the cache should be reset.
            hostname (str): The hostname of the inventory object.
            pagination (dict): Pagination settings.
            filter (dict): Filter settings.
            sorting (dict): Sorting settings.
            hierarchyType (str): The type of hierarchy.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(resetCache=resetCache)
        data = assign_params(
            pagination=pagination,
            filter=filter,
            sorting=sorting,
            hierarchyType=hierarchyType
        )
        headers = self._headers

        response = self._http_request(
            'post',
            f'api/v1/inventory/{hostname}',
            params=params,
            json_data=data,
            headers=headers
        )

        return response

    def get_session_request(self, id_):
        """
        Gets a session.

        Args:
            id_ (str): The session ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers

        response = self._http_request('get', f'api/v1/sessions/{id_}', headers=headers)

        return response

    def start_configuration_backup_request(self):
        """
        Starts configuration backup.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers

        response = self._http_request('post', 'api/v1/configBackup/backup', headers=headers)

        return response

    def start_instant_recovery_request(
        self, restorePointId, restore_type, vmTagsRestoreEnabled, secureRestore, nicsEnabled, powerUp, reason
    ):
        """
        Starts instant VM recovery.

        Args:
            restorePointId (str): The restore point ID.
            restore_type (str): The type of restore.
            vmTagsRestoreEnabled (bool): If true, Veeam Backup & Replication restores tags that were assigned
            to the original VM, and assign them to the restored VM.
            secureRestore (dict): Secure restore settings.
            nicsEnabled (bool): If true, the restored VM is connected to the network.
            powerUp (bool): If true, Veeam Backup & Replication powers on the restored VM on the target host.
            reason (str): The reason for the instant recovery.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            restorePointId=restorePointId,
            Type=restore_type,
            vmTagsRestoreEnabled=vmTagsRestoreEnabled,
            secureRestore=secureRestore,
            nicsEnabled=nicsEnabled,
            powerUp=powerUp,
            reason=reason
        )
        headers = self._headers

        response = self._http_request(
            'post',
            'api/v1/restore/instantRecovery/vSphere/vm',
            json_data=data,
            headers=headers
        )

        return response

    def start_instant_recovery_customized_request(
        self, restorePointId, restore_type, vmTagsRestoreEnabled, secureRestore, nicsEnabled, powerUp, reason,
        destination, datastore, overwrite
    ):
        """
        Starts customized instant VM recovery.

        Args:
            restorePointId (str): The restore point ID.
            restore_type (str): The type of restore.
            vmTagsRestoreEnabled (bool): If true, Veeam Backup & Replication restores tags that were assigned
            to the original VM, and assign them to the restored VM.
            secureRestore (dict): Secure restore settings.
            nicsEnabled (bool): If true, the restored VM is connected to the network.
            powerUp (bool): If true, Veeam Backup & Replication powers on the restored VM on the target host.
            reason (str): The reason for the instant recovery.
            destination (dict): Destination where the recovered VM resides.
            datastore (dict): Datastore that keeps redo logs with changes that take place while a VM is running from a backup.
            overwrite (bool): Flag indicating if the existing VM should be overwritten.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            restorePointId=restorePointId,
            Type=restore_type,
            vmTagsRestoreEnabled=vmTagsRestoreEnabled,
            secureRestore=secureRestore,
            nicsEnabled=nicsEnabled,
            powerUp=powerUp,
            reason=reason,
            destination=destination,
            datastore=datastore,
            overwrite=overwrite
        )

        headers = self._headers

        response = self._http_request(
            'post',
            'api/v1/restore/instantRecovery/vSphere/vm',
            json_data=data,
            headers=headers
        )

        return response


''' HELPER FUNCTIONS '''


def create_malware_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    detectiontimeutc = str(args.get('detectiontimeutc', ''))
    validate_time(detectiontimeutc)
    machine_fqdn = str(args.get('machine_fqdn', ''))
    machine_ipv4 = str(args.get('machine_ipv4', ''))
    validate_ipv4(machine_ipv4)
    machine_ipv6 = str(args.get('machine_ipv6', ''))
    validate_ipv6(machine_ipv6)
    machine_uuid = str(args.get('machine_uuid', ''))
    validate_uuid(machine_uuid)
    machine = assign_params(fqdn=machine_fqdn, ipv4=machine_ipv4, ipv6=machine_ipv6, uuid=machine_uuid)
    details = str(args.get('details', ''))
    engine = str(args.get('engine', ''))

    response = client.create_malware_event_request(detectiontimeutc, machine, details, engine)
    event_id = response['data'][0].get('id')
    context = demisto.getIntegrationContext()
    post_event_ids = context.get('post_event_ids')
    if post_event_ids:
        post_event_ids.append(str(event_id))
    else:
        post_event_ids = [str(event_id)]
    context['post_event_ids'] = post_event_ids
    demisto.setIntegrationContext(context)

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR',
        outputs_key_field='',
        outputs=response.get('data'),
        raw_response=response.get('data')
    )

    return command_results


def get_all_malware_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get('skip', ''))
    try_cast_to_int(skip)
    limit = str(args.get('limit', ''))
    try_cast_to_int(limit)
    orderColumn = str(args.get('orderColumn', ''))
    orderAsc = str(args.get('orderAsc', ''))
    try_cast_to_bool(orderAsc)
    typeFilter = str(args.get('typeFilter', ''))
    detectedAfterTimeUtcFilter = str(args.get('detectedAfterTimeUtcFilter', ''))
    validate_time(detectedAfterTimeUtcFilter)
    detectedBeforeTimeUtcFilter = str(args.get('detectedBeforeTimeUtcFilter', ''))
    validate_time(detectedBeforeTimeUtcFilter)
    backupObjectIdFilter = str(args.get('backupObjectIdFilter', ''))
    validate_uuid(backupObjectIdFilter)
    stateFilter = str(args.get('stateFilter', ''))
    sourceFilter = str(args.get('sourceFilter', ''))
    severityFilter = str(args.get('severityFilter', ''))
    createdByFilter = str(args.get('createdByFilter', ''))
    engineFilter = str(args.get('engineFilter', ''))

    response = client.get_all_malware_events_request(
        skip, limit, orderColumn, orderAsc, typeFilter, detectedAfterTimeUtcFilter,
        detectedBeforeTimeUtcFilter, backupObjectIdFilter, stateFilter, sourceFilter,
        severityFilter, createdByFilter, engineFilter
    )

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_malware_events.data',
        outputs_key_field='',
        outputs=response.get('data'),
        raw_response=response.get('data')
    )

    return command_results


def get_all_repository_states_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get('skip', ''))
    try_cast_to_int(skip)
    limit = str(args.get('limit', ''))
    try_cast_to_int(limit)
    orderColumn = str(args.get('orderColumn', ''))
    orderAsc = str(args.get('orderAsc', ''))
    try_cast_to_bool(orderAsc)
    idFilter = str(args.get('idFilter', ''))
    validate_uuid(idFilter)
    nameFilter = str(args.get('nameFilter', ''))
    typeFilter = str(args.get('typeFilter', ''))
    capacityFilter = str(args.get('capacityFilter', ''))
    try_cast_to_double(capacityFilter)
    freeSpaceFilter = str(args.get('freeSpaceFilter', ''))
    try_cast_to_double(freeSpaceFilter)
    usedSpaceFilter = str(args.get('usedSpaceFilter', ''))
    try_cast_to_double(usedSpaceFilter)

    response = client.get_all_repository_states_request(
        skip, limit, orderColumn, orderAsc, idFilter, nameFilter, typeFilter, capacityFilter, freeSpaceFilter, usedSpaceFilter
    )

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_repository_states.data',
        outputs_key_field='',
        outputs=response.get('data'),
        raw_response=response.get('data')
    )

    return command_results


def get_all_restore_points_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get('skip', ''))
    try_cast_to_int(skip)
    limit = str(args.get('limit', ''))
    try_cast_to_int(limit)
    orderColumn = str(args.get('orderColumn', ''))
    orderAsc = str(args.get('orderAsc', ''))
    try_cast_to_bool(orderAsc)
    createdAfterFilter = str(args.get('createdAfterFilter', ''))
    validate_time(createdAfterFilter)
    createdBeforeFilter = str(args.get('createdBeforeFilter', ''))
    validate_time(createdBeforeFilter)
    nameFilter = str(args.get('nameFilter', ''))
    platformNameFilter = str(args.get('platformNameFilter', ''))
    platformIdFilter = str(args.get('platformIdFilter', ''))
    validate_uuid(platformIdFilter)
    backupIdFilter = str(args.get('backupIdFilter', ''))
    validate_uuid(backupIdFilter)
    backupObjectIdFilter = str(args.get('backupObjectIdFilter', ''))
    validate_uuid(backupObjectIdFilter)
    malwareStatusFilter = str(args.get('malwareStatusFilter', ''))

    response = client.get_all_restore_points_request(
        skip, limit, orderColumn, orderAsc, createdAfterFilter, createdBeforeFilter,
        nameFilter, platformNameFilter, platformIdFilter, backupIdFilter,
        backupObjectIdFilter, malwareStatusFilter
    )

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_restore_points.data',
        outputs_key_field='',
        outputs=response.get('data'),
        raw_response=response.get('data')
    )

    return command_results


def get_backup_object_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    validate_uuid(id_)

    response = client.get_backup_object_request(id_)
    path = response.get('path', '')
    vcenter_name = get_vcentername(path)
    response['vcenter_name'] = vcenter_name

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.backup_object',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_configuration_backup_command(client: Client, args: dict[str, Any]) -> CommandResults:

    response = client.get_configuration_backup_request()
    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_configuration_backup',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_inventory_objects_command(client: Client, args: dict[str, Any]) -> CommandResults:
    resetCache = str(args.get('resetCache', ''))
    try_cast_to_bool(resetCache)
    hostname = str(args.get('hostname', ''))
    skip = str(args.get('skip', ''))
    try_cast_to_int(skip)
    limit = str(args.get('limit', ''))
    try_cast_to_int(limit)
    pagination = assign_params(skip=skip, limit=limit)
    filter_str = str(args.get('filter', ''))
    filter = convert_to_json(filter_str)

    object_name = str(args.get('objectName', ''))
    vi_type = str(args.get('viType', ''))
    if vi_type and object_name:
        filter = {
            "type": "GroupExpression",
            "operation": "and",
            "items": [
                {
                    "type": "PredicateExpression",
                    "operation": "equals",
                    "property": "Name",
                    "value": object_name
                },
                {
                    "type": "PredicateExpression",
                    "operation": "in",
                    "property": "Type",
                    "value": vi_type
                }
            ]
        }

    sorting_str = str(args.get('sorting', ''))
    sorting = convert_to_json(sorting_str)
    hierarchyType = str(args.get('hierarchyType', ''))

    response = client.get_inventory_objects_request(resetCache, hostname, pagination, filter, sorting, hierarchyType)

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_inventory_objects.data',
        outputs_key_field='',
        outputs=response.get('data'),
        raw_response=response.get('data')
    )

    return command_results


def get_session_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))
    validate_uuid(id_)

    response = client.get_session_request(id_)
    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.get_session',
        outputs_key_field='',
        outputs=response,
        raw_response=response,
        replace_existing=True
    )

    return command_results


def start_configuration_backup_command(client: Client, args: dict[str, Any]) -> CommandResults:

    response = client.start_configuration_backup_request()
    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.Configurationbackuphasbeenstarted',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def start_instant_recovery_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get('restorePointId', ''))
    validate_uuid(restorePointId)
    restore_type = MODE_ORIGINAL_LOCATION
    vmTagsRestoreEnabled = str(args.get('vmTagsRestoreEnabled', ''))
    try_cast_to_bool(vmTagsRestoreEnabled)
    antivirusScanEnabled = str(args.get('antivirusScanEnabled', ''))
    try_cast_to_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get('virusDetectionAction', ''))
    entireVolumeScanEnabled = str(args.get('entireVolumeScanEnabled', ''))
    try_cast_to_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled
    )
    nicsEnabled = str(args.get('nicsEnabled', ''))
    try_cast_to_bool(nicsEnabled)
    powerUp = str(args.get('powerUp', ''))
    try_cast_to_bool(powerUp)
    reason = str(args.get('reason', ''))

    response = client.start_instant_recovery_request(
        restorePointId, restore_type, vmTagsRestoreEnabled, secureRestore, nicsEnabled, powerUp, reason
    )

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.start_recovery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def start_instant_recovery_customized_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get('restorePointId', ''))
    validate_uuid(restorePointId)
    restore_type = MODE_CUSTOMIZED
    vmTagsRestoreEnabled = str(args.get('vmTagsRestoreEnabled', ''))
    try_cast_to_bool(vmTagsRestoreEnabled)
    antivirusScanEnabled = str(args.get('antivirusScanEnabled', ''))
    try_cast_to_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get('virusDetectionAction', ''))
    entireVolumeScanEnabled = str(args.get('entireVolumeScanEnabled', ''))
    try_cast_to_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled
    )
    nicsEnabled = str(args.get('nicsEnabled', ''))
    try_cast_to_bool(nicsEnabled)
    powerUp = str(args.get('powerUp', ''))
    try_cast_to_bool(powerUp)
    reason = str(args.get('reason', ''))

    restoredVmName = str(args.get('restoredVmName', ''))
    vCenterName = str(args.get('vCenterName', ''))
    platform = str(args.get('platform', ''))
    biosUuidPolicy = str(args.get('biosUuidPolicy', ''))

    hostObjectId = str(args.get('hostObjectId', ''))
    destinationHost = assign_params(type="Host", hostName=vCenterName, name=vCenterName, objectId=hostObjectId, platform=platform)

    folderObjectId = str(args.get('folderObjectId', ''))
    folder = assign_params(type="Folder", hostName=vCenterName, objectId=folderObjectId, platform=platform)

    destination = assign_params(
        restoredVmName=restoredVmName, destinationHost=destinationHost, folder=folder, biosUuidPolicy=biosUuidPolicy
    )

    resObjectId = str(args.get('resObjectId', ''))
    if resObjectId:
        resourcePool = assign_params(type="ResourcePool", hostName=vCenterName, objectId=resObjectId, platform=platform)
        destination['resourcePool'] = resourcePool

    redirectEnabled = str(args.get('redirectEnabled', ''))
    try_cast_to_bool(redirectEnabled)
    datastore = assign_params(redirectEnabled=redirectEnabled)
    overwrite = str(args.get('overwrite', ''))
    try_cast_to_bool(overwrite)

    response = client.start_instant_recovery_customized_request(
        restorePointId, restore_type, vmTagsRestoreEnabled, secureRestore, nicsEnabled, powerUp, reason,
        destination, datastore, overwrite
    )

    command_results = CommandResults(
        outputs_prefix='Veeam.VBR.start_recovery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_vcentername(string: str) -> str:
    index = string.find('\\')

    if index != -1:
        vcentername = string[:index]
        return vcentername
    else:
        return string


def convert_to_json(string: str) -> dict:
    if not string:
        return {}

    try:
        data = json.loads(string)
    except ValueError as e:
        raise ValueError(f"Invalid JSON string. Exception: {str(e)}")

    return data


def validate_uuid(uuid_: str) -> None:
    if uuid_:
        try:
            uuid.UUID(uuid_)
        except ValueError as e:
            raise ValueError(f"Invalid UUID string: '{uuid_}'. Exception: {str(e)}")


def validate_ipv4(ipv4: str) -> None:
    if ipv4:
        try:
            ipaddress.IPv4Address(ipv4)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            try:
                socket.inet_pton(socket.AF_INET, ipv4)
            except OSError as e:
                raise ValueError(f"Invalid IPv4 address: '{ipv4}'. Exception: {str(e)}")


def validate_ipv6(ipv6: str) -> None:
    if ipv6:
        try:
            ipaddress.IPv6Address(ipv6)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            try:
                socket.inet_pton(socket.AF_INET6, ipv6)
            except OSError as e:
                raise ValueError(f"Invalid IPv6 address: '{ipv6}'. Exception: {str(e)}")


def validate_time(time: str) -> None:
    if time:
        try:
            datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%fZ')
        except ValueError:
            try:
                datetime.strptime(time, DATE_FORMAT)
            except ValueError as e:
                raise ValueError(f"Invalid date format: '{time}'. Exception: {str(e)}")


def try_cast_to_int(value: str) -> None:
    if value:
        try:
            int(value)
        except ValueError as e:
            raise ValueError(f"Failed to convert '{value}' to integer. Exception: {str(e)}")


def try_cast_to_bool(value: str) -> None:
    if value:
        value = value.strip().lower()
        if value != 'true' and value != 'false':
            raise ValueError(f"Failed to convert '{value}' to boolean")


def try_cast_to_double(value: str) -> None:
    if value:
        try:
            float(value)
        except ValueError as e:
            raise ValueError(f"Failed to convert '{value}' to double. Exception: {str(e)}")


def test_module(client: Client) -> str:
    """
    Tests the integration by making a request to the Veeam Backup & Replication server.

    Args:
        client (Client): The Veeam Backup & Replication client.

    Returns:
        str: The result of the test. Returns 'ok' if the test is successful.

    Raises:
        Exception: If an error occurred during the test.
    """
    try:
        client.get_backup_server_information_request()
    except Exception as e:
        exception_text = str(e).lower()
        if 'forbidden' in exception_text or 'authorization' in exception_text:
            return 'Authentication Error: Invalid API Key'
        else:
            raise e
    return 'ok'


def update_token(client: Client, username: str, password: str) -> str:
    response = client.get_access_token_request(GRANT_TYPE, username, password)
    token = response.get('access_token')
    return token


def search_with_paging(
    method: Callable[..., Any],
    args: dict[str, Any] = {},
    page_size=DEFAULT_PAGE_SIZE,
    size_limit=DEFAULT_SIZE_LIMIT
) -> list[dict]:

    skip_items = 0
    args['skip'] = 0
    items_to_fetch = size_limit
    items: list[dict] = []

    while True:
        if 0 < items_to_fetch < page_size:
            page_size = items_to_fetch
        args['limit'] = page_size

        response = method(**args)

        items = items + response['data']
        response_len = len(response['data'])

        if response_len < page_size:
            break

        items_to_fetch -= response_len
        skip_items += page_size

        if (size_limit and items_to_fetch <= 0):
            items = items[:size_limit]
            break

        args['skip'] = skip_items
    return items


def overwrite_last_fetch_time(last_fetch_time: str, event: dict) -> str:
    last_fetch_datetime = parser.isoparse(last_fetch_time)
    event_datetime = parser.isoparse(event['detectionTimeUtc'])

    if event_datetime > last_fetch_datetime:
        last_fetch_time = event['detectionTimeUtc']

    return last_fetch_time


def process_error(error_count: int, error_message: str) -> tuple[dict, int]:
    error_count += 1
    incident = {}
    if error_count in ERROR_COUNT_MAP:
        integration_instance = demisto.callingContext.get('context', {}).get('IntegrationInstance', '')
        incident_name = f"Veeam - Fetch incident error has occurred on {integration_instance}"
        incident = {
            'name': incident_name,
            'occurred': datetime.now().strftime(DATE_FORMAT),
            'rawJSON': json.dumps({'incident_type': 'Incident Fetch Error', 'details': error_message}),
            'severity': ERROR_COUNT_MAP[error_count]
        }

    return incident, error_count


def get_malware_incidents(
    client: Client, start_time: datetime, existed_ids: set, max_results: int
) -> tuple[list[dict], set[str], str]:

    last_fetch_time = start_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    response = search_with_paging(
        method=client.get_all_malware_events_request,
        args={'detectedAfterTimeUtcFilter': last_fetch_time, 'orderColumn': 'detectionTimeUtc', 'orderAsc': 'true'},
        page_size=MALWARE_EVENTS_PAGE_SIZE
    )
    incidents: list[dict] = []
    new_ids = set()

    for event in response:
        if len(incidents) >= max_results:
            break

        event_id = str(event.get("id"))

        source_: str = str(event.get('source'))
        source_exist = DESIRED_SOURCE.get(source_)
        type_: str = str(event.get('type'))
        type_exist = DESIRED_TYPES.get(type_)
        event_severity: str = str(event.get('severity'))
        severity = SEVERITY_MAP.get(event_severity)

        if source_exist and type_exist and severity and event_id not in existed_ids:
            hostname = event['machine'].get('displayName')
            details = f"{event['details']}; Hostname: {hostname}"
            incident_name = f"Veeam - Malware activity detected on {hostname}"
            event['description'] = details
            event['incident_type'] = type_
            event['type_description'] = type_exist
            event['source_description'] = source_exist
            incident = {
                'name': incident_name,
                'occurred': event['detectionTimeUtc'],
                'rawJSON': json.dumps(event),
                'severity': severity
            }
            new_ids.add(event_id)
            incidents.append(incident)
            last_fetch_time = overwrite_last_fetch_time(last_fetch_time, event)

    if not new_ids:
        new_ids = existed_ids

    return incidents, new_ids, last_fetch_time


def get_configuration_backup_incident(
    client: Client, last_successful_backup_date: str, backup_older_then_days: int
) -> tuple[dict, str]:

    last_successful_backup_date = last_successful_backup_date if last_successful_backup_date else ''
    if last_successful_backup_date:
        last_successful_backup_datetime = parser.isoparse(last_successful_backup_date)
    else:
        last_successful_backup_datetime = None
        demisto.debug(f"no {last_successful_backup_date=}")

    last_fetch_time = datetime.now().strftime(DATE_FORMAT)
    response = client.get_configuration_backup_request()
    today = datetime.now().date()

    last_time_backup = response.get('lastSuccessfulBackup').get('lastSuccessfulTime')
    difference = None
    if last_time_backup:
        last_backup_date = parser.isoparse(last_time_backup).date()
        difference = (today - last_backup_date).days
    else:
        last_time_backup = EARLIEST_TIME

    incident: dict = {}
    last_backup_datetime = parser.isoparse(last_time_backup)
    if difference is None or difference >= backup_older_then_days:
        if not last_successful_backup_date or (last_successful_backup_datetime is not None
                                               and last_backup_datetime > last_successful_backup_datetime):
            time_ = NOT_APPLICABLE if last_time_backup == EARLIEST_TIME else last_time_backup
            details = f"Last successful backup: {time_}"
            integration_instance = demisto.callingContext.get('context', {}).get('IntegrationInstance', '')
            incident_name = f"Veeam - {integration_instance} has no configuration backups"
            response['details'] = details
            response['incident_type'] = CONFIGURATION_BACKUP_INCIDENT_TYPE
            incident = {
                'name': incident_name,
                'occurred': last_fetch_time,
                'rawJSON': json.dumps(response),
                'severity': IncidentSeverity.MEDIUM
            }

            last_successful_backup_date = last_time_backup
    return incident, last_successful_backup_date


def get_repository_space_incidents(
    client: Client, existed_ids: set, max_results: int, free_space_less_then: int
) -> tuple[list[dict], set[str]]:

    last_fetch_time = datetime.now().strftime(DATE_FORMAT)
    response = search_with_paging(
        method=client.get_all_repository_states_request,
        args={'orderColumn': 'FreeGB', 'orderAsc': 'true'},
        page_size=REPOSITORY_STATE_REQUEST_PAGE_SIZE
    )

    incidents: list[dict] = []
    incident_repository_ids = existed_ids

    repository_ids = {repository['id'] for repository in response}
    incident_repository_ids.intersection_update(repository_ids)

    for repository in response:
        if len(incidents) >= max_results:
            break

        repository_id = str(repository.get("id"))

        if repository['freeGB'] < free_space_less_then and repository['capacityGB'] > 0:

            hostname = repository.get('hostName', '')
            hostname = hostname if hostname else NOT_APPLICABLE

            if repository_id not in incident_repository_ids:
                details = (
                    f"{repository['description']}; Repository Name: {repository['name']}; "
                    f"Free Space (GB): {repository['freeGB']}; Hostname: {hostname}"
                )
                incident_name = (
                    f"Veeam - Repository {repository['name']} is running low on disk space. Free space: {repository['freeGB']}"
                )
                repository['details'] = details
                repository['incident_type'] = REPOSITORY_STATE_INCIDENT_TYPE
                incident = {
                    'name': incident_name,
                    'occurred': last_fetch_time,
                    'rawJSON': json.dumps(repository),
                    'severity': IncidentSeverity.HIGH
                }

                incident_repository_ids.add(repository_id)
                incidents.append(incident)

    return incidents, incident_repository_ids


def fetch_malware_events(
    client: Client, last_run: dict, last_fetch: str, max_results: int, errors_by_command: dict
) -> tuple[list[dict], set[str], str]:

    last_fetch_time = last_fetch
    malware_incidents: list[dict] = []
    error_count: int = errors_by_command.get(ERROR_COUNT_IN_MALWARE_INCIDENTS, 0)
    try:
        malwareIds = set(last_run.get("malware_ids", []))
        context = demisto.getIntegrationContext()
        post_events_ids: list = context.get('post_event_ids', [])
        malwareIds.update(post_events_ids)
        context['post_event_ids'] = []
        demisto.setIntegrationContext(context)
        malware_incidents, malwareIds, last_fetch_time = handle_command_with_token_refresh(
            get_malware_incidents,
            {'client': client, 'start_time': parser.parse(last_fetch), 'existed_ids': malwareIds, 'max_results': max_results},
            client
        )
        error_count = 0
    except Exception as e:
        error_message = str(e)
        demisto.debug(error_message)
        incident, error_count = process_error(error_count, error_message)
        if incident:
            malware_incidents.append(incident)
    finally:
        errors_by_command[ERROR_COUNT_IN_MALWARE_INCIDENTS] = error_count
        return malware_incidents, malwareIds, last_fetch_time


def fetch_repository_space_incidents(
    client: Client, last_run: dict, max_results: int, free_space_less_then: int, errors_by_command: dict
) -> tuple[list[dict], set[str]]:

    free_space_incidents: list[dict] = []
    error_count: int = errors_by_command.get(ERROR_COUNT_IN_FREE_SPACE_INCIDENTS, 0)
    try:
        repositoryIds = set(last_run.get("repository_ids", []))
        free_space_incidents, repositoryIds = handle_command_with_token_refresh(
            get_repository_space_incidents,
            {
                'client': client,
                'existed_ids': repositoryIds,
                'max_results': max_results,
                'free_space_less_then': free_space_less_then
            },
            client
        )
        error_count = 0
    except Exception as e:
        error_message = str(e)
        demisto.debug(error_message)
        incident, error_count = process_error(error_count, error_message)
        if incident:
            free_space_incidents.append(incident)
    finally:
        errors_by_command[ERROR_COUNT_IN_FREE_SPACE_INCIDENTS] = error_count
        return free_space_incidents, repositoryIds


def fetch_configuration_backup_incident(
    client: Client, last_run: dict, backup_older_then_days: int, errors_by_command: dict
) -> tuple[list[dict], str]:

    configuration_backup_incidents: list[dict] = []
    backup_incident: dict = {}
    error_count: int = errors_by_command.get(ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS, 0)
    try:
        backupDate = last_run.get("backup_date", None)
        backup_incident, backupDate = handle_command_with_token_refresh(
            get_configuration_backup_incident,
            {'client': client, 'last_successful_backup_date': backupDate, 'backup_older_then_days': backup_older_then_days},
            client
        )
        if backup_incident:
            configuration_backup_incidents.append(backup_incident)
        error_count = 0
    except Exception as e:
        error_message = str(e)
        demisto.debug(error_message)
        incident, error_count = process_error(error_count, error_message)
        if incident:
            configuration_backup_incidents.append(incident)
    finally:
        errors_by_command[ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS] = error_count
        return configuration_backup_incidents, backupDate


def fetch_incidents(
    client: Client, last_run: dict, first_fetch_time: str, max_malware_events_for_fetch: int,
    max_repos_space_events_for_fetch: int, backup_older_then_days: int, free_space_less_then: int,
    fetch_malware_incidents: bool, fetch_backup_repository_events: bool,
    fetch_configuration_backup_events: bool
) -> tuple[dict, list[dict]]:

    demisto.debug(f'Last run: {json.dumps(last_run)}')
    last_fetch = last_run.get('last_fetch', None)

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = last_fetch

    assert last_fetch

    incidents: list[dict[str, Any]] = []
    errors_by_command: dict = last_run.get('errors_by_command', {})

    malware_incidents: list[dict] = []
    malwareIds: set[str] = set()
    last_fetch_time: str = datetime.now().strftime(DATE_FORMAT)
    if max_malware_events_for_fetch > 0 and fetch_malware_incidents is True:
        malware_incidents, malwareIds, last_fetch_time = fetch_malware_events(
            client=client, last_run=last_run, last_fetch=last_fetch, max_results=max_malware_events_for_fetch,
            errors_by_command=errors_by_command
        )
        incidents.extend(malware_incidents)

    free_space_incidents: list[dict] = []
    repositoryIds: set[str] = set()
    if max_repos_space_events_for_fetch > 0 and fetch_backup_repository_events is True:
        free_space_incidents, repositoryIds = fetch_repository_space_incidents(
            client=client, last_run=last_run, max_results=max_repos_space_events_for_fetch,
            free_space_less_then=free_space_less_then, errors_by_command=errors_by_command
        )
        incidents.extend(free_space_incidents)

    backup_incidents: list[dict] = []
    backupDate: str = ''
    if fetch_configuration_backup_events is True:
        backup_incidents, backupDate = fetch_configuration_backup_incident(
            client=client, last_run=last_run, backup_older_then_days=backup_older_then_days, errors_by_command=errors_by_command
        )
        incidents.extend(backup_incidents)

    next_run = {
        'last_fetch': last_fetch_time, 'malware_ids': list(malwareIds), 'repository_ids': list(repositoryIds),
        'backup_date': backupDate, 'errors_by_command': errors_by_command
    }
    demisto.debug(f'Number of incidents: {len(incidents)}')
    demisto.debug(f'Next run after incident fetching: {json.dumps(next_run)}')
    return next_run, incidents


def validate_filter_parameter(value: int) -> None:
    if value < 0 or value > MAX_INT:
        raise ValueError(f"Invalid input parameter value: {value}. "
                         f"Parameter value must be non-negative and less than maximum integer value")


def process_command(command: Any, client: Client, first_fetch_time: datetime,
                    params: dict, args: dict, max_attempts: int = MAX_ATTEMPTS):
    commands = {

        'veeam-vbr-create-malware-event': create_malware_event_command,

        'veeam-vbr-get-malware-events': get_all_malware_events_command,

        'veeam-vbr-get-repository-states': get_all_repository_states_command,

        'veeam-vbr-get-restore-points': get_all_restore_points_command,

        'veeam-vbr-get-backup-object': get_backup_object_command,

        'veeam-vbr-get-configuration-backup': get_configuration_backup_command,

        'veeam-vbr-get-inventory-objects': get_inventory_objects_command,

        'veeam-vbr-get-session': get_session_command,

        'veeam-vbr-start-configuration-backup': start_configuration_backup_command,

        'veeam-vbr-start-instant-recovery': start_instant_recovery_command,

        'veeam-vbr-start-instant-recovery-customized': start_instant_recovery_customized_command

    }

    if command == 'test-module':
        result = handle_command_with_token_refresh(test_module, {'client': client}, client, max_attempts)
        return result

    elif command == 'fetch-incidents':
        max_malware_events_for_fetch = int(params.get('malware_events_per_request', MAX_EVENTS_FOR_FETCH))
        max_repos_space_events_for_fetch = int(params.get('backup_repository_events_per_request', MAX_REPOSITORIES_FOR_FETCH))

        backup_older_then_days = int(params.get('days_since_last_configuration_backup', CONFIGURATION_BACKUP_OLDER_THEN_DAYS))
        validate_filter_parameter(backup_older_then_days)

        free_space_less_then = int(params.get('backup_repository_free_space', REPOSITORY_FREE_SPACE_LESS_THEN))
        validate_filter_parameter(free_space_less_then)

        fetch_configuration_backup_events: bool = params.get('fetch_configuration_backup_events', False)
        fetch_backup_repository_events: bool = params.get('fetch_backup_repository_events', False)
        fetch_malware_incidents: bool = params.get('fetch_malware_events', False)

        next_run, incidents = fetch_incidents(
            client=client,
            last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
            first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),
            max_malware_events_for_fetch=max_malware_events_for_fetch,
            max_repos_space_events_for_fetch=max_repos_space_events_for_fetch,
            backup_older_then_days=backup_older_then_days,
            free_space_less_then=free_space_less_then,
            fetch_malware_incidents=fetch_malware_incidents,
            fetch_backup_repository_events=fetch_backup_repository_events,
            fetch_configuration_backup_events=fetch_configuration_backup_events
        )

        demisto.setLastRun(next_run)
        demisto.incidents(incidents)
        return None

    elif command in commands:
        result = handle_command_with_token_refresh(commands[command], {'client': client, 'args': args}, client, max_attempts)
        return result
    else:
        raise NotImplementedError(f'Command {command} is not implemented.')


def get_api_key(client: Client) -> str:
    credentials: dict[str, str] = demisto.params().get('credentials')
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    token = update_token(client, username, password)
    api_key = f'Bearer {token}'
    return api_key


def set_api_key(client: Client, api_key: str) -> None:
    headers = client.get_headers()
    headers['Authorization'] = api_key
    client.set_headers(headers)


def handle_command_with_token_refresh(command: Callable, command_params: dict, client: Client, max_attempts: int = MAX_ATTEMPTS):
    attempts = 0

    while attempts < max_attempts:
        try:
            context = demisto.getIntegrationContext()
            api_key = context.get('token')
            if not api_key:
                api_key = get_api_key(client)
                demisto.setIntegrationContext({'token': api_key})

            set_api_key(client, api_key)

            res = command(**command_params)
            return res
        except Exception as e:
            status_code = getattr(getattr(e, 'res', None), 'status_code', None)
            if status_code == HTTPStatus.UNAUTHORIZED:
                attempts += 1
                context = demisto.getIntegrationContext()
                context['token'] = None
                demisto.setIntegrationContext(context)
            else:
                raise e

    raise ValueError('Failed to obtain valid API Key after 3 attempts')


def main() -> None:

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url: str = params.get('url', '')
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=False
    )

    if not first_fetch_time:
        first_fetch_time = datetime.now()

    http_request_timeout_sec = int(params.get('http_request_timeout_sec', 120))

    headers = {}
    headers['x-api-version'] = X_API_VERSION
    headers['Content-Type'] = CONTENT_TYPE

    command = demisto.command()
    demisto.debug(f'Command {command} has been run with the following arguments: {args}')

    try:
        client: Client = Client(
            urljoin(url, '/'),
            verify_certificate,
            proxy,
            headers=headers,
            auth=None,
            timeout=http_request_timeout_sec
        )
        result = process_command(command, client, first_fetch_time, params, args)
        return_results(result)

    except Exception as e:
        error_message: Union[str, dict[str, Any]] = str(e)
        res = getattr(e, 'res', None)
        status_code = getattr(res, 'status_code', None)
        if res is not None and status_code:
            error_dict = res.__dict__
            content = convert_to_json(error_dict['_content'])
            message = content.get('message')
            message = message if message else str(e)
            error_message = {'status_code': status_code, 'message': message}

        return_error(error_message)


''' ENTRY POINT '''

if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
