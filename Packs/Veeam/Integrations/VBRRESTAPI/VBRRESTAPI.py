import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """
import ipaddress
import json
import socket
import uuid
from collections.abc import Callable
from datetime import datetime
from http import HTTPStatus
from typing import Any

import urllib3
from dateutil import parser

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
REPOSITORY_STATE_INCIDENT_TYPE = "Repository Capacity"
CONFIGURATION_BACKUP_INCIDENT_TYPE = "Configuration Backup"
SECURITY_ANALYZER_INCIDENT_TYPE = "Security Analyzer Violation"
SURE_BACKUP_INCIDENT_TYPE = "SureBackup Content Scan Failed"
MAX_ATTEMPTS = 3
MAX_EVENTS_FOR_FETCH = 160
MAX_REPOSITORIES_FOR_FETCH = 39
GRANT_TYPE = "password"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INT = 2147483647
CONFIGURATION_BACKUP_OLDER_THEN_DAYS = 30
REPOSITORY_FREE_SPACE_LESS_THEN = 200
EARLIEST_TIME = "1970-01-01T00:00:00Z"
NOT_APPLICABLE = "N/A"
MODE_CUSTOMIZED = "Customized"
MODE_ORIGINAL_LOCATION = "OriginalLocation"
X_API_VERSION = "1.3-rev1"
CONTENT_TYPE = "application/json"
ERROR_COUNT_IN_MALWARE_INCIDENTS = "error_count_in_malware_incidents"
ERROR_COUNT_IN_FREE_SPACE_INCIDENTS = "error_count_in_free_space_incidents"
ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS = "error_count_in_configuration_backup"
ERROR_COUNT_IN_SECURITY_ANALYZER_INCIDENTS = "error_count_in_security_analyzer"
ERROR_COUNT_IN_SURE_BACKUP_INCIDENTS = "error_count_in_sure_backup"
REPOSITORY_STATE_REQUEST_PAGE_SIZE = 500
MALWARE_EVENTS_PAGE_SIZE = 500
JOB_STATES_REQUEST_PAGE_SIZE = 500
DEFAULT_PAGE_SIZE = 100
DEFAULT_SIZE_LIMIT = 0  # Unlimited


DESIRED_TYPES = {
    "EncryptedData": "Encrypted files",
    "RenamedFiles": "Renamed files",
    "RansomwareNotes": "Ransomware notes",
    "MalwareExtensions": "Suspicious files and extensions",
    "YaraScan": "YARA scan",
    "AntivirusScan": "Antivirus scan",
    "DeletedUsefulFiles": "Deleted files",
    "Unknown": "Unknown",
    "IndicatorOfCompromise": "Indicator of compromise",
    "All": "Unknown",
}

DESIRED_SOURCE = {
    "External": "Third-party malware detection software",
    "Manual": "Added manually",
    "InternalVeeamDetector": "Veeam malware detection",
}

SEVERITY_MAP = {
    "Suspicious": IncidentSeverity.HIGH,
    "Infected": IncidentSeverity.CRITICAL,
}


ERROR_COUNT_MAP = {
    2: IncidentSeverity.LOW,
    6: IncidentSeverity.MEDIUM,
    48: IncidentSeverity.CRITICAL,
}

ACCEPTABLE_LICENSES = [
    {"type": "Subscription", "package": "Suite"},
    {"type": "Evaluation", "package": "Suite"},
    {"type": "NFR", "package": "Suite"},
    {"type": "Rental", "edition": "EnterprisePlus"},
]


""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth, timeout):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth, timeout=timeout)

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

    def general_api_request(self, path, method, data=None, params=None):
        """
        Sends a generic HTTP request to any VBR REST API endpoint.

        Args:
            path (str): The API endpoint path (e.g. 'api/v1/jobs').
            method (str): The HTTP method (e.g. 'get', 'post', 'put', 'delete').
            data (dict): Optional JSON body for the request.
            params (dict): Optional query parameters for the request.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request(method, path, json_data=data, params=params, headers=headers)

        return response

    def get_access_token_request(
        self, grant_type, username=None, password=None, refresh_token=None, code=None, use_short_term_refresh=False, v__token=None
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
            v__token=v__token,
        )
        headers = self._headers.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        response = self._http_request("post", "api/oauth2/token", data=data, headers=headers)

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
        data = assign_params(detectionTimeUtc=detection_time_utc, machine=machine, details=details, engine=engine)
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/malwareDetection/events", json_data=data, headers=headers)

        return response

    def get_all_malware_events_request(
        self,
        skip=None,
        limit=None,
        orderColumn=None,
        orderAsc=None,
        typeFilter=None,
        detectedAfterTimeUtcFilter=None,
        detectedBeforeTimeUtcFilter=None,
        backupObjectIdFilter=None,
        stateFilter=None,
        sourceFilter=None,
        severityFilter=None,
        createdByFilter=None,
        engineFilter=None,
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
            engineFilter=engineFilter,
        )
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/malwareDetection/events", params=params, headers=headers)

        return response

    def get_yara_rules_request(self):
        """
        Gets all YARA rules.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/malwareDetection/yaraRules", headers=headers)

        return response

    def start_malware_backup_scan_request(
        self, backupObjectPair, scanMode, scanEngine, scanRange=None, continueScan=None, type_=None
    ):
        """
        Starts a malware scan for a backup.

        Args:
            backupObjectPair (list): Array of objects containing the backup IDs and backup object IDs.
            scanMode (str): Backup scan mode.
            scanEngine (dict): Type of backup scan engine.
            scanRange (dict): Backup scan range.
            continueScan (bool): If true, the backup scan will continue even after it finds affected restore points.
            type(str): Malware backup scan specification type.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            backupObjectPair=backupObjectPair,
            scanMode=scanMode,
            scanEngine=scanEngine,
            scanRange=scanRange,
            continueScan=continueScan,
            type=type_,
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/malwareDetection/scanBackup", json_data=data, headers=headers)

        return response

    def start_disk_publishing_request(self, restorePointId, allowedIps, diskNames=None, mountHostId=None):
        """
        Starts disk publishing via the Data Integration API.

        Args:
            restorePointId (str): Restore point ID.
            allowedIps (list): Array of IP addresses allowed to access the iSCSI target server.
            diskNames (list): Array of disk names.
            mountHostId (str): Mount server ID.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            restorePointId=restorePointId,
            diskNames=diskNames,
            type="ISCSITarget",
            allowedIps=allowedIps,
            mountHostId=mountHostId,
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/dataIntegration/publish", json_data=data, headers=headers)

        return response

    def stop_disk_publishing_request(self, mountId):
        """
        Stops disk publishing and unmounts the published disk content.

        Args:
            mountId (str): Mount point ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("post", f"api/v1/dataIntegration/{mountId}/unpublish", headers=headers)

        return response

    def get_license_request(self):
        """
        Gets the current license information.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/license", headers=headers)

        return response

    def get_disk_publishing_mount_point_request(self, mountId):
        """
        Gets a disk publishing mount point by its ID.

        Args:
            mountId (str): Mount point ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", f"api/v1/dataIntegration/{mountId}", headers=headers)

        return response

    def mount_entra_id_tenant_request(self, backupId):
        """
        Mounts a Microsoft Entra ID tenant from its backup and starts a mount session.

        Args:
            backupId (str): ID of a Microsoft Entra ID tenant backup.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(backupId=backupId)
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/restore/entraId/tenant", json_data=data, headers=headers)

        return response

    def unmount_entra_id_tenant_request(self, sessionId, gracefulStop=None):
        """
        Unmounts a Microsoft Entra ID tenant and stops the mount session.

        Args:
            sessionId (str): Mount session ID.
            gracefulStop (bool): If true, Veeam Backup & Replication will produce a new restore point
                for those VMs that have already been processed and for VMs that are being processed.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(gracefulStop=gracefulStop)
        headers = self._headers.copy()

        response = self._http_request("post", f"api/v1/restore/entraId/tenant/{sessionId}/stop", json_data=data, headers=headers)

        return response

    def get_entra_id_items_request(self, backupId, type_, skip=None, limit=None, filter=None, sorting=None):
        """
        Browses Microsoft Entra ID items available in a backup.

        Args:
            backupId (str): Backup ID.
            type_ (str): Item type (e.g. User, Group).
            skip (int): Number of items to skip.
            limit (int): Maximum number of items to return.
            filter (dict): Filtering options.
            sorting (dict): Sorting options.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(type=type_, skip=skip, limit=limit, filter=filter, sorting=sorting)
        headers = self._headers.copy()

        response = self._http_request(
            "post", f"api/v1/backupBrowser/entraIdTenant/{backupId}/browse", json_data=data, headers=headers
        )

        return response

    def get_entra_id_item_restore_points_request(self, backupId, itemId, skip=None, limit=None, sorting=None):
        """
        Gets restore points created for a Microsoft Entra ID item.

        Args:
            backupId (str): Backup ID.
            itemId (str): Item ID.
            skip (int): Number of restore points to skip.
            limit (int): Maximum number of restore points to return.
            sorting (dict): Sorting options.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(skip=skip, limit=limit, sorting=sorting)
        headers = self._headers.copy()

        response = self._http_request(
            "post",
            f"api/v1/backupBrowser/entraIdTenant/{backupId}/browse/{itemId}/restorePoints",
            json_data=data,
            headers=headers,
        )

        return response

    def compare_entra_id_item_properties_request(
        self,
        sessionId,
        itemId,
        itemType,
        oldRestorePointId,
        newRestorePointId=None,
        showUnchangedAttributes=None,
        reloadCache=None,
    ):
        """
        Compares Microsoft Entra ID item properties between restore points or production.

        Args:
            sessionId (str): Mount session ID.
            itemId (str): ID of Microsoft Entra ID item.
            itemType (str): Item type.
            oldRestorePointId (str): ID of an earlier restore point.
            newRestorePointId (str): ID of a later restore point.
            showUnchangedAttributes (bool): If true, both changed and unchanged item properties are returned.
            reloadCache (bool): If true, the mount session cache will be reset for this request.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            itemId=itemId,
            itemType=itemType,
            oldRestorePointId=oldRestorePointId,
            newRestorePointId=newRestorePointId,
            showUnchangedAttributes=showUnchangedAttributes,
            reloadCache=reloadCache,
        )
        headers = self._headers.copy()

        response = self._http_request(
            "post", f"api/v1/backupBrowser/entraIdTenant/{sessionId}/compare", json_data=data, headers=headers
        )

        return response

    def get_authorization_events_request(
        self,
        skip=None,
        limit=None,
        orderColumn=None,
        orderAsc=None,
        nameFilter=None,
        createdAfterFilter=None,
        createdBeforeFilter=None,
        processedAfterFilter=None,
        processedBeforeFilter=None,
        stateFilter=None,
        createdByFilter=None,
        processedByFilter=None,
        expireBeforeFilter=None,
        expireAfterFilter=None,
    ):
        """
        Gets all authorization events.

        Args:
            skip (int): The number of events to skip.
            limit (int): The maximum number of events to return.
            orderColumn (str): Sorts authorization events by one of the authorization events parameters.
            orderAsc (bool): If true, sorts authorization events in the ascending order by the orderColumn parameter.
            nameFilter (str): Filters authorization events by the nameFilter pattern.
            createdAfterFilter (str): Returns authorization events created after the specified date and time.
            createdBeforeFilter (str): Returns authorization events created before the specified date and time.
            processedAfterFilter (str): Returns authorization events processed after the specified date and time.
            processedBeforeFilter (str): Returns authorization events processed before the specified date and time.
            stateFilter (str): Filters authorization events by state.
            createdByFilter (str): Filters authorization events created by the specified user.
            processedByFilter (str): Filters authorization events processed by the specified user.
            expireBeforeFilter (str): Returns authorization events that expire before the specified date and time.
            expireAfterFilter (str): Returns authorization events that expire after the specified date and time.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(
            skip=skip,
            limit=limit,
            orderColumn=orderColumn,
            orderAsc=orderAsc,
            nameFilter=nameFilter,
            createdAfterFilter=createdAfterFilter,
            createdBeforeFilter=createdBeforeFilter,
            processedAfterFilter=processedAfterFilter,
            processedBeforeFilter=processedBeforeFilter,
            stateFilter=stateFilter,
            createdByFilter=createdByFilter,
            processedByFilter=processedByFilter,
            expireBeforeFilter=expireBeforeFilter,
            expireAfterFilter=expireAfterFilter,
        )
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/authorization/events", params=params, headers=headers)

        return response

    def get_all_repository_states_request(
        self,
        skip=None,
        limit=None,
        orderColumn=None,
        orderAsc=None,
        idFilter=None,
        nameFilter=None,
        typeFilter=None,
        capacityFilter=None,
        freeSpaceFilter=None,
        usedSpaceFilter=None,
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
            usedSpaceFilter=usedSpaceFilter,
        )
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/backupInfrastructure/repositories/states", params=params, headers=headers)

        return response

    def get_all_restore_points_request(
        self,
        skip,
        limit,
        orderColumn,
        orderAsc,
        createdAfterFilter,
        createdBeforeFilter,
        nameFilter,
        platformNameFilter,
        platformIdFilter,
        backupIdFilter,
        backupObjectIdFilter,
        malwareStatusFilter,
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
            malwareStatusFilter=malwareStatusFilter,
        )
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/restorePoints", params=params, headers=headers)

        return response

    def get_backup_object_request(self, id_):
        """
        Gets backup object.

        Args:
            id_ (str): The backup object ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", f"api/v1/backupObjects/{id_}", headers=headers)

        return response

    def get_backup_server_information_request(self):
        """
        Gets backup server information.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/serverInfo", headers=headers)

        return response

    def get_configuration_backup_request(self):
        """
        Gets configuration backup.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/configBackup", headers=headers)

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
        data = assign_params(pagination=pagination, filter=filter, sorting=sorting, hierarchyType=hierarchyType)
        headers = self._headers.copy()

        response = self._http_request("post", f"api/v1/inventory/{hostname}", params=params, json_data=data, headers=headers)

        return response

    def get_session_request(self, id_):
        """
        Gets a session.

        Args:
            id_ (str): The session ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", f"api/v1/sessions/{id_}", headers=headers)

        return response

    def get_session_logs_request(self, id_):
        """
        Gets log records for a session.

        Args:
            id_ (str): The session ID.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", f"api/v1/sessions/{id_}/logs", headers=headers)

        return response

    def start_security_analyzer_request(self):
        """
        Starts the Security & Compliance Analyzer scan.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/securityAnalyzer/start", headers=headers)

        return response

    def get_security_analyzer_best_practices_request(self):
        """
        Gets the Security & Compliance Analyzer best practices results.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/securityAnalyzer/bestPractices", headers=headers)

        return response

    def get_security_analyzer_last_run_request(self):
        """
        Gets the Security & Compliance Analyzer last run details.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/securityAnalyzer/lastRun", headers=headers)

        return response

    def get_job_states_request(
        self,
        skip=None,
        limit=None,
        orderColumn=None,
        orderAsc=None,
        nameFilter=None,
        typeFilter=None,
        statusFilter=None,
        lastResultFilter=None,
        idFilter=None,
    ):
        """
        Gets all job states.

        Args:
            skip (int): The number of job states to skip.
            limit (int): The maximum number of job states to return.
            orderColumn (str): Sorts job states by one of the state parameters.
            orderAsc (bool): Sorts job states in the ascending order by the orderColumn parameter.
            nameFilter (str): Filters job states by the job name pattern.
            typeFilter (str): Filters job states by the job type.
            statusFilter (str): Filters job states by the job status.
            lastResultFilter (str): Filters job states by the last job result.
            idFilter (str): Filters job states by the job ID.

        Returns:
            dict: The response from the server.
        """
        params = assign_params(
            skip=skip,
            limit=limit,
            orderColumn=orderColumn,
            orderAsc=orderAsc,
            nameFilter=nameFilter,
            typeFilter=typeFilter,
            statusFilter=statusFilter,
            lastResultFilter=lastResultFilter,
            idFilter=idFilter,
        )
        headers = self._headers.copy()

        response = self._http_request("get", "api/v1/jobs/states", params=params, headers=headers)

        return response

    def start_vsphere_quick_backup_request(
        self, platform, name, type_, hostName, objectId=None, urn=None, size=None, isEnabled=None
    ):
        """
        Starts a quick backup for a vSphere object.

        Args:
            name (str): Name of the VMware vSphere object.
            type_ (str): Type of the VMware vSphere object.
            hostName (str): Name of the VMware vSphere server that hosts the object.
            objectId (str): ID of the VMware vSphere object.
            urn (str): Uniform Resource Name (URN) of the object.
            size (str): Object size.
            isEnabled (bool): Indicates whether the VMware vSphere object is enabled or disabled.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            platform=platform,
            name=name,
            type=type_,
            hostName=hostName,
            objectId=objectId,
            urn=urn,
            size=size,
            isEnabled=isEnabled,
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/jobs/quickBackup/vSphere", json_data=data, headers=headers)

        return response

    def start_configuration_backup_request(self):
        """
        Starts configuration backup.

        Returns:
            dict: The response from the server.
        """
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/configBackup/backup", headers=headers)

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
            reason=reason,
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/restore/instantRecovery/vSphere/vm", json_data=data, headers=headers)

        return response

    def start_instant_recovery_hyperv_vm_request(self, restorePointId, restore_type, secureRestore, powerUp, reason):
        """
        Starts Instant Recovery of a Microsoft Hyper-V VM.

        Args:
            restorePointId (str): The restore point ID.
            restore_type (str): The type of restore (OriginalLocation or Customized).
            secureRestore (dict): Secure restore settings.
            powerUp (bool): If true, Veeam Backup & Replication powers on the restored VM on the target host.
            reason (str): The reason for restoring the VM.

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            restorePointId=restorePointId, type=restore_type, secureRestore=secureRestore, powerUp=powerUp, reason=reason
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/restore/instantRecovery/hyperV/vm", json_data=data, headers=headers)

        return response

    def start_instant_recovery_customized_request(
        self,
        restorePointId,
        restore_type,
        vmTagsRestoreEnabled,
        secureRestore,
        nicsEnabled,
        powerUp,
        reason,
        destination,
        datastore,
        overwrite,
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
            overwrite=overwrite,
        )

        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/restore/instantRecovery/vSphere/vm", json_data=data, headers=headers)

        return response

    def start_instant_recovery_hyperv_vm_customized_request(
        self, restorePointId, restore_type, secureRestore, powerUp, reason, destinationHost, target
    ):
        """
        Starts customized Instant Recovery of a Microsoft Hyper-V VM.

        Args:
            restorePointId (str): The restore point ID.
            restore_type (str): The type of restore (Customized).
            secureRestore (dict): Secure restore settings.
            powerUp (bool): If true, Veeam Backup & Replication powers on the restored VM on the target host.
            reason (str): The reason for restoring the VM.
            destinationHost (dict): Microsoft Hyper-V object representing the target host.
            target (dict): Destination VM settings (name, UUID policy, cluster resource, overwrite flags).

        Returns:
            dict: The response from the server.
        """
        data = assign_params(
            restorePointId=restorePointId,
            type=restore_type,
            secureRestore=secureRestore,
            powerUp=powerUp,
            reason=reason,
            destinationHost=destinationHost,
            target=target,
        )
        headers = self._headers.copy()

        response = self._http_request("post", "api/v1/restore/instantRecovery/hyperV/vm", json_data=data, headers=headers)

        return response


""" HELPER FUNCTIONS """


def start_security_analyzer_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.start_security_analyzer_request()

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_security_analyzer",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_security_analyzer_best_practices_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.get_security_analyzer_best_practices_request()

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.security_analyzer_best_practices.items",
        outputs_key_field="",
        outputs=response.get("items"),
        raw_response=response.get("items"),
    )

    return command_results


def get_security_analyzer_last_run_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.get_security_analyzer_last_run_request()

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.security_analyzer_last_run",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_job_states_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    orderColumn = str(args.get("orderColumn", ""))
    orderAsc = str(args.get("orderAsc", ""))
    validate_bool(orderAsc)
    nameFilter = str(args.get("nameFilter", ""))
    typeFilter = str(args.get("typeFilter", ""))
    statusFilter = str(args.get("statusFilter", ""))
    lastResultFilter = str(args.get("lastResultFilter", ""))
    idFilter = str(args.get("idFilter", ""))
    validate_uuid(idFilter)

    response = client.get_job_states_request(
        skip, limit, orderColumn, orderAsc, nameFilter, typeFilter, statusFilter, lastResultFilter, idFilter
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_job_states.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def create_malware_event_command(client: Client, args: dict[str, Any]) -> CommandResults:
    detectiontimeutc = str(args.get("detectiontimeutc", ""))
    validate_time(detectiontimeutc)
    machine_fqdn = str(args.get("machine_fqdn", ""))
    machine_ipv4 = str(args.get("machine_ipv4", ""))
    validate_ipv4(machine_ipv4)
    machine_ipv6 = str(args.get("machine_ipv6", ""))
    validate_ipv6(machine_ipv6)
    machine_uuid = str(args.get("machine_uuid", ""))
    validate_uuid(machine_uuid)
    machine = assign_params(fqdn=machine_fqdn, ipv4=machine_ipv4, ipv6=machine_ipv6, uuid=machine_uuid)
    details = str(args.get("details", ""))
    engine = str(args.get("engine", ""))

    response = client.create_malware_event_request(detectiontimeutc, machine, details, engine)
    event_id = response["data"][0].get("id")
    context = demisto.getIntegrationContext()
    post_event_ids = context.get("post_event_ids")
    if post_event_ids:
        post_event_ids.append(str(event_id))
    else:
        post_event_ids = [str(event_id)]
    context["post_event_ids"] = post_event_ids
    demisto.setIntegrationContext(context)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR", outputs_key_field="", outputs=response.get("data"), raw_response=response.get("data")
    )

    return command_results


def get_all_malware_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    orderColumn = str(args.get("orderColumn", ""))
    orderAsc = str(args.get("orderAsc", ""))
    validate_bool(orderAsc)
    typeFilter = str(args.get("typeFilter", ""))
    detectedAfterTimeUtcFilter = str(args.get("detectedAfterTimeUtcFilter", ""))
    validate_time(detectedAfterTimeUtcFilter)
    detectedBeforeTimeUtcFilter = str(args.get("detectedBeforeTimeUtcFilter", ""))
    validate_time(detectedBeforeTimeUtcFilter)
    backupObjectIdFilter = str(args.get("backupObjectIdFilter", ""))
    validate_uuid(backupObjectIdFilter)
    stateFilter = str(args.get("stateFilter", ""))
    sourceFilter = str(args.get("sourceFilter", ""))
    severityFilter = str(args.get("severityFilter", ""))
    createdByFilter = str(args.get("createdByFilter", ""))
    engineFilter = str(args.get("engineFilter", ""))

    response = client.get_all_malware_events_request(
        skip,
        limit,
        orderColumn,
        orderAsc,
        typeFilter,
        detectedAfterTimeUtcFilter,
        detectedBeforeTimeUtcFilter,
        backupObjectIdFilter,
        stateFilter,
        sourceFilter,
        severityFilter,
        createdByFilter,
        engineFilter,
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_malware_events.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_yara_rules_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.get_yara_rules_request()

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_yara_rules.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def start_malware_backup_scan_command(client: Client, args: dict[str, Any]) -> CommandResults:
    backupId = str(args.get("backupId", ""))
    validate_uuid(backupId)
    backupObjectId = str(args.get("backupObjectId", ""))
    validate_uuid(backupObjectId)
    backup_object_pair = [assign_params(backupId=backupId, backupObjectId=backupObjectId)]
    scanMode = str(args.get("scanMode", ""))
    useAntivirusEngine = str(args.get("useAntivirusEngine", ""))
    validate_bool(useAntivirusEngine)
    useYaraRule = str(args.get("useYaraRule", ""))
    validate_bool(useYaraRule)
    yaraRule = str(args.get("yaraRule", ""))
    yaraRule = convert_to_json(yaraRule)
    scanEngine = assign_params(useAntivirusEngine=useAntivirusEngine, useYaraRule=useYaraRule, yaraRule=yaraRule)
    useMostRecentPoint = str(args.get("useMostRecentPoint", ""))
    validate_bool(useMostRecentPoint)
    startDate = str(args.get("startDate", ""))
    validate_time(startDate)
    useOldestPoint = str(args.get("useOldestPoint", ""))
    validate_bool(useOldestPoint)
    endDate = str(args.get("endDate", ""))
    validate_time(endDate)
    from_ = assign_params(useMostRecentPoint=useMostRecentPoint, startDate=startDate)
    to_ = assign_params(useOldestPoint=useOldestPoint, endDate=endDate)
    scanRange = {"from": from_, "to": to_}
    continueScan = str(args.get("continueScan", ""))
    validate_bool(continueScan)
    if is_api_version_higher_or_equal_than(client._headers["x-api-version"], "1.3-rev2"):
        type_ = "Backup"
    else:
        type_ = None

    response = client.start_malware_backup_scan_request(backup_object_pair, scanMode, scanEngine, scanRange, continueScan, type_)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_malware_backup_scan", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_disk_publishing_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get("restorePointId", ""))
    validate_uuid(restorePointId)
    allowedIps_str = str(args.get("allowedIps", ""))
    allowedIps = [ip.strip() for ip in allowedIps_str.split(",") if ip.strip()]
    diskNames_str = str(args.get("diskNames", ""))
    diskNames = [d.strip() for d in diskNames_str.split(",") if d.strip()] if diskNames_str else None
    mountHostId = str(args.get("mountHostId", ""))
    validate_uuid(mountHostId)

    response = client.start_disk_publishing_request(restorePointId, allowedIps, diskNames, mountHostId)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_disk_publishing", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def stop_disk_publishing_command(client: Client, args: dict[str, Any]) -> CommandResults:
    mountId = str(args.get("mountId", ""))
    validate_uuid(mountId)

    response = client.stop_disk_publishing_request(mountId)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.stop_disk_publishing", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def general_api_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    path = str(args.get("path", ""))
    method = str(args.get("method", "get")).lower()
    data_str = args.get("data", None)
    data = json.loads(data_str) if data_str else None
    params_str = args.get("params", None)
    params = json.loads(params_str) if params_str else None

    response = client.general_api_request(path, method, data, params)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.general_api_request", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_disk_publishing_mount_point_command(client: Client, args: dict[str, Any]) -> CommandResults:
    mountId = str(args.get("mountId", ""))
    validate_uuid(mountId)

    response = client.get_disk_publishing_mount_point_request(mountId)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_disk_publishing_mount_point", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def mount_entra_id_tenant_command(client: Client, args: dict[str, Any]) -> CommandResults:
    backupId = str(args.get("backupId", ""))
    validate_uuid(backupId)

    response = client.mount_entra_id_tenant_request(backupId)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.mount_entra_id_tenant", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def unmount_entra_id_tenant_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sessionId = str(args.get("sessionId", ""))
    validate_uuid(sessionId)
    gracefulStop = str(args.get("gracefulStop", ""))
    validate_bool(gracefulStop)

    response = client.unmount_entra_id_tenant_request(sessionId, gracefulStop)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.unmount_entra_id_tenant", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_entra_id_items_command(client: Client, args: dict[str, Any]) -> CommandResults:
    backupId = str(args.get("backupId", ""))
    validate_uuid(backupId)
    type_ = str(args.get("type", ""))
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)

    displayName = str(args.get("displayName", ""))
    mailAddress = str(args.get("mailAddress", ""))
    filter = assign_params(displayName=displayName, mailAddress=mailAddress) or None

    sorting_str = str(args.get("sorting", ""))
    sorting = convert_to_json(sorting_str) if sorting_str else None

    response = client.get_entra_id_items_request(backupId, type_, skip, limit, filter, sorting)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_entra_id_items.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_entra_id_item_restore_points_command(client: Client, args: dict[str, Any]) -> CommandResults:
    backupId = str(args.get("backupId", ""))
    validate_uuid(backupId)
    itemId = str(args.get("itemId", ""))
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    sorting_str = str(args.get("sorting", ""))
    sorting = convert_to_json(sorting_str) if sorting_str else None

    response = client.get_entra_id_item_restore_points_request(backupId, itemId, skip, limit, sorting)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_entra_id_item_restore_points.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def compare_entra_id_item_properties_command(client: Client, args: dict[str, Any]) -> CommandResults:
    sessionId = str(args.get("sessionId", ""))
    validate_uuid(sessionId)
    itemId = str(args.get("itemId", ""))
    itemType = str(args.get("itemType", ""))
    oldRestorePointId = str(args.get("oldRestorePointId", ""))
    validate_uuid(oldRestorePointId)
    newRestorePointId = str(args.get("newRestorePointId", ""))
    validate_uuid(newRestorePointId)
    showUnchangedAttributes = str(args.get("showUnchangedAttributes", ""))
    validate_bool(showUnchangedAttributes)
    reloadCache = str(args.get("reloadCache", ""))
    validate_bool(reloadCache)

    response = client.compare_entra_id_item_properties_request(
        sessionId, itemId, itemType, oldRestorePointId, newRestorePointId, showUnchangedAttributes, reloadCache
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.compare_entra_id_item_properties", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_authorization_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    orderColumn = str(args.get("orderColumn", ""))
    orderAsc = str(args.get("orderAsc", ""))
    validate_bool(orderAsc)
    nameFilter = str(args.get("nameFilter", ""))
    createdAfterFilter = str(args.get("createdAfterFilter", ""))
    validate_time(createdAfterFilter)
    createdBeforeFilter = str(args.get("createdBeforeFilter", ""))
    validate_time(createdBeforeFilter)
    processedAfterFilter = str(args.get("processedAfterFilter", ""))
    validate_time(processedAfterFilter)
    processedBeforeFilter = str(args.get("processedBeforeFilter", ""))
    validate_time(processedBeforeFilter)
    stateFilter = str(args.get("stateFilter", ""))
    createdByFilter = str(args.get("createdByFilter", ""))
    processedByFilter = str(args.get("processedByFilter", ""))
    expireBeforeFilter = str(args.get("expireBeforeFilter", ""))
    validate_time(expireBeforeFilter)
    expireAfterFilter = str(args.get("expireAfterFilter", ""))
    validate_time(expireAfterFilter)

    response = client.get_authorization_events_request(
        skip,
        limit,
        orderColumn,
        orderAsc,
        nameFilter,
        createdAfterFilter,
        createdBeforeFilter,
        processedAfterFilter,
        processedBeforeFilter,
        stateFilter,
        createdByFilter,
        processedByFilter,
        expireBeforeFilter,
        expireAfterFilter,
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_authorization_events.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_all_repository_states_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    orderColumn = str(args.get("orderColumn", ""))
    orderAsc = str(args.get("orderAsc", ""))
    validate_bool(orderAsc)
    idFilter = str(args.get("idFilter", ""))
    validate_uuid(idFilter)
    nameFilter = str(args.get("nameFilter", ""))
    typeFilter = str(args.get("typeFilter", ""))
    capacityFilter = str(args.get("capacityFilter", ""))
    validate_float(capacityFilter)
    freeSpaceFilter = str(args.get("freeSpaceFilter", ""))
    validate_float(freeSpaceFilter)
    usedSpaceFilter = str(args.get("usedSpaceFilter", ""))
    validate_float(usedSpaceFilter)

    response = client.get_all_repository_states_request(
        skip, limit, orderColumn, orderAsc, idFilter, nameFilter, typeFilter, capacityFilter, freeSpaceFilter, usedSpaceFilter
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_repository_states.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_all_restore_points_command(client: Client, args: dict[str, Any]) -> CommandResults:
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    orderColumn = str(args.get("orderColumn", ""))
    orderAsc = str(args.get("orderAsc", ""))
    validate_bool(orderAsc)
    createdAfterFilter = str(args.get("createdAfterFilter", ""))
    validate_time(createdAfterFilter)
    createdBeforeFilter = str(args.get("createdBeforeFilter", ""))
    validate_time(createdBeforeFilter)
    nameFilter = str(args.get("nameFilter", ""))
    platformNameFilter = str(args.get("platformNameFilter", ""))
    platformIdFilter = str(args.get("platformIdFilter", ""))
    validate_uuid(platformIdFilter)
    backupIdFilter = str(args.get("backupIdFilter", ""))
    validate_uuid(backupIdFilter)
    backupObjectIdFilter = str(args.get("backupObjectIdFilter", ""))
    validate_uuid(backupObjectIdFilter)
    malwareStatusFilter = str(args.get("malwareStatusFilter", ""))

    response = client.get_all_restore_points_request(
        skip,
        limit,
        orderColumn,
        orderAsc,
        createdAfterFilter,
        createdBeforeFilter,
        nameFilter,
        platformNameFilter,
        platformIdFilter,
        backupIdFilter,
        backupObjectIdFilter,
        malwareStatusFilter,
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_restore_points.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_backup_object_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = str(args.get("id_", ""))
    validate_uuid(id_)

    response = client.get_backup_object_request(id_)
    path = response.get("path", "")
    vcenter_name = get_vcentername(path)
    response["vcenter_name"] = vcenter_name

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.backup_object", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_configuration_backup_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.get_configuration_backup_request()
    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_configuration_backup", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_inventory_objects_command(client: Client, args: dict[str, Any]) -> CommandResults:
    resetCache = str(args.get("resetCache", ""))
    validate_bool(resetCache)
    hostname = str(args.get("hostname", ""))
    skip = str(args.get("skip", ""))
    validate_int(skip)
    limit = str(args.get("limit", ""))
    validate_int(limit)
    pagination = assign_params(skip=skip, limit=limit)
    filter_str = str(args.get("filter", ""))
    filter = convert_to_json(filter_str)

    object_name = str(args.get("objectName", ""))
    vi_type = str(args.get("viType", ""))
    if vi_type and object_name:
        filter = {
            "type": "GroupExpression",
            "operation": "and",
            "items": [
                {"type": "PredicateExpression", "operation": "equals", "property": "Name", "value": object_name},
                {"type": "PredicateExpression", "operation": "in", "property": "Type", "value": vi_type},
            ],
        }

    sorting_str = str(args.get("sorting", ""))
    sorting = convert_to_json(sorting_str)
    hierarchyType = str(args.get("hierarchyType", ""))

    response = client.get_inventory_objects_request(resetCache, hostname, pagination, filter, sorting, hierarchyType)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_inventory_objects.data",
        outputs_key_field="",
        outputs=response.get("data"),
        raw_response=response.get("data"),
    )

    return command_results


def get_session_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = str(args.get("id_", ""))
    validate_uuid(id_)

    response = client.get_session_request(id_)
    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_session",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
        replace_existing=True,
    )

    return command_results


def get_session_logs_command(client: Client, args: dict[str, Any]) -> CommandResults:
    id_ = str(args.get("id_", ""))
    validate_uuid(id_)

    response = client.get_session_logs_request(id_)
    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.get_session_logs", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_configuration_backup_command(client: Client, args: dict[str, Any]) -> CommandResults:
    response = client.start_configuration_backup_request()
    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.Configurationbackuphasbeenstarted",
        outputs_key_field="",
        outputs=response,
        raw_response=response,
    )

    return command_results


def start_vsphere_quick_backup_command(client: Client, args: dict[str, Any]) -> CommandResults:
    name = str(args.get("name", ""))
    platform = str(args.get("platform", ""))
    type_ = str(args.get("type", ""))
    hostName = str(args.get("hostName", ""))
    objectId = str(args.get("objectId", ""))
    urn = str(args.get("urn", ""))
    size = str(args.get("size", ""))
    isEnabled = str(args.get("isEnabled", ""))
    validate_bool(isEnabled)

    response = client.start_vsphere_quick_backup_request(platform, name, type_, hostName, objectId, urn, size, isEnabled)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_vsphere_quick_backup", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_instant_recovery_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get("restorePointId", ""))
    validate_uuid(restorePointId)
    restore_type = MODE_ORIGINAL_LOCATION
    vmTagsRestoreEnabled = str(args.get("vmTagsRestoreEnabled", ""))
    validate_bool(vmTagsRestoreEnabled)
    antivirusScanEnabled = str(args.get("antivirusScanEnabled", ""))
    validate_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get("virusDetectionAction", ""))
    entireVolumeScanEnabled = str(args.get("entireVolumeScanEnabled", ""))
    validate_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled,
    )
    nicsEnabled = str(args.get("nicsEnabled", ""))
    validate_bool(nicsEnabled)
    powerUp = str(args.get("powerUp", ""))
    validate_bool(powerUp)
    reason = str(args.get("reason", ""))

    response = client.start_instant_recovery_request(
        restorePointId, restore_type, vmTagsRestoreEnabled, secureRestore, nicsEnabled, powerUp, reason
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_recovery", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_instant_recovery_hyperv_vm_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get("restorePointId", ""))
    validate_uuid(restorePointId)
    restore_type = MODE_ORIGINAL_LOCATION
    antivirusScanEnabled = str(args.get("antivirusScanEnabled", ""))
    validate_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get("virusDetectionAction", ""))
    entireVolumeScanEnabled = str(args.get("entireVolumeScanEnabled", ""))
    validate_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled,
    )
    powerUp = str(args.get("powerUp", ""))
    validate_bool(powerUp)
    reason = str(args.get("reason", ""))

    response = client.start_instant_recovery_hyperv_vm_request(restorePointId, restore_type, secureRestore, powerUp, reason)

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_hv_recovery", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_instant_recovery_hyperv_vm_customized_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get("restorePointId", ""))
    validate_uuid(restorePointId)
    restore_type = MODE_CUSTOMIZED
    antivirusScanEnabled = str(args.get("antivirusScanEnabled", ""))
    validate_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get("virusDetectionAction", ""))
    entireVolumeScanEnabled = str(args.get("entireVolumeScanEnabled", ""))
    validate_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled,
    )
    powerUp = str(args.get("powerUp", ""))
    validate_bool(powerUp)
    reason = str(args.get("reason", ""))

    hostName = str(args.get("hostName", ""))
    hostObjectId = str(args.get("hostObjectId", ""))
    destinationHost = assign_params(platform="HyperV", name=hostName, type="Host", hostName=hostName, objectId=hostObjectId)

    vmName = str(args.get("vmName", ""))
    preserveUUID = str(args.get("preserveUUID", ""))
    validate_bool(preserveUUID)
    registerAsClusterResource = str(args.get("registerAsClusterResource", ""))
    validate_bool(registerAsClusterResource)
    overwriteExistingVm = str(args.get("overwriteExistingVm", ""))
    validate_bool(overwriteExistingVm)
    overwriteExistingDisks = str(args.get("overwriteExistingDisks", ""))
    validate_bool(overwriteExistingDisks)
    target = assign_params(
        vmName=vmName,
        preserveUUID=preserveUUID,
        registerAsClusterResource=registerAsClusterResource,
        overwriteExistingVm=overwriteExistingVm,
        overwriteExistingDisks=overwriteExistingDisks,
    )

    response = client.start_instant_recovery_hyperv_vm_customized_request(
        restorePointId, restore_type, secureRestore, powerUp, reason, destinationHost, target
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_hv_recovery", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def start_instant_recovery_customized_command(client: Client, args: dict[str, Any]) -> CommandResults:
    restorePointId = str(args.get("restorePointId", ""))
    validate_uuid(restorePointId)
    restore_type = MODE_CUSTOMIZED
    vmTagsRestoreEnabled = str(args.get("vmTagsRestoreEnabled", ""))
    validate_bool(vmTagsRestoreEnabled)
    antivirusScanEnabled = str(args.get("antivirusScanEnabled", ""))
    validate_bool(antivirusScanEnabled)
    virusDetectionAction = str(args.get("virusDetectionAction", ""))
    entireVolumeScanEnabled = str(args.get("entireVolumeScanEnabled", ""))
    validate_bool(entireVolumeScanEnabled)
    secureRestore = assign_params(
        antivirusScanEnabled=antivirusScanEnabled,
        virusDetectionAction=virusDetectionAction,
        entireVolumeScanEnabled=entireVolumeScanEnabled,
    )
    nicsEnabled = str(args.get("nicsEnabled", ""))
    validate_bool(nicsEnabled)
    powerUp = str(args.get("powerUp", ""))
    validate_bool(powerUp)
    reason = str(args.get("reason", ""))

    restoredVmName = str(args.get("restoredVmName", ""))
    vCenterName = str(args.get("vCenterName", ""))
    platform = str(args.get("platform", ""))
    biosUuidPolicy = str(args.get("biosUuidPolicy", ""))

    hostObjectId = str(args.get("hostObjectId", ""))
    destinationHost = assign_params(type="Host", hostName=vCenterName, name=vCenterName, objectId=hostObjectId, platform=platform)

    folderObjectId = str(args.get("folderObjectId", ""))
    folder = assign_params(type="Folder", hostName=vCenterName, objectId=folderObjectId, platform=platform)

    destination = assign_params(
        restoredVmName=restoredVmName, destinationHost=destinationHost, folder=folder, biosUuidPolicy=biosUuidPolicy
    )

    resObjectId = str(args.get("resObjectId", ""))
    if resObjectId:
        resourcePool = assign_params(type="ResourcePool", hostName=vCenterName, objectId=resObjectId, platform=platform)
        destination["resourcePool"] = resourcePool

    redirectEnabled = str(args.get("redirectEnabled", ""))
    validate_bool(redirectEnabled)
    datastore = assign_params(redirectEnabled=redirectEnabled)
    overwrite = str(args.get("overwrite", ""))
    validate_bool(overwrite)

    response = client.start_instant_recovery_customized_request(
        restorePointId,
        restore_type,
        vmTagsRestoreEnabled,
        secureRestore,
        nicsEnabled,
        powerUp,
        reason,
        destination,
        datastore,
        overwrite,
    )

    command_results = CommandResults(
        outputs_prefix="Veeam.VBR.start_recovery", outputs_key_field="", outputs=response, raw_response=response
    )

    return command_results


def get_vcentername(string: str) -> str:
    index = string.find("\\")

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
        raise ValueError(f"Invalid JSON string. Exception: {e!s}")

    return data


def is_api_version_higher_or_equal_than(current_version: str, comp_version: str) -> bool:
    def parse_version(version: str):
        base, rev_part = version.split("-rev")
        major, minor = base.split(".")
        return int(major), int(minor), int(rev_part)

    return parse_version(current_version) >= parse_version(comp_version)


def validate_uuid(uuid_: str) -> None:
    if uuid_:
        try:
            uuid.UUID(uuid_)
        except ValueError as e:
            raise ValueError(f"Invalid UUID string: '{uuid_}'. Exception: {e!s}")


def validate_ipv4(ipv4: str) -> None:
    if ipv4:
        try:
            ipaddress.IPv4Address(ipv4)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            try:
                socket.inet_pton(socket.AF_INET, ipv4)
            except OSError as e:
                raise ValueError(f"Invalid IPv4 address: '{ipv4}'. Exception: {e!s}")


def validate_ipv6(ipv6: str) -> None:
    if ipv6:
        try:
            ipaddress.IPv6Address(ipv6)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            try:
                socket.inet_pton(socket.AF_INET6, ipv6)
            except OSError as e:
                raise ValueError(f"Invalid IPv6 address: '{ipv6}'. Exception: {e!s}")


def validate_time(time: str) -> None:
    if time:
        try:
            datetime.strptime(time, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            try:
                datetime.strptime(time, DATE_FORMAT)
            except ValueError as e:
                raise ValueError(f"Invalid date format: '{time}'. Exception: {e!s}")


def validate_int(value: str) -> None:
    if value:
        try:
            int(value)
        except ValueError as e:
            raise ValueError(f"Invalid integer value: '{value}'") from e


def validate_bool(value: str) -> None:
    if value and value.strip().lower() not in ("true", "false"):
        raise ValueError(f"Invalid boolean value: '{value}'")


def validate_float(value: str) -> None:
    if value:
        try:
            float(value)
        except ValueError as e:
            raise ValueError(f"Invalid float value: '{value}'") from e


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
        handle_command_with_token_refresh(client.get_backup_server_information_request, {}, client)
    except Exception as e:
        exception_text = str(e).lower()
        if "forbidden" in exception_text or "authorization" in exception_text:
            return "Authentication Error: Invalid API Key"
        elif "license" in exception_text:
            return "Valid Veeam license required"
        else:
            raise e
    return "ok"


def get_access_token(client: Client, username: str, password: str) -> str:
    response = client.get_access_token_request(GRANT_TYPE, username, password)
    token = response.get("access_token")
    return token


def search_with_paging(
    method: Callable[..., Any], args: dict[str, Any] = None, page_size=DEFAULT_PAGE_SIZE, size_limit=DEFAULT_SIZE_LIMIT
) -> list[dict]:
    if args is None:
        args = {}
    else:
        args = dict(args)

    skip_items = 0
    args["skip"] = 0
    items_to_fetch = size_limit
    items: list[dict] = []

    while True:
        if 0 < items_to_fetch < page_size:
            page_size = items_to_fetch
        args["limit"] = page_size

        response = method(**args)

        items = items + response["data"]
        response_len = len(response["data"])

        if response_len < page_size:
            break

        items_to_fetch -= response_len
        skip_items += page_size

        if size_limit and items_to_fetch <= 0:
            items = items[:size_limit]
            break

        args["skip"] = skip_items
    return items


def overwrite_last_fetch_time(last_fetch_time: str, event: dict) -> str:
    last_fetch_datetime = parser.isoparse(last_fetch_time)
    event_datetime = parser.isoparse(event["detectionTimeUtc"])

    if event_datetime > last_fetch_datetime:
        last_fetch_time = event["detectionTimeUtc"]

    return last_fetch_time


def process_error(error_count: int, error_message: str) -> tuple[dict, int]:
    error_count += 1
    incident = {}
    if error_count in ERROR_COUNT_MAP:
        integration_instance = demisto.callingContext.get("context", {}).get("IntegrationInstance", "")
        incident_name = f"Veeam - Fetch incident error has occurred on {integration_instance}"
        incident = {
            "name": incident_name,
            "occurred": datetime.now().strftime(DATE_FORMAT),
            "rawJSON": json.dumps({"incident_type": "Incident Fetch Error", "details": error_message}),
            "severity": ERROR_COUNT_MAP[error_count],
        }

    return incident, error_count


class FetchClient:
    def __init__(self, client: Client, last_run: dict):
        self.client = client
        self.last_run = last_run
        self.errors_by_command: dict = last_run.get("errors_by_command", {})
        self.incidents: list[dict] = []
        self.next_run: dict = {
            "last_fetch": datetime.now().strftime(DATE_FORMAT),
            "malware_ids": last_run.get("malware_ids", []),
            "repository_ids": last_run.get("repository_ids", []),
            "security_ids": last_run.get("security_ids", []),
            "sure_backup_ids": last_run.get("sure_backup_ids", []),
            "backup_date": last_run.get("backup_date", ""),
            "errors_by_command": self.errors_by_command,
        }

    def get_malware_incidents(self, start_time: datetime, existed_ids: set, max_results: int) -> tuple[list[dict], set[str], str]:
        last_fetch_time = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        def _paged_malware_method(**kwargs):
            return handle_command_with_token_refresh(self.client.get_all_malware_events_request, kwargs, self.client)

        response = search_with_paging(
            method=_paged_malware_method,
            args={"detectedAfterTimeUtcFilter": last_fetch_time, "orderColumn": "detectionTimeUtc", "orderAsc": "true"},
            page_size=MALWARE_EVENTS_PAGE_SIZE,
        )
        incidents: list[dict] = []
        new_ids = set()

        for event in response:
            if len(incidents) >= max_results:
                break

            event_id = str(event.get("id"))

            source_: str = str(event.get("source"))
            source_exist = DESIRED_SOURCE.get(source_)
            type_: str = str(event.get("type"))
            type_exist = DESIRED_TYPES.get(type_)
            event_severity: str = str(event.get("severity"))
            severity = SEVERITY_MAP.get(event_severity)

            if source_exist and type_exist and severity and event_id not in existed_ids:
                hostname = event["machine"].get("displayName")
                details = f"{event['details']}; Hostname: {hostname}"
                incident_name = f"Veeam - Malware activity detected on {hostname}"
                event["description"] = details
                event["incident_type"] = type_
                event["type_description"] = type_exist
                event["source_description"] = source_exist
                incident = {
                    "name": incident_name,
                    "occurred": event["detectionTimeUtc"],
                    "rawJSON": json.dumps(event),
                    "severity": severity,
                }
                new_ids.add(event_id)
                incidents.append(incident)
                last_fetch_time = overwrite_last_fetch_time(last_fetch_time, event)

        if not new_ids:
            new_ids = existed_ids

        return incidents, new_ids, last_fetch_time

    def get_configuration_backup_incident(
        self, last_successful_backup_date: str, backup_older_then_days: int
    ) -> tuple[dict, str]:
        last_successful_backup_date = last_successful_backup_date if last_successful_backup_date else ""
        if last_successful_backup_date:
            last_successful_backup_datetime = parser.isoparse(last_successful_backup_date)
        else:
            last_successful_backup_datetime = None
            demisto.debug(f"no {last_successful_backup_date=}")

        last_fetch_time = datetime.now().strftime(DATE_FORMAT)
        response = handle_command_with_token_refresh(self.client.get_configuration_backup_request, {}, self.client)
        today = datetime.now().date()

        last_time_backup = response.get("lastSuccessfulBackup").get("lastSuccessfulTime")
        difference = None
        if last_time_backup:
            last_backup_date = parser.isoparse(last_time_backup).date()
            difference = (today - last_backup_date).days
        else:
            last_time_backup = EARLIEST_TIME

        incident: dict = {}
        last_backup_datetime = parser.isoparse(last_time_backup)
        if (difference is None or difference >= backup_older_then_days) and (
            not last_successful_backup_date
            or (last_successful_backup_datetime is not None and last_backup_datetime > last_successful_backup_datetime)
        ):
            time_ = NOT_APPLICABLE if last_time_backup == EARLIEST_TIME else last_time_backup
            details = f"Last successful backup: {time_}"
            integration_instance = demisto.callingContext.get("context", {}).get("IntegrationInstance", "")
            incident_name = f"Veeam - {integration_instance} has no configuration backups"
            response["details"] = details
            response["incident_type"] = CONFIGURATION_BACKUP_INCIDENT_TYPE
            incident = {
                "name": incident_name,
                "occurred": last_fetch_time,
                "rawJSON": json.dumps(response),
                "severity": IncidentSeverity.MEDIUM,
            }

            last_successful_backup_date = last_time_backup
        return incident, last_successful_backup_date

    def get_repository_space_incidents(
        self, existed_ids: set, max_results: int, free_space_less_then: int
    ) -> tuple[list[dict], set[str]]:
        last_fetch_time = datetime.now().strftime(DATE_FORMAT)

        def _paged_repo_method(**kwargs):
            return handle_command_with_token_refresh(self.client.get_all_repository_states_request, kwargs, self.client)

        response = search_with_paging(
            method=_paged_repo_method,
            args={"orderColumn": "FreeGB", "orderAsc": "true"},
            page_size=REPOSITORY_STATE_REQUEST_PAGE_SIZE,
        )

        incidents: list[dict] = []
        incident_repository_ids = existed_ids

        repository_ids = {repository["id"] for repository in response}
        incident_repository_ids.intersection_update(repository_ids)

        for repository in response:
            if len(incidents) >= max_results:
                break

            repository_id = str(repository.get("id"))

            if repository["freeGB"] < free_space_less_then and repository["capacityGB"] > 0:
                hostname = repository.get("hostName", "")
                hostname = hostname if hostname else NOT_APPLICABLE

                if repository_id not in incident_repository_ids:
                    details = (
                        f"{repository['description']}; Repository Name: {repository['name']}; "
                        f"Free Space (GB): {repository['freeGB']}; Hostname: {hostname}"
                    )
                    repo_name = repository["name"]
                    repo_free = repository["freeGB"]
                    incident_name = f"Veeam - Repository {repo_name} is running low on disk space. " f"Free space: {repo_free}"
                    repository["details"] = details
                    repository["incident_type"] = REPOSITORY_STATE_INCIDENT_TYPE
                    incident = {
                        "name": incident_name,
                        "occurred": last_fetch_time,
                        "rawJSON": json.dumps(repository),
                        "severity": IncidentSeverity.HIGH,
                    }

                    incident_repository_ids.add(repository_id)
                    incidents.append(incident)

        return incidents, incident_repository_ids

    def get_security_analyzer_incidents(self, existed_ids: set) -> tuple[list[dict], set[str]]:
        last_fetch_time = datetime.now().strftime(DATE_FORMAT)
        response = handle_command_with_token_refresh(self.client.get_security_analyzer_best_practices_request, {}, self.client)
        items = response.get("items", [])

        incidents: list[dict] = []
        incident_security_ids = existed_ids

        security_ids = {security_result["id"] for security_result in items}
        incident_security_ids.intersection_update(security_ids)

        for security_result in items:
            security_result_id = str(security_result.get("id"))

            if security_result["status"] == "Violation":
                note = security_result.get("note", "")
                note = note if note else NOT_APPLICABLE

                if security_result_id not in incident_security_ids:
                    best_practice = security_result["bestPractice"]
                    status = security_result["status"]
                    details = f"{best_practice}; Status: {status}; Note: {note}"
                    incident_name = (
                        "Veeam - Configuration is not compliant with security best practices. "
                        f"Affected parameter: {best_practice}"
                    )
                    security_result["details"] = details
                    security_result["incident_type"] = SECURITY_ANALYZER_INCIDENT_TYPE
                    incident = {
                        "name": incident_name,
                        "occurred": last_fetch_time,
                        "rawJSON": json.dumps(security_result),
                        "severity": IncidentSeverity.CRITICAL,
                    }

                    incident_security_ids.add(security_result_id)
                    incidents.append(incident)

        return incidents, incident_security_ids

    def get_sure_backup_incidents(self, existed_ids: set) -> tuple[list[dict], set[str]]:
        last_fetch_time = datetime.now().strftime(DATE_FORMAT)

        def _paged_job_method(**kwargs):
            return handle_command_with_token_refresh(self.client.get_job_states_request, kwargs, self.client)

        response = search_with_paging(
            method=_paged_job_method,
            args={"typeFilter": "SureBackupContentScan", "statusFilter": "Stopped"},
            page_size=JOB_STATES_REQUEST_PAGE_SIZE,
        )

        incidents: list[dict] = []
        incident_sure_backup_ids = existed_ids

        sure_backup_ids = {sure_backup["id"] for sure_backup in response}
        incident_sure_backup_ids.intersection_update(sure_backup_ids)

        for sure_backup in response:
            sure_backup_id = str(sure_backup.get("id"))

            if sure_backup["lastResult"] == "Failed":
                last_run = sure_backup.get("lastRun", "")
                last_run = last_run if last_run else NOT_APPLICABLE

                if sure_backup_id not in incident_sure_backup_ids:
                    sb_name = sure_backup["name"]
                    details = (
                        f"{sure_backup['description']}; Job Name: {sb_name}; "
                        f"Object Count: {sure_backup['objectsCount']}; Last Run: {last_run}"
                    )
                    incident_name = f"Veeam - SureBackup job {sb_name} " "(backup verification and content scan only) has failed"
                    sure_backup["details"] = details
                    sure_backup["incident_type"] = SURE_BACKUP_INCIDENT_TYPE
                    incident = {
                        "name": incident_name,
                        "occurred": last_fetch_time,
                        "rawJSON": json.dumps(sure_backup),
                        "severity": IncidentSeverity.CRITICAL,
                    }

                    incident_sure_backup_ids.add(sure_backup_id)
                    incidents.append(incident)

        return incidents, incident_sure_backup_ids

    def fetch_malware_events(self, first_fetch_time: str, max_results: int) -> None:
        error_count: int = self.errors_by_command.get(ERROR_COUNT_IN_MALWARE_INCIDENTS, 0)

        last_fetch = self.last_run.get("last_fetch", None) or first_fetch_time
        assert last_fetch

        try:
            malwareIds = set(self.last_run.get("malware_ids", []))
            context = demisto.getIntegrationContext()
            post_events_ids: list = context.get("post_event_ids", [])
            malwareIds.update(post_events_ids)
            context["post_event_ids"] = []
            demisto.setIntegrationContext(context)
            malware_incidents, malwareIds, last_fetch_time = self.get_malware_incidents(
                parser.parse(last_fetch), malwareIds, max_results
            )
            self.incidents.extend(malware_incidents)
            self.next_run["malware_ids"] = list(malwareIds)
            self.next_run["last_fetch"] = last_fetch_time
            error_count = 0
        except Exception as e:
            error_message = str(e)
            demisto.debug(error_message)
            incident, error_count = process_error(error_count, error_message)
            if incident:
                self.incidents.append(incident)
        finally:
            self.errors_by_command[ERROR_COUNT_IN_MALWARE_INCIDENTS] = error_count

    def fetch_repository_space_incidents(self, max_results: int, free_space_less_then: int) -> None:
        error_count: int = self.errors_by_command.get(ERROR_COUNT_IN_FREE_SPACE_INCIDENTS, 0)
        try:
            repositoryIds = set(self.last_run.get("repository_ids", []))
            free_space_incidents, repositoryIds = self.get_repository_space_incidents(
                repositoryIds, max_results, free_space_less_then
            )
            self.incidents.extend(free_space_incidents)
            self.next_run["repository_ids"] = list(repositoryIds)
            error_count = 0
        except Exception as e:
            error_message = str(e)
            demisto.debug(error_message)
            incident, error_count = process_error(error_count, error_message)
            if incident:
                self.incidents.append(incident)
        finally:
            self.errors_by_command[ERROR_COUNT_IN_FREE_SPACE_INCIDENTS] = error_count

    def fetch_configuration_backup_incident(self, backup_older_then_days: int) -> None:
        backupDate: str = self.last_run.get("backup_date", None)
        error_count: int = self.errors_by_command.get(ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS, 0)
        try:
            backup_incident, backupDate = self.get_configuration_backup_incident(backupDate, backup_older_then_days)
            if backup_incident:
                self.incidents.append(backup_incident)
            self.next_run["backup_date"] = backupDate
            error_count = 0
        except Exception as e:
            error_message = str(e)
            demisto.debug(error_message)
            incident, error_count = process_error(error_count, error_message)
            if incident:
                self.incidents.append(incident)
        finally:
            self.errors_by_command[ERROR_COUNT_IN_CONFIGURATION_BACKUP_INCIDENTS] = error_count

    def fetch_security_analyzer_incidents(self) -> None:
        error_count: int = self.errors_by_command.get(ERROR_COUNT_IN_SECURITY_ANALYZER_INCIDENTS, 0)
        try:
            security_ids = set(self.last_run.get("security_ids", []))
            security_analyzer_incidents, security_ids = self.get_security_analyzer_incidents(security_ids)
            self.incidents.extend(security_analyzer_incidents)
            self.next_run["security_ids"] = list(security_ids)
            error_count = 0
        except Exception as e:
            error_message = str(e)
            demisto.debug(error_message)
            incident, error_count = process_error(error_count, error_message)
            if incident:
                self.incidents.append(incident)
        finally:
            self.errors_by_command[ERROR_COUNT_IN_SECURITY_ANALYZER_INCIDENTS] = error_count

    def fetch_sure_backup_incidents(self) -> None:
        error_count: int = self.errors_by_command.get(ERROR_COUNT_IN_SURE_BACKUP_INCIDENTS, 0)
        try:
            sure_backup_ids = set(self.last_run.get("sure_backup_ids", []))
            sure_backup_incidents, sure_backup_ids = self.get_sure_backup_incidents(sure_backup_ids)
            self.incidents.extend(sure_backup_incidents)
            self.next_run["sure_backup_ids"] = list(sure_backup_ids)
            error_count = 0
        except Exception as e:
            error_message = str(e)
            demisto.debug(error_message)
            incident, error_count = process_error(error_count, error_message)
            if incident:
                self.incidents.append(incident)
        finally:
            self.errors_by_command[ERROR_COUNT_IN_SURE_BACKUP_INCIDENTS] = error_count

    def fetch_incidents(
        self,
        first_fetch_time: str,
        max_malware_events_for_fetch: int,
        max_repos_space_events_for_fetch: int,
        backup_older_then_days: int,
        free_space_less_then: int,
        fetch_malware_incidents: bool,
        fetch_backup_repository_events: bool,
        fetch_configuration_backup_events: bool,
        fetch_security_analyzer_events: bool,
        fetch_sure_backup_events: bool,
    ) -> tuple[dict, list[dict]]:
        demisto.debug(f"Last run: {json.dumps(self.last_run)}")

        if max_malware_events_for_fetch > 0 and fetch_malware_incidents is True:
            self.fetch_malware_events(first_fetch_time=first_fetch_time, max_results=max_malware_events_for_fetch)

        if max_repos_space_events_for_fetch > 0 and fetch_backup_repository_events is True:
            self.fetch_repository_space_incidents(
                max_results=max_repos_space_events_for_fetch, free_space_less_then=free_space_less_then
            )

        if fetch_configuration_backup_events is True:
            self.fetch_configuration_backup_incident(backup_older_then_days=backup_older_then_days)

        if fetch_security_analyzer_events is True:
            self.fetch_security_analyzer_incidents()

        if fetch_sure_backup_events is True:
            self.fetch_sure_backup_incidents()

        demisto.debug(f"Number of incidents: {len(self.incidents)}")
        demisto.debug(f"Next run after incident fetching: {json.dumps(self.next_run)}")
        return self.next_run, self.incidents


def validate_filter_parameter(value: int) -> None:
    if value < 0 or value > MAX_INT:
        raise ValueError(
            f"Invalid input parameter value: {value}. "
            f"Parameter value must be non-negative and less than maximum integer value"
        )


def process_command(
    command: Any, client: Client, first_fetch_time: datetime, params: dict, args: dict, max_attempts: int = MAX_ATTEMPTS
):
    commands = {
        "veeam-vbr-create-malware-event": create_malware_event_command,
        "veeam-vbr-get-malware-events": get_all_malware_events_command,
        "veeam-vbr-get-authorization-events": get_authorization_events_command,
        "veeam-vbr-get-yara-rules": get_yara_rules_command,
        "veeam-vbr-get-repository-states": get_all_repository_states_command,
        "veeam-vbr-get-restore-points": get_all_restore_points_command,
        "veeam-vbr-get-backup-object": get_backup_object_command,
        "veeam-vbr-get-configuration-backup": get_configuration_backup_command,
        "veeam-vbr-get-inventory-objects": get_inventory_objects_command,
        "veeam-vbr-get-session": get_session_command,
        "veeam-vbr-get-session-logs": get_session_logs_command,
        "veeam-vbr-start-configuration-backup": start_configuration_backup_command,
        "veeam-vbr-start-instant-recovery": start_instant_recovery_command,
        "veeam-vbr-start-instant-recovery-customized": start_instant_recovery_customized_command,
        "veeam-vbr-start-instant-recovery-hyperv-vm": start_instant_recovery_hyperv_vm_command,
        "veeam-vbr-start-instant-recovery-hyperv-vm-customized": start_instant_recovery_hyperv_vm_customized_command,
        "veeam-vbr-start-security-analyzer": start_security_analyzer_command,
        "veeam-vbr-get-security-analyzer-best-practices": get_security_analyzer_best_practices_command,
        "veeam-vbr-get-security-analyzer-last-run": get_security_analyzer_last_run_command,
        "veeam-vbr-get-job-states": get_job_states_command,
        "veeam-vbr-start-vsphere-quick-backup": start_vsphere_quick_backup_command,
        "veeam-vbr-start-malware-backup-scan": start_malware_backup_scan_command,
        "veeam-vbr-mount-entra-id-tenant": mount_entra_id_tenant_command,
        "veeam-vbr-unmount-entra-id-tenant": unmount_entra_id_tenant_command,
        "veeam-vbr-get-entra-id-items": get_entra_id_items_command,
        "veeam-vbr-get-entra-id-item-restore-points": get_entra_id_item_restore_points_command,
        "veeam-vbr-compare-entra-id-item-properties": compare_entra_id_item_properties_command,
        "veeam-vbr-start-disk-publishing": start_disk_publishing_command,
        "veeam-vbr-stop-disk-publishing": stop_disk_publishing_command,
        "veeam-vbr-get-disk-publishing-mount-point": get_disk_publishing_mount_point_command,
        "veeam-vbr-general-api-request": general_api_request_command,
    }

    if command == "test-module":
        result = test_module(client)
        return result

    elif command == "fetch-incidents":
        max_malware_events_for_fetch = int(params.get("malware_events_per_request", MAX_EVENTS_FOR_FETCH))
        max_repos_space_events_for_fetch = int(params.get("backup_repository_events_per_request", MAX_REPOSITORIES_FOR_FETCH))

        backup_older_then_days = int(params.get("days_since_last_configuration_backup", CONFIGURATION_BACKUP_OLDER_THEN_DAYS))
        validate_filter_parameter(backup_older_then_days)

        free_space_less_then = int(params.get("backup_repository_free_space", REPOSITORY_FREE_SPACE_LESS_THEN))
        validate_filter_parameter(free_space_less_then)

        fetch_configuration_backup_events: bool = params.get("fetch_configuration_backup_events", False)
        fetch_backup_repository_events: bool = params.get("fetch_backup_repository_events", False)
        fetch_malware_incidents: bool = params.get("fetch_malware_events", False)
        fetch_security_analyzer_events: bool = params.get("fetch_security_analyzer_events", False)
        fetch_sure_backup_events: bool = params.get("fetch_sure_backup_events", False)

        fetch_client = FetchClient(client, last_run=demisto.getLastRun())
        next_run, incidents = fetch_client.fetch_incidents(
            first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),
            max_malware_events_for_fetch=max_malware_events_for_fetch,
            max_repos_space_events_for_fetch=max_repos_space_events_for_fetch,
            backup_older_then_days=backup_older_then_days,
            free_space_less_then=free_space_less_then,
            fetch_malware_incidents=fetch_malware_incidents,
            fetch_backup_repository_events=fetch_backup_repository_events,
            fetch_configuration_backup_events=fetch_configuration_backup_events,
            fetch_security_analyzer_events=fetch_security_analyzer_events,
            fetch_sure_backup_events=fetch_sure_backup_events,
        )

        demisto.setLastRun(next_run)
        demisto.incidents(incidents)
        return None

    elif command in commands:
        result = handle_command_with_token_refresh(commands[command], {"client": client, "args": args}, client, max_attempts)
        return result
    else:
        raise NotImplementedError(f"Command {command} is not implemented.")


def get_api_key(client: Client) -> str:
    credentials: dict[str, str] = demisto.params().get("credentials")
    username: str = credentials.get("identifier", "")
    password: str = credentials.get("password", "")
    token = get_access_token(client, username, password)
    api_key = f"Bearer {token}"
    return api_key


def set_api_key(client: Client, api_key: str) -> None:
    headers = client.get_headers()
    headers["Authorization"] = api_key
    client.set_headers(headers)


def check_license(license_response: dict) -> None:
    instanceLicenseSummary = license_response.get("instanceLicenseSummary", {})
    license_dict = {**license_response, **instanceLicenseSummary}
    for license in ACCEPTABLE_LICENSES:
        if all(license_dict.get(key) == license.get(key) for key in license):
            return
    raise ValueError("Valid Veeam license required")


def handle_command_with_token_refresh(command: Callable, command_params: dict, client: Client, max_attempts: int = MAX_ATTEMPTS):
    attempts = 0

    while attempts < max_attempts:
        try:
            context = demisto.getIntegrationContext()
            api_key = context.get("token")
            new_token = False
            if not api_key:
                api_key = get_api_key(client)
                new_token = True

            set_api_key(client, api_key)

            if new_token:
                response = client.get_license_request()
                check_license(response)
                context["token"] = api_key
                demisto.setIntegrationContext(context)

            res = command(**command_params)
            return res
        except Exception as e:
            status_code = getattr(getattr(e, "res", None), "status_code", None)
            if status_code == HTTPStatus.UNAUTHORIZED:
                attempts += 1
                context = demisto.getIntegrationContext()
                context["token"] = None
                demisto.setIntegrationContext(context)
            else:
                raise e

    raise ValueError("Failed to obtain a valid API Key after 3 attempts")


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    url: str = params.get("url", "")
    verify_certificate: bool = not params.get("insecure", False)
    proxy: bool = params.get("proxy", False)

    first_fetch_time = arg_to_datetime(arg=params.get("first_fetch", "3 days"), arg_name="First fetch time", required=False)

    if not first_fetch_time:
        first_fetch_time = datetime.now()

    http_request_timeout_sec = int(params.get("http_request_timeout_sec", 120))

    headers = {}
    headers["x-api-version"] = params.get("api-version", X_API_VERSION)
    headers["Content-Type"] = CONTENT_TYPE

    command = demisto.command()
    demisto.debug(f"Command {command} has been run with the following arguments: {args}")

    try:
        client: Client = Client(
            urljoin(url, "/"), verify_certificate, proxy, headers=headers, auth=None, timeout=http_request_timeout_sec
        )
        result = process_command(command, client, first_fetch_time, params, args)
        return_results(result)

    except Exception as e:
        error_message: Union[str, dict[str, Any]] = str(e)
        res = getattr(e, "res", None)
        status_code = getattr(res, "status_code", None)
        if res is not None and status_code:
            error_dict = res.__dict__
            content = convert_to_json(error_dict["_content"])
            message = content.get("message")
            message = message if message else str(e)
            error_message = {"status_code": status_code, "message": message}

        return_error(error_message)


""" ENTRY POINT """

if __name__ in ["__main__", "builtin", "builtins"]:
    main()
