import dataclasses
import http
from typing import Tuple

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


@dataclasses.dataclass
class ScheduleCommandMetadata:
    """Schedule commands metadata."""

    outputs_prefix: str
    message: str = ""
    headers: list[str] = dataclasses.field(default_factory=list)

    def format_message(self, id):
        self.message = self.message.format(id=id)


REGISTRY_VALUE_TYPE_MAP = {
    "DWORD (REG_DWORD)": "DWORD",
    "STRING (REG_GZ)": "STRING",
}

MIN_PAGE_NUM = 1
MAX_PAGE_SIZE = 50
MIN_PAGE_SIZE = 1
MAX_LIMIT = 50
MIN_LIMIT = 1
DEFAULT_HEADERS = [
    "machine_id",
    "machine_name",
    "operation_status",
    "operation_response_output",
    "operation_response_status",
]

DEFAULT_FILTER_TYPE = "Contains"
DEFAULT_SUFFIX_MESSAGE = "was added to the push operation list successfully."

COLUMN_NAMES_MAPPER = {
    "computer_ids": "computerId",
    "computer_names": "computerName",
    "computer_ips": "computerIP",
    "computer_types": "computerType",
    "computer_deployment_statuses": "computerDeploymentStatus",
}
COLUMN_NAMES = [
    "emonJsonDataColumns",
    "computerId",
    "computerName",
    "computerDeploymentStatus",
    "computerIP",
    "computerClientVersion",
    "osName",
    "osVersion",
    "daInstalled",
    "computerDeployTime",
    "computerDeployTimeFrom",
    "computerDeployTimeTo",
    "computerLastErrorCode",
    "computerLastErrorDescription",
    "computerLastConnection",
    "computerLastConnectionFrom",
    "computerLastConnectionTo",
    "computerSyncedonTo",
    "computerSyncedon",
    "computerSyncedonFrom",
    "syncedOn",
    "computerLastLoggedInUser",
    "computerLastLoggedInPrebootUser",
    "computerFdeStatus",
    "computerFdeVersion",
    "computerFdeLastRecoveryDate",
    "computerFdeLastRecoveryDateFrom",
    "computerFdeLastRecoveryDateTo",
    "computerFdeWilWolStatus",
    "computerFdeTpmId",
    "computerFdeTpmStatus",
    "computerFdeTpmVersion",
    "computerFdeWilWolStatusUpdatedOn",
    "computerFdeWilWolStatusUpdatedOnFrom",
    "computerFdeWilWolStatusUpdatedOnTo",
    "computerFdeProgress",
    "computerFdeProgressFrom",
    "computerFdeProgressTo",
    "computerType",
    "endpointType",
    "amUpdatedOn",
    "amUpdatedOnFrom",
    "amUpdatedOnTo",
    "amStatus",
    "isolated",
    "isDeleted",
    "complianceStatus",
    "amUpdatedIntervalStatus",
    "isInDomain",
    "domainName",
    "o_x",
    "devices_emon_status_data_selector",
    "deleted_devices_emon_status_data_selector",
    "computerAmDatVersion",
    "computerAmDatDate",
    "computerAmDatDateFrom",
    "computerAmDatDateTo",
    "computerAmLicExpirationDate",
    "computerAmProviderBrandReport",
    "computerAmLicExpirationDateFrom",
    "computerAmLicExpirationDateTo",
    "computerAmTotalInfected",
    "computerAmTotalInfectedFrom",
    "computerAmTotalInfectedTo",
    "computerAmInfections",
    "computerSdPackageName",
    "computerSdPolicyName",
    "computerSdPolicyVersion",
    "computerAbState",
    "computerAbStatusBotNames",
    "computerAmScannedon",
    "computerAmScannedonFrom",
    "computerAmScannedonTo",
    "computerAmTotalQuarantined",
    "computerAmTotalQuarantinedFrom",
    "computerAmTotalQuarantinedTo",
    "computerLastContactedPolicyServerIp",
    "computerLastContactedPolicyServerName",
    "computerSdPackageVersion",
    "computerComplianceViolationIds",
    "computerSmartCardStatus",
    "fdeRemoteUnlockOperation",
    "fdeRemoteUnlockStatus",
    "computerCanonicalName",
    "stoppedBlades",
    "enforcedModifiedOn",
    "enforcedPolicyMalware20",
    "enforcedPolicyTe130",
    "enforcedPolicyEfr120",
    "enforcedPolicyAntibot100",
    "enforcedPolicyMe30",
    "enforcedPolicyFdeDevice35",
    "enforcedPolicyFdeUser36",
    "enforcedPolicyFw10",
    "enforcedPolicyCompliance60",
    "enforcedPolicyApplicationControl22",
    "enforcedPolicySaAccessZones11",
    "enforcedPolicyCommonClientSettings51",
    "enforcedPolicyDocSecPolicy91",
    "enforcedVersionPolicyMalware20",
    "enforcedVersionPolicyTe130",
    "enforcedVersionPolicyEfr120",
    "enforcedVersionPolicyAntibot100",
    "enforcedVersionPolicyMe30",
    "enforcedVersionPolicyFdeDevice35",
    "enforcedVersionPolicyFdeUser36",
    "enforcedVersionPolicyFw10",
    "enforcedVersionPolicyCompliance60",
    "enforcedVersionPolicyApplicationControl22",
    "enforcedVersionPolicySaAccessZones11",
    "enforcedVersionPolicyCommonClientSettings51",
    "enforcedVersionPolicyDocSecPolicy91",
    "enforcedNamePolicyMalware20",
    "enforcedNamePolicyTe130",
    "enforcedNamePolicyEfr120",
    "enforcedNamePolicyAntibot100",
    "enforcedNamePolicyMe30",
    "enforcedNamePolicyFdeDevice35",
    "enforcedNamePolicyFdeUser36",
    "enforcedNamePolicyFw10",
    "enforcedNamePolicyCompliance60",
    "enforcedNamePolicyApplicationControl22",
    "enforcedNamePolicySaAccessZones11",
    "enforcedNamePolicyCommonClientSettings51",
    "enforcedNamePolicyDocSecPolicy91",
    "deployedModifiedOn",
    "deployedPolicyMalware20",
    "deployedPolicyTe130",
    "deployedPolicyEfr120",
    "deployedPolicyAntibot100",
    "deployedPolicyMe30",
    "deployedPolicyFdeDevice35",
    "deployedPolicyFdeUser36",
    "deployedPolicyFw10",
    "deployedPolicyCompliance60",
    "deployedPolicyApplicationControl22",
    "deployedPolicySaAccessZones11",
    "deployedPolicyCommonClientSettings51",
    "deployedPolicyDocSecPolicy91",
    "deployedVersionPolicyMalware20",
    "deployedVersionPolicyTe130",
    "deployedVersionPolicyEfr120",
    "deployedVersionPolicyAntibot100",
    "deployedVersionPolicyMe30",
    "deployedVersionPolicyFdeDevice35",
    "deployedVersionPolicyFdeUser36",
    "deployedVersionPolicyFw10",
    "deployedVersionPolicyCompliance60",
    "deployedVersionPolicyApplicationControl22",
    "deployedVersionPolicySaAccessZones11",
    "deployedVersionPolicyCommonClientSettings51",
    "deployedVersionPolicyDocSecPolicy91",
    "deployedNamePolicyMalware20",
    "deployedNamePolicyTe130",
    "deployedNamePolicyEfr120",
    "deployedNamePolicyAntibot100",
    "deployedNamePolicyMe30",
    "deployedNamePolicyFdeDevice35",
    "deployedNamePolicyFdeUser36",
    "deployedNamePolicyFw10",
    "deployedNamePolicyCompliance60",
    "deployedNamePolicyApplicationControl22",
    "deployedNamePolicySaAccessZones11",
    "deployedNamePolicyCommonClientSettings51",
    "deployedNamePolicyDocSecPolicy91",
    "computerCpuLoadCategory",
    "computerTotalCpuLoadCategory",
    "computerCpuRank",
    "computerTotalCpuRank",
    "computerGroups",
    "computerOrUsers",
    "computerInactiveCapabilities",
    "filterAndThoseComputers",
    "filterAndThoseComputersOrUsers",
    "filterComplianceStatus",
    "computerFreeSearch",
    "computerEnforcedInstalledPolicyName",
    "computerEnforcedInstalledPolicyVersion",
    "computerStoppedBlades",
    "Is_Device_In_Group",
    "global",
    "permission",
]
FILTER_TYPES = [
    "Contains",
    "StartsWith",
    "EndsWith",
    "Exact",
    "Grater",
    "Smaller",
    "BitOr",
    "BitAnd",
    "IsNull",
    "NotNull",
    "Not",
    "JsonbExact",
    "JsonbContainsAnd",
    "JsonbContainsOr",
    "NestedJsonbContainsAnd",
    "NestedJsonbContainsOr",
    "NestedJsonbExactAnd",
    "NestedJsonbExactOr",
    "NestedJsonbDateRange",
    "ArrayContains",
    "Between",
]
SCHEDULED_COMMANDS_MAPPER = {
    "harmony-ep-policy-rule-install": ScheduleCommandMetadata(
        outputs_prefix="PolicyRuleInstall", message="Policies have been installed successfully."
    ),
    "harmony-ep-policy-rule-modifications-get": ScheduleCommandMetadata(
        outputs_prefix="Rule",
        message="Rule {id} modification:",
        headers=["id", "name", "family", "connectionState", "lastModifiedBy", "job_id"],
    ),
    "harmony-ep-policy-rule-metadata-list": ScheduleCommandMetadata(
        outputs_prefix="Rule", message="Rule metadata list:"
    ),
    "harmony-ep-push-operation-status-list": ScheduleCommandMetadata(
        outputs_prefix="PushOperation",
        message="Push operations status list:",
        headers=["id", "comment", "type", "createdOn", "overallStatus"],
    ),
    "harmony-ep-push-operation-get": ScheduleCommandMetadata(
        outputs_prefix="PushOperation",
        message="Push operations:",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-push-operation-abort": ScheduleCommandMetadata(
        outputs_prefix="PushOperationAbort",
        message=f"Remediation operation abort {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-remediation-computer-isolate": ScheduleCommandMetadata(
        outputs_prefix="ComputerIsolate.PushOperation",
        message=f"Remediation isolate {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-remediation-computer-deisolate": ScheduleCommandMetadata(
        outputs_prefix="ComputerDeisolate.PushOperation",
        message=f"Remediation de-isolate {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-anti-malware-scan": ScheduleCommandMetadata(
        outputs_prefix="AntiMalwareScan.PushOperation",
        message=f"Anti-Malware scan {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-anti-malware-update": ScheduleCommandMetadata(
        outputs_prefix="AntiMalwareUpdate.PushOperation",
        message=f"Anti-Malware Signature Database update {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-anti-malware-restore": ScheduleCommandMetadata(
        outputs_prefix="AntiMalwareRestore.PushOperation",
        message=f"File restore {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-forensics-indicator-analyze": ScheduleCommandMetadata(
        outputs_prefix="IndicatorAnalyze.PushOperation",
        message=f"IOC analyze {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-forensics-file-quarantine": ScheduleCommandMetadata(
        outputs_prefix="FileQuarantine.PushOperation",
        message=f"File quarantine {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-forensics-file-restore": ScheduleCommandMetadata(
        outputs_prefix="FileRestore.PushOperation",
        message=f"File restore {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-computer-list": ScheduleCommandMetadata(
        outputs_prefix="Computer",
        message="Computer list:",
        headers=[
            "id",
            "name",
            "ip",
            "type",
            "groups",
            "user_name",
            "client_version",
        ],
    ),
    "harmony-ep-agent-computer-restart": ScheduleCommandMetadata(
        outputs_prefix="ComputerReset.PushOperation",
        message=f"Computer reset restore {DEFAULT_SUFFIX_MESSAGE}",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-computer-shutdown": ScheduleCommandMetadata(
        outputs_prefix="ComputerShutdown.PushOperation",
        message=f"Computer shutdown {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-computer-repair": ScheduleCommandMetadata(
        outputs_prefix="ComputerRepair.PushOperation",
        message=f"Computer repair {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-process-information-get": ScheduleCommandMetadata(
        outputs_prefix="ProcessInformation.PushOperation",
        message=f"Process information fetch {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-process-terminate": ScheduleCommandMetadata(
        outputs_prefix="ProcessTerminate.PushOperation",
        message=f"Process terminate {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-registry-key-add": ScheduleCommandMetadata(
        outputs_prefix="RegistryKeyAdd.PushOperation",
        message=f"Registry key addition {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-registry-key-delete": ScheduleCommandMetadata(
        outputs_prefix="RegistryKeyDelete.PushOperation",
        message=f"Registry key delete {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-file-copy": ScheduleCommandMetadata(
        outputs_prefix="FileCopy.PushOperation",
        message=f"File copy {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-file-move": ScheduleCommandMetadata(
        outputs_prefix="FileMove",
        message=f"File move {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-file-delete": ScheduleCommandMetadata(
        outputs_prefix="FileDelete.PushOperation",
        message=f"File delete {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-vpn-site-add": ScheduleCommandMetadata(
        outputs_prefix="VPNsiteConfigurationAdd.PushOperation",
        message=f"VPN site configuration addition {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
    "harmony-ep-agent-vpn-site-remove": ScheduleCommandMetadata(
        outputs_prefix="VPNsiteConfigurationRemove.PushOperation",
        message=f"VPN site configuration remove {DEFAULT_SUFFIX_MESSAGE}.",
        headers=DEFAULT_HEADERS,
    ),
}


class Client(BaseClient):
    URL_PREFIX = "app/endpoint-web-mgmt/harmony/endpoint/api/v1"

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        verify_certificate: bool,
        proxy: bool,
    ):
        self.token: str
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url

        super().__init__(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            headers={},
        )

    def get_token(self):
        """Get temporary authentication token from CheckPoint.
        This token will expire 30 minutes from its generation time."""
        self._headers = {}
        self._session.cookies.clear()

        response = self._http_request(
            method="POST",
            url_suffix="auth/external",
            json_data={"clientId": self.client_id, "accessKey": self.client_secret},
        )
        try:
            self.token = response["data"]["token"]
        except DemistoException as exc:
            raise DemistoException(f"Authentication failed: token not found. {exc}")

    def login(self):
        """Login to Harmony with the generated temporary token and get new token for HarmonyEP."""
        self._session.cookies.clear()
        self._headers["Authorization"] = f"Bearer {self.token}"
        self._base_url = urljoin(self.base_url, self.URL_PREFIX)

        try:
            response = self._http_request(
                method="POST",
                url_suffix="/session/login/cloud",
            )
            self._headers["x-mgmt-api-token"] = response["apiToken"]

        except DemistoException as exc:
            if (
                exc.res is not None
                and exc.res.status_code == http.HTTPStatus.BAD_REQUEST
            ):
                raise DemistoException(
                    f"Authentication failed: cookie not found. {exc}"
                )

    def job_status_get(self, job_id: str) -> dict[str, Any]:
        """Get job status and data by ID.

        Args:
            job_id (str): The job ID.

        Returns:
            dict[str,Any]: API response.
        """

        return self._http_request(
            method="GET",
            url_suffix=f"/jobs/{job_id}",
        )

    def ioc_list(
        self,
        page: int,
        page_size: int,
        ioc_filter: str = None,
        field: str = None,
        sort_direction: str = None,
    ) -> dict[str, Any]:
        """Fetch IOCs list.

        Args:
            page (str): Index of page to return.
            page_size (int): Size of the page to return.
            ioc_filter (str, optional): The indicator value or comment to search for. Defaults to None.
            sort_field (str, optional): The Indicator of Compromise field to search by. Defaults to None.
            sort_direction (str, optional): The ways in which to sort the results. Defaults to None.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "off"
        data = remove_empty_elements(
            {
                "filter": ioc_filter,
                "page": page,
                "size": page_size,
                "sort": [{"field": field, "direction": sort_direction}],
            }
        )
        return self._http_request(method="POST", url_suffix="/ioc/get", json_data=data)

    def ioc_update(
        self,
        ioc_type: str,
        value: str,
        comment: str,
        ioc_id: str,
    ) -> dict[str, Any]:
        """Update IOC by ID.

        Args:
            ioc_type (str): The IOC type to update.
            value (str): The IOC value to update.
            comment (str): The IOC comment to update.
            ioc_id (str): The ID of the IOC to update.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "off"
        return self._http_request(
            method="PUT",
            url_suffix="/ioc/edit",
            json_data=[
                {"comment": comment, "id": ioc_id, "type": ioc_type, "value": value}
            ],
        )

    def ioc_create(
        self,
        ioc_type: str | None = None,
        value: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """Create an IOC.

        Args:
            ioc_type (str): The IOC type.
            value (str): The IOC value.
            comment (str): The IOC comment.

        Returns:
            dict[str,Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "off"

        return self._http_request(
            method="POST",
            url_suffix="/ioc/create",
            json_data=[{"comment": comment, "type": ioc_type, "value": value}],
        )

    def ioc_delete(
        self,
        delete_all: bool,
        ioc_ids: str | None,
    ) -> dict[str, Any]:
        """Delete IOCs by IDs or delete all IOCs.

        Args:
            ioc_ids (list[int]): IOC IDs list to delete.
            delete_all (bool): Whether to delete all IOCs or not.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "off"
        url = "/ioc/delete/all" if delete_all else f"/ioc/delete?ids={ioc_ids}"
        return self._http_request(
            method="DELETE",
            url_suffix=url,
        )

    def rule_assignments_get(
        self,
        rule_id: str,
    ) -> dict[str, Any]:
        """Gets all entities directly assigned to the given rule.

        Args:
            rule_id (str): The rule ID.

        Returns:
            dict[str, Any]: API response.
        """

        self._headers["x-mgmt-run-as-job"] = "off"

        return self._http_request(
            "GET",
            f"/policy/{rule_id}/assignments",
        )

    def rule_assignments_add(
        self, rule_id: str, entities_ids: list[str]
    ) -> dict[str, Any]:
        """Assigns the specified entities to the given rule.
            Specified IDs that are already assigned to the rule are ignored.

        Args:
            rule_id (str): The ID of the rule to add assignments to.
            entities_ids (list[str]): The entities IDs to assign.

        Returns:
            dict[str, Any]: API response.
        """

        self._headers["x-mgmt-run-as-job"] = "off"

        return self._http_request(
            "PUT",
            f"/policy/{rule_id}/assignments/add",
            json_data=entities_ids,
        )

    def rule_assignments_remove(
        self, rule_id: str, entities_ids: list[str]
    ) -> dict[str, Any]:
        """Removes the specified entities from the given rule's assignments.
            Specified IDs that are not assigned to the rule are ignored.

        Args:
            rule_id (str): The ID of the rule to remove assignments from.
            entities_ids (list[str]): The entities IDs to remove.

        Returns:
            dict[str, Any]: API response.
        """

        self._headers["x-mgmt-run-as-job"] = "off"

        return self._http_request(
            "PUT",
            f"/policy/{rule_id}/assignments/remove",
            json_data=entities_ids,
        )

    def rule_policy_install(self) -> dict[str, Any]:
        """Installs all policies. If a rule ID is specified,
            only the policies associated with that rule will be installed.

        Args:
            rule_id (str, optional): The ID of the rule. Defaults to None.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/policy/install",
        )

    def rule_modifications_get(
        self,
        rule_id: str,
    ) -> dict[str, Any]:
        """Gets information on modifications to a given rule
        (modifications are the addition or removal of assignments on a rule since it was last installed).

        Args:
            rule_id (str): The rule ID.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"
        return self._http_request(
            "GET",
            f"/policy/{rule_id}/modifications",
        )

    def rule_metadata_list(
        self,
        rule_id: str | None = None,
        rule_family: str | None = None,
        connection_state: str | None = None,
    ) -> list[dict[str, Any]]:
        """Gets the metadata of all rules or the given rule's metadata
        (Metadata refers to all information relating to the rule except it's actual settings).

        Args:
            rule_id (str): The rule ID.
            rule_family (str): An optional filter.
                Used to filter the results to only the selected capability family (e.g. only 'Threat Prevention').
            connection_state (str): An optional filter. Used to filter the results to only
                the selected Connection State (e.g. only rules pertaining to policies for 'Connected' clients).

        Returns:
            list[dict[str,Any]]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "off"
        params = {"ruleFamily": rule_family, "connectionState": connection_state}

        return self._http_request(
            "GET",
            (f"/policy/{rule_id}/metadata" if rule_id else "/policy/metadata"),
            params=params,
        )

    def push_operation_status_list(
        self, remediation_operation_id: str | None
    ) -> dict[str, Any]:
        """Gets the current statuses of all remediation operations or if a specific ID is specified,
        retrieve the current status of the given remediation operation.

        Args:
            remediation_operation_id (str): Remediation operations ID.

        Returns:
            Dict[str,Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "GET",
            (
                f"/remediation/{remediation_operation_id}/status"
                if remediation_operation_id
                else "/remediation/status"
            ),
        )

    def push_operation_get(
        self,
        remediation_operation_id: str,
        filter_text: str | None = None,
        new_page: int | None = None,
        new_page_size: int | None = None,
    ) -> dict[str, Any]:
        """Gets the results of a given Remediation Operation. Remediation Operations may produce results
        such a Forensics Report or yield status updates such as an Anti-Malware scan progress.

        Args:
            remediation_operation_id (str): Remediation operation ID.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            f"/remediation/{remediation_operation_id}/results/slim",
            json_data=remove_empty_elements(
                {
                    "filters": {"freeText": filter_text},
                    "paging": {"pageSize": new_page_size, "offset": new_page},
                }
            ),
        )

    def push_operation_abort(self, remediation_operation_id: str) -> dict[str, Any]:
        """Aborts the given Remediation Operation.
            Aborting an operation prevents it from being sent to further Harmony Endpoint Clients.
            Clients that have already received the operation are not affected.

        Args:
            remediation_operation_id (str): Remediation operation ID.

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            f"/remediation/{remediation_operation_id}/abort",
        )

    def anti_malware_scan(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Performs an Anti-Malware scan on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"
        return self._http_request(
            "POST",
            "/remediation/anti-malware/scan",
            json_data=request_body,
        )

    def anti_malware_update(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Updates the Anti-Malware Signature Database on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"
        return self._http_request(
            "POST",
            "/remediation/anti-malware/update",
            json_data=request_body,
        )

    def anti_malware_restore(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Restores a file that was previously quarantined by the Harmony Endpoint Client's Anti-Malware capability.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """

        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/anti-malware/restore",
            json_data=request_body,
        )

    def indicator_analyze(
        self,
        indicator_type: str,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Collects forensics data whenever a computer that matches the given query
            accesses or executes the given IP, URL, file name, MD5, or path.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """

        self._headers["x-mgmt-run-as-job"] = "on"
        return self._http_request(
            "POST",
            f"/remediation/forensics/analyze-by-indicator/{indicator_type.lower()}",
            json_data=request_body,
        )

    def file_quarantine(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Quarantines files given by path or MD5 or detections relating to a forensic incident.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/forensics/file/quarantine",
            json_data=request_body,
        )

    def file_restore(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Restores previously quarantined files given by path or MD5 or detections relating to a forensic incident.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/forensics/file/restore",
            json_data=request_body,
        )

    def remediation_computer_isolate(
        self, request_body: dict[str, Any]
    ) -> dict[str, Any]:
        """Isolates the computers matching the given query. Isolation is the act of denying all
        network access from a given computer.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/isolate",
            json_data=request_body,
        )

    def remediation_computer_deisolate(
        self, request_body: dict[str, Any]
    ) -> dict[str, Any]:
        """De-Isolates the computers matching the given query. De-isolating a computer restores
            its access to network resources.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/de-isolate",
            json_data=request_body,
        )

    def computer_restart(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Restarts computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/reset-computer",
            json_data=request_body,
        )

    def computer_shutdown(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Shuts-down computers match the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/shutdown-computer",
            json_data=request_body,
        )

    def computer_repair(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Repairs the Harmony Endpoint Client installation on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/repair-computer",
            json_data=request_body,
        )

    def computer_list(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Gets a list of computers matching the given filters.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/asset-management/computers/filtered",
            json_data=request_body,
        )

    def process_information_get(self, request_body: dict[str, Any]) -> dict[str, Any]:
        """Collects information about processes on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/process/information",
            json_data=request_body,
        )

    def process_terminate(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Terminates the given process on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/process/terminate",
            json_data=request_body,
        )

    def agent_registry_key_add(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Adds a given registry key and/or value to the registry of computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/registry/key/add",
            json_data=request_body,
        )

    def agent_registry_key_delete(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Removes the given registry key or value to the registry of computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"
        return self._http_request(
            "POST",
            "/remediation/agent/registry/key/delete",
            json_data=request_body,
        )

    def agent_file_copy(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Copies the given file from the given source to the given destination on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/file/copy",
            json_data=request_body,
        )

    def agent_file_move(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Moves the given file from the given source to the given destination on computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/file/move",
            json_data=request_body,
        )

    def agent_file_delete(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Deletes the given file from the given source on computers matching the given query.
            This operation is risky! Use with caution as it allows you to change Harmony Endpoint protected
            files or registry entries that are in use by your operating system.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/file/delete",
            json_data=request_body,
        )

    def agent_vpn_site_add(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Adds the given VPN Site's configuration to computers matching the given query.
            Adding a VPN Site allows Harmony Endpoint Clients to connect to it.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/vpn/site/add",
            json_data=request_body,
        )

    def agent_vpn_site_remove(
        self,
        request_body: dict[str, Any],
    ) -> dict[str, Any]:
        """Removes the given VPN Site's configuration to computers matching the given query.

        Args:
            request_body (dict[str, Any]): The request body for the API request (query computers).

        Returns:
            dict[str, Any]: API response.
        """
        self._headers["x-mgmt-run-as-job"] = "on"

        return self._http_request(
            "POST",
            "/remediation/agent/vpn/site/remove",
            json_data=request_body,
        )


def job_status_get_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Get job status and data by ID.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    response = client.job_status_get(job_id=args.get("job_id", ""))

    return CommandResults(
        outputs_prefix="HarmonyEP.Job",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def ioc_list_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Fetch IOCs list.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    new_page, new_page_size, pagination_message = get_pagination_args(args)

    response = client.ioc_list(
        page=new_page,
        page_size=new_page_size,
        ioc_filter=args.get("filter"),
        field=args.get("field"),
        sort_direction=args.get("sort_direction"),
    )

    for ioc in response["content"]:
        ioc["modifiedOn"] = convert_unix_to_date_string(ioc["modifiedOn"])

    readable_output = tableToMarkdown(
        name="IOC List:",
        metadata=pagination_message,
        t=response["content"],
        headers=["id", "type", "value", "comment", "modifiedOn"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="HarmonyEP.IOC",
        outputs_key_field="id",
        outputs=response["content"],
        raw_response=response,
    )


def ioc_update_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Update IOC by ID.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ioc_id = args.get("ioc_id", "")

    response = client.ioc_update(
        ioc_type=args.get("type", ""),
        value=args.get("value", ""),
        comment=args.get("comment", ""),
        ioc_id=ioc_id,
    )
    readable_output = tableToMarkdown(
        name=f"IOC {ioc_id} was updated successfully.",
        t=response,
        headers=["id", "type", "value", "comment", "modifiedOn"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="HarmonyEP.IOC",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def ioc_create_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Create new IOC.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    client.ioc_create(
        ioc_type=args.get("type"),
        value=args.get("value"),
        comment=args.get("comment"),
    )
    return CommandResults(readable_output="IOC was created successfully.")


def ioc_delete_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Delete IOCs by IDs or delete all IOCs.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    ioc_ids = args.get("ids")
    delete_all = argToBoolean(args.get("delete_all"))

    client.ioc_delete(ioc_ids=ioc_ids, delete_all=delete_all)

    return CommandResults(
        readable_output=(
            "All IOCs were deleted successfully."
            if delete_all
            else f"IOCs {ioc_ids} was deleted successfully."
        )
    )


def rule_assignments_get_command(
    args: dict[str, Any], client: Client
) -> CommandResults:
    """Gets all entities directly assigned to the given rule.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    rule_id = args.get("rule_id", "")

    response = client.rule_assignments_get(
        rule_id=rule_id,
    )
    output = {"id": rule_id, "assignments": response}
    readable_output = tableToMarkdown(
        name=f"Rule {rule_id} assignments:",
        t=response,
        headers=["id", "name", "type"],
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="HarmonyEP.Rule",
        outputs_key_field="id",
        outputs=output,
        raw_response=response,
    )


def rule_assignments_add_command(
    args: dict[str, Any], client: Client
) -> CommandResults:
    """Assigns the specified entities to the given rule. Specified IDs that are already assigned to the rule are ignored.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    rule_id = args.get("rule_id", "")
    entities_ids = argToList(args.get("entities_ids"))

    client.rule_assignments_add(rule_id=rule_id, entities_ids=entities_ids)
    return CommandResults(
        readable_output=f"Entities {entities_ids} were assigned to rule {rule_id} successfully."
    )


def rule_assignments_remove_command(
    args: dict[str, Any], client: Client
) -> CommandResults:
    """Removes the specified entities from the given rule's assignments.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    rule_id = args.get("rule_id", "")
    entities_ids = argToList(args.get("entities_ids"))

    client.rule_assignments_remove(rule_id=rule_id, entities_ids=entities_ids)
    return CommandResults(
        readable_output=f"Entities {entities_ids} were removed from rule {rule_id} successfully."
    )


@polling_function(
    name="harmony-ep-policy-rule-install",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Policy installation request is executing",
    requires_polling_arg=False,
)
def rule_policy_install_command(args: dict[str, Any], client: Client) -> PollResult:
    """Installs all policies. If a rule ID is specified, only the policies associated with that rule will be installed.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        response = client.rule_policy_install()
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-policy-rule-install")


@polling_function(
    name="harmony-ep-policy-rule-modifications-get",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Fetch rule modifications request is executing",
    requires_polling_arg=False,
)
def rule_modifications_get_command(args: dict[str, Any], client: Client) -> PollResult:
    """Gets information on modifications to a given rule (modifications are the addition or
        removal of assignments on a rule since it was last installed).

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    rule_id = args.get("rule_id", "")
    SCHEDULED_COMMANDS_MAPPER[
        "harmony-ep-policy-rule-modifications-get"
    ].format_message(rule_id)

    if not args.get("job_id"):
        response = client.rule_modifications_get(rule_id=rule_id)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-policy-rule-modifications-get")


def rule_metadata_list_command(args: dict[str, Any], client: Client) -> CommandResults:
    """Gets the metadata of all rules or the given rule's metadata
        (Metadata refers to all information relating to the rule except it's actual settings).

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    rule_id = args.get("rule_id")
    rule_family = args.get("rule_family")
    connection_state = args.get("connection_state")
    limit = arg_to_number(args.get("limit"))
    all_results = argToBoolean(args.get("all_results"))

    response = client.rule_metadata_list(rule_id, rule_family, connection_state)

    if not rule_id and not all_results:
        response = response[:limit]

    readable_output = tableToMarkdown(
        name="Rule metadata List:" if not rule_id else f"Rule {rule_id} metadata:",
        metadata=f"Showing {len(response)} items." if not rule_id else None,
        t=response,
        headers=[
            "id",
            "name",
            "family",
            "comment",
            "orientation",
            "connectionState",
            "assignments",
        ],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="HarmonyEP.Rule",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


@polling_function(
    name="harmony-ep-push-operation-status-list",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Fetch remediation status list request is executing",
    requires_polling_arg=False,
)
def push_operation_status_list_command(
    args: dict[str, Any], client: Client
) -> PollResult:
    """Gets the current statuses of all remediation operations or if a specific ID is specified,
        retrieve the current status of the given remediation operation.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """

    if not args.get("job_id"):
        remediation_operation_id = args.get("remediation_operation_id")
        response = client.push_operation_status_list(
            remediation_operation_id=remediation_operation_id
        )
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-push-operation-status-list")


@polling_function(
    name="harmony-ep-push-operation-get",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Fetch remediation request is executing",
    requires_polling_arg=False,
)
def push_operation_get_command(args: dict[str, Any], client: Client) -> PollResult:
    """Gets the results of a given Remediation Operation.
    Remediation Operations may produce results such a Forensics Report or yield status
    updates such as an Anti-Malware scan progress.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """

    if not args.get("job_id"):
        new_page, new_page_size, _ = get_pagination_args(args)

        response = client.push_operation_get(
            remediation_operation_id=args.get("remediation_operation_id", ""),
            filter_text=args.get("filter_text"),
            new_page=new_page,
            new_page_size=new_page_size,
        )
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-push-operation-get")


@polling_function(
    name="harmony-ep-push-operation-abort",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Remediation operation abort request is executing",
    requires_polling_arg=False,
)
def push_operation_abort_command(args: dict[str, Any], client: Client) -> PollResult:
    """Aborts the given Remediation Operation.
       Aborting an operation prevents it from being sent to further Harmony Endpoint Clients.
       Clients that have already received the operation are not affected.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        remediation_operation_id = args.get("remediation_operation_id", "")
        SCHEDULED_COMMANDS_MAPPER["harmony-ep-push-operation-abort"].message = (
            f"Remediation operation {remediation_operation_id} was aborted successfully."
        )

        response = client.push_operation_abort(
            remediation_operation_id=remediation_operation_id
        )
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-push-operation-abort")


@polling_function(
    name="harmony-ep-anti-malware-scan",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Anti malware scan request is executing",
    requires_polling_arg=False,
)
def anti_malware_scan_command(args: dict[str, Any], client: Client) -> PollResult:
    """Performs an Anti-Malware scan on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """

    if not args.get("job_id"):
        request_body = build_request_body(args)
        response = client.anti_malware_scan(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-anti-malware-scan")


@polling_function(
    name="harmony-ep-anti-malware-update",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Anti malware update request is executing",
    requires_polling_arg=False,
)
def anti_malware_update_command(args: dict[str, Any], client: Client) -> PollResult:
    """Updates the Anti-Malware Signature Database on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "updateFromEpServer": arg_to_bool(args.get("update_from_ep_server")),
            "updateFromCpServer": arg_to_bool(args.get("update_from_cp_server")),
        }

        response = client.anti_malware_update(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-anti-malware-update")


@polling_function(
    name="harmony-ep-anti-malware-restore",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Anti malware restore request is executing",
    requires_polling_arg=False,
)
def anti_malware_restore_command(args: dict[str, Any], client: Client) -> PollResult:
    """Restores a file that was previously quarantined by the Harmony Endpoint Client's Anti-Malware capability.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {"files": argToList(args.get("files"))}

        response = client.anti_malware_restore(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-anti-malware-restore")


@polling_function(
    name="harmony-ep-forensics-indicator-analyze",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Indicator analyze request is executing",
    requires_polling_arg=False,
)
def indicator_analyze_command(args: dict[str, Any], client: Client) -> PollResult:
    """Collects forensics data whenever a computer that matches the given query accesses
        or executes the given IP, URL, file name, MD5, or path.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """

    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "generateActivityLogs": arg_to_bool(args.get("generate_activity_logs")),
            "indicator": args.get("indicator_value"),
        }

        response = client.indicator_analyze(
            indicator_type=args.get("indicator_type", ""),
            request_body=request_body,
        )
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-forensics-indicator-analyze")


@polling_function(
    name="harmony-ep-forensics-file-quarantine",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="File quarantine request is executing",
    requires_polling_arg=False,
)
def file_quarantine_command(args: dict[str, Any], client: Client) -> PollResult:
    """Quarantines files given by path or MD5 or detections relating to a forensic incident.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "items": {
                "type": args.get("file_type"),
                "value": args.get("file_value"),
            }
        }

        response = client.file_quarantine(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-forensics-file-quarantine")


@polling_function(
    name="harmony-ep-forensics-file-restore",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="File restore request is executing",
    requires_polling_arg=False,
)
def file_restore_command(args: dict[str, Any], client: Client) -> PollResult:
    """Restores previously quarantined files given by path or MD5 or detections relating to a forensic incident.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "items": {
                "type": args.get("file_type"),
                "value": args.get("file_value"),
            }
        }

        response = client.file_restore(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-forensics-file-restore")


@polling_function(
    name="harmony-ep-remediation-computer-isolate",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer isolate request is executing",
    requires_polling_arg=False,
)
def remediation_computer_isolate_command(
    args: dict[str, Any], client: Client
) -> PollResult:
    """Isolates the computers matching the given query. Isolation is the act of denying all network access from a given computer.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        response = client.remediation_computer_isolate(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-remediation-computer-isolate")


@polling_function(
    name="harmony-ep-remediation-computer-deisolate",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer de-isolate request is executing",
    requires_polling_arg=False,
)
def remediation_computer_deisolate_command(
    args: dict[str, Any], client: Client
) -> PollResult:
    """De-Isolates the computers matching the given query. De-isolating a computer restores its access to network resources.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        response = client.remediation_computer_deisolate(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-remediation-computer-deisolate")


@polling_function(
    name="harmony-ep-agent-computer-restart",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer restart request is executing",
    requires_polling_arg=False,
)
def computer_restart_command(args: dict[str, Any], client: Client) -> PollResult:
    """Restarts computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "forceAppsShutdown": args.get("force_apps_shutdown"),
        }
        response = client.computer_restart(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-computer-restart")


@polling_function(
    name="harmony-ep-agent-computer-shutdown",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer shutdown request is executing",
    requires_polling_arg=False,
)
def computer_shutdown_command(args: dict[str, Any], client: Client) -> PollResult:
    """Shuts-down computers match the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "forceAppsShutdown": args.get("force_apps_shutdown"),
        }
        response = client.computer_shutdown(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-computer-shutdown")


@polling_function(
    name="harmony-ep-agent-computer-repair",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer repair request is executing",
    requires_polling_arg=False,
)
def computer_repair_command(args: dict[str, Any], client: Client) -> PollResult:
    """Repairs the Harmony Endpoint Client installation on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        response = client.computer_repair(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-computer-repair")


@polling_function(
    name="harmony-ep-computer-list",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Computer list fetch request is executing",
    requires_polling_arg=False,
)
def computer_list_command(args: dict[str, Any], client: Client) -> PollResult:
    """Gets a list of computers matching the given filters.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        new_page, new_page_size, _ = get_pagination_args(args)
        request_body = {
            "filters": extract_query_filter(args),
            "paging": {"pageSize": new_page_size, "offset": new_page},
        }

        response = client.computer_list(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-computer-list")


@polling_function(
    name="harmony-ep-agent-process-information-get",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Process information fetch request is executing",
    requires_polling_arg=False,
)
def process_information_get_command(args: dict[str, Any], client: Client) -> PollResult:
    """Collects information about processes on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "processName": args.get("process_name"),
            "additionalFields": argToList(args.get("additional_fields")),
        }
        response = client.process_information_get(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-process-information-get")


@polling_function(
    name="harmony-ep-agent-process-terminate",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Process terminate request is executing",
    requires_polling_arg=False,
)
def process_terminate_command(args: dict[str, Any], client: Client) -> PollResult:
    """Terminates the given process on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "name": args.get("name"),
            "pid": arg_to_number(args.get("pid")),
            "terminateAllInstances": arg_to_bool(args.get("terminate_all_instances")),
        }
        response = client.process_terminate(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-process-terminate")


@polling_function(
    name="harmony-ep-agent-registry-key-add",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Registry key add request is executing",
    requires_polling_arg=False,
)
def agent_registry_key_add_command(args: dict[str, Any], client: Client) -> PollResult:
    """Adds a given registry key and/or value to the registry of computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "hive": args.get("hive"),
            "key": args.get("key"),
            "valueName": args.get("value_name"),
            "valueType": REGISTRY_VALUE_TYPE_MAP[args.get("value_type", "")],
            "valueData": args.get("value_data"),
            "isRedirected": arg_to_bool(args.get("is_redirected")),
        }
        response = client.agent_registry_key_add(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-registry-key-add")


@polling_function(
    name="harmony-ep-agent-registry-key-delete",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Registry key remove request is executing",
    requires_polling_arg=False,
)
def agent_registry_key_delete_command(
    args: dict[str, Any], client: Client
) -> PollResult:
    """Removes the given registry key or value to the registry of computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "hive": args.get("hive"),
            "key": args.get("key"),
            "valueName": args.get("value_name"),
            "isRedirected": arg_to_bool(args.get("is_redirected")),
        }
        response = client.agent_registry_key_delete(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-registry-key-delete")


@polling_function(
    name="harmony-ep-agent-file-copy",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="File copy request is executing",
    requires_polling_arg=False,
)
def agent_file_copy_command(args: dict[str, Any], client: Client) -> PollResult:
    """Copies the given file from the given source to the given destination on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "sourceAbsolutePath": args.get("destination_absolute_path"),
            "destinationAbsolutePath": args.get("source_absolute_path"),
        }
        response = client.agent_file_copy(remove_empty_elements(request_body))

        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-file-copy")


@polling_function(
    name="harmony-ep-agent-file-move",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="File move request is executing",
    requires_polling_arg=False,
)
def agent_file_move_command(args: dict[str, Any], client: Client) -> PollResult:
    """Moves the given file from the given source to the given destination on computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "sourceAbsolutePath": args.get("destination_absolute_path"),
            "destinationAbsolutePath": args.get("source_absolute_path"),
        }
        response = client.agent_file_move(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-file-move")


@polling_function(
    name="harmony-ep-agent-file-delete",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="File delete request is executing",
    requires_polling_arg=False,
)
def agent_file_delete_command(args: dict[str, Any], client: Client) -> PollResult:
    """Deletes the given file from the given source on computers matching the given query.
        This operation is risky! Use with caution as it allows you to change Harmony Endpoint protected
        files or registry entries that are in use by your operating system.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "targetAbsolutePath": args.get("target_absolute_path"),
        }
        response = client.agent_file_delete(request_body)
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-file-delete")


@polling_function(
    name="harmony-ep-agent-vpn-site-add",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Add VPN Site's configuration request is executing",
    requires_polling_arg=False,
)
def agent_vpn_site_add_command(args: dict[str, Any], client: Client) -> PollResult:
    """Adds the given VPN Site's configuration to computers matching the given query.
        Adding a VPN Site allows Harmony Endpoint Clients to connect to it.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "remoteAccessGatewayName": args.get("remote_access_gateway_name"),
            "fingerprint": args.get("fingerprint"),
            "authentication": {"method": args.get("authentication_method")},
            "host": args.get("host"),
            "displayName": args.get("display_name"),
        }
        response = client.agent_vpn_site_add(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-vpn-site-add")


@polling_function(
    name="harmony-ep-agent-vpn-site-remove",
    interval=arg_to_number(demisto.args().get("interval", 30)),
    timeout=arg_to_number(demisto.args().get("timeout", 600)),
    poll_message="Remove VPN Site's configuration request is executing",
    requires_polling_arg=False,
)
def agent_vpn_site_remove_command(args: dict[str, Any], client: Client) -> PollResult:
    """Removes the given VPN Site's configuration to computers matching the given query.

    Args:
        client (Client): Harmony API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        PollResult: outputs, readable outputs and raw response for XSOAR.
    """
    if not args.get("job_id"):
        request_body = build_request_body(args)
        request_body["operationParameters"] |= {
            "displayName": args.get("display_name"),
        }
        response = client.agent_vpn_site_remove(remove_empty_elements(request_body))
        args["job_id"] = response.get("jobId")

    return schedule_command(args, client, "harmony-ep-agent-vpn-site-remove")


def test_module(client: Client) -> str:
    """
    Builds the iterator to check that the feed is accessible.

    Args:
        client: Client object.

    Returns:
        Outputs.
    """
    try:
        client.ioc_list(0, 1)
    except DemistoException as exc:
        if exc.res is not None and (
            exc.res.status_code == http.HTTPStatus.UNAUTHORIZED
            or exc.res.status_code == http.HTTPStatus.FORBIDDEN
        ):
            return "Authorization Error: Invalid URL or credentials."
        raise exc

    return "ok"


# Helper Commands #


def schedule_command(
    args: dict[str, Any], client: Client, command_name: str
) -> PollResult:
    """Build scheduled command in case:
        - Job state is not 'DONE'
        - Job state is 'DONE' but the API response data is a remediation operation ID.

    Args:
        client (Client): Harmony Endpoint API client.
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        PollResult: Command, args, timeout and interval for CommandResults.
    """
    if last_job_id := dict_safe_get(get_integration_context(), ["job_id"]):
        args["job_id"] = last_job_id

    command_results: CommandResults = job_status_get_command(args, client)
    sample_state = dict_safe_get(command_results.raw_response, ["status"])

    if sample_state == "DONE":
        command_data = dict_safe_get(command_results.raw_response, ["data"])

        # Check if data is a remediation operation ID
        # If so, will fetch another job ID for the push operation data
        if isinstance(command_data, str):
            response = client.push_operation_get(command_data)

            # Save new schedule arguments in integration context
            # (cause for the second run there are new arguments or/and values)
            set_integration_context(
                {"job_id": response["jobId"], "remediation_operation_id": command_data}
            )
            return PollResult(
                response=command_results,
                continue_to_poll=True,
                args_for_next_run=args,
            )
        else:

            updated_command_readable_output, updated_command_response = (
                prepare_command_output_and_readable_output(
                    command_data=command_data,
                    command_name=command_name,
                    job_id=args["job_id"],
                )
            )

            command_results.readable_output = get_readable_output(
                command_name=command_name,
                updated_command_data=updated_command_readable_output,
                args=args,
            )

            clear_integration_context()

            return PollResult(
                response=update_command_results(
                    command_name=command_name,
                    updated_command_response=updated_command_response,
                    command_results=command_results,
                ),
                continue_to_poll=False,
            )

    if sample_state == "FAILED":
        clear_integration_context()
        # In case the job not succeeded raise the error
        raise DemistoException(
            f"Executing {args['job_id']} for Harmony Endpoint failed. Error: {command_results.raw_response}"
        )

    return PollResult(
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=args,
    )


def update_command_results(
    command_name: str,
    updated_command_response: dict | list,
    command_results: CommandResults,
) -> CommandResults:
    """Update the command results for schedule commands.

    Args:
        command_name (str): The command name.
        updated_command_response (dict | list): The updated command response.
        command_results (CommandResults): The exist command results.

    Returns:
        CommandResults: The updated command results.
    """
    command_results.raw_response = updated_command_response
    command_results.outputs = updated_command_response
    command_results.outputs_key_field = "job_id"
    command_results.outputs_prefix = (
        f"HarmonyEP.{SCHEDULED_COMMANDS_MAPPER[command_name].outputs_prefix}"
    )

    return command_results


def get_readable_output(
    command_name: str,
    updated_command_data: list | dict[str, Any] | None,
    args: dict[str, Any],
) -> Any:
    """Get readable output for schedule command.

    Args:
        command_name (str): The command name.
        updated_command_data (list | dict[str, Any]): The updated command data.
        args (dict[str, Any]): Command arguments.

    Returns:
        Any: tableToMarkdown object.
    """
    _, page_size, pagination_message = get_pagination_args(args)
    if page_size:
        SCHEDULED_COMMANDS_MAPPER[command_name].message += f"\n\n{pagination_message}"

    return tableToMarkdown(
        name=SCHEDULED_COMMANDS_MAPPER[command_name].message,
        t=remove_empty_elements(updated_command_data),
        headers=SCHEDULED_COMMANDS_MAPPER[command_name].headers,
        headerTransform=string_to_table_header,
        removeNull=True,
    )


def prepare_command_output_and_readable_output(
    command_data: dict[str, Any],
    command_name: str,
    job_id: str,
) -> tuple[dict | list | None, dict | list]:
    """Prepare the command output and readable output according the API response type.

    Args:
        command_data (dict[str, Any]): The command data.
        command_name (str): The command name.
        job_id (str): The job ID.

    Returns:
        tuple: The command output and readable output for the command results.
    """
    SCHEDULED_COMMANDS_MAPPER[command_name].message += f"\nJob ID: {job_id}"

    # check if API response is empty
    if not command_data:
        return None, {"job_id": job_id}

    # check if API return computers data
    if computer_list := dict_safe_get(command_data, ["computers"]):
        return prepare_computer_list_output_and_readable_output(
            computers_data=computer_list,
            job_id=job_id,
        )

    # check if API return data is push operation list
    if SCHEDULED_COMMANDS_MAPPER[command_name].headers == DEFAULT_HEADERS:
        return prepare_push_operation_output_and_readable_output(
            command_data=dict_safe_get(
                dict_object=command_data,
                keys=["data"],
                default_return_value=command_data,
            ),
            job_id=job_id,
        )

    if isinstance(command_data, list):
        for data in command_data:
            data["job_id"] = job_id

    else:
        command_data["job_id"] = job_id

    return command_data, command_data


def prepare_computer_list_output_and_readable_output(
    computers_data: list[dict[str, Any]], job_id: str
) -> tuple[list, dict[str, Any]]:
    """Prepare the computer list command output and readable output.

    Args:
        computers_data (list[dict[str, Any]]): The computer list data.
        job_id (str): The job ID.

    Returns:
        tuple[list, dict[str, Any]]: The command output and readable output.
    """
    updated_response = []
    for computer in computers_data:
        updated_response.append(
            {
                "id": computer.get("computerId"),
                "name": computer.get("computerName"),
                "ip": computer.get("computerIP"),
                "type": computer.get("computerType"),
                "deployment_status": computer.get("computerDeploymentStatus"),
                "client_version": computer.get("computerClientVersion"),
                "groups": computer.get("computerGroups"),
                "user_name": computer.get("computerUserName"),
                "domain_name": computer.get("domainName"),
                "isolation_status": computer.get("isolationStatus"),
                "last_logged_in_user": computer.get("computerLastLoggedInUser"),
                "os_name": computer.get("osName"),
                "os_version": computer.get("osVersion"),
            }
        )
    return updated_response, {"job_id": job_id, "Computer": updated_response}


def prepare_push_operation_output_and_readable_output(
    command_data: list[dict[str, Any]],
    job_id: str,
) -> Tuple[list | dict[str, Any], list | dict[str, Any]]:
    """Update the API response data for the readable output in case the API response is push operation data.

    Args:
        command_name (str): The commands name.
        command_data (dict[str, Any]): The API response.
        job_id (str): The job ID.

    Returns:
        Tuple[list | dict[str, Any], list | dict[str, Any]]: The updated command data.
    """
    updated_command_readable_output = []

    for data in command_data:
        updated_command_readable_output.append(
            {
                "machine_id": dict_safe_get(data, ["machine", "id"]),
                "machine_name": dict_safe_get(data, ["machine", "name"]),
                "operation_status": dict_safe_get(data, ["operation", "status"]),
                "operation_response_status": dict_safe_get(
                    data, ["operation", "response", "status"]
                ),
                "operation_response_output": dict_safe_get(
                    data, ["operation", "response", "output"]
                ),
            }
        )
        data["operation"] |= {
            "id": dict_safe_get(get_integration_context(), ["remediation_operation_id"])
        }
        data["job_id"] = job_id

    return updated_command_readable_output, command_data


def validate_pagination_arguments(
    page: int | None | None = None,
    page_size: int | None | None = None,
    limit: int | None | None = None,
):
    """Validate pagination arguments according to their default.

    Args:
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of items per page.
        limit (int, optional): The maximum number of records to retrieve.

    Raises:
        ValueError: Appropriate error message.
    """
    if page_size and (page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE):
        raise ValueError(
            f"page_size argument must be greater than {MIN_PAGE_SIZE} and smaller than {MAX_PAGE_SIZE}."
        )
    if page and page < MIN_PAGE_NUM:
        raise ValueError(f"page argument must be greater than {MIN_PAGE_NUM - 1}.")
    if limit and limit <= MIN_LIMIT:
        raise ValueError(f"limit argument must be greater than {MIN_LIMIT}.")


def get_pagination_args(args: dict[str, Any]) -> tuple:
    """Return the correct limit and offset for the API
        based on the user arguments page, page_size and limit.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        Tuple: new_limit, offset, pagination_message.
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))

    validate_pagination_arguments(page, page_size, limit)

    new_page = 0
    new_page_size = limit

    if page and page_size:
        new_page_size = page_size
        new_page = page - 1

    pagination_message = (
        f"Showing page {new_page+1}.\nCurrent page size: {new_page_size}."
    )

    return new_page, new_page_size, pagination_message


def validate_filter_arguments(column_name: str | None = None, filter_type: str = None):
    """Validate filter arguments values are allowed.

    Args:
        column_name (str, optional): The column name to filter by. Defaults to None.
        filter_type (str, optional): The filter operator. Defaults to None.

    Raises:
        ValueError: Raise error in case column_name or filter_type values are not allowed.
    """
    if column_name and column_name not in COLUMN_NAMES:
        raise ValueError(
            f"'column_name' must be one of the followings: {COLUMN_NAMES}."
        )

    if filter_type and filter_type not in FILTER_TYPES:
        raise ValueError(
            f"'filter_type' must be one of the followings: {FILTER_TYPES}."
        )


def extract_query_filter(args: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract query filters from the specified arguments.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        list[dict[str, Any]]: The updated query filter according to Harmony requirements.
    """
    query_filter = []

    if filter_by_query := args.get("filter"):
        queries = argToList(filter_by_query, "' , ")

        for query in queries:
            query_parts = query.split(" ")

            if len(query_parts) != 3:
                raise ValueError(
                    "'filter' must be in the following format: 'column_name filter_type filter_value'."
                )

            column_name = query_parts[0]
            filter_type = query_parts[1]
            filter_values = query_parts[2].replace("'", "")

            validate_filter_arguments(column_name, filter_type)

            query_filter.append(
                {
                    "columnName": column_name,
                    "filterValues": argToList(filter_values),
                    "filterType": filter_type,
                }
            )
    for key, value in args.items():
        if key in COLUMN_NAMES_MAPPER:
            query_filter.append(
                {
                    "columnName": COLUMN_NAMES_MAPPER[key],
                    "filterValues": argToList(value),
                    "filterType": DEFAULT_FILTER_TYPE,
                }
            )

    if computer_last_connection := args.get("computer_last_connection"):
        computer_last_connection_times = argToList(computer_last_connection)

        if len(computer_last_connection_times) != 2:
            raise ValueError(
                "'computer_last_connection' must be in the following format: 'YYYY-MM-DD HH:MM, YYYY-MM-DD HH:MM'."
            )

        query_filter += [
            {
                "columnName": "computerLastConnection",
                "filterValues": computer_last_connection_times[0],
                "filterType": "Grater",
            },
            {
                "columnName": "computerLastConnection",
                "filterValues": computer_last_connection_times[1],
                "filterType": "Smaller",
            },
        ]

    if not query_filter:
        raise DemistoException(
            """At least one of the following query arguments are required: computer_ids, computer_names, computer_ips,
            computer_group_names, computer_types, computer_deployment_status, computer_last_connection, or filter."""
        )

    return query_filter


def build_request_body(args: dict[str, Any]) -> dict[str, Any]:
    """Build a query for Harmony API.

    Args:
        args (dict[str, Any]): Command arguments from XSOAR.

    Returns:
        dict[str, Any]: The query for Harmony API.
    """

    new_page, new_page_size, _ = get_pagination_args(args)

    computers_to_include = []
    if computers_ids_to_include := args.get("computers_ids_to_include"):
        for computer_id in argToList(computers_ids_to_include):
            computers_to_include.append({"id": computer_id})

    return remove_empty_elements(
        {
            "comment": args.get("comment"),
            "timing": {
                "expirationSeconds": args.get("expiration_seconds"),
                "schedulingDateTime": args.get("scheduling_date_time"),
            },
            "targets": {
                "query": {
                    "filter": extract_query_filter(args),
                    "paging": {"pageSize": new_page_size, "offset": new_page},
                },
                "exclude": {
                    "groupsIds": argToList(args.get("groups_ids_to_exclude")),
                    "computerIds": argToList(args.get("computers_ids_to_exclude")),
                },
                "include": {"computers": computers_to_include},
            },
            "operationParameters": {
                "informUser": arg_to_bool(args.get("inform_user")),
                "allowPostpone": arg_to_bool(args.get("allow_postpone")),
            },
        }
    )


def arg_to_bool(arg: str = None) -> bool | None:
    """Convert string to boolean if value is not none.

    Args:
        arg (str, optional): The argument value. Defaults to None.

    Returns:
        bool | None: The converted value or none.
    """
    return argToBoolean(arg) if arg else None


def clear_integration_context() -> None:
    """Reset integration context."""
    set_integration_context({"job_id": None, "remediation_operation_id": None})


def convert_unix_to_date_string(unix_timestamp: int) -> str:
    """Convert unix timestamp to date string.

    Args:
        unix_timestamp (int): unix.

    Returns:
        str: Datetime string.
    """
    timestamp_in_seconds = unix_timestamp / 1000
    date_time = datetime.fromtimestamp(timestamp_in_seconds, tz=timezone.utc)
    return date_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def main() -> None:

    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    base_url = params.get("base_url", "")
    client_id = dict_safe_get(params, ["credentials", "identifier"])
    secret_key = dict_safe_get(params, ["credentials", "password"])

    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:

        client: Client = Client(
            base_url=base_url,
            client_id=client_id,
            client_secret=secret_key,
            verify_certificate=verify_certificate,
            proxy=proxy,
        )
        client.get_token()
        client.login()

        commands = {
            "harmony-ep-job-status-get": job_status_get_command,
            "harmony-ep-ioc-list": ioc_list_command,
            "harmony-ep-ioc-update": ioc_update_command,
            "harmony-ep-ioc-create": ioc_create_command,
            "harmony-ep-ioc-delete": ioc_delete_command,
            "harmony-ep-policy-rule-assignments-get": rule_assignments_get_command,
            "harmony-ep-policy-rule-assignments-add": rule_assignments_add_command,
            "harmony-ep-policy-rule-assignments-remove": rule_assignments_remove_command,
            "harmony-ep-policy-rule-install": rule_policy_install_command,
            "harmony-ep-policy-rule-modifications-get": rule_modifications_get_command,
            "harmony-ep-policy-rule-metadata-list": rule_metadata_list_command,
            "harmony-ep-push-operation-status-list": push_operation_status_list_command,
            "harmony-ep-push-operation-get": push_operation_get_command,
            "harmony-ep-push-operation-abort": push_operation_abort_command,
            "harmony-ep-anti-malware-scan": anti_malware_scan_command,
            "harmony-ep-anti-malware-update": anti_malware_update_command,
            "harmony-ep-anti-malware-restore": anti_malware_restore_command,
            "harmony-ep-forensics-indicator-analyze": indicator_analyze_command,
            "harmony-ep-forensics-file-quarantine": file_quarantine_command,
            "harmony-ep-forensics-file-restore": file_restore_command,
            "harmony-ep-remediation-computer-isolate": remediation_computer_isolate_command,
            "harmony-ep-remediation-computer-deisolate": remediation_computer_deisolate_command,
            "harmony-ep-computer-list": computer_list_command,
            "harmony-ep-agent-computer-restart": computer_restart_command,
            "harmony-ep-agent-computer-shutdown": computer_shutdown_command,
            "harmony-ep-agent-computer-repair": computer_repair_command,
            "harmony-ep-agent-process-information-get": process_information_get_command,
            "harmony-ep-agent-process-terminate": process_terminate_command,
            "harmony-ep-agent-registry-key-add": agent_registry_key_add_command,
            "harmony-ep-agent-registry-key-delete": agent_registry_key_delete_command,
            "harmony-ep-agent-file-copy": agent_file_copy_command,
            "harmony-ep-agent-file-move": agent_file_move_command,
            "harmony-ep-agent-file-delete": agent_file_delete_command,
            "harmony-ep-agent-vpn-site-add": agent_vpn_site_add_command,
            "harmony-ep-agent-vpn-site-remove": agent_vpn_site_remove_command,
        }

        if command == "test-module":
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](args, client))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        clear_integration_context()
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
