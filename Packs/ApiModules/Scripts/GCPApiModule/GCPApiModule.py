import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from COOCApiModule import *  # noqa: E402

import urllib.parse
from enum import Enum

import httplib2
from google.oauth2 import service_account as google_service_account
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError

# Placeholder resource used by the Cloud Functions connectivity probe. That API exposes
# testIamPermissions only at function scope, and returns an empty permission set (rather than
# NOT_FOUND) for a resource that does not exist, so no real function has to be present.
# A concrete location is used rather than the "-" wildcard, which is only accepted by list methods.
CLOUD_FUNCTIONS_PROBE_LOCATION = "us-central1"
CLOUD_FUNCTIONS_PROBE_FUNCTION = "connectivity-probe"

# Existing (mapped) polling commands are decorated with @polling_function and therefore take (args, creds)
# instead of (creds, args). Registered commands declare polling via @GCPIntegration.register(..., polling=True).
POLLING_COMMANDS = {
    "gcp-compute-zone-operation-wait",
    "gcp-compute-region-operation-wait",
    "gcp-compute-global-operation-wait",
}

# Command prefixes (the second word of gcp-<prefix>-...) that do not match a GCPServices member name.
SERVICE_PREFIX_MAP: dict[str, str] = {
    "gke": "CONTAINER",
    "resource": "RESOURCE_MANAGER",
    "iam": "RESOURCE_MANAGER",
    "bq": "BIGQUERY",
    "cloudrun": "CLOUD_FUNCTIONS",
    # gcp-cloudfunctions-function-execute: functions().call is only exposed by the v1 Cloud Functions API.
    "cloudfunctions": "CLOUD_FUNCTIONS_V1",
}


class GCPServices(Enum):
    """
    Enumeration of Google Cloud Platform services with API details.

    Each service contains:
    - API name: The service name used in Google API client
    - Version: The API version to use
    - API endpoint: The full endpoint URL for service enablement checks

    Example:
        compute = integration.get_service_client(credentials, GCPServices.COMPUTE)
    """

    COMPUTE = ("compute", "v1", "compute.googleapis.com")
    STORAGE = ("storage", "v1", "storage.googleapis.com")
    CONTAINER = ("container", "v1", "container.googleapis.com")
    RESOURCE_MANAGER = ("cloudresourcemanager", "v3", "cloudresourcemanager.googleapis.com")
    BIGQUERY = ("bigquery", "v2", "bigquery.googleapis.com")
    CLOUD_FUNCTIONS = ("cloudfunctions", "v2", "cloudfunctions.googleapis.com")
    # The synchronous invocation method (functions().call) is only exposed by the v1 Cloud Functions
    # API, so a dedicated v1 service is used for the execute command.
    CLOUD_FUNCTIONS_V1 = ("cloudfunctions", "v1", "cloudfunctions.googleapis.com")
    KMS = ("cloudkms", "v1", "cloudkms.googleapis.com")
    LOGGING = ("logging", "v2", "logging.googleapis.com")

    # The following services are currently unsupported:
    # IAM_V1 = ("iam", "v1", "iam.googleapis.com")
    # IAM_V2 = ("iam", "v2", "iam.googleapis.com")
    # CLOUD_IDENTITY = ("cloudidentity", "v1", "cloudidentity.googleapis.com")

    def __init__(self, api_name: str, version: str, api_endpoint: str):
        """
        Initialize GCP service configuration.

        Args:
            api_name (str): The Google API service name (e.g., 'compute').
            version (str): The API version (e.g., 'v1').
            api_endpoint (str): The full API endpoint for enablement checks (e.g., 'compute.googleapis.com').
        """
        self._api_name = api_name
        self._version = version
        self._api_endpoint = api_endpoint

    @property
    def api_name(self) -> str:
        """Get the Google API service name."""
        return self._api_name

    @property
    def version(self) -> str:
        """Get the API version."""
        return self._version

    @property
    def api_endpoint(self) -> str:
        """Get the full API endpoint for service enablement checks."""
        return self._api_endpoint

    def build(self, credentials) -> Resource:
        """Build a Google API client for this service.

        Used by existing handlers, which take ``(creds, args)`` and build their own client. New commands
        should register with ``@GCPIntegration.register`` and receive the client from ``get_client()``.
        """
        return GCPIntegration.build_service_client(
            self, credentials, is_platform_path=bool(get_connector_id()), params=demisto.params()
        )


# Command requirements mapping: (GCP_Service_Enum, [Required_Permissions])
COMMAND_REQUIREMENTS: dict[str, tuple[GCPServices, list[str]]] = {
    "gcp-compute-firewall-patch": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.update",
            "compute.firewalls.get",
            "compute.firewalls.list",
            "compute.networks.updatePolicy",
            "compute.networks.list",
        ],
    ),
    "gcp-compute-firewall-insert": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.create",
        ],
    ),
    "gcp-compute-firewall-list": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.list",
        ],
    ),
    "gcp-compute-firewalls-list": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.list",
        ],
    ),
    "gcp-compute-firewall-get": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.get",
        ],
    ),
    "gcp-compute-firewall-delete": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.delete",
        ],
    ),
    "gcp-compute-address-get": (GCPServices.COMPUTE, ["compute.addresses.get"]),
    "gcp-compute-address-list": (GCPServices.COMPUTE, ["compute.addresses.list"]),
    "gcp-compute-address-aggregated-list": (GCPServices.COMPUTE, ["compute.addresses.list"]),
    "gcp-compute-address-insert": (GCPServices.COMPUTE, ["compute.addresses.create"]),
    "gcp-compute-address-delete": (GCPServices.COMPUTE, ["compute.addresses.delete"]),
    "gcp-compute-global-address-get": (GCPServices.COMPUTE, ["compute.globalAddresses.get"]),
    "gcp-compute-global-address-list": (GCPServices.COMPUTE, ["compute.globalAddresses.list"]),
    "gcp-compute-global-address-insert": (GCPServices.COMPUTE, ["compute.globalAddresses.create"]),
    "gcp-compute-global-address-delete": (GCPServices.COMPUTE, ["compute.globalAddresses.delete"]),
    "gcp-compute-snapshots-list": (
        GCPServices.COMPUTE,
        [
            "compute.snapshots.list",
        ],
    ),
    "gcp-compute-snapshot-get": (
        GCPServices.COMPUTE,
        [
            "compute.snapshots.get",
        ],
    ),
    "gcp-compute-snapshot-delete": (
        GCPServices.COMPUTE,
        [
            "compute.snapshots.delete",
        ],
    ),
    "gcp-compute-snapshot-labels-set": (
        GCPServices.COMPUTE,
        [
            "compute.snapshots.setLabels",
            "compute.snapshots.get",
        ],
    ),
    "gcp-compute-instances-aggregated-list-by-ip": (
        GCPServices.COMPUTE,
        [
            "cloudasset.assets.searchAllResources",
        ],
    ),
    "gcp-compute-network-tag-set": (
        GCPServices.COMPUTE,
        [
            "compute.instances.setTags",
        ],
    ),
    "gcp-compute-subnet-update": (
        GCPServices.COMPUTE,
        [
            "compute.subnetworks.setPrivateIpGoogleAccess",
            "compute.subnetworks.update",
            "compute.subnetworks.get",
            "compute.subnetworks.list",
        ],
    ),
    "gcp-compute-instance-service-account-set": (
        GCPServices.COMPUTE,
        ["compute.instances.setServiceAccount", "compute.instances.get"],
    ),
    "gcp-compute-instance-service-account-remove": (
        GCPServices.COMPUTE,
        ["compute.instances.setServiceAccount", "compute.instances.get"],
    ),
    "gcp-compute-disks-list": (GCPServices.COMPUTE, ["compute.disks.list"]),
    "gcp-compute-disks-aggregated-list": (GCPServices.COMPUTE, ["compute.disks.list"]),
    "gcp-compute-disk-get": (GCPServices.COMPUTE, ["compute.disks.get"]),
    "gcp-compute-disk-insert": (GCPServices.COMPUTE, ["compute.disks.create"]),
    "gcp-compute-disk-delete": (GCPServices.COMPUTE, ["compute.disks.delete"]),
    "gcp-compute-disk-resize": (GCPServices.COMPUTE, ["compute.disks.resize"]),
    "gcp-compute-disk-labels-set": (GCPServices.COMPUTE, ["compute.disks.setLabels"]),
    "gcp-compute-disk-snapshot-create": (GCPServices.COMPUTE, ["compute.disks.createSnapshot", "compute.snapshots.create"]),
    "gcp-compute-disk-types-list": (GCPServices.COMPUTE, ["compute.diskTypes.list"]),
    "gcp-compute-disk-types-aggregated-list": (GCPServices.COMPUTE, ["compute.diskTypes.list"]),
    "gcp-compute-disk-type-get": (GCPServices.COMPUTE, ["compute.diskTypes.get"]),
    "gcp-compute-instance-start": (GCPServices.COMPUTE, ["compute.instances.start"]),
    "gcp-compute-instance-stop": (GCPServices.COMPUTE, ["compute.instances.stop"]),
    "gcp-compute-instance-insert": (GCPServices.COMPUTE, ["compute.instances.create"]),
    "gcp-compute-instance-delete": (GCPServices.COMPUTE, ["compute.instances.delete"]),
    "gcp-compute-instance-reset": (GCPServices.COMPUTE, ["compute.instances.reset"]),
    "gcp-compute-instance-metadata-set": (GCPServices.COMPUTE, ["compute.instances.setMetadata"]),
    "gcp-compute-instance-machine-type-set": (GCPServices.COMPUTE, ["compute.instances.setMachineType"]),
    "gcp-compute-instances-aggregated-list": (GCPServices.COMPUTE, ["compute.instances.list"]),
    "gcp-compute-instances-list": (GCPServices.COMPUTE, ["compute.instances.list"]),
    "gcp-compute-instance-get": (GCPServices.COMPUTE, ["compute.instances.get"]),
    "gcp-compute-instance-labels-set": (GCPServices.COMPUTE, ["compute.instances.setLabels"]),
    "gcp-storage-bucket-policy-delete": (GCPServices.STORAGE, ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"]),
    "gcp-storage-bucket-metadata-update": (GCPServices.STORAGE, ["storage.buckets.update"]),
    "gcp-storage-bucket-list": (
        GCPServices.STORAGE,
        ["storage.buckets.list"],
    ),
    "gcp-storage-buckets-list": (
        GCPServices.STORAGE,
        ["storage.buckets.list"],
    ),
    "gcp-storage-bucket-get": (
        GCPServices.STORAGE,
        ["storage.buckets.get"],
    ),
    "gcp-storage-bucket-objects-list": (
        GCPServices.STORAGE,
        ["storage.objects.list"],
    ),
    "gcp-storage-bucket-policy-list": (
        GCPServices.STORAGE,
        ["storage.buckets.getIamPolicy", "storage.buckets.get"],
    ),
    "gcp-storage-bucket-policies-list": (
        GCPServices.STORAGE,
        ["storage.buckets.getIamPolicy", "storage.buckets.get"],
    ),
    "gcp-storage-bucket-policy-set": (
        GCPServices.STORAGE,
        ["storage.buckets.setIamPolicy"],
    ),
    "gcp-storage-bucket-object-policy-list": (
        GCPServices.STORAGE,
        ["storage.objects.getIamPolicy"],
    ),
    "gcp-storage-bucket-object-policies-list": (
        GCPServices.STORAGE,
        ["storage.objects.getIamPolicy"],
    ),
    "gcp-storage-bucket-object-policy-set": (
        GCPServices.STORAGE,
        ["storage.objects.setIamPolicy"],
    ),
    "gcp-storage-bucket-create": (
        GCPServices.STORAGE,
        ["storage.buckets.create"],
    ),
    "gcp-storage-bucket-delete": (
        GCPServices.STORAGE,
        ["storage.buckets.delete", "storage.objects.list", "storage.objects.delete"],
    ),
    "gcp-storage-bucket-public-access-block": (
        GCPServices.STORAGE,
        ["storage.buckets.update", "storage.buckets.setIamPolicy"],
    ),
    "gcp-storage-bucket-object-upload": (
        GCPServices.STORAGE,
        ["storage.objects.create"],
    ),
    "gcp-storage-bucket-object-download": (
        GCPServices.STORAGE,
        ["storage.objects.get"],
    ),
    "gcp-storage-bucket-object-copy": (
        GCPServices.STORAGE,
        ["storage.objects.get", "storage.objects.create"],
    ),
    "gcp-storage-bucket-object-delete": (
        GCPServices.STORAGE,
        ["storage.objects.delete"],
    ),
    "gcp-storage-bucket-object-policy-delete": (
        GCPServices.STORAGE,
        ["storage.objects.get", "storage.objects.update"],
    ),
    "gcp-compute-zone-operation-wait": (GCPServices.COMPUTE, ["compute.zoneOperations.get"]),
    "gcp-compute-region-operation-wait": (GCPServices.COMPUTE, ["compute.regionOperations.get"]),
    "gcp-compute-global-operation-wait": (GCPServices.COMPUTE, ["compute.globalOperations.get"]),
    "gcp-compute-network-get": (GCPServices.COMPUTE, ["compute.networks.get"]),
    "gcp-compute-image-get": (GCPServices.COMPUTE, ["compute.images.get"]),
    "gcp-compute-image-get-from-family": (GCPServices.COMPUTE, ["compute.images.get"]),
    "gcp-compute-images-list": (GCPServices.COMPUTE, ["compute.images.list"]),
    "gcp-compute-image-delete": (GCPServices.COMPUTE, ["compute.images.delete"]),
    "gcp-compute-image-labels-set": (GCPServices.COMPUTE, ["compute.images.setLabels"]),
    "gcp-compute-image-insert": (GCPServices.COMPUTE, ["compute.images.create"]),
    "gcp-compute-instance-group-get": (GCPServices.COMPUTE, ["compute.instanceGroups.get"]),
    "gcp-compute-instance-groups-list": (GCPServices.COMPUTE, ["compute.instanceGroups.list"]),
    "gcp-compute-instance-groups-aggregated-list": (GCPServices.COMPUTE, ["compute.instanceGroups.list"]),
    "gcp-compute-instance-group-instances-list": (GCPServices.COMPUTE, ["compute.instanceGroups.list"]),
    "gcp-compute-instance-group-insert": (GCPServices.COMPUTE, ["compute.instanceGroups.create"]),
    "gcp-compute-instance-group-delete": (GCPServices.COMPUTE, ["compute.instanceGroups.delete"]),
    "gcp-compute-instance-group-instances-add": (GCPServices.COMPUTE, ["compute.instanceGroups.update"]),
    "gcp-compute-instance-group-instances-remove": (GCPServices.COMPUTE, ["compute.instanceGroups.update"]),
    "gcp-compute-instance-group-named-ports-set": (GCPServices.COMPUTE, ["compute.instanceGroups.update"]),
    "gcp-compute-region-get": (GCPServices.COMPUTE, ["compute.regions.get"]),
    "gcp-compute-regions-list": (GCPServices.COMPUTE, ["compute.regions.list"]),
    "gcp-compute-zone-get": (GCPServices.COMPUTE, ["compute.zones.get"]),
    "gcp-compute-zones-list": (GCPServices.COMPUTE, ["compute.zones.list"]),
    "gcp-compute-networks-list": (GCPServices.COMPUTE, ["compute.networks.list"]),
    "gcp-compute-network-insert": (GCPServices.COMPUTE, ["compute.networks.create"]),
    "gcp-compute-network-peering-add": (GCPServices.COMPUTE, ["compute.networks.addPeering"]),
    "gcp-compute-network-delete": (GCPServices.COMPUTE, ["compute.networks.delete"]),
    "gcp-compute-network-peering-remove": (GCPServices.COMPUTE, ["compute.networks.removePeering"]),
    "gcp-compute-machine-type-get": (GCPServices.COMPUTE, ["compute.machineTypes.get"]),
    "gcp-compute-machine-types-list": (GCPServices.COMPUTE, ["compute.machineTypes.list"]),
    "gcp-compute-machine-types-aggregated-list": (GCPServices.COMPUTE, ["compute.machineTypes.list"]),
    "gcp-compute-global-operation-get": (GCPServices.COMPUTE, ["compute.globalOperations.get"]),
    "gcp-compute-zone-operation-get": (GCPServices.COMPUTE, ["compute.zoneOperations.get"]),
    "gcp-compute-region-operation-get": (GCPServices.COMPUTE, ["compute.regionOperations.get"]),
    "gcp-compute-global-operation-list": (GCPServices.COMPUTE, ["compute.globalOperations.list"]),
    "gcp-compute-zone-operation-list": (GCPServices.COMPUTE, ["compute.zoneOperations.list"]),
    "gcp-compute-region-operation-list": (GCPServices.COMPUTE, ["compute.regionOperations.list"]),
    "gcp-compute-global-operation-delete": (GCPServices.COMPUTE, ["compute.globalOperations.delete"]),
    "gcp-compute-zone-operation-delete": (GCPServices.COMPUTE, ["compute.zoneOperations.delete"]),
    "gcp-compute-region-operation-delete": (GCPServices.COMPUTE, ["compute.regionOperations.delete"]),
    "gcp-container-cluster-security-update": (
        GCPServices.CONTAINER,
        [
            "container.clusters.update",
            "container.clusters.get",
            "container.clusters.list",
        ],
    ),
    "gcp-gke-cluster-legacy-abac-auth-set": (GCPServices.CONTAINER, ["container.clusters.update"]),
    "gcp-gke-clusters-list": (GCPServices.CONTAINER, ["container.clusters.list"]),
    "gcp-gke-cluster-get": (GCPServices.CONTAINER, ["container.clusters.get"]),
    "gcp-gke-node-pools-list": (GCPServices.CONTAINER, ["container.clusters.get"]),
    "gcp-gke-node-pool-get": (GCPServices.CONTAINER, ["container.clusters.get"]),
    "gcp-gke-node-pool-management-set": (GCPServices.CONTAINER, ["container.clusters.update"]),
    "gcp-gke-operations-list": (GCPServices.CONTAINER, ["container.operations.list"]),
    "gcp-gke-operation-get": (GCPServices.CONTAINER, ["container.operations.get"]),
    "gcp-gke-operation-cancel": (GCPServices.CONTAINER, ["container.operations.update"]),
    "gcp-gke-cluster-security-update": (
        GCPServices.CONTAINER,
        ["container.clusters.update", "container.clusters.get", "container.clusters.list"],
    ),
    "gcp-bq-dataset-policy-remove": (
        GCPServices.BIGQUERY,
        ["bigquery.datasets.update", "bigquery.datasets.get", "bigquery.datasets.getIamPolicy", "bigquery.datasets.setIamPolicy"],
    ),
    "gcp-iam-project-policy-binding-remove": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"],
    ),
    "gcp-resource-manager-project-create": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.create"],
    ),
    "gcp-resource-manager-project-get": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.get"],
    ),
    "gcp-resource-manager-project-search": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.get"],
    ),
    "gcp-resource-manager-project-update": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.update"],
    ),
    "gcp-resource-manager-project-delete": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.delete"],
    ),
    "gcp-resource-manager-project-undelete": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.undelete"],
    ),
    "gcp-resource-manager-organization-search": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.organizations.get"],
    ),
    "gcp-resource-manager-organization-get": (GCPServices.RESOURCE_MANAGER, ["resourcemanager.organizations.get"]),
    # Cloud Run functions commands
    "gcp-cloudrun-functions-list": (
        GCPServices.CLOUD_FUNCTIONS,
        ["cloudfunctions.functions.list"],
    ),
    "gcp-cloudrun-locations-list": (
        GCPServices.CLOUD_FUNCTIONS,
        ["cloudfunctions.locations.list"],
    ),
    "gcp-cloudrun-function-get": (
        GCPServices.CLOUD_FUNCTIONS,
        ["cloudfunctions.functions.get"],
    ),
    "gcp-cloudfunctions-function-execute": (
        GCPServices.CLOUD_FUNCTIONS_V1,
        ["cloudfunctions.functions.call"],
    ),
    # KMS commands
    "gcp-kms-key-rings-list": (GCPServices.KMS, ["cloudkms.keyRings.list"]),
    "gcp-kms-keys-list": (GCPServices.KMS, ["cloudkms.cryptoKeys.list"]),
    "gcp-kms-keys-list-all": (GCPServices.KMS, ["cloudkms.keyRings.list", "cloudkms.cryptoKeys.list"]),
    "gcp-kms-key-get": (GCPServices.KMS, ["cloudkms.cryptoKeys.get"]),
    "gcp-kms-key-create": (GCPServices.KMS, ["cloudkms.cryptoKeys.create"]),
    "gcp-kms-key-update": (GCPServices.KMS, ["cloudkms.cryptoKeys.update"]),
    "gcp-kms-key-version-enable": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.update", "cloudkms.cryptoKeys.get"]),
    "gcp-kms-key-version-disable": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.update", "cloudkms.cryptoKeys.get"]),
    "gcp-kms-key-version-destroy": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.destroy", "cloudkms.cryptoKeys.get"]),
    "gcp-kms-key-version-restore": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.restore", "cloudkms.cryptoKeys.get"]),
    "gcp-kms-public-key-get": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.viewPublicKey"]),
    "gcp-kms-symmetric-encrypt": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.useToEncrypt"]),
    "gcp-kms-symmetric-decrypt": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.useToDecrypt"]),
    "gcp-kms-asymmetric-encrypt": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.viewPublicKey"]),
    "gcp-kms-asymmetric-decrypt": (GCPServices.KMS, ["cloudkms.cryptoKeyVersions.useToDecrypt"]),
    "gcp-logging-log-entries-list": (
        GCPServices.LOGGING,
        ["logging.logEntries.list"],
    ),
    # The following commands are currently unsupported:
    # "gcp-compute-instance-metadata-add": (
    #     GCPServices.COMPUTE,
    #     ["compute.instances.setMetadata", "compute.instances.get", "compute.instances.list", "iam.serviceAccounts.actAs"],
    # ),
    # "gcp-iam-project-deny-policy-create": (
    #     GCPServices.IAM_V2,
    #     ["iam.denypolicies.create"]
    # ),
    # "gcp-iam-service-account-delete": (
    #     GCPServices.IAM_V1,
    #     ["iam.serviceAccounts.delete"]
    # ),
    # "gcp-iam-group-membership-delete": (
    #     GCPServices.CLOUD_IDENTITY,
    #     ["cloudidentity.groups.memberships.delete"]
    # ),
}


MISSING_PROJECT_ID_ERROR = (
    "Missing required parameter 'project_id'. Provide it as a command argument, set the 'GCP Project ID' field "
    "in the integration configuration, or include 'project_id' in the Service Account JSON key."
)


class GCPIntegration(CloudIntegration):
    """COOC GCP implementation of ``CloudIntegration``.

    - **Marketplace path** (Cortex XSOAR / Cortex XSIAM): authenticates with the service account
      JSON key from the ``credentials`` parameter.
    - **Cortex Platform path**: fetches a short-lived access token from CTS for the
      ``identifier`` (global commands) or ``project_id`` (resource commands) argument.

    Like AWS, ``get_client()`` returns the service client for the current command. The service is
    resolved from the command name (see ``_resolve_service``).

    - **Registered commands** (``@GCPIntegration.register``): ``(client, args)``, or ``(args, client)``
      when registered with ``polling=True``.
    - **Existing commands** (``commands_mapping``): ``(creds, args)``, or ``(args, creds)`` for
      ``POLLING_COMMANDS``. They build their own client via ``GCPServices.<SERVICE>.build(creds)``.
    """

    cloud_type = CloudTypes.GCP.value
    account_id_arg = "project_id"

    def __init__(self, command: str, args: dict, params: dict) -> None:
        super().__init__(command, args, params)
        # Global commands provide ``identifier`` (project, folder, or organization ID) instead of
        # ``project_id``. Some commands have both (e.g. gcp-resource-manager-project-create), so
        # ``identifier`` is prioritized as the account used to create the CTS token.
        self.account_id = args.get("identifier") or self.account_id

    def get_client(self) -> Resource:
        """Build the Google API client for the service of the current command.

        Raises:
            DemistoException: If credentials cannot be retrieved or are invalid.
        """
        return self.get_service_client(self._get_google_credentials(), self._resolve_service(self.command))

    def health_check(
        self, credentials: dict, account_id: str, connector_id: str
    ) -> HealthCheckError | list[HealthCheckError] | None:
        """Test connectivity to every GCP service for one project.

        Args:
            credentials: Pre-fetched CTS credentials.
            account_id: The GCP project ID to check against.
            connector_id: The connector ID for the Cloud integration.

        Returns:
            ``None`` if successful, otherwise a ``HealthCheckError`` or a list of them.
        """
        token = credentials.get("access_token")
        if not token:
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message="Failed to authenticate with GCP - token is missing from credentials",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
        google_credentials = Credentials(token=token)
        # Perform sample check on GCP services
        errors_list = []
        for service in GCPServices:
            try:
                api = self.get_service_client(google_credentials, service)
                self._test_service_connectivity(api, service, account_id)
            except Exception as e:
                error_message = str(e)
                if "Permission" not in error_message:
                    errors_list.append(
                        HealthCheckError(
                            account_id=account_id,
                            connector_id=connector_id,
                            message=f"Sample check failed for account {account_id}. Error: {error_message}",
                            error_type=ErrorType.CONNECTIVITY_ERROR,
                        )
                    )
        if errors_list:
            return errors_list
        return None

    def test_module(self) -> str:
        """Test connectivity to GCP by issuing a lightweight, project-scoped probe per service.

        The Resource Manager API is tried first (using its permission-free ``testIamPermissions``
        endpoint). If its API is not enabled on the project (403 SERVICE_DISABLED), the probe falls
        back to the other GCP services in turn, so a single disabled API does not fail the whole
        connectivity test. The test passes as soon as any service responds successfully.

        Returns:
            str: "ok" if the test is successful.

        Raises:
            DemistoException: If credentials are invalid, the API call fails, or every probed
                service has its API disabled.
        """
        credentials = self._get_google_credentials()
        project_id = self._get_configured_project_id()

        services_to_try = [
            GCPServices.RESOURCE_MANAGER,
            GCPServices.COMPUTE,
            GCPServices.STORAGE,
            GCPServices.CONTAINER,
            GCPServices.BIGQUERY,
            GCPServices.CLOUD_FUNCTIONS,
            GCPServices.KMS,
            GCPServices.LOGGING,
        ]

        for service in services_to_try:
            try:
                api = self.get_service_client(credentials, service)
                self._test_service_connectivity(api, service, project_id)
                demisto.debug(f"[GCP test_module] Successfully authenticated against project {project_id} via {service.api_name}")
                return "ok"
            except Exception as e:
                # A disabled-API 403 is not a real failure - skip this service and try the next one.
                if isinstance(e, HttpError) and self._is_service_disabled_error(e):
                    demisto.debug(
                        f"[GCP test_module] {service.api_name} API is disabled on project {project_id}; trying next service."
                    )
                    continue
                demisto.debug(f"[GCP test_module] Test failed on {service.api_name}: {str(e)}")
                raise DemistoException(f"Failed to connect to GCP project '{project_id}': {str(e)}")

        # Every probed service had its API disabled - none could be reached.
        raise DemistoException(
            f"Failed to connect to GCP project '{project_id}': all probed GCP service APIs are disabled. "
            "Enable at least one of the required GCP APIs on the project and try again."
        )

    def handle_error(self, error: Exception) -> None:
        """Route ``HttpError`` to the permission error flow; any other error is handled by the base class."""
        if isinstance(error, HttpError):
            self.handle_permission_error(error, self.account_id or "N/A", self.command)
            return
        super().handle_error(error)

    @staticmethod
    def handle_permission_error(error: HttpError, project_id: str, command_name: str) -> None:
        """Report a GCP permission error, or return the original error for any other ``HttpError``.

        A 401/403 with a JSON body is reported through ``return_multiple_permissions_error`` with one
        entry per permission of ``command_name`` (from ``COMMAND_REQUIREMENTS``) named in the error
        message, or one ``"N/A"`` entry when none is named or the command has no declared permissions.

        Args:
            error: The error raised by the Google API client.
            project_id: The account (project, folder, or organization) to report the error for.
            command_name: The name of the command that failed.
        """
        status_code = error.resp.status
        if int(status_code) in (401, 403) and error.resp.get("content-type", "").startswith("application/json"):
            message_content = json.loads(error.content)
            error_message = message_content.get("error", {}).get("message", "")

            _, command_permissions = COMMAND_REQUIREMENTS.get(command_name, (None, []))
            found_permissions = [perm for perm in command_permissions if perm.lower() in error_message.lower()] or ["N/A"]
            demisto.debug(f"The info {error_message=} {found_permissions=} {message_content=}")

            error_entries = [{"account_id": project_id, "message": error_message, "name": perm} for perm in found_permissions]
            return_multiple_permissions_error(error_entries)
            return

        # Not a 401/403, or no JSON body: return the original error.
        return_error(f"Failed to execute command {command_name}. Error: {str(error)}")

    def execute_mapped_command(self, handler: Callable) -> Any:
        """Call an existing command with Google credentials: ``(args, creds)`` for ``POLLING_COMMANDS``,
        ``(creds, args)`` otherwise."""
        creds = self._get_google_credentials()
        if self.command in POLLING_COMMANDS:
            demisto.debug(f"[GCP] The {self.command=} is a polling command, calling it with args as the first argument.")
            return handler(self.args, creds)
        return handler(creds, self.args)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def get_service_client(self, credentials, service: GCPServices) -> Resource:
        """Build the Google API client for ``service`` using this integration's context."""
        return self.build_service_client(service, credentials, is_platform_path=bool(self.connector_id), params=self.params)

    @staticmethod
    def build_service_client(service: GCPServices, credentials, is_platform_path: bool, params: dict) -> Resource:
        """Build the Google API client for ``service``. Shared by ``get_service_client`` and ``GCPServices.build``.

        - **Marketplace path** (Cortex XSOAR / Cortex XSIAM): requests go through an ``AuthorizedHttp``
          over a custom ``httplib2.Http`` transport, so the *Use system proxy settings* and
          *Trust any certificate (not secure)* parameters are enforced.
        - **Cortex Platform path**: connectivity is handled by the platform, so the Google client's
          standard transport is used.

        Args:
            service: The GCP service to build a client for.
            credentials: Google credentials (service account or CTS access token).
            is_platform_path: ``True`` when running through a Cortex Cloud connector.
            params: The integration parameters (``proxy`` and ``insecure`` are read).
        """
        if is_platform_path:
            return build(service.api_name, service.version, credentials=credentials)
        http = GCPIntegration._build_http_client(
            use_proxy=argToBoolean(params.get("proxy", False)),
            verify_ssl=not argToBoolean(params.get("insecure", False)),
        )
        return build(service.api_name, service.version, http=AuthorizedHttp(credentials, http=http))

    @staticmethod
    def _resolve_service(command: str) -> GCPServices:
        """Resolve the GCP service for ``command``.

        Takes the second word of ``gcp-<service>-...`` and maps it through ``SERVICE_PREFIX_MAP``,
        falling back to the upper-cased word as the ``GCPServices`` member name.
        """
        prefix = command.split("-")[1] if command.count("-") >= 1 else ""
        service_name = SERVICE_PREFIX_MAP.get(prefix, prefix.upper())
        if service_name not in GCPServices.__members__:
            raise DemistoException(f"Could not resolve a GCP service for command '{command}'.")
        return GCPServices[service_name]

    @staticmethod
    def _build_http_client(use_proxy: bool, verify_ssl: bool) -> httplib2.Http:
        """Builds an httplib2.Http honoring the given proxy and SSL settings.

        Args:
            use_proxy (bool): When True, the system proxy (from ``handle_proxy``) is applied.
            verify_ssl (bool): When False, SSL certificate validation is disabled.

        Returns:
            httplib2.Http: A configured HTTP client.
        """
        proxy_info = None
        proxies = handle_proxy()
        if use_proxy:
            https_proxy = proxies.get("https")
            if not https_proxy:
                raise DemistoException("https proxy value is empty. Check the Cortex server configuration.")
            if not https_proxy.startswith(("http://", "https://")):
                https_proxy = "https://" + https_proxy
            parsed_proxy = urllib.parse.urlparse(https_proxy)
            proxy_info = httplib2.ProxyInfo(
                proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
                proxy_host=parsed_proxy.hostname,
                proxy_port=parsed_proxy.port or (443 if https_proxy.startswith("https://") else 80),
                proxy_user=parsed_proxy.username,
                proxy_pass=parsed_proxy.password,
            )

        ca_bundle = os.getenv("REQUESTS_CA_BUNDLE") or os.getenv("SSL_CERT_FILE")
        if verify_ssl and not ca_bundle:
            # No environment-provided bundle: httplib2 falls back to its own bundled CA certs.
            demisto.debug("[GCP] No system CA bundle env var set; httplib2 will use its bundled CA certs.")

        return httplib2.Http(
            proxy_info=proxy_info,
            disable_ssl_certificate_validation=not verify_ssl,
            ca_certs=ca_bundle,
        )

    def _get_google_credentials(self) -> Credentials:
        """Return Google credentials based on the deployment type (service account JSON or CTS token)."""
        password = self._get_service_account_password()
        return self._get_service_account_credentials(password) if password else self._get_cts_credentials()

    def _get_service_account_password(self) -> str:
        """Return the service account JSON key from the ``credentials`` parameter, or ``""`` when not set."""
        return ((self.params.get("credentials") or {}).get("password") or "").strip()

    def _get_configured_project_id(self, service_account_info: Optional[dict] = None) -> str:
        """Return the project ID configured on the integration instance.

        Priority: the 'GCP Project ID' parameter, then the ``project_id`` field of the service account JSON
        (``service_account_info`` when given, otherwise read from the ``credentials`` parameter).

        Raises:
            DemistoException: If neither source has a project ID.
        """
        project_id = (self.params.get("project_id") or "").strip()
        if not project_id:
            if service_account_info is None:
                service_account_info = self._read_service_account_info()
            project_id = str(service_account_info.get("project_id") or "").strip()
        if not project_id:
            raise DemistoException(MISSING_PROJECT_ID_ERROR)
        return project_id

    def _read_service_account_info(self) -> dict:
        """Parse the service account JSON from the ``credentials`` parameter; ``{}`` when it is missing or invalid."""
        password = self._get_service_account_password()
        if not password:
            return {}
        try:
            service_account_info = json.loads(password)
        except json.JSONDecodeError:
            return {}
        return service_account_info if isinstance(service_account_info, dict) else {}

    @staticmethod
    def _is_service_disabled_error(error: HttpError) -> bool:
        """Return whether ``error`` is a 403 SERVICE_DISABLED error from the Google API.

        This is raised when the service's API has not been enabled on the project, so the
        connectivity probe should move on to another service rather than fail the test.
        """
        try:
            if isinstance(error.content, bytes | bytearray):
                content_lower = error.content.decode("utf-8", errors="ignore").lower()
            else:
                content_lower = str(error.content).lower()
        except Exception:
            content_lower = ""
        return error.resp.status == 403 and (
            "service_disabled" in content_lower or "has not been used in project" in content_lower
        )

    @staticmethod
    def _test_service_connectivity(api: Resource, service: GCPServices, project_id: str) -> None:
        """Issues a lightweight, project-scoped API call to verify connectivity to ``service``.

        Resource Manager and Cloud Functions use ``testIamPermissions``, which succeeds for any
        authenticated caller regardless of the roles granted (it returns the subset of granted
        permissions), making it a permission-agnostic probe. The remaining services do not expose
        ``testIamPermissions`` at all, so a minimal ``list`` call is used instead. Each service
        exposes the call on a different resource, so the correct shape is selected per service.

        Args:
            api: The Google API client for ``service``.
            service: The GCP service to probe.
            project_id: The GCP project ID to test against.

        Raises:
            HttpError: If the API call fails (e.g. the service's API is disabled).
            NotImplementedError: If the service does not have a connectivity probe defined here.
        """
        if service == GCPServices.RESOURCE_MANAGER:
            api.projects().testIamPermissions(  # pylint: disable=E1101
                resource=f"projects/{project_id}", body={"permissions": ["resourcemanager.projects.get"]}
            ).execute()
        elif service == GCPServices.COMPUTE:
            # Compute has no project-level testIamPermissions; a minimal firewalls list verifies connectivity.
            api.firewalls().list(project=project_id, maxResults=1).execute()  # pylint: disable=E1101
        elif service == GCPServices.STORAGE:
            # Storage has no project-level testIamPermissions; a minimal bucket list verifies connectivity.
            api.buckets().list(project=project_id, maxResults=1).execute()  # pylint: disable=E1101
        elif service == GCPServices.CONTAINER:
            # Container has no testIamPermissions; a lightweight cluster list verifies connectivity.
            api.projects().locations().clusters().list(  # pylint: disable=E1101
                parent=f"projects/{project_id}/locations/-"
            ).execute()
        elif service == GCPServices.BIGQUERY:
            # BigQuery has no project-level testIamPermissions; a lightweight dataset list verifies connectivity.
            api.datasets().list(projectId=project_id, maxResults=1).execute()  # pylint: disable=E1101
        elif service in (GCPServices.CLOUD_FUNCTIONS, GCPServices.CLOUD_FUNCTIONS_V1):
            # Cloud Functions exposes testIamPermissions only at function scope (the API requires a
            # resource matching projects/*/locations/*/functions/*), so a placeholder function is used.
            # Per the API contract a non-existent resource returns an empty permission set rather than
            # NOT_FOUND, which keeps this probe permission-agnostic like the Resource Manager one.
            api.projects().locations().functions().testIamPermissions(  # pylint: disable=E1101
                resource=(
                    f"projects/{project_id}/locations/{CLOUD_FUNCTIONS_PROBE_LOCATION}"
                    f"/functions/{CLOUD_FUNCTIONS_PROBE_FUNCTION}"
                ),
                body={"permissions": ["cloudfunctions.functions.get"]},
            ).execute()
        elif service == GCPServices.KMS:
            # KMS has no project-level testIamPermissions; a lightweight locations list verifies connectivity.
            api.projects().locations().list(  # pylint: disable=E1101
                name=f"projects/{project_id}", pageSize=1
            ).execute()
        elif service == GCPServices.LOGGING:
            # Logging has no project-level testIamPermissions; a minimal log-entries list verifies connectivity.
            api.entries().list(  # pylint: disable=E1101
                body={"resourceNames": [f"projects/{project_id}"], "pageSize": 1}
            ).execute()
        else:
            raise NotImplementedError(f"No connectivity probe defined for service {service.api_name}")

    def _get_service_account_credentials(self, password: str) -> Credentials:
        """Build credentials from the service account JSON key (marketplace path).

        If ``project_id`` is not already in ``self.args``, it is set from ``_get_configured_project_id``
        (the 'GCP Project ID' parameter, then the service account JSON). ``self.account_id`` is set to it
        only when it is still empty, so an ``identifier`` argument keeps priority.
        """
        try:
            service_account_info = json.loads(password)
        except json.JSONDecodeError:
            raise DemistoException(
                "Invalid Service Account JSON format in the 'credentials' parameter. "
                "Please paste the raw contents of the downloaded JSON key file."
            )
        try:
            creds = google_service_account.Credentials.from_service_account_info(
                service_account_info,
                scopes=["https://www.googleapis.com/auth/cloud-platform"],
            )
        except Exception as e:
            raise DemistoException(f"Failed to build GCP credentials from service account JSON: {str(e)}")

        # Propagate project_id to args using priority: args > params > service account JSON
        if not self.args.get("project_id"):
            self.args["project_id"] = self._get_configured_project_id(service_account_info)
        if not self.account_id:
            self.account_id = self.args["project_id"]

        demisto.debug("[GCP get_client] Using service account credentials (marketplace path)")
        return creds

    def _get_cts_credentials(self) -> Credentials:
        """Fetch a short-lived access token from CTS (Cortex Platform path) via ``get_credentials``.

        ``self.account_id`` is the ``identifier`` (global commands) or ``project_id`` (resource commands).
        """
        if not self.account_id:
            raise DemistoException(
                "Missing required parameter. Provide 'project_id' (resource commands) or 'identifier' "
                "(a project, folder, or organization ID for global commands) to create the CTS token."
            )

        try:
            cts_credentials = self.get_credentials()
        except Exception as e:
            raise DemistoException(f"Failed to authenticate with GCP via CTS: {str(e)}")

        token = cts_credentials.get("access_token")
        if not token:
            raise DemistoException("Failed to retrieve GCP access token - token is missing from CTS credentials")

        demisto.debug(f"[GCP get_client] {self.account_id}: Using CTS token-based credentials (Cortex Platform path)")
        return Credentials(token=token)
