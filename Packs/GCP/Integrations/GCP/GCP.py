from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.oauth2 import service_account as google_service_account
import urllib3
from COOCApiModule import *

urllib3.disable_warnings()


class GCPServices(Enum):
    """
    Enumeration of Google Cloud Platform services with API details.

    Each service contains:
    - API name: The service name used in Google API client
    - Version: The API version to use
    - API endpoint: The full endpoint URL for service enablement checks

    Example:
        compute_service = GCPServices.COMPUTE
        client = compute_service.build(credentials)
        api_endpoint = compute_service.api_endpoint
    """

    COMPUTE = ("compute", "v1", "compute.googleapis.com")
    STORAGE = ("storage", "v1", "storage.googleapis.com")
    CONTAINER = ("container", "v1", "container.googleapis.com")
    RESOURCE_MANAGER = ("cloudresourcemanager", "v3", "cloudresourcemanager.googleapis.com")
    SERVICE_USAGE = ("serviceusage", "v1", "serviceusage.googleapis.com")

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

    def build(self, credentials, **kwargs):
        """
        Build a Google API client for this service.

        Args:
            credentials: Google Cloud credentials object.
            **kwargs: Additional arguments passed to the Google API client builder.

        Returns:
            Google API client instance for this service.
        """
        return build(self.api_name, self.version, credentials=credentials, **kwargs)

    def test_connectivity(self, credentials, project_id: str) -> tuple[bool, str]:
        """
        Test connectivity to GCP services using only the permissions available to this integration.

        Args:
            credentials: Google Cloud credentials object.
            project_id: The GCP project ID to test against.

        Returns:
            tuple[bool, str]: (success, error_message). Success is True if service is accessible,
                             error_message is empty on success.
        """
        try:
            client = self.build(credentials)
            if self == GCPServices.COMPUTE:
                # Use compute.firewalls.list (from firewall-patch command)
                client.firewalls().list(project=project_id, maxResults=1).execute()  # pylint: disable=E1101
            elif self == GCPServices.CONTAINER:
                # Use container.clusters.list (from cluster-security-update command)
                client.projects().locations().clusters().list(parent=f"projects/{project_id}/locations/-").execute()  # pylint: disable=E1101
            elif self == GCPServices.RESOURCE_MANAGER:
                # Use resourcemanager.projects.getIamPolicy (from policy-binding-remove command)
                client.projects().getIamPolicy(resource=f"projects/{project_id}").execute()  # pylint: disable=E1101
            # For other services, just test client building
            return True, ""
        except Exception as e:
            return False, str(e)

    @classmethod
    def test_all_services(cls, credentials, project_id: str) -> list[tuple[str, bool, str]]:
        """
        Test connectivity for all GCP services with real API calls.

        Args:
            credentials: Google Cloud credentials object.
            project_id: The GCP project ID to test against.

        Returns:
            list[tuple[str, bool, str]]: List of (service_name, success, error_message) for each service.
        """
        results = []
        for service in cls:
            success, error = service.test_connectivity(credentials, project_id)
            results.append((service.api_name, success, error))
        return results


# Command requirements mapping: (GCP_Service_Enum, [Required_Permissions])
COMMAND_REQUIREMENTS = {
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
    "gcp-compute-instance-start": (GCPServices.COMPUTE, ["compute.instances.start"]),
    "gcp-compute-instance-stop": (GCPServices.COMPUTE, ["compute.instances.stop"]),
    "gcp-storage-bucket-policy-delete": (GCPServices.STORAGE, ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"]),
    "gcp-storage-bucket-metadata-update": (GCPServices.STORAGE, ["storage.buckets.update"]),
    "gcp-container-cluster-security-update": (
        GCPServices.CONTAINER,
        ["container.clusters.update", "container.clusters.get", "container.clusters.list"],
    ),
    "gcp-iam-project-policy-binding-remove": (
        GCPServices.RESOURCE_MANAGER,
        ["resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"],
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

OPERATION_TABLE = ["id", "kind", "name", "operationType", "progress", "zone", "status"]
# taken from GoogleCloudCompute
FIREWALL_RULE_REGEX = re.compile(r"ipprotocol=([\w\d_:.-]+),ports=([ /\w\d@_,.\*-]+)", flags=re.I)
METADATA_ITEM_REGEX = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)", flags=re.I)


def parse_firewall_rule(rule_str: str) -> list[dict[str, list[str] | str]]:
    """
    Transforms a string of firewall rules into a list of dictionaries.

    Args:
        rule_str (str): A semicolon-separated string of firewall rules,
                        e.g., "ipprotocol=abc,ports=123;ipprotocol=ded,ports=22,443".

    Returns:
        list[dict[str, list[str] | str]]: A list of dictionaries containing 'IPProtocol' and 'ports'.
    """
    rules = []
    for f in rule_str.split(";"):
        match = FIREWALL_RULE_REGEX.match(f)
        if match is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided like so: "
                "ipprotocol=abc,ports=123;ipprotocol=fed,ports=456"
            )
        rules.append({"IPProtocol": match.group(1), "ports": match.group(2).split(",")})
    return rules


def parse_metadata_items(tags_str: str) -> list[dict[str, str]]:
    """
    Transforms a string of metadata items into a list of dictionaries.

    Args:
        tags_str (str): A semicolon-separated string of metadata items,
                        e.g., "key=abc,value=123;key=fed,value=456".

    Returns:
        list[dict[str, str]]: A list of dictionaries containing 'key' and 'value' pairs.
    """
    tags = []
    for f in tags_str.split(";"):
        match = METADATA_ITEM_REGEX.match(f)
        if match is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided like so: key=abc,value=123;key=fed,value=456"
            )
        tags.append({"key": match.group(1), "value": match.group(2)})
    return tags


def extract_zone_name(zone_input: str | None) -> str:
    """
    Extracts the GCP zone name from a full URL or returns it directly if already a zone string.

    Args:
        zone_input (str): The zone string or full GCP zone URL.

    Returns:
        str: The zone name, e.g., "us-central1-b".
        https://www.googleapis.com/compute/v1/projects/test/zones/us-central1-b -> us-central1-b

    Raises:
        DemistoException: If the zone input is empty or invalid.
    """
    if not zone_input or not zone_input.strip():
        raise DemistoException("The zone argument cannot be empty")

    if "/" in zone_input:
        return zone_input.strip().split("/")[-1]
    return zone_input.strip()


##########


def compute_firewall_patch(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Disables a firewall rule in a GCP project.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id' and 'resource_name'.

    Returns:
        CommandResults: Result of the firewall patch operation.
    """
    project_id = args.get("project_id")
    resource_name = args.get("resource_name")
    config = {}

    if description := args.get("description"):
        config["description"] = description
    if network := args.get("network"):
        config["network"] = network
    if priority := args.get("priority"):
        config["priority"] = priority
    if sourceRanges := args.get("sourceRanges"):
        config["sourceRanges"] = argToList(sourceRanges)
    if destinationRanges := args.get("destinationRanges"):
        config["destinationRanges"] = destinationRanges
    if sourceTags := args.get("sourceTags"):
        config["sourceTags"] = argToList(sourceTags)
    if targetTags := args.get("targetTags"):
        config["targetTags"] = argToList(targetTags)
    if sourceServiceAccounts := args.get("sourceServiceAccounts"):
        config["sourceServiceAccounts"] = argToList(sourceServiceAccounts)
    if targetServiceAccounts := args.get("targetServiceAccounts"):
        config["targetServiceAccounts"] = argToList(targetServiceAccounts)
    if allowed := args.get("allowed"):
        config["allowed"] = parse_firewall_rule(allowed)
    if denied := args.get("denied"):
        config["denied"] = parse_firewall_rule(denied)
    if direction := args.get("direction"):
        config["direction"] = direction
    if logConfigEnable := args.get("logConfigEnable"):
        config["logConfig"] = {"enable": argToBoolean(logConfigEnable)}
    if disabled := args.get("disabled"):
        config["disabled"] = argToBoolean(disabled)

    compute = GCPServices.COMPUTE.build(creds)
    demisto.debug(f"Firewall patch config for {resource_name} in project {project_id}: {config}")
    response = (
        compute.firewalls()  # pylint: disable=E1101
        .patch(project=project_id, firewall=resource_name, body=config)
        .execute()
    )

    hr = tableToMarkdown(
        "Google Cloud Compute Firewall Rule Update Operation Started Successfully",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def storage_bucket_policy_delete(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Deletes public IAM policy bindings from a GCS bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'resource_name' (bucket name) and optional 'entity'.

    Returns:
        CommandResults: Result of the policy removal operation.
    """
    bucket = args.get("resource_name")
    entities_to_remove = set(argToList(args.get("entity", "allUsers")))

    storage = GCPServices.STORAGE.build(creds)
    policy = storage.buckets().getIamPolicy(bucket=bucket).execute()  # pylint: disable=E1101

    modified = False
    updated_bindings = []
    bindings = policy.get("bindings", [])
    for binding in bindings:
        role = binding["role"]
        original_members = set(binding.get("members", []))
        filtered_members = original_members - entities_to_remove
        removed = original_members & entities_to_remove
        if removed:
            modified = True
            demisto.debug(f"Removing members {removed} from role '{role}'.")
        if filtered_members:
            updated_bindings.append({"role": role, "members": list(filtered_members)})

    if modified:
        policy["bindings"] = updated_bindings
        storage.buckets().setIamPolicy(bucket=bucket, body=policy).execute()  # pylint: disable=E1101
        hr = (
            f"Access permissions for {', '.join(f'`{e}`' for e in entities_to_remove)} were successfully "
            f"revoked from bucket **{bucket}**"
        )
    else:
        hr = f"No IAM changes made for bucket '{bucket}'."
    return CommandResults(readable_output=hr)


def compute_subnet_update(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Updates subnet properties such as flow logs and private Google access.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'region', 'resource_name',
        and optional flow log and private access flags.

    Returns:
        CommandResults: Result of the subnet patch operation.
    """
    project_id = args.get("project_id")
    region = args.get("region")
    resource_name = args.get("resource_name")

    compute = GCPServices.COMPUTE.build(creds)
    hr, response_patch, response_set = "", {}, {}
    patch_body = {}
    if enable_flow_logs := args.get("enable_flow_logs"):
        patch_body["enableFlowLogs"] = argToBoolean(enable_flow_logs)
        subnetwork = (
            compute.subnetworks()  # pylint: disable=E1101
            .get(project=project_id, region=region, subnetwork=resource_name)
            .execute()
        )
        fingerprint = subnetwork.get("fingerprint")
        if not fingerprint:
            raise DemistoException("Fingerprint for the subnetwork is missing.")
        patch_body["fingerprint"] = fingerprint
        response_patch = (
            compute.subnetworks()  # pylint: disable=E1101
            .patch(project=project_id, region=region, subnetwork=resource_name, body=patch_body)
            .execute()
        )

        hr += tableToMarkdown(
            f"Flow Logs configuration for subnet {resource_name} in project {project_id}",
            t=response_patch,
            headers=OPERATION_TABLE,
            removeNull=True,
        )
    if enable_private_access := args.get("enable_private_ip_google_access"):
        response_set = (
            compute.subnetworks()  # pylint: disable=E1101
            .setPrivateIpGoogleAccess(
                project=project_id,
                region=region,
                subnetwork=resource_name,
                body={"privateIpGoogleAccess": argToBoolean(enable_private_access)},
            )
            .execute()
        )
        hr += tableToMarkdown(
            f"Private IP Google Access configuration for subnet {resource_name} in project {project_id}",
            t=response_set,
            headers=OPERATION_TABLE,
            removeNull=True,
        )

    if not hr:
        hr = f"No updates were made to subnet configuration for {resource_name} in project {project_id}"
        return CommandResults(readable_output=hr)
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=[response_patch, response_set])


# def compute_instance_metadata_add(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Adds metadata key-value pairs to a GCE instance.
#
#     Args:
#         creds (Credentials): GCP credentials.
#         args (dict[str, Any]): Must include 'project_id', 'zone', 'resource_name', and 'metadata' in key=value format.
#
#     Returns:
#         CommandResults: Result of the metadata update operation.
#     """
#     project_id = args.get("project_id")
#     zone = extract_zone_name(args.get("zone"))
#     resource_name = args.get("resource_name")
#     metadata_str: str = args.get("metadata", "")
#     compute = GCPServices.COMPUTE.build(creds)
#
#     instance = compute.instances().get(project=project_id, zone=zone, instance=resource_name).execute()  # pylint: disable=E1101
#     fingerprint = instance.get("metadata", {}).get("fingerprint")
#     existing_items = instance.get("metadata", {}).get("items", [])
#     existing_metadata = {item["key"]: item["value"] for item in existing_items}
#
#     new_items = parse_metadata_items(metadata_str)
#     for item in new_items:
#         existing_metadata[item["key"]] = item["value"]
#
#     body = {"fingerprint": fingerprint, "items": [{"key": k, "value": v} for k, v in existing_metadata.items()]}
#     response = (
#         compute.instances()  # pylint: disable=E1101
#         .setMetadata(
#             project=project_id,
#             zone=zone,
#             instance=resource_name,
#             body=body,
#         )
#         .execute()
#     )
#
#     hr = tableToMarkdown(
#         "Google Cloud Compute Project Metadata Update Operation Started Successfully",
#         t=response,
#         headers=OPERATION_TABLE,
#         removeNull=True,
#     )
#     return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def container_cluster_security_update(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Updates security-related configurations for a GKE cluster.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'region', 'resource_name' and optional security flags.
            - enable_intra_node_visibility: Whether to enable intra-node visibility.
            - enable_master_authorized_networks: Whether to enable master authorized networks (required if cidrs provided).
            - cidrs: Comma-separated list of CIDR blocks (e.g. "192.168.0.0/24,10.0.0.0/32").
                     Required if enable_master_authorized_networks is True.

    Returns:
        CommandResults: Result of the cluster update operation.
    """
    project_id = args.get("project_id")
    region = args.get("region")
    resource_name = args.get("resource_name")
    cidrs = argToList(args.get("cidrs"))
    if "enable_master_authorized_networks" in args and "enable_intra_node_visibility" in args:
        raise DemistoException(
            "Only one update can be applied to a cluster with each request. "
            "Please provide either 'enable_intra_node_visibility' "
            "or 'enable_master_authorized_networks', not both."
        )

    if cidrs and not args.get("enable_master_authorized_networks"):
        raise DemistoException(
            "You provided CIDRs, but 'enable_master_authorized_networks' is not enabled. "
            "To apply CIDRs, you must enable Master Authorized Networks."
        )

    container = GCPServices.CONTAINER.build(creds)
    update_fields: dict[str, Any] = {}

    if enable_intra := args.get("enable_intra_node_visibility"):
        update_fields["desiredIntraNodeVisibilityConfig"] = {"enabled": argToBoolean(enable_intra)}

    if enable_master := args.get("enable_master_authorized_networks"):
        update_fields["desiredControlPlaneEndpointsConfig"] = {
            "ipEndpointsConfig": {
                "authorizedNetworksConfig": {
                    "enabled": argToBoolean(enable_master),
                    "cidrBlocks": [{"cidrBlock": cidr} for cidr in cidrs],
                }
            }
        }

    response = (
        container.projects()  # pylint: disable=E1101
        .locations()
        .clusters()
        .update(name=f"projects/{project_id}/locations/{region}/clusters/{resource_name}", body={"update": update_fields})
        .execute()
    )

    hr = tableToMarkdown(
        "Google Cloud Container Cluster Security Update Operation Started Successfully",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )

    return CommandResults(readable_output=hr, outputs_prefix="GCP.Container.Operations", outputs=response)


def storage_bucket_metadata_update(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Updates metadata configuration for a GCS bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'resource_name' (bucket name) and optional versioning/uniform access flags.

    Returns:
        CommandResults: Result of the metadata update operation.
    """
    bucket = args.get("resource_name")

    storage = GCPServices.STORAGE.build(creds)

    body: dict[str, Any] = {}
    if enable_versioning := args.get("enable_versioning"):
        body["versioning"] = {"enabled": argToBoolean(enable_versioning)}
    if enable_uniform_access := args.get("enable_uniform_access"):
        body.setdefault("iamConfiguration", {})["uniformBucketLevelAccess"] = {"enabled": argToBoolean(enable_uniform_access)}

    response = storage.buckets().patch(bucket=bucket, body=body).execute()  # pylint: disable=E1101
    data_res = {
        "name": response.get("name"),
        "id": response.get("id"),
        "kind": response.get("kind"),
        "selfLink": response.get("selfLink"),
        "projectNumber": response.get("projectNumber"),
        "updated": response.get("updated"),
        "location": response.get("location"),
        "versioning": response.get("versioning", {}).get("enabled"),
        "uniformBucketLevelAccess": response.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled"),
    }
    hr = tableToMarkdown(f"Metadata for bucket {bucket} was successfully updated.", data_res, removeNull=True)
    return CommandResults(
        readable_output=hr, outputs_prefix="GCP.StorageBucket.Metadata", outputs=response, outputs_key_field="name"
    )


def iam_project_policy_binding_remove(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Removes specified IAM role bindings from a GCP project.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'member', and 'role'.
                              'member' can be a single member or a comma-separated list.

    Returns:
        CommandResults: Result of the IAM binding removal operation.
    """
    project_id = args.get("project_id")
    entities_to_remove = set(argToList(args.get("member")))
    role = args.get("role")

    resource_manager = GCPServices.RESOURCE_MANAGER.build(creds)

    policy_request = resource_manager.projects().getIamPolicy(resource=f"projects/{project_id}")  # pylint: disable=E1101
    policy = policy_request.execute()

    modified = False
    updated_bindings = []
    bindings = policy.get("bindings", [])

    for binding in bindings:
        binding_role = binding["role"]
        if binding_role == role:
            original_members = set(binding.get("members", []))
            filtered_members = original_members - entities_to_remove
            removed = original_members & entities_to_remove

            if removed:
                modified = True
                demisto.debug(f"Removing members {removed} from role '{binding_role}'.")

            if filtered_members:
                updated_bindings.append({"role": binding_role, "members": list(filtered_members)})
        else:
            updated_bindings.append(binding)

    if modified:
        policy["bindings"] = updated_bindings
        set_policy_request = resource_manager.projects().setIamPolicy(  # pylint: disable=E1101
            resource=f"projects/{project_id}", body={"policy": policy}
        )
        set_policy_request.execute()

        hr = (
            f"IAM role '{role}' was successfully removed from {', '.join(f'`{e}`' for e in entities_to_remove)} "
            f"in project **{project_id}**"
        )
    else:
        hr = f"No IAM changes made for role '{role}' in project '{project_id}'."

    return CommandResults(readable_output=hr)


# The command is currently unsupported.
# def iam_project_deny_policy_create(creds, args: dict[str, Any]) -> CommandResults:
#     """
#     Creates an IAM deny policy to explicitly block access to specific resources.
#
#     Args:
#         creds: GCP credentials.
#         args (dict[str, Any]):
#             - project_id (str): GCP project ID.
#             - policy_id (str): Deny policy identifier.
#             - display_name (str): Display name for the policy.
#             - denied_principals (str): Comma-separated principals to deny.
#             - denied_permissions (str): Comma-separated permissions to deny.
#
#     Returns:
#         CommandResults: Result of the deny policy creation.
#     """
#
#     project_id = args.get("project_id")
#     policy_id = args.get("policy_id")
#     display_name = args.get("display_name")
#     denied_principals = argToList(args.get("denied_principals"))
#     denied_permissions = argToList(args.get("denied_permissions"))
#
#     iam = GCPServices.IAM_V2.build(creds)
#     attachment_point = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{project_id}"
#     parent = f"policies/{attachment_point}/denypolicies"
#
#     policy = {
#         "displayName": display_name,
#         "rules": [
#             {
#                 "denyRule": {
#                     "deniedPrincipals": denied_principals,
#                     "deniedPermissions": denied_permissions,
#                 }
#             }
#         ],
#     }
#
#     response = iam.policies().createPolicy(parent=parent, policyId=policy_id, body=policy).execute()  # pylint: disable=E1101
#
#     readable_output = f"Deny policy `{policy_id}` was successfully created and attached to `{project_id}`."
#     return CommandResults(
#         readable_output=readable_output,
#         outputs_prefix="GCP.IAM.DenyPolicy",
#         outputs=response,
#     )


def compute_instance_service_account_set(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Sets the service account for a GCP Compute Engine VM instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', 'resource_name',
                              and optional 'service_account' and 'scopes'.

    Returns:
        CommandResults: Result of the service account update operation.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    resource_name = args.get("resource_name")
    service_account_email = args.get("service_account_email", "")
    scopes = argToList(args.get("scopes", []))

    compute = GCPServices.COMPUTE.build(creds)

    body = {"email": service_account_email, "scopes": scopes}

    response = (
        compute.instances()  # pylint: disable=E1101
        .setServiceAccount(project=project_id, zone=zone, instance=resource_name, body=body)
        .execute()
    )

    hr = tableToMarkdown(
        f"Service Account Updated Operation Started Successfully for VM Instance {resource_name} in project {project_id}.",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def compute_instance_service_account_remove(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Removes a service account from a GCP Compute Engine VM instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', and 'resource_name'.

    Returns:
        CommandResults: Result of the service account removal operation.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    resource_name = args.get("resource_name")

    compute = GCPServices.COMPUTE.build(creds)

    body = {"email": "", "scopes": []}
    response = (
        compute.instances()  # pylint: disable=E1101
        .setServiceAccount(project=project_id, zone=zone, instance=resource_name, body=body)
        .execute()
    )

    hr = tableToMarkdown(
        f"Service Account Removed Operation Started Successfully for VM Instance {resource_name} in project {project_id}.",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


# The command is currently unsupported.
# def iam_group_membership_delete(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Removes a user or service account from a Google Cloud Identity group.
#
#     Args:
#         creds (Credentials): GCP credentials.
#         args (dict[str, Any]): Must include 'group_id' and 'membership_id'.
#
#     Returns:
#         CommandResults: Result of the group membership removal.
#     """
#     group_id = args.get("group_id")
#     membership_id = args.get("membership_id")
#
#     cloud_identity = GCPServices.CLOUD_IDENTITY.build(creds)
#     membership_name = f"groups/{group_id}/memberships/{membership_id}"
#     cloud_identity.groups().memberships().delete(name=membership_name).execute()  # pylint: disable=E1101
#
#     hr = f"Membership {membership_id} was deleted from group {group_id} successfully."
#
#     return CommandResults(readable_output=hr)

# The command is currently unsupported.
# def iam_service_account_delete(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Deletes a GCP IAM service account.
#
#     Args:
#         creds (Credentials): GCP credentials.
#         args (dict[str, Any]): Must include 'project_id' and 'service_account_email'.
#
#     Returns:
#         CommandResults: Result of the service account deletion.
#     """
#     project_id = args.get("project_id")
#     service_account_email = args.get("service_account_email")
#
#     iam = GCPServices.IAM_V1.build(creds)
#
#     name = f"projects/{project_id}/serviceAccounts/{service_account_email}"
#
#     iam.projects().serviceAccounts().delete(name=name).execute()  # pylint: disable=E1101
#     hr = f"Service account {service_account_email} was successfully deleted from project {project_id}."
#     return CommandResults(readable_output=hr)


def compute_instance_start(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Starts a stopped Compute Engine VM instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', and 'resource_name'.

    Returns:
        CommandResults: Result of the VM start operation.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    resource_name = args.get("resource_name")

    compute = GCPServices.COMPUTE.build(creds)

    response = (
        compute.instances()  # pylint: disable=E1101
        .start(project=project_id, zone=zone, instance=resource_name)
        .execute()
    )

    hr = tableToMarkdown(
        f"VM instance {resource_name} was started in project {project_id}",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )

    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def compute_instance_stop(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Stops a running Compute Engine VM instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', and 'resource_name'.

    Returns:
        CommandResults: Result of the VM stop operation.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    resource_name = args.get("resource_name")

    compute = GCPServices.COMPUTE.build(creds)

    response = (
        compute.instances()  # pylint: disable=E1101
        .stop(project=project_id, zone=zone, instance=resource_name)
        .execute()
    )

    hr = tableToMarkdown(
        f"VM instance {resource_name} was stopped in project {project_id}",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )

    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


# The command is currently unsupported.
# def admin_user_update(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Updates user account fields in GSuite, such as names, org unit, or status.
#
#     Args:
#         creds (Credentials): GCP credentials with admin directory scopes.
#         args (dict[str, Any]): Must include 'user_key' and 'update_fields'.
#
#     Returns:
#         CommandResults: Result of the user update operation.
#     """
#     user_key = args.get("user_key")
#     update_fields = json.loads(args.get("update_fields", "{}"))
#
#     directory = GCPServices.ADMIN_DIRECTORY.build(creds)
#
#     try:
#         response = directory.users().update(userKey=user_key, body=update_fields).execute()  # pylint: disable=E1101
#         hr = f"GSuite user {user_key} was successfully updated."
#     except Exception as e:
#         raise DemistoException(f"Failed to update user: {str(e)}") from e
#
#     return CommandResults(readable_output=hr, outputs_prefix="GCP.GSuite.User", outputs=response)

# The command is currently unsupported.
# def admin_user_password_reset(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Resets the password for a GSuite user account.
#
#     Args:
#         creds (Credentials): GCP credentials with admin directory security scope.
#         args (dict[str, Any]): Must include 'user_key' and 'new_password'.
#
#     Returns:
#         CommandResults: Result of the password reset operation.
#     """
#     user_key = args.get("user_key")
#     new_password = args.get("new_password")
#
#     directory = GCPServices.ADMIN_DIRECTORY.build(creds)
#
#     try:
#         # Create password update body
#         password_update = {"password": new_password}
#
#         response = directory.users().update(userKey=user_key, body=password_update).execute()  # pylint: disable=E1101
#         hr = f"Password for GSuite user {user_key} was successfully reset."
#     except Exception as e:
#         raise DemistoException(f"Failed to reset password: {str(e)}") from e
#
#     return CommandResults(readable_output=hr, outputs_prefix="GCP.GSuite.User.Password", outputs=response)

# The command is currently unsupported.
# def admin_user_signout(creds: Credentials, args: dict[str, Any]) -> CommandResults:
#     """
#     Invalidates all active sessions for a GSuite user, forcing them to sign in again.
#
#     Args:
#         creds (Credentials): GCP credentials with admin directory security scope.
#         args (dict[str, Any]): Must include 'user_key'.
#
#     Returns:
#         CommandResults: Result of the signout operation.
#     """
#     user_key = args.get("user_key")
#
#     directory = GCPServices.ADMIN_DIRECTORY.build(creds)
#
#     try:
#         directory.users().signOut(userKey=user_key).execute()  # pylint: disable=E1101
#         hr = f"All active sessions for GSuite user {user_key} were successfully signed out."
#     except Exception as e:
#         raise DemistoException(f"Failed to sign out user: {str(e)}") from e
#
#     return CommandResults(readable_output=hr)


def _get_commands_for_requirement(requirement: str, req_type: str) -> list[str]:
    """
    Find which commands require a specific API or permission.

    Args:
        requirement (str): The API endpoint or permission to search for.
        req_type (str): Either 'apis' or 'permissions' to specify search type.

    Returns:
        str: Comma-separated list of command names that require the specified resource.
             Returns 'unknown commands' if no matches found.
    """
    commands = [
        cmd
        for cmd, (service, permissions) in COMMAND_REQUIREMENTS.items()
        if (req_type == "apis" and requirement == service.api_endpoint)
        or (req_type == "permissions" and requirement in permissions)
    ]
    return commands or ["unknown commands"]


def validate_apis_enabled(creds: Credentials, project_id: str, apis: list[str]) -> list[str]:
    """
    Check if required Google Cloud APIs are enabled for the project.

    Uses the Service Usage API to verify that each required API is enabled.
    If the Service Usage API itself is unavailable, returns empty list to skip validation.

    Args:
        creds (Credentials): GCP credentials for API access.
        project_id (str): The GCP project ID to check.
        apis (list[str]): List of API endpoints to validate (e.g., ['compute.googleapis.com']).

    Returns:
        list[str]: List of API endpoints that are disabled and need to be enabled.
                  Returns empty list if Service Usage API is unavailable.
    """
    try:
        service_usage = GCPServices.SERVICE_USAGE.build(creds)
        disabled = []

        for api in apis:
            try:
                response = (
                    service_usage.services()  # pylint: disable=E1101
                    .get(name=f"projects/{project_id}/services/{api}")
                    .execute()
                )
                if response.get("state") != "ENABLED":
                    disabled.append(api)
            except Exception as e:
                demisto.debug(f"API check failed for {api}: {str(e)}")
                disabled.append(api)  # Assume disabled if check fails

        return disabled
    except Exception as e:
        demisto.debug(f"Service Usage API unavailable: {str(e)}")
        return []  # Skip validation if Service Usage API not accessible


def _get_requirements(command: str = "") -> tuple[list[str], list[str]]:
    """
    Extract API endpoints and permissions for a command or all commands.

    Uses frozenset union pattern to efficiently get unique values across all commands
    when no specific command is provided.

    Args:
        command (str, optional): Specific command name. If empty, returns requirements for all commands.

    Returns:
        tuple[list[str], list[str]]: Tuple containing:
            - List of required API endpoints
            - List of required IAM permissions
    """
    # Get service and permissions using the same pattern
    service, permissions = COMMAND_REQUIREMENTS.get(
        command, (None, list(frozenset().union(*[perms for _, perms in COMMAND_REQUIREMENTS.values()])))
    )

    # Get APIs using the same pattern
    apis = (
        [service.api_endpoint]
        if service
        else list(frozenset().union(*[[svc.api_endpoint] for svc, _ in COMMAND_REQUIREMENTS.values()]))
    )

    return apis, permissions


def check_required_permissions(
    creds: Credentials, project_id: str, connector_id: str = None, command: str = ""
) -> list[HealthCheckError] | HealthCheckError | None:
    """
    Comprehensive validation of GCP APIs and IAM permissions for commands.

    Validation order:
    1. IAM Permissions: Tests IAM permissions using Resource Manager's testIamPermissions API
    2. API Enablement: Verifies required Google Cloud APIs are enabled using Service Usage API

    Special handling:
    - Cloud Identity permissions are skipped (cannot be tested via API)
    - Service Usage API failures are logged but don't block execution
    - Provides actionable error messages with gcloud commands for remediation

    Args:
        creds (Credentials): GCP credentials to test.
        project_id (str): The GCP project ID to validate against.
        connector_id (str, optional): Connector ID for COOC health checks.
                                    If provided, returns HealthCheckError objects.
                                    If None, raises DemistoException on failures.
        command (str, optional): Specific command to validate.
                               If empty, validates all integration commands.

    Returns:
        For COOC context (connector_id provided):
            - None: All validations passed
            - HealthCheckError: Single validation error
            - list[HealthCheckError]: Multiple validation errors

        For integration context (no connector_id):
            - None: All validations passed
            - Raises DemistoException: On any validation failure

    Raises:
        DemistoException: When validation fails and not in COOC context.
    """
    apis, permissions = _get_requirements(command)
    errors = []

    untestable_permissions = [p for p in permissions if p.startswith("cloudidentity.")]
    testable_permissions = list(set(permissions) - set(untestable_permissions))

    if untestable_permissions:
        demisto.info(f"The following permissions cannot be verified and will be assumed granted: {untestable_permissions}")

    if testable_permissions:
        try:
            resource_manager = GCPServices.RESOURCE_MANAGER.build(creds)
            response = (
                resource_manager.projects()
                .testIamPermissions(  # pylint: disable=E1101
                    resource=f"projects/{project_id}", body={"permissions": testable_permissions}
                )
                .execute()
            )
            granted = set(response.get("permissions", []))
            missing = set(testable_permissions) - granted
            if missing:
                for perm in missing:
                    commands = _get_commands_for_requirement(perm, "permissions")
                    message = f"'{perm}' missing for {'command' if len(commands) == 1 else 'commands'}: {', '.join(commands)}"
                    errors.append(message)
        except Exception as e:
            error_message = f"Failed to test permissions for GCP integration: {str(e)}"
            raise DemistoException(error_message)

    for api in validate_apis_enabled(creds, project_id, apis):
        commands = _get_commands_for_requirement(api, "apis")
        message = f"API '{api}' disabled, required for {'command' if len(commands) == 1 else 'commands'}: {', '.join(commands)}"
        errors.append(message)

    if errors:
        raise DemistoException("Missing required permissions/API for GCP integration:\n-" + "\n-".join(errors))

    return None


def health_check(shared_creds: dict, project_id: str, connector_id: str) -> HealthCheckError | list[HealthCheckError] | None:
    """Tests connectivity to GCP.
    This function is specifically used for COOC health checks
    to verify connectivity.

    Args:
        shared_creds (dict): Pre-fetched cloud credentials (format varies by provider).
        project_id (str): The GCP project ID to check against.
        connector_id (str): The connector ID for the Cloud integration.

    Returns:
        HealthCheckError or a list of HealthCheckError or None: A list of HealthCheckError if there's at least one issue, None if successful.
    """
    try:
        token = shared_creds.get("access_token")
        if not token:
            raise DemistoException("Failed to authenticate with GCP - token is missing from credentials")
        creds = Credentials(token=token)
    except Exception as e:
        return HealthCheckError(
            account_id=project_id,
            connector_id=connector_id,
            message=str(e),
            error_type=ErrorType.CONNECTIVITY_ERROR,
        )
    # Perform sample check on GCP services
    service_results = GCPServices.test_all_services(creds, project_id)
    errors_list = []
    for _, success, error_message in service_results:
        if not success and "Permission" not in error_message:
            errors_list.append(HealthCheckError(
                account_id=project_id,
                connector_id=connector_id,
                message=f"Sample check failed for account {project_id}. Error: {error_message}",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            ))
    if errors_list:
        return errors_list
    return None


def test_module(creds: Credentials, args: dict[str, Any]) -> str:
    """
    Tests connectivity to GCP and checks for required permissions.

    This function is used for the integration's test button functionality.
    It verifies connectivity and basic permissions.

    Args:
        creds (Credentials): GCP credentials to test.
        args (dict[str, Any]): Command arguments with 'project_id'.

    Returns:
        str: "ok" if test is successful.

    Raises:
        DemistoException: If the test fails for any reason.
    """
    project_id = args.get("project_id")
    if not project_id:
        raise DemistoException("Missing required parameter 'project_id'")

    try:
        check_required_permissions(creds, project_id)
        return "ok"
    except Exception as e:
        demisto.debug(f"Test module failed: {str(e)}")
        raise DemistoException(f"Failed to connect to GCP: {str(e)}")


def get_credentials(args: dict, params: dict) -> Credentials:
    """
    Helper function to get and validate GCP credentials from either service account or token.

    Args:
        args: Command arguments
        params: Integration parameters

    Returns:
        Credentials: Authenticated GCP credentials object

    Raises:
        DemistoException: If credentials cannot be retrieved or are invalid
    """

    # Set up credentials - first try service account, then token-based auth
    if (credentials := params.get("credentials")) and (password := credentials.get("password")):
        try:
            service_account_info = json.loads(password)
            creds = google_service_account.Credentials.from_service_account_info(service_account_info)
            # If project_id wasn't provided in args, try to get it from service account
            if not args.get("project_id") and "project_id" in service_account_info:
                args["project_id"] = service_account_info.get("project_id")
            demisto.debug("Using service account credentials")
            return creds
        except json.JSONDecodeError as e:
            raise DemistoException(f"Invalid service account JSON format: {str(e)}")
        except Exception as e:
            demisto.debug(f"Error creating service account credentials: {str(e)}")

    # Fall back to token-based authentication for COOC
    project_id = args.get("project_id")
    if not project_id:
        raise DemistoException("Missing required parameter 'project_id'")
    try:
        credential_data = get_cloud_credentials(CloudTypes.GCP.value, project_id)
        token = credential_data.get("access_token")
        if not token:
            raise DemistoException("Failed to retrieve GCP access token - token is missing from credentials")

        creds = Credentials(token=token)
        demisto.debug(f"{project_id}: Using token-based credentials")
        return creds
    except Exception as e:
        raise DemistoException(f"Failed to authenticate with GCP: {str(e)}")


def main():  # pragma: no cover
    """
    Main function to route commands and execute logic.

    This function processes the incoming command, sets up the appropriate credentials,
    and routes the execution to the corresponding handler function.
    """
    try:
        command = demisto.command()
        args = demisto.args()
        params = demisto.params()

        command_map = {
            "test-module": test_module,
            # Compute Engine commands
            "gcp-compute-firewall-patch": compute_firewall_patch,
            "gcp-compute-subnet-update": compute_subnet_update,
            "gcp-compute-instance-service-account-set": compute_instance_service_account_set,
            "gcp-compute-instance-service-account-remove": compute_instance_service_account_remove,
            "gcp-compute-instance-start": compute_instance_start,
            "gcp-compute-instance-stop": compute_instance_stop,
            # Storage commands
            "gcp-storage-bucket-policy-delete": storage_bucket_policy_delete,
            "gcp-storage-bucket-metadata-update": storage_bucket_metadata_update,
            # Container (GKE) commands
            "gcp-container-cluster-security-update": container_cluster_security_update,
            # IAM commands
            "gcp-iam-project-policy-binding-remove": iam_project_policy_binding_remove,
            # The following commands are currently unsupported:
            # # Compute Engine commands
            # "gcp-compute-instance-metadata-add": compute_instance_metadata_add,
            # "gcp-iam-project-deny-policy-create": iam_project_deny_policy_create,
            # "gcp-iam-service-account-delete": iam_service_account_delete,
            # "gcp-iam-group-membership-delete": iam_group_membership_delete,
            # # Admin Directory commands
            # "gcp-admin-user-update": admin_user_update,
            # "gcp-admin-user-password-reset": admin_user_password_reset,
            # "gcp-admin-user-signout": admin_user_signout,
        }

        if command == "test-module" and (connector_id := get_connector_id()):
            demisto.debug(f"Running health check for connector ID: {connector_id}")
            return_results(run_health_check_for_accounts(connector_id, CloudTypes.GCP.value, health_check))

        elif command in command_map:
            creds = get_credentials(args, params)
            return_results(command_map[command](creds, args))
        else:
            raise NotImplementedError(f"Command not implemented: {command}")

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
