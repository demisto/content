from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.oauth2 import service_account
import urllib3
from COOCApiModule import *

urllib3.disable_warnings()

# API versions
COMPUTE_API_VERSION = "v1"
STORAGE_API_VERSION = "v1"
CONTAINER_API_VERSION = "v1"
RESOURCE_MANAGER_API_VERSION = "v3"

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
REQUIRED_PERMISSIONS: dict[str, list[str]] = {
    "gcp-compute-firewall-patch": [
        "compute.firewalls.update",
        "compute.firewalls.get",
        "compute.firewalls.list",
        "compute.networks.updatePolicy",
        "compute.networks.list",
    ],
    "gcp-compute-subnet-update": [
        "compute.subnetworks.setPrivateIpGoogleAccess",
        "compute.subnetworks.update",
        "compute.subnetworks.get",
        "compute.subnetworks.list",
    ],
    "gcp-compute-instance-metadata-add": ["compute.instances.setMetadata", "compute.instances.get", "compute.instances.list"],
    "gcp-storage-bucket-policy-delete": ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"],
    "gcp-container-cluster-security-update": ["container.clusters.update", "container.clusters.get", "container.clusters.list"],
    "gcp-storage-bucket-metadata-update": ["storage.buckets.update"],
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
        list[dict[str, Union[str, list[str]]]]: A list of dictionaries containing 'IPProtocol' and 'ports'.
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

    compute = build("compute", COMPUTE_API_VERSION, credentials=creds)
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

    storage = build("storage", STORAGE_API_VERSION, credentials=creds)
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

    compute = build("compute", COMPUTE_API_VERSION, credentials=creds)
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


def compute_instance_metadata_add(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Adds metadata key-value pairs to a GCE instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', 'resource_name', and 'metadata' in key=value format.

    Returns:
        CommandResults: Result of the metadata update operation.
    """
    project_id = args.get("project_id")
    zone = args.get("zone")
    resource_name = args.get("resource_name")
    metadata_str: str = args.get("metadata", "")
    compute = build("compute", COMPUTE_API_VERSION, credentials=creds)

    instance = compute.instances().get(project=project_id, zone=zone, instance=resource_name).execute()  # pylint: disable=E1101
    fingerprint = instance.get("metadata", {}).get("fingerprint")
    existing_items = instance.get("metadata", {}).get("items", [])
    existing_metadata = {item["key"]: item["value"] for item in existing_items}

    new_items = parse_metadata_items(metadata_str)
    for item in new_items:
        existing_metadata[item["key"]] = item["value"]

    body = {"fingerprint": fingerprint, "items": [{"key": k, "value": v} for k, v in existing_metadata.items()]}
    response = (
        compute.instances()  # pylint: disable=E1101
        .setMetadata(
            project=project_id,
            zone=zone,
            instance=resource_name,
            body=body,
        )
        .execute()
    )

    hr = tableToMarkdown(
        "Google Cloud Compute Project Metadata Update Operation Started Successfully",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


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

    if args.get("enable_master_authorized_networks") and not cidrs:
        raise DemistoException("CIDRs must be provided when enabling master authorized networks.")

    container = build("container", CONTAINER_API_VERSION, credentials=creds)
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

    storage = build("storage", STORAGE_API_VERSION, credentials=creds)

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


def check_required_permissions(creds: Credentials, args: dict[str, Any], command: str = "") -> str:
    """
    Checks if the provided GCP credentials have the required IAM permissions.
    API: https://cloud.google.com/resource-manager/reference/rest/v3/projects/testIamPermissions
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id'.
        command (Optional[str]): Specific command to check, or all if None.

    Returns:
        str: 'ok' if permissions are sufficient, otherwise raises an error.
    """
    project_id = args.get("project_id")

    permissions = REQUIRED_PERMISSIONS.get(command, list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms}))

    try:
        resource_manager = build("cloudresourcemanager", RESOURCE_MANAGER_API_VERSION, credentials=creds)
        response = (
            resource_manager.projects()  # pylint: disable=E1101
            .testIamPermissions(name=f"projects/{project_id}", body={"permissions": permissions})
            .execute()
        )
    except Exception as e:
        raise DemistoException(f"Permission check failed: {e}") from e

    granted = set(response.get("permissions", []))
    if missing := "\n".join(set(permissions) - granted):
        raise DemistoException(f"Missing permissions for '{command}': {missing}")
    return "ok"


def main():
    """Main function to route commands and execute logic"""
    try:
        command = demisto.command()
        args = demisto.args()
        params = demisto.params()

        command_map = {
            "gcp-compute-firewall-patch": compute_firewall_patch,
            "gcp-storage-bucket-policy-delete": storage_bucket_policy_delete,
            "gcp-compute-subnet-update": compute_subnet_update,
            "gcp-compute-instance-metadata-add": compute_instance_metadata_add,
            "gcp-container-cluster-security-update": container_cluster_security_update,
            "gcp-storage-bucket-metadata-update": storage_bucket_metadata_update,
        }

        if command != "test-module" and command not in command_map:
            raise NotImplementedError(f"Command not implemented: {command}")

        creds = None
        if (credentials := params.get("credentials")) and (password := credentials.get("password")):
            service_account_info = json.loads(password)
            creds = service_account.Credentials.from_service_account_info(service_account_info)
            args["project_id"] = service_account_info.get("project_id")
            demisto.debug("Using service account credentials")
        if not creds:
            token = get_cloud_credentials(CloudTypes.GCP.value).get("access_token")
            if not token:
                raise DemistoException("Failed to retrieve GCP access token - token is missing from credentials")
            creds = Credentials(token=token)
            demisto.debug("Using token-based credentials")

        result: CommandResults | str = check_required_permissions(creds, args, command)
        result = command_map[command](creds, args) if command in command_map else result
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
