import urllib3
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


# common

# taken from GoogleCloudCompute


def parse_resource_ids(resource_id):
    """
    Split the resource ids to a list
    parameter: (string) resource_id
    Return the resource_ids as a list
    """
    id_list = resource_id.replace(" ", "")
    resource_ids = id_list.split(",")
    return resource_ids


def parse_firewall_rule(rule_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) rules
        A firewall rule in the specified project
    Return firewall rules as dictionary list
    """
    rules = []
    regex = re.compile(r"ipprotocol=([\w\d_:.-]+),ports=([ /\w\d@_,.\*-]+)", flags=re.I)
    for f in rule_str.split(";"):
        match = regex.match(f)
        if match is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided like so: "
                "ipprotocol=abc,ports=123;ipprotocol=fed,ports=456"
            )

        rules.append({"IPProtocol": match.group(1), "ports": match.group(2).split(",")})

    return rules


def parse_metadata_items(tags_str):
    """
    Transforms a string of multiple inputes to a dictionary list
    parameter: (string) metadata_items

    Return metadata items as a dictionary list
    """
    tags = []
    regex = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)", flags=re.I)
    for f in tags_str.split(";"):
        match = regex.match(f)
        if match is None:
            raise ValueError(
                f"Could not parse field: {f}. Please make sure you provided like so: key=abc,value=123;key=fed,value=456"
            )

        tags.append({"key": match.group(1), "value": match.group(2)})

    return tags


###


urllib3.disable_warnings()
REQUIRED_PERMISSIONS: Dict[str, List[str]] = {
    "gcp-compute-patch-firewall": ["compute.firewalls.update"],
    "gcp-compute-update-subnet": [
        "compute.subnetworks.setPrivateIpGoogleAccess",
        "compute.subnetworks.update"
    ],
    "gcp-compute-project-info-add-metadata": ["compute.instances.setMetadata"],
    "gcp-storage-delete-bucket-policy": [
        "storage.buckets.getIamPolicy",
        "storage.buckets.setIamPolicy"
    ],
    "gcp-container-cluster-update-security-config": ["container.clusters.update"],
    "gcp-storage-update-bucket-metadata": ["storage.buckets.update"],
}


def get_access_token(
    args: Dict[str, Any]) -> str:
    """
    Retrieves a valid access token using the default GCP configuration.

    Args:
        args (Dict[str, Any]): Dictionary containing 'project_id' which is used to get the token.

    Returns:
        str: Access token for GCP.

    Raises:
        ValueError: If 'project_id' is not provided.
    """
    if not args.get("project_id"):
        raise ValueError("project_id is required to retrieve a token.")

    params = {
        "cloud_type": "GCP",
        "account_id": args.get("project_id"),
    }
    return {}
    # return demisto.get_token(params)


def compute_patch_firewall(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Disables a firewall rule in a GCP project.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id' and 'resource_name'.

    Returns:
        CommandResults: Result of the firewall patch operation.
    """
    project_id = args.get("project_id")
    resource_name = args.get("resource_name")
    config = {}

    if args.get("description"):
        config["description"] = args.get("description")

    if args.get("network"):
        config["network"] = args.get("network")

    if args.get("priority"):
        config["priority"] = int(args.get("priority"))

    if args.get("sourceRanges"):
        config["sourceRanges"] = parse_resource_ids(args.get("sourceRanges"))

    if args.get("destinationRanges"):
        config["destinationRanges"] = parse_resource_ids(args.get("destinationRanges"))

    if args.get("sourceTags"):
        config["sourceTags"] = parse_resource_ids(args.get("sourceTags"))

    if args.get("targetTags"):
        config["targetTags"] = parse_resource_ids(args.get("targetTags"))

    if args.get("sourceServiceAccounts"):
        config["sourceServiceAccounts"] = parse_resource_ids(
            args.get("sourceServiceAccounts")
        )

    if args.get("targetServiceAccounts"):
        config["targetServiceAccounts"] = parse_resource_ids(
            args.get("targetServiceAccounts")
        )

    if args.get("allowed"):
        config["allowed"] = parse_firewall_rule(args.get("allowed"))

    if args.get("denied"):
        config["denied"] = parse_firewall_rule(args.get("denied"))

    if args.get("direction"):
        config["direction"] = args.get("direction")

    if args.get("logConfigEnable"):
        log_config_enable = args.get("logConfigEnable") == "true"
        config["logConfig"] = {"enable": log_config_enable}

    if args.get("disabled"):
        disabled = args.get("disabled") == "true"
        config["disabled"] = disabled

    compute = build("compute", "v1", credentials=creds)

    response = compute.firewalls().patch(
        project=project_id,
        firewall=resource_name,
        body=config
    ).execute()

    hr = f"Firewall rule {resource_name} was successfully patched (disabled) in project {project_id}."
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def gcp_storage_delete_bucket_policy(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Deletes public IAM policy bindings from a GCS bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'resource_name' (bucket name) and optional 'entity'.

    Returns:
        CommandResults: Result of the policy removal operation.
    """
    bucket = args.get("resource_name")
    entities = argToList(args.get("entity", "allUsers"))
    storage = build("storage", "v1", credentials=creds)

    policy = storage.buckets().getIamPolicy(bucket=bucket).execute()
    bindings = policy.get("bindings", [])

    modified = False
    for b in bindings[:]:
        b["members"] = [m for m in b.get("members", []) if m not in entities]
        if not b["members"]:
            bindings.remove(b)
            modified = True

    if modified:
        policy["bindings"] = bindings
        storage.buckets().setIamPolicy(bucket=bucket, body={"policy": policy}).execute()

    hr = f"Public access permissions were successfully revoked from bucket {bucket}."
    return CommandResults(readable_output=hr)


def compute_update_subnet(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Updates subnet properties such as flow logs and private Google access.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id', 'region', 'resource_name',
        and optional flow log and private access flags.

    Returns:
        CommandResults: Result of the subnet patch operation.
    """
    project_id = args.get("project_id")
    region = args.get("region")
    resource_name = args.get("resource_name")
    enable_flow_logs = argToBoolean(args.get("enable_flow_logs"))
    enable_private_access = argToBoolean(args.get("enable_private_ip_google_access"))

    compute = build("compute", "v1", credentials=creds)

    if enable_private_access is not None:
        compute.subnetworks().setPrivateIpGoogleAccess(
            project=project_id,
            region=region,
            subnetwork=resource_name,
            body={"privateIpGoogleAccess": enable_private_access}
        ).execute()

    patch_body = {"enableFlowLogs": enable_flow_logs} if enable_flow_logs is not None else {}
    response = compute.subnetworks().patch(
        project=project_id,
        region=region,
        subnetwork=resource_name,
        body=patch_body
    ).execute()

    hr = f"Subnet configuration for {resource_name} was successfully updated in project {project_id}."
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def compute_add_metadata(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Adds metadata key-value pairs to a GCE instance.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id', 'zone', 'resource_name', and 'metadata' in key=value format.

    Returns:
        CommandResults: Result of the metadata update operation.
    """
    project_id = args.get("project_id")
    zone = args.get("zone")
    resource_name = args.get("resource_name")
    metadata_str = args.get("metadata")
    compute = build("compute", "v1", credentials=creds)

    instance = compute.instances().get(project=project_id, zone=zone, instance=resource_name).execute()
    fingerprint = instance.get("metadata", {}).get("fingerprint")

    items = parse_metadata_items(metadata_str)

    body = {"fingerprint": fingerprint, "items": items}
    response = compute.instances().setMetadata(project=project_id, zone=zone, instance=resource_name, body=body).execute()

    hr = f"Metadata was successfully added to instance {resource_name} in project {project_id}."
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.ProjectMetadata", outputs=response)


def gcp_container_cluster_update_security_config(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Updates security-related configurations for a GKE cluster.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id', 'region', 'resource_name' and optional security flags.

    Returns:
        CommandResults: Result of the cluster update operation.
    """
    project_id = args.get("project_id")
    region = args.get("region")
    resource_name = args.get("resource_name")
    enable_intra = argToBoolean(args.get("enable_intra_node_visibility"))
    enable_master = argToBoolean(args.get("enable_master_authorized_networks"))

    container = build("container", "v1", credentials=creds)
    update_fields = {}
    if enable_intra:
        update_fields["intraNodeVisibilityConfig"] = {"enabled": True}
    if enable_master:
        update_fields["masterAuthorizedNetworksConfig"] = {"enabled": True, "cidrBlocks": []}

    response = container.projects().locations().clusters().update(
        name=f"projects/{project_id}/locations/{region}/clusters/{resource_name}",
        body={"update": update_fields}
    ).execute()

    hr = f"Cluster security configuration for {resource_name} was successfully updated in project {project_id}."
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Container.Operation", outputs=response)


def gcp_storage_update_bucket_metadata(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Updates metadata configuration for a GCS bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'resource_name' (bucket name) and optional versioning/uniform access flags.

    Returns:
        CommandResults: Result of the metadata update operation.
    """
    bucket = args.get("resource_name")
    enable_versioning = argToBoolean(args.get("enable_versioning"))
    enable_uniform_access = argToBoolean(args.get("enable_uniform_access"))

    storage = build("storage", "v1", credentials=creds)
    body: Dict[str, Any] = {}
    if enable_versioning is not None:
        body["versioning"] = {"enabled": enable_versioning}
    if enable_uniform_access is not None:
        body.setdefault("iamConfiguration", {})["uniformBucketLevelAccess"] = {"enabled": enable_uniform_access}

    response = storage.buckets().patch(bucket=bucket, body=body).execute()
    hr = f"Metadata for bucket {bucket} was successfully updated."
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Storage.Bucket.Metadata", outputs=response)


def test_module(creds: Credentials, args: Dict[str, Any]) -> str:
    """
    Verifies that the provided GCP credentials have the necessary permissions for each command.

    Args:
        creds (Credentials): Authenticated GCP credentials.
        args (Dict[str, Any]): Command arguments, must include 'project_id'.

    Returns:
        str: 'ok' if all required permissions are present, raises an error otherwise.
    """
    project_id = args.get("project_id")
    if not project_id:
        raise ValueError("project_id is required for testing permissions.")

    all_permissions = list({perm for perms in REQUIRED_PERMISSIONS.values() for perm in perms})
    cloudresourcemanager = build("cloudresourcemanager", "v1", credentials=creds)
    body = {"permissions": all_permissions}

    try:
        response = cloudresourcemanager.projects().testIamPermissions(
            resource=project_id,
            body=body
        ).execute()
    except Exception as e:
        raise Exception(f"Failed to test permissions: {str(e)}")

    granted = set(response.get("permissions", []))
    missing_per_command: Dict[str, List[str]] = {}

    for command, perms in REQUIRED_PERMISSIONS.items():
        missing = [perm for perm in perms if perm not in granted]
        if missing:
            missing_per_command[command] = missing

    if missing_per_command:
        missing_str = "\n".join(
            f"- `{cmd}`: missing permissions: {', '.join(perms)}"
            for cmd, perms in missing_per_command.items()
        )
        raise Exception(f"The following required permissions are missing:\n{missing_str}")

    return "ok"


def main():
    """Main function to route commands and execute logic"""
    try:
        command = demisto.command()
        args = demisto.args()

        command_map = {
            "test-module": test_module,
            "gcp-compute-patch-firewall": compute_patch_firewall,
            "gcp-compute-patch-firewall-quick-action": compute_patch_firewall,
            "gcp-storage-delete-bucket-policy": gcp_storage_delete_bucket_policy,
            "gcp-compute-update-subnet": compute_update_subnet,
            "gcp-compute-project-info-add-metadata": compute_add_metadata,
            "gcp-container-cluster-update-security-config": gcp_container_cluster_update_security_config,
            "gcp-storage-update-bucket-metadata": gcp_storage_update_bucket_metadata,
        }

        if command not in command_map:
            raise NotImplementedError(f"Command not implemented: {command}")

        token = get_access_token(args)
        creds = Credentials(token)

        result = command_map[command](creds, args)
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
