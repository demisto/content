import urllib3
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

urllib3.disable_warnings()
REQUIRED_PERMISSIONS: Dict[str, List[str]] = {
    "gcp-compute-firewall-patch": [
        "compute.firewalls.update",
        "compute.firewalls.get",
        "compute.networks.updatePolicy"
    ],
    "gcp-compute-subnet-update": [
        "compute.subnetworks.setPrivateIpGoogleAccess",
        "compute.subnetworks.update",
        "compute.subnetworks.get"
    ],
    "gcp-compute-project-metadata-add": [
        "compute.instances.setMetadata",
        "compute.instances.get"
    ],
    "gcp-storage-bucket-policy-delete": [
        "storage.buckets.getIamPolicy",
        "storage.buckets.setIamPolicy"
    ],
    "gcp-container-cluster-security-update": [
        "container.clusters.update"
    ],
    "gcp-storage-bucket-metadata-update": [
        "storage.buckets.update"
    ],
}

OPERATION_TABLE = ["id", "kind", "name", "operationType", "progress", "zone", "status"]
########## taken from GoogleCloudCompute


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


##########




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
        raise DemistoException("project_id is required to retrieve a token.")
    #
    # params = {
    #     "cloud_type": "GCP",
    #     "account_id": args.get("project_id"),
    # }
    return ""
    # return demisto.get_token(params)


def compute_firewall_patch(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
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
        config["priority"] = args.get("priority")

    if args.get("sourceRanges"):
        config["sourceRanges"] = argToList(args.get("sourceRanges"))

    if args.get("destinationRanges"):
        config["destinationRanges"] = argToList(args.get("destinationRanges"))

    if args.get("sourceTags"):
        config["sourceTags"] = argToList(args.get("sourceTags"))

    if args.get("targetTags"):
        config["targetTags"] = argToList(args.get("targetTags"))

    if args.get("sourceServiceAccounts"):
        config["sourceServiceAccounts"] = argToList(
            args.get("sourceServiceAccounts")
        )

    if args.get("targetServiceAccounts"):
        config["targetServiceAccounts"] = argToList(
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

    hr = tableToMarkdown(f"Firewall rule {resource_name} was successfully patched (disabled) in project {project_id}",
                         t=response, headers=OPERATION_TABLE, removeNull=True)
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def storage_bucket_policy_delete(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
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

    hr = f"Access permissions {', '.join(f'`{e}`' for e in entities)} were successfully revoked from bucket **{bucket}**."
    return CommandResults(readable_output=hr)


def compute_subnet_update(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
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

    compute = build("compute", "v1", credentials=creds)
    hr, response_patch, response_set = "", {}, {}
    patch_body = {}
    if enable_flow_logs := args.get("enable_flow_logs"):
        patch_body["enableFlowLogs"] = argToBoolean(enable_flow_logs)
        subnetwork = compute.subnetworks().get(
            project=project_id,
            region=region,
            subnetwork=resource_name
        ).execute()
        fingerprint = subnetwork.get("fingerprint")
        if not fingerprint:
            raise DemistoException("Fingerprint for the subnetwork is missing.")
        patch_body["fingerprint"] = fingerprint
        response_patch = compute.subnetworks().patch(
            project=project_id,
            region=region,
            subnetwork=resource_name,
            body=patch_body
        ).execute()

        hr += tableToMarkdown(
            f"Flow Logs configuration for subnet {resource_name} in project {project_id}",
            t=response_patch, headers=OPERATION_TABLE, removeNull=True
        )
    if enable_private_access := args.get("enable_private_ip_google_access"):
        response_set = compute.subnetworks().setPrivateIpGoogleAccess(
            project=project_id,
            region=region,
            subnetwork=resource_name,
            body={"privateIpGoogleAccess": argToBoolean(enable_private_access)}
        ).execute()
        hr += tableToMarkdown(
            f"Private IP Google Access configuration for subnet {resource_name} in project {project_id}",
            t=response_set, headers=OPERATION_TABLE, removeNull=True
        )

    if not hr:
        hr = f"No updates were made to subnet configuration for {resource_name} in project {project_id}"

    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=[response_patch, response_set])


def compute_project_metadata_add(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
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

    hr = tableToMarkdown(f"Metadata was successfully added to instance {resource_name} in project {project_id}",
                         t=response, headers=OPERATION_TABLE, removeNull=True)
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operation", outputs=response)


def container_cluster_security_update(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Updates security-related configurations for a GKE cluster.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id', 'region', 'resource_name' and optional security flags.
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

    if args.get("enable_master_authorized_networks") and not cidrs:
        raise DemistoException("CIDRs must be provided when enabling master authorized networks.")

    container = build("container", "v1", credentials=creds)
    update_fields: Dict[str, Any] = {}

    if enable_intra := args.get("enable_intra_node_visibility"):
        update_fields["desiredIntraNodeVisibilityConfig"] = {"enabled": argToBoolean(enable_intra)}

    if enable_master := args.get("enable_master_authorized_networks"):
        update_fields["desiredControlPlaneEndpointsConfig"] = {
            "ipEndpointsConfig": {
                "authorizedNetworksConfig": {
                    "enabled": argToBoolean(enable_master),
                    "cidrBlocks": [{"cidrBlock": cidr} for cidr in cidrs]
                }
            }
        }

    response = container.projects().locations().clusters().update(
        name=f"projects/{project_id}/locations/{region}/clusters/{resource_name}",
        body={
            "update": update_fields
        }
    ).execute()

    hr = tableToMarkdown(
        f"Cluster security configuration for {resource_name} was successfully updated in project {project_id}",
        t=response, headers=OPERATION_TABLE,
        removeNull=True
    )

    return CommandResults(readable_output=hr, outputs_prefix="GCP.Container.Operation", outputs=response)


def storage_bucket_metadata_update(creds: Credentials, args: Dict[str, Any]) -> CommandResults:
    """
    Updates metadata configuration for a GCS bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'resource_name' (bucket name) and optional versioning/uniform access flags.

    Returns:
        CommandResults: Result of the metadata update operation.
    """
    bucket = args.get("resource_name")

    storage = build("storage", "v1", credentials=creds)
    body: Dict[str, Any] = {}
    if enable_versioning := args.get("enable_versioning"):
        body["versioning"] = {"enabled":  argToBoolean(enable_versioning)}
    if enable_uniform_access := args.get("enable_uniform_access"):
        body.setdefault("iamConfiguration", {})["uniformBucketLevelAccess"] = {"enabled": argToBoolean(enable_uniform_access)}

    response = storage.buckets().patch(bucket=bucket, body=body).execute()
    data_res = {
        "name": response.get("name"),
        "id": response.get("id"),
        "kind": response.get("kind"),
        "selfLink": response.get("selfLink"),
        "projectNumber": response.get("projectNumber"),
        "updated": response.get("updated"),
        "location": response.get("location"),
        "versioning": response.get("versioning", {}).get("enabled"),
        "uniformBucketLevelAccess": response.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled")
    }
    hr = tableToMarkdown(f"Metadata for bucket {bucket} was successfully updated.", data_res, removeNull=True)
    return CommandResults(readable_output=hr, outputs_prefix="GCP.StorageBucket.Metadata", outputs=response, outputs_key_field="name")


def check_required_permissions(creds: Credentials, args: Dict[str, Any], command: Optional[str] = None) -> str:
    """
    Checks if the provided GCP credentials have the required IAM permissions.

    Args:
        creds (Credentials): GCP credentials.
        args (Dict[str, Any]): Must include 'project_id'.
        command (Optional[str]): Specific command to check, or all if None.

    Returns:
        str: 'ok' if permissions are sufficient, otherwise raises an error.
    """
    project_id = args.get("project_id")
    if not project_id:
        raise DemistoException("'project_id' is required.")

    if command:
        permissions = REQUIRED_PERMISSIONS.get(command, [])
    else:
        permissions = list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms})

    try:
        response = build("cloudresourcemanager", "v1", credentials=creds).projects().testIamPermissions(
            resource=project_id, body={"permissions": permissions}
        ).execute()
    except Exception as e:
        raise DemistoException(f"Permission check failed: {e}") from e

    granted = set(response.get("permissions", []))

    if command:
        missing_permissions = [p for p in permissions if p not in granted]
        if missing_permissions:
            raise DemistoException(f"Missing permissions for `{command}`: {', '.join(missing_permissions)}")
    else:
        missing_per_command: Dict[str, List[str]] = {
            cmd: [p for p in perms if p not in granted]
            for cmd, perms in REQUIRED_PERMISSIONS.items()
            if any(p not in granted for p in perms)
        }
        if missing_per_command:
            issues = "\n".join(f"- `{cmd}`: {', '.join(perms)}" for cmd, perms in missing_per_command.items())
            raise DemistoException(f"Missing permissions:\n{issues}")

    return "ok"


def main():
    """Main function to route commands and execute logic"""
    try:
        command = demisto.command()
        args = demisto.args()
        command_map = {
            # "test-module": test_module,
            "gcp-compute-firewall-patch": compute_firewall_patch,
            "gcp-storage-bucket-policy-delete": storage_bucket_policy_delete,
            "gcp-compute-subnet-update": compute_subnet_update,
            "gcp-compute-project-metadata-add": compute_project_metadata_add,
            "gcp-container-cluster-security-update": container_cluster_security_update,
            "gcp-storage-bucket-metadata-update": storage_bucket_metadata_update,
        }

        if command not in command_map:
            raise NotImplementedError(f"Command not implemented: {command}")

        token = get_access_token(args)
        creds = Credentials(token)
        check_required_permissions(creds, args, command)
        result = command_map[command](creds, args)
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
