from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.oauth2 import service_account
import urllib3
from enum import Enum
from COOCApiModule import *

urllib3.disable_warnings()


class GCPServices(Enum):
    COMPUTE = ("compute", "v1")
    STORAGE = ("storage", "v1")
    CONTAINER = ("container", "v1")
    RESOURCE_MANAGER = ("cloudresourcemanager", "v3")
    IAM_V1 = ("iam", "v1")
    IAM_V2 = ("iam", "v2")
    ADMIN_DIRECTORY = ("admin", "directory_v1")

    def __init__(self, api_name: str, version: str):
        self._api_name = api_name
        self._version = version

    @property
    def api_name(self):
        return self._api_name

    @property
    def version(self):
        return self._version

    def build(self, credentials, **kwargs):
        return build(self.api_name, self.version, credentials=credentials, **kwargs)


# SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
REQUIRED_PERMISSIONS: dict[str, list[str]] = {
    # Compute Engine commands
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
    "gcp-compute-instance-service-account-set": ["compute.instances.setServiceAccount", "compute.instances.get"],
    "gcp-compute-instance-service-account-remove": ["compute.instances.setServiceAccount", "compute.instances.get"],
    "gcp-compute-instance-start": ["compute.instances.start"],
    "gcp-compute-instance-stop": ["compute.instances.stop"],
    # Storage commands
    "gcp-storage-bucket-policy-delete": ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"],
    "gcp-storage-bucket-metadata-update": ["storage.buckets.update"],
    # Container (GKE) commands
    "gcp-container-cluster-security-update": ["container.clusters.update", "container.clusters.get", "container.clusters.list"],
    # IAM commands
    "gcp-iam-project-policy-binding-remove": ["resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"],
    "gcp-iam-project-deny-policy-create": ["iam.denypolicies.create"],
    "gcp-iam-service-account-delete": ["iam.serviceAccounts.delete"],
    # Admin Directory commands
    "gcp-iam-group-membership-delete": ["admin.directory.group.member.delete"],  # TODO
    # "gcp-admin-user-update": ["admin.directory.user.update"],
    # "gcp-admin-user-password-reset": ["admin.directory.user.security"],
    # "gcp-admin-user-signout": ["admin.directory.user.security"],
}
UNTESTABLE_PREFIXES = ["iam", "admin"]
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
    compute = GCPServices.COMPUTE.build(creds)

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


def iam_project_deny_policy_create(creds, args: dict[str, Any]) -> CommandResults:
    """
    Creates an IAM deny policy to explicitly block access to specific resources.

    Args:
        creds: GCP credentials.
        args (dict[str, Any]):
            - project_id (str): GCP project ID.
            - policy_id (str): Deny policy identifier.
            - display_name (str): Display name for the policy.
            - denied_principals (str): Comma-separated principals to deny.
            - denied_permissions (str): Comma-separated permissions to deny.

    Returns:
        CommandResults: Result of the deny policy creation.
    """

    project_id = args.get("project_id")
    policy_id = args.get("policy_id")
    display_name = args.get("display_name")
    denied_principals = argToList(args.get("denied_principals"))
    denied_permissions = argToList(args.get("denied_permissions"))

    iam = GCPServices.IAM_V2.build(creds)
    attachment_point = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{project_id}"
    parent = f"policies/{attachment_point}/denypolicies"

    policy = {
        "displayName": display_name,
        "rules": [
            {
                "denyRule": {
                    "deniedPrincipals": denied_principals,
                    "deniedPermissions": denied_permissions,
                }
            }
        ],
    }

    response = iam.policies().createPolicy(parent=parent, policyId=policy_id, body=policy).execute()  # pylint: disable=E1101

    readable_output = f"Deny policy `{policy_id}` was successfully created and attached to `{project_id}`."
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.IAM.DenyPolicy",
        outputs=response,
    )


def compute_instance_service_account_set(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Sets or removes a service account from a GCP Compute Engine VM instance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id', 'zone', 'resource_name',
                              and optional 'service_account' and 'scopes'.

    Returns:
        CommandResults: Result of the service account update operation.
    """
    project_id = args.get("project_id")
    zone = args.get("zone")
    resource_name = args.get("resource_name")
    service_account = args.get("service_account", "")
    scopes = argToList(args.get("scopes", []))

    compute = GCPServices.COMPUTE.build(creds)

    body = {"email": service_account, "scopes": scopes}

    response = (
        compute.instances()  # pylint: disable=E1101
        .setServiceAccount(project=project_id, zone=zone, instance=resource_name, body=body)
        .execute()
    )

    action = "updated" if service_account else "removed"

    hr = tableToMarkdown(
        f"Service account was successfully {action} for VM instance {resource_name} in project {project_id}.",
        t=response,
        headers=OPERATION_TABLE,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response)


def iam_group_membership_delete(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Removes a user or service account from a GSuite group.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'group_id' and 'member_key'.

    Returns:
        CommandResults: Result of the group membership removal.
    """
    group_id = args.get("group_id")
    member_key = args.get("member_key")

    directory = GCPServices.ADMIN_DIRECTORY.build(creds)
    try:
        directory.members().delete(groupKey=group_id, memberKey=member_key).execute()  # pylint: disable=E1101
        hr = f"Member {member_key} was removed from group {group_id}."
    except Exception as e:
        raise DemistoException(f"Failed to remove member from group: {str(e)}") from e

    return CommandResults(readable_output=hr)


def iam_service_account_delete(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Deletes a GCP IAM service account.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id' and 'service_account_email'.

    Returns:
        CommandResults: Result of the service account deletion.
    """
    project_id = args.get("project_id")
    service_account_email = args.get("service_account_email")

    iam = GCPServices.IAM_V1.build(creds)

    name = f"projects/{project_id}/serviceAccounts/{service_account_email}"

    try:
        iam.projects().serviceAccounts().delete(name=name).execute()  # pylint: disable=E1101
        hr = f"Service account {service_account_email} was successfully deleted from project {project_id}."
    except Exception as e:
        raise DemistoException(f"Failed to delete service account: {str(e)}") from e

    return CommandResults(readable_output=hr)


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
    zone = args.get("zone")
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
    zone = args.get("zone")
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
#
#
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
#
#
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


def check_required_permissions(creds: Credentials, args: dict[str, Any], command: str = "") -> str:
    """
    Verifies the credentials have all required permissions, using testIamPermissions when applicable,
    and IAM role expansion as fallback for untestable permissions.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Must include 'project_id'.
        command (str): Specific command to check, or all if empty.

    Returns:
        str: 'ok' if permissions are sufficient, otherwise raises an error.
    """
    project_id = args.get("project_id")
    if not project_id:
        raise DemistoException("Missing required argument: 'project_id'.")

    permissions = REQUIRED_PERMISSIONS.get(command, list({p for perms in REQUIRED_PERMISSIONS.values() for p in perms}))
    testable_perms = [p for p in permissions if not any(p.startswith(prefix) for prefix in UNTESTABLE_PREFIXES)]
    missing = set()
    if testable_perms:
        try:
            resource_manager = GCPServices.RESOURCE_MANAGER.build(creds)
            response = (
                resource_manager.projects()
                .testIamPermissions(  # pylint: disable=E1101
                    resource=f"projects/{project_id}", body={"permissions": testable_perms}
                )
                .execute()
            )

            granted = set(response.get("permissions", []))
            missing |= set(testable_perms) - granted
        except Exception as e:
            demisto.debug(f"testIamPermissions failed: {str(e)}")

    # Check untestable permissions with simple API calls
    api_checks = {
        "iam.": lambda: GCPServices.IAM_V1.build(creds)
        .projects()
        .serviceAccounts()
        .list(  # pylint: disable=E1101
            name=f"projects/{project_id}"
        )
        .execute(),
        "admin.": lambda: GCPServices.ADMIN_DIRECTORY.build(creds)
        .members()
        .list(  # pylint: disable=E1101
            domain="example.com", maxResults=1
        )
        .execute(),
    }

    for prefix, check_func in api_checks.items():
        if any(p.startswith(prefix) for p in permissions):
            try:
                check_func()
            except Exception as e:
                if "Permission denied" in str(e) or "forbidden" in str(e).lower():
                    missing |= {p for p in permissions if p.startswith(prefix)}
                demisto.debug(f"{prefix} API access check failed: {str(e)}")

    if missing:
        perm_to_cmds = {perm: [cmd for cmd, perms in REQUIRED_PERMISSIONS.items() if perm in perms] for perm in missing}
        # Format error message
        error_lines = [f"- {perm} (required for: {', '.join(cmds)})" for perm, cmds in perm_to_cmds.items()]

        raise DemistoException("Missing permissions:\n" + "\n".join(error_lines))

    return "ok"


def test_module(creds: Credentials, args: dict[str, Any]) -> str:
    """
    Tests connectivity to GCP and checks for required permissions.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments.

    Returns:
        str: "ok" if test is successful.
    """
    project_id = args.get("project_id")
    if not project_id:
        raise DemistoException("Missing required parameter 'project_id'")

    return check_required_permissions(creds, args)


def main():
    """Main function to route commands and execute logic"""
    try:
        command = demisto.command()
        args = demisto.args()
        params = demisto.params()

        command_map = {
            "test-module": test_module,
            # Compute Engine commands
            "gcp-compute-firewall-patch": compute_firewall_patch,
            "gcp-compute-subnet-update": compute_subnet_update,
            "gcp-compute-instance-metadata-add": compute_instance_metadata_add,
            "gcp-compute-instance-service-account-set": compute_instance_service_account_set,
            # "gcp-compute-instance-service-account-remove": compute_instance_service_account_remove,
            "gcp-compute-instance-start": compute_instance_start,
            "gcp-compute-instance-stop": compute_instance_stop,
            # Storage commands
            "gcp-storage-bucket-policy-delete": storage_bucket_policy_delete,
            "gcp-storage-bucket-metadata-update": storage_bucket_metadata_update,
            # Container (GKE) commands
            "gcp-container-cluster-security-update": container_cluster_security_update,
            # IAM commands
            "gcp-iam-project-policy-binding-remove": iam_project_policy_binding_remove,
            "gcp-iam-project-deny-policy-create": iam_project_deny_policy_create,
            "gcp-iam-service-account-delete": iam_service_account_delete,
            "gcp-iam-group-membership-delete": iam_group_membership_delete,
            # Admin Directory commands
            # "gcp-admin-user-update": admin_user_update,
            # "gcp-admin-user-password-reset": admin_user_password_reset,
            # "gcp-admin-user-signout": admin_user_signout,
        }

        if command not in command_map:
            raise NotImplementedError(f"Command not implemented: {command}")

        creds = None
        if (credentials := params.get("credentials")) and (password := credentials.get("password")):
            service_account_info = json.loads(password)
            creds = service_account.Credentials.from_service_account_info(service_account_info)
            args["project_id"] = service_account_info.get("project_id")
            demisto.debug("Using service account credentials")
        if not creds:
            token = get_cloud_credentials(CloudTypes.GCP.value, args.get("project_id")).get("access_token")
            if not token:
                raise DemistoException("Failed to retrieve GCP access token - token is missing from credentials")
            creds = Credentials(token=token)
            demisto.debug("Using token-based credentials")

        # result: CommandResults | str = check_required_permissions(creds, args, command)
        result = command_map[command](creds, args)  # if command in command_map else result
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
