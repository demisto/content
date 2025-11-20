from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.oauth2 import service_account as google_service_account
import urllib3
from COOCApiModule import *
from googleapiclient.errors import HttpError

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
    "gcp-compute-firewall-get": (
        GCPServices.COMPUTE,
        [
            "compute.firewalls.get",
        ],
    ),
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
    "gcp-compute-instance-start": (GCPServices.COMPUTE, ["compute.instances.start"]),
    "gcp-compute-instance-stop": (GCPServices.COMPUTE, ["compute.instances.stop"]),
    "gcp-compute-instances-list": (GCPServices.COMPUTE, ["compute.instances.list"]),
    "gcp-compute-instance-get": (GCPServices.COMPUTE, ["compute.instances.get"]),
    "gcp-compute-instance-labels-set": (GCPServices.COMPUTE, ["compute.instances.setLabels"]),
    "gcp-storage-bucket-policy-delete": (GCPServices.STORAGE, ["storage.buckets.getIamPolicy", "storage.buckets.setIamPolicy"]),
    "gcp-storage-bucket-metadata-update": (GCPServices.STORAGE, ["storage.buckets.update"]),
    "gcp-storage-bucket-list": (
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
    "gcp-storage-bucket-policy-set": (
        GCPServices.STORAGE,
        ["storage.buckets.setIamPolicy"],
    ),
    "gcp-storage-bucket-object-policy-list": (
        GCPServices.STORAGE,
        ["storage.objects.getIamPolicy"],
    ),
    "gcp-storage-bucket-object-policy-set": (
        GCPServices.STORAGE,
        ["storage.objects.setIamPolicy"],
    ),
    "gcp-compute-network-get": (GCPServices.COMPUTE, ["compute.networks.get"]),
    "gcp-compute-image-get": (GCPServices.COMPUTE, ["compute.images.get"]),
    "gcp-compute-instance-group-get": (GCPServices.COMPUTE, ["compute.instanceGroups.get"]),
    "gcp-compute-region-get": (GCPServices.COMPUTE, ["compute.regions.get"]),
    "gcp-compute-zone-get": (GCPServices.COMPUTE, ["compute.zone.get"]),
    "gcp-compute-networks-list": (GCPServices.COMPUTE, ["compute.networks.list"]),
    "gcp-compute-network-insert": (GCPServices.COMPUTE, ["compute.networks.insert"]),
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
KEY_VALUE_ITEM_REGEX = re.compile(r"key=([\w\d_:.-]+),value=([ /\w\d@_,.\*-]+)", flags=re.I)


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
        match = KEY_VALUE_ITEM_REGEX.match(f)
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


def parse_labels(labels_str: str) -> dict:
    """
    Transforms a string of multiple inputs to a dictionary
    Args:
        labels_str (str): The actual string to parse to a key & value pair.

    Returns:
        Returns the labels dictionary with the extracted key & value pairs.
    """
    labels = {}
    for f in labels_str.strip().split(";"):
        if f:
            match = KEY_VALUE_ITEM_REGEX.match(f)
            if match is None:
                raise ValueError(
                    f"Could not parse field: {f}. Please make sure you provided like so: key=abc,value=123;key=def,value=456"
                )

            labels.update({match.group(1).lower(): match.group(2).lower()})
    return labels


def handle_permission_error(e: HttpError, project_id: str, command_name: str):
    """
    Given an error, extract the relevant information (account_id & message & permission name) to report to the backend.
    Args:
        e (HttpError): The error object.
        project_id (str): The project identifier.
        command_name (str): The name of the command that was executed.

    Returns:
        Returns the labels dictionary with the extracted key & value pairs.
    """
    status_code = e.resp.status
    if int(status_code) in [403, 401] and e.resp.get("content-type", "").startswith("application/json"):
        message_content = json.loads(e.content)
        error_message = message_content.get("error", {}).get("message", "")

        # get the relevant permissions for the relevant command
        command_permissions: list[str]
        command_permissions = COMMAND_REQUIREMENTS[command_name][1]

        # find out which permissions are relevant for the current execution failure from the list of command permissions.
        found_permissions = [perm for perm in command_permissions if perm.lower() in error_message.lower()] or ["N/A"]

        demisto.debug(f"The info {error_message=} {found_permissions=} {message_content=}")

        # create an error entry for each missing permission.
        error_entries = [{"account_id": project_id, "message": error_message, "name": perm} for perm in found_permissions]

        return_multiple_permissions_error(error_entries)
    else:  # Return the original error if it's not a 403, 401 or doesn't have a JSON body
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


def _format_gcp_datetime(ts: str | None) -> str | None:
    if not ts:
        return None
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _is_ubla_enabled(storage_client, bucket_name: str) -> bool:
    """Returns True if Uniform Bucket-Level Access (UBLA) is enabled for the bucket."""
    try:
        meta = storage_client.buckets().get(bucket=bucket_name, fields="iamConfiguration").execute()  # pylint: disable=E1101
        return meta.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled") is True
    except Exception as e:
        demisto.debug(f"_is_ubla_enabled: failed to fetch bucket metadata for {bucket_name}: {e}")
        return False


def _is_ubla_error(e: HttpError) -> bool:
    """Detects UBLA-related 400 error content from Google API."""
    try:
        if isinstance(e.content, bytes | bytearray):
            content_lower = e.content.decode("utf-8", errors="ignore").lower()
        else:
            content_lower = str(e.content).lower()
    except Exception:
        content_lower = ""
    return e.resp.status == 400 and "uniform bucket-level access" in content_lower


def _validate_bucket_policy_for_set(policy: dict[str, Any], add_mode: bool) -> None:
    """Validate the structure of a bucket IAM policy for set operation.

    Args:
        policy: The JSON-decoded policy payload provided by the user.
        add_mode: If True, we only require valid bindings for merge; if False, validate full policy fields where applicable.

    Raises:
        DemistoException: If validation fails.
    """
    if not isinstance(policy, dict):
        raise DemistoException("Policy must be a JSON object.")

    bindings = policy.get("bindings")
    if bindings is not None and (not isinstance(bindings, list) or any(not isinstance(b, dict) for b in bindings)):
        if add_mode:
            raise DemistoException("Policy must include 'bindings' as an array of objects when add=true.")
        else:
            raise DemistoException("'bindings' must be an array of objects if provided.")

    if isinstance(bindings, list):
        for idx, b in enumerate(bindings):
            role = b.get("role")
            if not isinstance(role, str) or not role:
                raise DemistoException(f"Binding at index {idx} is missing a valid 'role' string.")
            members = b.get("members", [])
            if not isinstance(members, list) or any(not isinstance(m, str) for m in members):
                raise DemistoException(f"Binding at index {idx} must include 'members' as an array of strings.")
            if "condition" in b:
                version = policy.get("version", 1)
                if not isinstance(version, int) or version < 3:
                    raise DemistoException("Policy with IAM Conditions requires 'version' to be 3 or greater.")


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


def storage_bucket_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the list of buckets in the project associated with the client.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments including optional project_id, max_results, prefix, page_token.

    Returns:
        CommandResults: List of buckets with their metadata.
    """
    project_id = args.get("project_id")
    max_results = arg_to_number(args.get("limit"))
    prefix = args.get("prefix")
    page_token = args.get("page_token")
    demisto.debug(f"[GCP: storage_bucket_list] \nMax results: {max_results}, \nPrefix: {prefix}, \nPage token: {page_token}")

    storage = GCPServices.STORAGE.build(creds)

    # Build request parameters
    request_params = {"project": project_id, "maxResults": max_results, "prefix": prefix, "pageToken": page_token}

    remove_nulls_from_dictionary(request_params)

    demisto.debug(f"[GCP: storage_bucket_list] Request params: {request_params}")
    response = storage.buckets().list(**request_params).execute()  # pylint: disable=E1101

    buckets = response.get("items", [])
    demisto.debug(f"[GCP: storage_bucket_list] Buckets returned: {len(buckets)}")
    hr_bucket_data: list[dict[str, Any]] = []

    for bucket in buckets:
        hr_bucket_data.append(
            {
                "Name": bucket.get("name"),
                "TimeCreated": _format_gcp_datetime(bucket.get("timeCreated")),
                "TimeUpdated": _format_gcp_datetime(bucket.get("updated")),
                "OwnerID": bucket.get("owner", {}).get("entityId", ""),
                "Location": bucket.get("location"),
                "StorageClass": bucket.get("storageClass"),
            }
        )
    hr = tableToMarkdown("GCP Storage Buckets", hr_bucket_data, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.Bucket",
        outputs=buckets,
        outputs_key_field=["name", "id"],
        raw_response=buckets,
    )


def storage_bucket_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves information about a specific bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments including required bucket_name.

    Returns:
        CommandResults: Bucket information.
    """
    bucket_name = args.get("bucket_name", "")

    storage = GCPServices.STORAGE.build(creds)

    response = storage.buckets().get(bucket=bucket_name).execute()  # pylint: disable=E1101

    demisto.debug(f"[GCP: storage_bucket_get] \nResponse: \n{response}")

    bucket_info = {
        "Name": response.get("name"),
        "TimeCreated": _format_gcp_datetime(response.get("timeCreated")),
        "TimeUpdated": _format_gcp_datetime(response.get("updated")),
        "OwnerID": response.get("owner", {}).get("entityId", ""),
        "Location": response.get("location"),
        "StorageClass": response.get("storageClass"),
    }

    hr = tableToMarkdown(f"GCP Storage Bucket: {bucket_name}", bucket_info, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.Bucket",
        outputs=response,
        outputs_key_field=["name", "id"],
        raw_response=response,
    )


def storage_bucket_objects_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the list of objects in a bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments including required bucket_name and optional filters.

    Returns:
        CommandResults: List of objects in the bucket.
    """
    bucket_name = args.get("bucket_name", "")

    prefix = args.get("prefix", "")
    delimiter = args.get("delimiter", "")
    max_results = arg_to_number(args.get("limit"))
    page_token = args.get("page_token", "")

    storage = GCPServices.STORAGE.build(creds)

    # Build request parameters
    request_params = {
        "bucket": bucket_name,
        "prefix": prefix,
        "delimiter": delimiter,
        "maxResults": max_results,
        "pageToken": page_token,
    }
    remove_nulls_from_dictionary(request_params)
    demisto.debug(f"[GCP: storage_bucket_objects_list] Request params: {request_params}")

    response = storage.objects().list(**request_params).execute()  # pylint: disable=E1101
    demisto.debug(f" \nResponse: \n{response}")

    objects = response.get("items", [])
    demisto.debug(f"[GCP: storage_bucket_objects_list] Objects returned: {len(objects)}")
    object_data: list[dict[str, Any]] = []

    for obj in objects:
        object_info = {
            "Name": obj.get("name", ""),
            "Bucket": obj.get("bucket", ""),
            "ContentType": obj.get("contentType", ""),
            "Size": obj.get("size", ""),
            "TimeCreated": _format_gcp_datetime(obj.get("timeCreated", "")),
            "TimeUpdated": _format_gcp_datetime(obj.get("updated", "")),
            "MD5Hash": obj.get("md5Hash", ""),
            "CRC32c": obj.get("crc32c", ""),
        }
        object_data.append(object_info)
    hr = tableToMarkdown(f"Objects in bucket: {bucket_name}", object_data, removeNull=True, headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.BucketObject",
        outputs=objects,
        outputs_key_field=["name", "id"],
        raw_response=objects,
    )


def storage_bucket_policy_list(
    creds: Credentials,
    args: dict[str, Any],
    outputs_prefix: str = "GCP.Storage.BucketPolicy",
    object_name: str = "",
) -> CommandResults:
    """
    Retrieves the IAM policy for a bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments including required bucket_name and optional requested_policy_version.

    Returns:
        CommandResults: IAM policy for the bucket.
    """
    bucket_name = args.get("bucket_name", "")
    requested_policy_version = arg_to_number(args.get("requested_policy_version"))
    storage = GCPServices.STORAGE.build(creds)

    # Build request parameters
    request_params = {
        "bucket": bucket_name,
        "optionsRequestedPolicyVersion": requested_policy_version,
    }
    remove_nulls_from_dictionary(request_params)
    demisto.debug(f"[GCP: storage_bucket_policy_list] Request params: {request_params}")
    response = storage.buckets().getIamPolicy(**request_params).execute()  # pylint: disable=E1101

    policy_summary = {
        "Bucket": bucket_name,
        "Version": response.get("version"),
        "ETag": response.get("etag"),
        "Bindings count": len(response.get("bindings", [])),
    }
    bindings_rows = []
    for binding in response.get("bindings", []):
        role = binding.get("role", "")
        members = binding.get("members", [])
        bindings_rows.append({"Role": role, "Members": "\n".join(members) if members else ""})

    summary_object_type = f"bucket: {bucket_name}"
    outputs = response
    primary_key: str | list[str] = "resourceId"
    # Build outputs for object policy command
    if object_name:
        summary_object_type = f"object: {object_name}"
        outputs = {"bucketName": bucket_name, "objectName": object_name, "bindings": response.get("bindings", [])}
        primary_key = ["bucketName", "objectName"]

    summary_text = (
        f"IAM Policy for {summary_object_type}\n Version: {policy_summary['Version']}\n"
        f"ETag: {policy_summary['ETag']}\n Bindings count: {policy_summary['Bindings count']}"
    )

    hr_bindings = tableToMarkdown(
        "Bindings",
        bindings_rows,
        headers=["Role", "Members"],
        removeNull=True,
        headerTransform=pascalToSpace,
    )
    demisto.debug(f"[GCP: storage_bucket_policy_list] Bindings count: {len(bindings_rows)}")
    hr = f"{summary_text}\n\n{hr_bindings}"

    return CommandResults(
        readable_output=hr,
        outputs_prefix=outputs_prefix,
        outputs=outputs,
        raw_response=response,
        outputs_key_field=primary_key,
    )


def storage_bucket_policy_set(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Sets the IAM policy for a bucket.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Command arguments including required bucket_name and policy.

    Returns:
        CommandResults: Result of the policy update operation.
    """
    bucket_name = args.get("bucket_name", "")
    policy_json = args.get("policy", {})

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        raise DemistoException(f"Invalid JSON format for policy: {str(e)}")

    storage = GCPServices.STORAGE.build(creds)

    demisto.debug(f"[GCP: storage_bucket_policy_set] Bucket: {bucket_name}; Policy keys: {list(policy.keys())}")
    add_flag = argToBoolean(args.get("add"))

    _validate_bucket_policy_for_set(policy=policy, add_mode=add_flag)
    if add_flag:
        current = storage.buckets().getIamPolicy(bucket=bucket_name).execute()  # pylint: disable=E1101
        current_bindings: list[dict] = current.get("bindings", [])
        provided_bindings: list[dict] = policy.get("bindings", [])

        # Index current bindings by role
        by_role: dict[str, dict] = {
            str(b.get("role")): {"role": b.get("role"), "members": set(b.get("members", []))}
            for b in current_bindings
            if b.get("role")
        }
        # Merge provided bindings
        for pb in provided_bindings:
            role = pb.get("role")
            members = set(pb.get("members", []) or [])
            if not role:
                continue
            if role in by_role:
                by_role[role]["members"].update(members)
            else:
                by_role[role] = {"role": role, "members": set(members)}

        # Build merged bindings list
        merged_bindings = [{"role": r, "members": sorted(data["members"])} for r, data in by_role.items()]
        # Preserve other top-level fields from current policy if present (e.g., etag/version)
        merged_policy = dict(current)
        merged_policy["bindings"] = merged_bindings
        response = storage.buckets().setIamPolicy(bucket=bucket_name, body=merged_policy).execute()  # pylint: disable=E1101
    else:
        response = storage.buckets().setIamPolicy(bucket=bucket_name, body=policy).execute()  # pylint: disable=E1101

    demisto.debug(f" \nResponse: \n{response}")

    result_info = {"Bucket": bucket_name, "PolicyUpdatedSuccessfully": True, "NewPolicyVersion": response.get("version")}

    hr = tableToMarkdown(
        f"IAM Policy updated for bucket: {bucket_name}",
        result_info,
        removeNull=True,
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.BucketPolicy",
        outputs=response,
        outputs_key_field="etag",
        raw_response=response,
    )


def storage_bucket_object_policy_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Lists object-level ACLs for a specific object using the GCS ObjectAccessControls API.

    If Uniform Bucket-Level Access (UBLA) is enabled on the bucket, object-level ACLs are
    disabled and the command returns the bucket-level IAM policy instead for guidance.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]):
            - bucket_name (str): Target bucket name.
            - object_name (str): Target object name.
            - generation (Number, optional): Object generation to target when listing ACLs.

    Returns:
        CommandResults: Human-readable table of ACL entries and machine outputs under
        'GCP.Storage.BucketObjectPolicy'.
    """
    bucket_name = args.get("bucket_name", "")
    object_name = args.get("object_name", "")

    generation = arg_to_number(args.get("generation"))

    storage = GCPServices.STORAGE.build(creds)

    # UBLA short-circuit
    if _is_ubla_enabled(storage, bucket_name):
        demisto.debug(f"Uniform Bucket-Level Access is enabled for {bucket_name} bucket. return the bucket policy")
        return storage_bucket_policy_list(
            creds=creds,
            args=args,
            outputs_prefix="GCP.Storage.BucketObjectPolicy",
            object_name=object_name,
        )

    # Build request parameters
    request_params = {"bucket": bucket_name, "object": object_name, "generation": generation}
    remove_nulls_from_dictionary(request_params)

    demisto.debug(f"[GCP: storage_bucket_object_policy_list] Request params: {request_params}")
    try:
        response = (
            storage.objectAccessControls()  # pylint: disable=E1101
            .list(bucket=bucket_name, object=object_name)
            .execute()
        )
    except HttpError as e:
        if _is_ubla_error(e):
            demisto.debug(f"Uniform Bucket-Level Access is enabled for {bucket_name} bucket. return the bucket policy")
            return storage_bucket_policy_list(
                creds=creds,
                args=args,
                outputs_prefix="GCP.Storage.BucketObjectPolicy",
                object_name=object_name,
            )
        demisto.debug(f"[GCP: storage_bucket_object_policy_get] HttpError status={getattr(e.resp, 'status', None)}")
        raise
    # Build human readable output: summary + bindings table
    items = response.get("items", [])
    hr = tableToMarkdown(f"Policy for object: {object_name} in bucket: {bucket_name}", items, headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.BucketObjectPolicy",
        outputs=items,
        raw_response=response,
        outputs_key_field=["Bucket", "Key"],
    )


def storage_bucket_object_policy_set(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Sets object-level ACLs using the GCS ObjectAccessControls API.

    This command applies one or more ACL entries to a specific object. For each provided entry
    (with fields like 'entity' and 'role'), it attempts an idempotent update first and falls back
    to insert if the ACL entry does not exist. If Uniform Bucket-Level Access (UBLA) is enabled
    on the bucket, object-level ACLs are not permitted and the command returns guidance to use
    bucket-level IAM instead.

    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]):
            - bucket_name (str): Target bucket name.
            - object_name (str): Target object name.
            - policy (JSON str): A single ACL object or a JSON array of ACL objects. Each object must
              include 'entity' and 'role' (e.g., {"entity": "allUsers", "role": "READER"}).
            - generation (Number, optional): Object generation to target.

    Returns:
        CommandResults: Human-readable table of applied ACL entries and machine outputs under
        'GCP.Storage.BucketObjectPolicy'.
    """
    bucket_name = args.get("bucket_name", "")
    object_name = args.get("object_name", "")
    policy_json = args.get("policy", {})
    generation = arg_to_number(args.get("generation"))

    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as e:
        raise DemistoException(f"Invalid JSON format for policy: {str(e)}")

    storage = GCPServices.STORAGE.build(creds)

    # UBLA short-circuit
    ubla_message = f"""Uniform Bucket-Level Access (UBLA) is enabled for the bucket: {bucket_name}.
    Use `gcp-storage-bucket-policy-set` at the bucket level instead."""
    if _is_ubla_enabled(storage, bucket_name):
        return CommandResults(readable_output=ubla_message)

    # Interpret policy as one or many ObjectAccessControls entries
    entries: list[dict[str, Any]]
    if isinstance(policy, list):
        entries = policy
    elif isinstance(policy, dict):
        entries = [policy]
    else:
        raise DemistoException("'policy' must be a JSON object or an array of objects representing ACL entries.")

    results: list[dict[str, Any]] = []
    for idx, entry in enumerate(entries):
        entity = entry.get("entity")
        role = entry.get("role")
        if not entity or not role:
            raise DemistoException("Each ACL entry must include 'entity' and 'role'.")

        # Try update first (idempotent). If it doesn't exist, fallback to insert.
        update_params = {"bucket": bucket_name, "object": object_name, "entity": entity, "body": entry, "generation": generation}
        remove_nulls_from_dictionary(update_params)
        try:
            demisto.debug(f"[GCP: storage_bucket_object_policy_set] Updating ACL #{idx+1} for entity {entity}")
            resp = storage.objectAccessControls().patch(**update_params).execute()  # pylint: disable=E1101
            results.append(resp)
            continue
        except Exception as e:
            # If update fails (e.g., 404), attempt insert. If UBLA error detected, short-circuit.
            if isinstance(e, HttpError) and _is_ubla_error(e):
                return CommandResults(readable_output=ubla_message)
            demisto.debug(f"[GCP: storage_bucket_object_policy_set] Update failed for entity {entity}: {e}. Trying insert.")
            try:
                insert_params = {"bucket": bucket_name, "object": object_name, "body": entry, "generation": generation}
                remove_nulls_from_dictionary(insert_params)
                resp = storage.objectAccessControls().insert(**insert_params).execute()  # pylint: disable=E1101
                results.append(resp)
            except Exception as ie:
                if isinstance(ie, HttpError) and _is_ubla_error(ie):
                    return CommandResults(readable_output=ubla_message)
                raise

    hr = tableToMarkdown(
        f"Object ACLs set for object: {object_name} in bucket: {bucket_name}",
        results if results else [{"message": "No ACL changes applied"}],
        removeNull=True,
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Storage.BucketObjectPolicy",
        outputs=results,
        raw_response=results,
        outputs_key_field="resourceId",
    )


def compute_firewall_insert(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Creates a new Google Cloud Compute Engine firewall rule.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The ID of the GCP project where the rule will be created.
            - resource_name (str): The name of the firewall rule.
            - description (str, optional): Description of the rule.
            - network (str, optional): The URL of the network for the rule.
            - priority (int, optional): Priority value for the rule (lower means higher priority).
            - source_ranges (str, optional): Comma-separated list of CIDR blocks for allowed sources.
            - destination_ranges (str, optional): Comma-separated list of CIDR blocks for destinations.
            - source_tags (str, optional): Comma-separated list of source tags.
            - target_tags (str, optional): Comma-separated list of target tags.
            - source_service_accounts (str, optional): Comma-separated list of source service accounts.
            - target_service_accounts (str, optional): Comma-separated list of target service accounts.
            - allowed (str, optional): Allowed protocols and ports (in JSON format).
            - denied (str, optional): Denied protocols and ports (in JSON format).
            - direction (str, optional): Direction of traffic ('INGRESS' or 'EGRESS').
            - log_config_enable (bool, optional): Whether to enable logging for this rule.
            - disabled (bool, optional): Whether the rule should be disabled upon creation.

    Returns:
        CommandResults: Object containing the operation details of the firewall insert request,
        with `GCP.Compute.Operations` context output.
    """
    project_id = args.get("project_id")
    resource_name = args.get("resource_name")
    body: dict[str, Any] = {"name": resource_name}

    if description := args.get("description"):
        body["description"] = description
    if network := args.get("network"):
        body["network"] = network
    if priority := args.get("priority"):
        body["priority"] = arg_to_number(priority)
    if sourceRanges := args.get("source_ranges"):
        body["sourceRanges"] = argToList(sourceRanges)
    if destinationRanges := args.get("destination_ranges"):
        body["destinationRanges"] = argToList(destinationRanges)
    if sourceTags := args.get("source_tags"):
        body["sourceTags"] = argToList(sourceTags)
    if targetTags := args.get("target_tags"):
        body["targetTags"] = argToList(targetTags)
    if sourceServiceAccounts := args.get("source_service_accounts"):
        body["sourceServiceAccounts"] = argToList(sourceServiceAccounts)
    if targetServiceAccounts := args.get("target_service_accounts"):
        body["targetServiceAccounts"] = argToList(targetServiceAccounts)
    if allowed := args.get("allowed"):
        body["allowed"] = parse_firewall_rule(allowed)
    if denied := args.get("denied"):
        body["denied"] = parse_firewall_rule(denied)
    if direction := args.get("direction"):
        body["direction"] = direction
    if logConfigEnable := args.get("log_config_enable"):
        body["logConfig"] = {"enable": argToBoolean(logConfigEnable)}
    if disabled := args.get("disabled"):
        body["disabled"] = argToBoolean(disabled)

    compute = GCPServices.COMPUTE.build(creds)
    demisto.debug(f"Firewall insert body for {resource_name} in project {project_id}: {body}")
    response = (
        compute.firewalls()  # pylint: disable=E1101
        .insert(project=project_id, body=body)
        .execute()
    )

    hr = tableToMarkdown(
        "Google Cloud Compute Firewall Rule Insert Operation Started Successfully",
        t=response,
        headers=OPERATION_TABLE,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(readable_output=hr, outputs_prefix="GCP.Compute.Operations", outputs=response, raw_response=response)


def compute_firewall_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Lists all firewall rules in the specified GCP project.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - limit (int, optional): Maximum number of results to return (1–500). Defaults to API default.
            - page_token (str, optional): Token to retrieve the next page of results.
            - filter (str, optional): Expression for filtering the listed resources.

    Returns:
        CommandResults: Object containing the list of firewall rules in the project,
        with `GCP.Compute.Firewall` and `GCP.Compute.FirewallNextToken` context outputs.
    """
    project_id = args.get("project_id")
    limit = arg_to_number(args.get("limit"))
    page_token = args.get("page_token")
    flt = args.get("filter")
    validate_limit(limit)

    params: dict[str, Any] = {
        "project": project_id,
        "maxResults": limit,
        "pageToken": page_token,
        "filter": flt,
    }
    remove_nulls_from_dictionary(params)

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.firewalls().list(**params).execute()  # pylint: disable=E1101
    items = response.get("items", [])
    next_token = response.get("nextPageToken")
    headers = ["name", "id", "direction", "priority", "sourceRanges", "targetTags", "creationTimestamp", "network", "disabled"]
    metadata = (
        "Run the following command to retrieve the next batch of firewalls:\n"
        f"!gcp-compute-firewall-list project_id={project_id} page_token={next_token}"
        if next_token
        else None
    )
    readable_output = tableToMarkdown(
        "GCP Compute Firewalls",
        items,
        headers=headers,
        headerTransform=pascalToSpace,
        metadata=metadata,
    )

    outputs = {
        "GCP.Compute.Firewall(val.name && val.name == obj.name)": items,
        "GCP.Compute(true)": {"FirewallNextToken": next_token},
    }
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=items,
    )


def compute_firewall_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves details of a specific Google Cloud firewall rule.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - resource_name (str): The name of the firewall rule to retrieve.

    Returns:
        CommandResults: Object containing the firewall rule details under `GCP.Compute.Firewall`.
        If the firewall rule is not found, returns a human-readable message.
    """
    project_id = args.get("project_id")
    resource_name = args.get("resource_name")
    compute = GCPServices.COMPUTE.build(creds)
    try:
        response = compute.firewalls().get(project=project_id, firewall=resource_name).execute()  # pylint: disable=E1101
    except HttpError as e:
        reason = e._get_reason()
        if e.resp.status == 404 and ("The resource" and "was not found" in reason):
            return CommandResults(readable_output=f"Firewall '{resource_name}' not found in project '{project_id}'")
        raise
    demisto.debug(f"Firewall get response for {project_id}: \n{response}")
    hr = tableToMarkdown(
        f"GCP Compute Firewall: {resource_name}",
        response,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Compute.Firewall",
        outputs=response,
        outputs_key_field="name",
        raw_response=response,
    )


def compute_snapshots_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Lists all Compute Engine snapshots in a specified GCP project.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - limit (int, optional): Maximum number of results to return (1–500).
            - page_token (str, optional): Token for pagination.
            - filter (str, optional): Expression for filtering listed snapshots.

    Returns:
        CommandResults: Object containing a list of snapshot details under `GCP.Compute.Snapshot`
        and pagination token under `GCP.Compute.SnapshotNextToken`.
    """
    project_id = args.get("project_id")
    limit = arg_to_number(args.get("limit"))
    page_token = args.get("page_token")
    flt = args.get("filter")

    params: dict[str, Any] = {"project": project_id}
    validate_limit(limit)
    if limit:
        params["maxResults"] = limit
    if page_token:
        params["pageToken"] = page_token
    if flt:
        params["filter"] = flt

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.snapshots().list(**params).execute()  # pylint: disable=E1101
    demisto.debug(f"GCP Compute Snapshots \nresponse: \n{response}")
    items = response.get("items", [])
    next_token = response.get("nextPageToken")
    metadata = (
        "Run the following command to retrieve the next batch of snapshots:\n"
        f"!gcp-compute-snapshots-list project_id={project_id} page_token={next_token}"
        if next_token
        else None
    )
    headers = ["name", "status", "creationTimestamp"]
    hr = tableToMarkdown(
        "GCP Compute Snapshots",
        items,
        headers=headers,
        removeNull=True,
        metadata=metadata,
        headerTransform=pascalToSpace,
    )
    outputs = {
        "GCP.Compute.Snapshot(val.id && val.id == obj.id)": items,
        "GCP.Compute(true)": {"SnapshotNextToken": next_token},
    }
    return CommandResults(readable_output=hr, outputs=outputs, raw_response=response)


def compute_snapshot_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves a specific Compute Engine snapshot by name.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - resource_name (str): The name of the snapshot to retrieve.

    Returns:
        CommandResults: Object containing the snapshot details under `GCP.Compute.Snapshot`.
        If not found, returns a readable message instead of raising an exception.
    """
    project_id = args.get("project_id")
    resource_name = args.get("resource_name")
    compute = GCPServices.COMPUTE.build(creds)
    try:
        response = compute.snapshots().get(project=project_id, snapshot=resource_name).execute()  # pylint: disable=E1101
    except HttpError as e:
        reason = e._get_reason()
        if e.resp.status == 404 and ("The resource" and "was not found" in reason):
            return CommandResults(readable_output=f"Snapshot '{resource_name}' not found in project '{project_id}'")
        raise
    demisto.debug(f"Snapshot get response for {project_id}: \n{response}")

    hr = tableToMarkdown(
        f"GCP Compute Snapshot: {resource_name}",
        response,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Compute.Snapshot",
        outputs=response,
        outputs_key_field="id",
        raw_response=response,
    )


def _collect_instance_ips(instance: dict[str, Any]) -> tuple[list[str], list[str]]:
    """
    Collects internal and external IP addresses from a Compute Engine instance.

    Args:
        instance (dict): The instance resource object.

    Returns:
        Tuple[List[str], List[str]]: A tuple containing two lists -
        the first for internal IPs and the second for external IPs.
    """
    internal_ips: list[str] = []
    external_ips: list[str] = []
    for nic in instance.get("networkInterfaces", []) or []:
        if ip := nic.get("networkIP"):
            internal_ips.append(ip)
        for ac in nic.get("accessConfigs", []) or []:
            if eip := ac.get("natIP"):
                external_ips.append(eip)
    return internal_ips, external_ips


def _match_instance_by_ip(instance: dict[str, Any], ip_address: str, match_external: bool) -> tuple[bool, str]:
    """
    Checks if the given IP address matches the instance IPs based on the match mode.

    Args:
        instance (dict): The instance resource object.
        ip_address (str): The IP address to match.
        match_external (bool): Whether to check external IPs (True) or internal IPs (False).

    Returns:
        Tuple[bool, str]: A tuple indicating whether a match was found,
        and the match type ('internal', 'external', or 'none').
    """
    internal_ips, external_ips = _collect_instance_ips(instance)
    if match_external:
        return (ip_address in external_ips, "external" if ip_address in external_ips else "none")
    return (ip_address in internal_ips, "internal" if ip_address in internal_ips else "none")


def compute_instances_aggregated_list_by_ip(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Lists Compute Engine instances aggregated across all zones and filters them by IP address.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - ip_address (str): The IP address to match.
            - match_external (bool, optional): Whether to search external IPs (default is False).
            - limit (int, optional): Maximum number of results per API call.
            - page_token (str, optional): Token for pagination.

    Returns:
        CommandResults: Object containing matched instances under `GCP.Compute.Instance`,
        including match type and matched IP, along with readable summary table.
    """
    project_id = args.get("project_id")
    ip_address = args.get("ip_address", "")
    match_external = argToBoolean(args.get("match_external", "false"))
    limit = arg_to_number(args.get("limit"))
    page_token = args.get("page_token")
    validate_limit(limit)

    params: dict[str, Any] = {"project": project_id}
    if limit:
        params["maxResults"] = limit
    if page_token:
        params["pageToken"] = page_token

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.instances().aggregatedList(**params).execute()  # pylint: disable=E1101
    demisto.debug(f"Instances aggregated list response for {project_id}: \n{response}")

    matched: list[dict[str, Any]] = []
    hr_items: list[dict[str, str]] = []
    for scope in response.get("items", {}).values():
        for inst in scope.get("instances", []) or []:
            is_match, match_type = _match_instance_by_ip(inst, ip_address, match_external)
            if is_match:
                internal_ips, external_ips = _collect_instance_ips(inst)
                matched.append(inst)
                hr_items.append(
                    {
                        "name": inst.get("name"),
                        "id": inst.get("id"),
                        "status": inst.get("status"),
                        "zone": inst.get("zone"),
                        "networkIP": ", ".join(internal_ips),
                        "accessConfigs.natIP": ", ".join(external_ips),
                        "matchType": match_type,
                        "matchedIP": ip_address,
                    }
                )

    hr_headers = ["name", "id", "status", "zone", "networkIP", "accessConfigs.natIP", "matchType", "matchedIP"]
    hr = tableToMarkdown(
        "GCP Compute Instances (filtered by IP)",
        hr_items,
        headers=hr_headers,
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(
        readable_output=hr,
        outputs_prefix="GCP.Compute.Instance",
        outputs=matched,
        outputs_key_field="id",
        raw_response=response,
    )


def compute_network_tag_set(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Adds or updates network tags for a Compute Engine VM instance.

    Args:
        creds (Credentials): Authorized GCP credentials used to access the Compute Engine API.
        args (dict): Command arguments including:
            - project_id (str): The GCP project ID.
            - zone (str): The zone of the instance (e.g., "us-central1-a").
            - resource_name (str): The name of the VM instance.
            - tag (str): The tag or list of tags to apply.
            - add_tag (bool, optional): Whether to merge with existing tags (default: True).
            - tags_fingerprint (str): The current fingerprint of the instance's tags,
              required for updates.

    Returns:
        CommandResults: Object containing operation details under `GCP.Compute.Operations`,
        and a readable message confirming tag update.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    resource_name = args.get("resource_name")
    tags = argToList(args.get("tag"))
    add_tag = argToBoolean(args.get("add_tag", "true"))

    compute = GCPServices.COMPUTE.build(creds)
    fingerprint = args.get("tags_fingerprint", "")

    if add_tag:
        instance = compute.instances().get(project=project_id, zone=zone, instance=resource_name).execute()  # pylint: disable=E1101
        demisto.debug(f"Instance get response for {project_id}: \n{instance}")
        tags_obj = instance.get("tags", {})
        items = tags_obj.get("items", []) or []
        if tags not in items:
            tags.extend(items)

    body = {"items": tags, "fingerprint": fingerprint}

    response = (
        compute.instances()  # pylint: disable=E1101
        .setTags(project=project_id, zone=zone, instance=resource_name, body=body)
        .execute()
    )

    demisto.debug(f"Add network tag response for {project_id}: \n{response}")
    new_tag = args.get("tag")
    readable_output = f"Added '{new_tag}' tag to instance {resource_name} successfully\n" f"The full network tag list is: {tags}"

    return CommandResults(
        readable_output=readable_output,
        outputs=response,
        outputs_prefix=" GCP.Compute.Operations",
        outputs_key_field="id",
        raw_response=response,
    )


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


def gcp_compute_instances_list_command(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the list of instances contained within the specified zone.
    Args:
        creds (Credentials): GCP credentials with admin directory security scope.
        args (dict[str, Any]): Must include 'resource_name'.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    limit = (arg_to_number(args.get("limit")) or 50) if args.get("limit", "50") != "0" else 0
    filters = args.get("filters")
    order_by = args.get("order_by")
    page_token = args.get("page_token")

    validate_limit(limit)

    compute = GCPServices.COMPUTE.build(creds)
    response = (
        compute.instances()
        .list(project=project_id, zone=zone, filter=filters, maxResults=limit, orderBy=order_by, pageToken=page_token)
        .execute()
    )

    next_page_token = response.get("nextPageToken", "")
    metadata = (
        "Run the following command to retrieve the next batch of instances:\n"
        f"!gcp-compute-instances-list project_id={project_id} zone={zone} page_token={next_page_token}"
        if next_page_token
        else None
    )
    if limit != 50:
        metadata = f"{metadata} {limit=}"

    if next_page_token:
        response["InstancesNextPageToken"] = response.pop("nextPageToken")

    if response.get("items"):
        response["Instances"] = response.pop("items")

    hr_data = []
    for instance in response.get("Instances", [{}]):
        d = {
            "id": instance.get("id"),
            "name": instance.get("name"),
            "kind": instance.get("kind"),
            "creationTimestamp": instance.get("creationTimestamp"),
            "description": instance.get("description"),
            "status": instance.get("status"),
            "machineType": instance.get("machineType"),
            "zone": instance.get("zone"),
        }
        hr_data.append(d)

    readable_output = tableToMarkdown(
        "GCP Instances",
        hr_data,
        headers=["id", "name", "kind", "creationTimestamp", "description", "status", "machineType", "zone"],
        headerTransform=pascalToSpace,
        removeNull=True,
        metadata=metadata,
    )

    outputs = {
        "GCP.Compute.Instances(val.id && val.id == obj.id)": response.get("Instances", []),
        "GCP.Compute(true)": {
            "InstancesNextPageToken": response.get("InstancesNextPageToken"),
            "InstancesSelfLink": response.get("selfLink"),
            "InstancesWarning": response.get("warning"),
        },
    }
    remove_empty_elements(outputs)
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=response,
    )


def gcp_compute_instance_get_command(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Returns the specified Instance resource.
    Args:
        creds (Credentials): GCP credentials with admin directory security scope.
        args (dict[str, Any]): Must include 'resource_name'.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    instance = args.get("instance")

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.instances().get(project=project_id, zone=zone, instance=instance).execute()

    hr_data = {
        "id": response.get("id"),
        "name": response.get("name"),
        "kind": response.get("kind"),
        "creationTimestamp": response.get("creationTimestamp"),
        "description": response.get("description"),
        "status": response.get("status"),
        "machineType": response.get("machineType"),
        "labels": response.get("labels"),
        "labelFingerprint": response.get("labelFingerprint"),
    }
    readable_output = tableToMarkdown(
        f"GCP Instance {instance} from zone {zone}",
        hr_data,
        headers=["id", "name", "kind", "creationTimestamp", "description", "status", "machineType", "labels", "labelFingerprint"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Instances",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_instance_label_set_command(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Sets labels on an instance.
    Args:
        creds (Credentials): GCP credentials with admin directory security scope.
        args (dict[str, Any]): Must include 'resource_name'.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    project_id = args.get("project_id")
    zone = extract_zone_name(args.get("zone"))
    instance = args.get("instance")
    label_fingerprint = args.get("label_fingerprint", "")
    add_labels = argToBoolean(args.get("add_labels", False))
    labels = parse_labels(args.get("labels", ""))
    demisto.debug(f"The parsed {labels=}")

    current_labels = {}
    if add_labels:
        instance_info = gcp_compute_instance_get_command(creds, args).outputs
        if isinstance(instance_info, dict):
            current_labels = instance_info.get("labels", {})
            demisto.debug(f"Adding the new labels {labels=} to the current ones {current_labels}")

    body = {"labels": current_labels | labels, "labelFingerprint": label_fingerprint}

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.instances().setLabels(project=project_id, zone=zone, instance=instance, body=body).execute()

    data_res = {
        "status": response.get("status"),
        "kind": response.get("kind"),
        "name": response.get("name"),
        "id": response.get("id"),
        "progress": response.get("progress"),
        "operationType": response.get("operationType"),
    }

    headers = ["id", "name", "kind", "status", "progress", "operationType"]

    readable_output = tableToMarkdown(f"GCP instance {instance} labels update", data_res, headers=headers, removeNull=True)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Operations",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


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


def validate_limit(limit):
    """
    Validates that the provided limit argument is within the allowed range.

    Args:
        limit (int): The limit value to validate.

    Raises:
        DemistoException: If the limit is not set or is outside the allowed range (1-500 inclusive).
    """
    if limit > 500 or limit < 1:
        raise DemistoException(
            f"The acceptable values of the argument limit are 1 to 500, inclusive. Currently the value is {limit}"
        )


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
        HealthCheckError or None: HealthCheckError if there's an issue, None if successful.
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
    for _, success, error_message in service_results:
        if not success and "Permission" not in error_message:
            return HealthCheckError(
                account_id=project_id,
                connector_id=connector_id,
                message=f"Sample check failed for account {project_id}. Error: {error_message}",
                error_type=ErrorType.CONNECTIVITY_ERROR,
            )
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


def gcp_compute_network_get_command(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Returns the specified network.
    Args:
        creds (Credentials): GCP credentials with admin directory security scope.
        args (dict[str, Any]): _description_
    Returns:
        CommandResults: _description_
    """
    project = args.get("project_id")
    network = args.get("network")

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.networks().get(project=project, network=network).execute()

    data_res = {
        "name": response.get("name"),
        "id": response.get("id"),
        "creationTimestamp": response.get("creationTimestamp"),
        "description": response.get("description"),
    }

    headers = ["id", "name", "creationTimestamp", "description"]

    readable_output = tableToMarkdown(
        f"GCP network {network}", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Networks",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_image_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Returns the specified image.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): _description_
    Returns:
        CommandResults: _description_
    """
    project = args.get("project_id")
    image = args.get("image")

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.images().get(project=project, image=image).execute()

    data_res = {
        "id": response.get("id"),
        "name": response.get("name"),
        "creationTimestamp": response.get("creationTimestamp"),
        "description": response.get("description"),
    }
    headers = ["id", "name", "creationTimestamp", "description"]

    readable_output = tableToMarkdown(
        f"GCP image {image}", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Images",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_region_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Get a specified region resource.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): _description_
    Returns:
        CommandResults: _description_
    """
    project = args.get("project_id")
    region = args.get("region")

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.regions().get(project=project, region=region).execute()

    data_res = {"id": response.get("id"), "name": response.get("name"), "status": response.get("status")}
    headers = ["id", "name", "status"]

    readable_output = tableToMarkdown(
        f"GCP region {region}", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Regions",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_instance_group_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Returns the specified instance group.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): _description_
    Returns:
        CommandResults: _description_
    """
    project = args.get("project_id")
    instance_group = args.get("instance_group")
    zone = args.get("zone")

    compute = GCPServices.COMPUTE.build(creds)
    response = compute.instanceGroups().get(project=project, zone=zone, instanceGroup=instance_group).execute()

    data_res = {
        "id": response.get("id"),
        "name": response.get("name"),
        "zone": response.get("zone"),
        "network": response.get("network"),
    }
    headers = ["id", "name", "zone", "network"]

    readable_output = tableToMarkdown(
        f"GCP instanceGroups {instance_group}", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.InstanceGroups",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_zone_get(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Get a specified zone resource.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): _description_
    Returns:
        CommandResults: _description_
    """
    project = args.get("project_id")
    zone = args.get("zone")
    compute = GCPServices.COMPUTE.build(creds)
    response = compute.zones().get(project=project, zone=zone).execute()
    data_res = {
        "status": response.get("status"),
        "name": response.get("name"),
        "id": response.get("id"),
    }

    headers = ["id", "name", "status"]

    readable_output = tableToMarkdown(
        f"GCP zone {zone}", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Zones",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_network_insert(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Creates a subnet-mode network in the specified project using the data provided.
    Args:
        creds (Credentials): GCP credentials.
        args (dict[str, Any]): Arguments including:
            - name: Name of the network
            - description: Optional description
            - auto_create_sub_networks: "true"/"false" (optional, defaults to True)
            - routing_config_routing_mode: "REGIONAL" or "GLOBAL" (optional)
            - project_id: GCP project ID
    Returns:
        CommandResults: The result of the network creation operation.
    """
    config = {}

    # Name (required)
    if args.get("name"):
        config["name"] = args.get("name", "")
    else:
        raise ValueError("The 'name' argument is required to create a network.")

    # Description (optional)
    if args.get("description"):
        config["description"] = args.get("description")

    # Auto-create subnets (default to True)
    auto_create_sub_networks = argToBoolean(args.get("autoCreateSubnetworks", True))
    if auto_create_sub_networks is not None:
        config["autoCreateSubnetworks"] = auto_create_sub_networks
    else:
        config["autoCreateSubnetworks"] = True  # default to subnet-mode network

    # Optional routing config
    if args.get("routing_config_routing_mode"):
        config["routingConfig"] = {"routingMode": args["routing_config_routing_mode"]}

    # Project ID
    project = args.get("project_id")
    # Build the compute service
    compute = GCPServices.COMPUTE.build(creds)

    # Execute the insert network request
    response = compute.networks().insert(project=project, body=config).execute()

    # Prepare output
    data_res = {
        "status": response.get("status"),
        "kind": response.get("kind"),
        "name": response.get("name"),
        "id": response.get("id"),
        "progress": response.get("progress"),
        "operationType": response.get("operationType"),
    }

    headers = ["status", "kind", "id", "progress", "operationType", "name"]
    readable_output = tableToMarkdown(
        "Google Cloud Compute Network Insert", data_res, headers=headers, removeNull=True, headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Operations",
        outputs_key_field="id",
        outputs=response,
        raw_response=response,
    )


def gcp_compute_networks_list(creds: Credentials, args: dict[str, Any]) -> CommandResults:
    """
    Retrieves the list of networks available to the specified project.
    """
    project = args.get("project_id")
    limit = (arg_to_number(args.get("limit")) or 50) if args.get("limit", "50") != "0" else 0
    filters = args.get("filters")
    order_by = args.get("order_by")
    page_token = args.get("page_token")

    validate_limit(limit)

    data_res = []
    compute = GCPServices.COMPUTE.build(creds)
    response = (
        compute.networks()
        .list(
            project=project,
            filter=filters,
            maxResults=limit,
            orderBy=order_by,
            pageToken=page_token,
        )
        .execute()
    )

    next_page_token = response.get("nextPageToken")

    metadata = (
        "Run the following command to retrieve the next batch of networks:\n"
        f"!gcp-compute-networks-list project_id={project} page_token={next_page_token}"
        if next_page_token
        else None
    )

    if limit != 50:
        metadata = f"{metadata} {limit=}"

    if next_page_token:
        response["NetworksNextPageToken"] = response.pop("nextPageToken")

    if response.get("items"):
        response["Networks"] = response.pop("items")

    for item in response.get("Networks", [{}]):
        data_res_item = {
            "name": item.get("name"),
            "id": item.get("id"),
            "creationTimestamp": item.get("creationTimestamp"),
            "status": item.get("status"),
        }
        data_res.append(data_res_item)

    headers = ["name", "id", "creationTimestamp", "status"]
    readable_output = tableToMarkdown(
        "Google Cloud Compute Networks",
        data_res,
        headers=headers,
        removeNull=True,
        metadata=metadata,
        headerTransform=pascalToSpace,
    )

    outputs = {
        "GCP.Compute.Networks(val.id && val.id == obj.id)": response.get("Networks", []),
        "GCP.Compute(true)": {
            "NetworksNextPageToken": response.get("NetworksNextPageToken"),
            "NetworksSelfLink": response.get("selfLink"),
            "outputsWarning": response.get("warning"),
        },
    }
    remove_empty_elements(outputs)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="GCP.Compute.Networks",
        outputs_key_field="id",
        outputs=outputs,
        raw_response=response,
    )


def main():  # pragma: no cover
    """
    Main function to route commands and execute logic.

    This function processes the incoming command, sets up the appropriate credentials,
    and routes the execution to the corresponding handler function.
    """
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    try:
        command_map: dict[str, Callable[[Any, dict], Any]] = {
            "test-module": test_module,
            # Compute Engine commands
            "gcp-compute-firewall-patch": compute_firewall_patch,
            "gcp-compute-firewall-insert": compute_firewall_insert,
            "gcp-compute-firewall-list": compute_firewall_list,
            "gcp-compute-firewall-get": compute_firewall_get,
            "gcp-compute-snapshots-list": compute_snapshots_list,
            "gcp-compute-snapshot-get": compute_snapshot_get,
            "gcp-compute-instances-aggregated-list-by-ip": compute_instances_aggregated_list_by_ip,
            "gcp-compute-network-tag-set": compute_network_tag_set,
            "gcp-compute-subnet-update": compute_subnet_update,
            "gcp-compute-instance-service-account-set": compute_instance_service_account_set,
            "gcp-compute-instance-service-account-remove": compute_instance_service_account_remove,
            "gcp-compute-instance-start": compute_instance_start,
            "gcp-compute-instance-stop": compute_instance_stop,
            "gcp-compute-instances-list": gcp_compute_instances_list_command,
            "gcp-compute-instance-get": gcp_compute_instance_get_command,
            "gcp-compute-instance-labels-set": gcp_compute_instance_label_set_command,
            "gcp-compute-network-get": gcp_compute_network_get_command,
            "gcp-compute-image-get": gcp_compute_image_get,
            "gcp-compute-instance-group-get": gcp_compute_instance_group_get,
            "gcp-compute-region-get": gcp_compute_region_get,
            "gcp-compute-zone-get": gcp_compute_zone_get,
            "gcp-compute-networks-list": gcp_compute_networks_list,
            "gcp-compute-network-insert": gcp_compute_network_insert,
            # Storage commands
            "gcp-storage-bucket-list": storage_bucket_list,
            "gcp-storage-bucket-get": storage_bucket_get,
            "gcp-storage-bucket-objects-list": storage_bucket_objects_list,
            "gcp-storage-bucket-policy-list": storage_bucket_policy_list,
            "gcp-storage-bucket-policy-set": storage_bucket_policy_set,
            "gcp-storage-bucket-object-policy-list": storage_bucket_object_policy_list,
            "gcp-storage-bucket-object-policy-set": storage_bucket_object_policy_set,
            "gcp-storage-bucket-policy-delete": storage_bucket_policy_delete,
            "gcp-storage-bucket-metadata-update": storage_bucket_metadata_update,
            # Container (GKE) commands
            "gcp-container-cluster-security-update": container_cluster_security_update,
            # IAM commands
            "gcp-iam-project-policy-binding-remove": iam_project_policy_binding_remove,
            # Quick Actions - Firewall
            "gcp-compute-firewall-patch-disable-gcp-default-firewall-rule-quick-action": compute_firewall_patch,
            # Quick Actions - Storage Bucket Policy
            "gcp-storage-bucket-policy-delete-remove-allusers-access-quick-action": storage_bucket_policy_delete,
            "gcp-storage-bucket-policy-delete-remove-AllAuthenticatedUser-access-quick-action": storage_bucket_policy_delete,
            "gcp-storage-bucket-policy-delete-make-gcp-bucket-private-quick-action": storage_bucket_policy_delete,
            # Quick Actions - Subnet Update
            "gcp-compute-subnet-update-enable-gcp-subnet-flow-logs-quick-action": compute_subnet_update,
            "gcp-compute-subnet-update-enable-private-access-quick-action": compute_subnet_update,
            # Quick Actions - Container Cluster Security
            "gcp-container-cluster-security-update-enable-gke-cluster-intra-node-visibility-quick-action": container_cluster_security_update,  # noqa E501
            "gcp-container-cluster-security-update-enable-master-authorized-networks-on-gke-quick-action": container_cluster_security_update,  # noqa E501
            # Quick Actions - Storage Bucket Metadata
            "gcp-storage-bucket-metadata-update-enable-GCP-bucket-versioning-quick-action": storage_bucket_metadata_update,
            "gcp-storage-bucket-metadata-update-set-GCP-bucket-access-to-uniform-quick-action": storage_bucket_metadata_update,
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

    except HttpError as e:
        project_id = args.get("project_id") or args.get("folder_id") or "N/A"
        handle_permission_error(e, project_id, command)

    except Exception as e:
        return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
