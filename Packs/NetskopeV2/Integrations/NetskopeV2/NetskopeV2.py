import json
import re
import traceback
from typing import Any, NamedTuple

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DEVICE_API_USER_AGENT = "Netskope-XSOAR-Integration-1.0"
TAG_DEVICE_BATCH_SIZE = 100
MAX_TAG_LENGTH = 80
MAX_TAGS_PER_DEVICE = 5
TAG_NAME_PATTERN = re.compile(r"^[A-Za-z0-9\- ]+$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

PROFILE_NAME_MAX_LENGTH = 100
PROFILE_DESCRIPTION_MAX_LENGTH = 200
CHANGE_NOTE_MAX_LENGTH = 100
VALUES_OP_MAX_ITEMS = 10
DEPLOY_MAX_IDS = 50
DESTINATION_PROFILE_TYPES = ("regex", "sensitive", "insensitive")

URL_LOOKUP_MAX_URLS = 100
URL_LOOKUP_CATEGORIES = ("casb", "swg")

# Per the API spec, /api/v2/atp/scans/filescan expects a password-protected .zip whose one member
# file is one of these types - reject anything else before wasting a call (max 1000/day).
ALLOWED_FILE_SCAN_EXTENSIONS = ("zip", "exe", "pdf", "doc", "xls", "ppt", "rtf")


class ProfileResourceConfig(NamedTuple):
    outputs_prefix: str
    supports_type: bool
    supports_index_removal: bool


# "destinations" (Destination Profiles - URL/domain match lists) and "networks" (Network Profiles -
# IP/CIDR/range match lists) share an (almost) identical CRUD + interactive/deploy/revert/versions API
# shape. Only destination profiles have a "type" field, label_ids, index-based value removal, and the
# URL List migration endpoints.
PROFILE_RESOURCE_CONFIG = {
    "destinations": ProfileResourceConfig(
        outputs_prefix="Netskope.DestinationProfile", supports_type=True, supports_index_removal=True
    ),
    "networks": ProfileResourceConfig(
        outputs_prefix="Netskope.NetworkProfile", supports_type=False, supports_index_removal=False
    ),
}


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def __init__(self, base_url, verify, proxy, headers, api_key, api_v1_token=None):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)
        self._api_key = api_key
        self._api_v1_token = api_v1_token

    def _device_api_headers(self):
        # The Device Classification / Device Tags APIs (beta) require Bearer auth + a User-Agent,
        # unlike the policy/urllist APIs which use the Netskope-Api-Token header. Passing headers
        # here replaces self._headers entirely for the call (BaseClient does not merge).
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": DEVICE_API_USER_AGENT,
        }

    def get_lists(self):
        return self._http_request(method="GET", url_suffix="/api/v2/policy/urllist")

    def get_list(self, list_id):
        return self._http_request(method="GET", url_suffix=f"/api/v2/policy/urllist/{list_id}")

    def patch_list(self, list_id, url_list_object, action):
        return self._http_request(
            method="PATCH", url_suffix=f"/api/v2/policy/urllist/{list_id}/{action}", json_data=url_list_object
        )

    def replace_url_list(self, list_id, url_list_object):
        return self._http_request(method="PUT", url_suffix=f"/api/v2/policy/urllist/{list_id}", json_data=url_list_object)

    def deploy_lists(self):
        return self._http_request(method="POST", url_suffix="/api/v2/policy/urllist/deploy")

    def list_device_classification_tags(self):
        return self._http_request(
            method="GET", url_suffix="/api/v2/deviceclassification/tags", headers=self._device_api_headers()
        )

    def create_device_classification_tags(self, tags):
        return self._http_request(
            method="POST", url_suffix="/api/v2/deviceclassification/tags", json_data=tags, headers=self._device_api_headers()
        )

    def create_device_classification_rules(self, rules):
        # Confirmed against the live API: a successful create returns 201 with an empty body (no JSON), unlike the
        # documented example response ({"status": true, "data": [...]})  -- request resp_type="response" and let the
        # caller decide how to interpret a body that may or may not be present.
        return self._http_request(
            method="POST",
            url_suffix="/api/v2/deviceclassification/rules",
            json_data=rules,
            headers=self._device_api_headers(),
            resp_type="response",
        )

    def find_devices(self, start_time, end_time, fields):
        params = {"starttime": start_time, "endtime": end_time, "fields": fields}
        return self._http_request(
            method="GET",
            url_suffix="/api/v2/events/datasearch/clientstatus",
            params=params,
            headers=self._device_api_headers(),
        )

    def create_device_tag(self, name, description=None):
        body: dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        return self._http_request(
            method="POST", url_suffix="/api/v2/devices/device/tags", json_data=body, headers=self._device_api_headers()
        )

    def get_device_tags(self, device_id):
        return self._http_request(
            method="POST",
            url_suffix="/api/v2/devices/device/tags/gettags",
            json_data={"device_id": device_id},
            headers=self._device_api_headers(),
        )

    def apply_device_tags(self, tag_ids, devices, device_classifications=None):
        body = {"tags": tag_ids, "devices": devices, "device_classifications": device_classifications or []}
        return self._http_request(
            method="POST",
            url_suffix="/api/v2/devices/device/tags/bulkreplace",
            json_data=body,
            headers=self._device_api_headers(),
        )

    def list_profiles(self, profile_type, params):
        return self._http_request(
            method="GET", url_suffix=f"/api/v2/profiles/{profile_type}", params=params, headers=self._device_api_headers()
        )

    def create_profile(self, profile_type, body, params=None):
        return self._http_request(
            method="POST",
            url_suffix=f"/api/v2/profiles/{profile_type}",
            json_data=body,
            params=params,
            headers=self._device_api_headers(),
        )

    def get_profile(self, profile_type, profile_id, params=None):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}",
            params=params,
            headers=self._device_api_headers(),
        )

    def update_profile(self, profile_type, profile_id, body, params=None):
        return self._http_request(
            method="PATCH",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}",
            json_data=body,
            params=params,
            headers=self._device_api_headers(),
        )

    def update_profile_values(self, profile_type, profile_id, operation):
        # Confirmed against the live API: like the deploy endpoint below, this can take longer than
        # the default timeout to respond even though the update itself succeeds server-side. Without
        # an extended timeout, a client-side timeout here leads to a retry against an operation that
        # has no server-side dedup, silently double-applying the append/remove.
        return self._http_request(
            method="PATCH",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}/values",
            json_data={"operation": operation},
            headers=self._device_api_headers(),
            timeout=125,
        )

    def delete_profile(self, profile_type, profile_id, params=None):
        return self._http_request(
            method="DELETE",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}",
            params=params,
            headers=self._device_api_headers(),
        )

    def deploy_profiles(self, profile_type, body):
        # The deploy endpoint has an extended (120s) read timeout per the API specification.
        return self._http_request(
            method="POST",
            url_suffix=f"/api/v2/profiles/{profile_type}/deploy",
            json_data=body,
            headers=self._device_api_headers(),
            timeout=125,
        )

    def revert_profile(self, profile_type, profile_id, params=None):
        return self._http_request(
            method="POST",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}/revert",
            params=params,
            headers=self._device_api_headers(),
        )

    def get_profile_applied_version(self, profile_type, profile_id):
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v2/profiles/{profile_type}/{profile_id}/versions/applied",
            headers=self._device_api_headers(),
        )

    def migrate_url_list_to_profile(self, url_list_id, destination_profile_name=None):
        body: dict[str, Any] = {"url_list_id": url_list_id}
        if destination_profile_name:
            body["destination_profile_name"] = destination_profile_name
        return self._http_request(
            method="POST",
            url_suffix="/api/v2/profiles/destinations/migrate",
            json_data=body,
            headers=self._device_api_headers(),
        )

    def migrate_url_list_into_profile(self, profile_id, url_list_id):
        return self._http_request(
            method="PATCH",
            url_suffix=f"/api/v2/profiles/destinations/{profile_id}/migrate",
            json_data={"url_list_id": url_list_id},
            headers=self._device_api_headers(),
        )

    def update_file_hash_list(self, name, hashes):
        # Netskope API v1 uses a separate tenant-wide token, sent as a query parameter. Keep the
        # client's default headers unchanged to match the working reference implementation.
        # Confirmed against the live API: this endpoint can take longer than the default timeout
        # to respond even though the update itself succeeds server-side - use an extended timeout,
        # same reasoning as the profiles deploy endpoint above.
        api_v1_token = (self._api_v1_token or "").strip()
        if not api_v1_token:
            raise DemistoException(
                "API v1 Token is required for netskopev2-update-file-hash-list. "
                "Configure the token generated under Settings > Tools > REST API v1."
            )

        body = {"name": name, "list": ",".join(hashes)}
        return self._http_request(
            method="POST",
            url_suffix="/api/v1/updateFileHashList",
            json_data=body,
            params={"token": api_v1_token},
            timeout=125,
        )

    def list_private_apps(self):
        return self._http_request(method="GET", url_suffix="/api/v2/steering/apps/private")

    def list_publishers(self, params=None):
        return self._http_request(method="GET", url_suffix="/api/v2/infrastructure/publishers", params=params)

    def create_private_app(self, body):
        return self._http_request(method="POST", url_suffix="/api/v2/steering/apps/private", json_data=body)

    def update_private_app(self, app_id, body):
        return self._http_request(method="PATCH", url_suffix=f"/api/v2/steering/apps/private/{app_id}", json_data=body)

    def replace_private_app(self, app_id, body):
        # PUT (Netskope's own docs call this "Update a private application", same wording as the
        # PATCH endpoint - "replace" is used here instead to keep this unambiguous from
        # update_private_app above). Full-resource replace, not a merge: the request schema has
        # no required fields, but any field you omit may be cleared rather than left unchanged.
        return self._http_request(method="PUT", url_suffix=f"/api/v2/steering/apps/private/{app_id}", json_data=body)

    def update_private_app_tags(self, app_ids, tags):
        body = {"ids": app_ids, "tags": tags}
        return self._http_request(method="PUT", url_suffix="/api/v2/steering/apps/private/tags", json_data=body)

    def delete_private_app(self, app_id):
        return self._http_request(method="DELETE", url_suffix=f"/api/v2/steering/apps/private/{app_id}")

    def submit_file_scan(self, file_path, file_name):
        with open(file_path, "rb") as f:
            return self._http_request(
                method="POST",
                url_suffix="/api/v2/atp/scans/filescan",
                params={"scantype": "sandbox"},
                files={"file": (file_name, f)},
            )

    def get_scan_report(self, jobid):
        # 200 = report ready, 202 = scan still in progress - both are <400 so BaseClient's
        # default ok_codes handling already treats them as success; no special casing needed.
        return self._http_request(method="GET", url_suffix=f"/api/v2/atp/scans/reports/{jobid}")

    def url_lookup(self, query):
        # Same auth style as the profiles/device APIs above (Bearer + User-Agent) rather than the
        # plain Netskope-Api-Token header used by the older urllist endpoints - this is a newer
        # v2 API (tag "nsiq"), matching the pattern already established for the other v2 APIs here.
        return self._http_request(
            method="POST", url_suffix="/api/v2/nsiq/urllookup", json_data={"query": query}, headers=self._device_api_headers()
        )


""" HELPER FUNCTIONS """


def create_url_list_object(urls, type_="exact"):
    return {"data": {"urls": urls, "type": type_}}


def get_list_id_from_name(client, list_name):
    # get list ID from lists, filtered by list name
    lists = client.get_lists()
    list_id = [listt.get("id") for listt in lists if listt.get("name") == list_name]
    if len(list_id) == 0:
        raise Exception(f'A Netskope URL List with the name "{list_name}" does not exist')
    elif len(list_id) == 1:
        return str(list_id[0])
    else:
        raise Exception(f'Found multiple Netskope URL Lists with the name "{list_name}"')


def validate_tag_name(name):
    if not name or len(name) > MAX_TAG_LENGTH:
        raise DemistoException(f'Tag name must be between 1 and {MAX_TAG_LENGTH} characters: "{name}"')
    if not TAG_NAME_PATTERN.match(name):
        raise DemistoException(f'Tag name may only contain alphanumeric characters, hyphens, and spaces: "{name}"')


def validate_description(description):
    # Confirmed against the live API: description is capped at MAX_TAG_LENGTH, same as name.
    if description and len(description) > MAX_TAG_LENGTH:
        raise DemistoException(f'Description must be at most {MAX_TAG_LENGTH} characters: "{description}"')


def chunk_list(items, size):
    return [items[i: i + size] for i in range(0, len(items), size)]


def bool_query_param(value):
    return "true" if argToBoolean(value) else "false"


def build_list_profiles_params(args):
    params = {
        "fields": args.get("fields"),
        "offset": args.get("offset"),
        "limit": args.get("limit"),
        "sortby": args.get("sortby"),
        "sortorder": args.get("sortorder"),
        "filter": args.get("filter"),
    }
    return {k: v for k, v in params.items() if v is not None}


def validate_profile_name(name):
    if not name or len(name) > PROFILE_NAME_MAX_LENGTH:
        raise DemistoException(f'name must be between 1 and {PROFILE_NAME_MAX_LENGTH} characters: "{name}"')


def validate_profile_description(description):
    if description and len(description) > PROFILE_DESCRIPTION_MAX_LENGTH:
        raise DemistoException(f"description must be at most {PROFILE_DESCRIPTION_MAX_LENGTH} characters")


def parse_json_arg(args, name, required=False):
    # Playbooks commonly pass an explicit "" for an unfilled optional argument (rather than
    # omitting the key) - treat that the same as not provided, not as invalid JSON.
    raw = args.get(name)
    if not raw:
        if required:
            raise DemistoException(f'the "{name}" argument is required')
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise DemistoException(f'"{name}" argument must be valid JSON: {e}')


def parse_json_object_list_arg(args, name, example, required=False):
    # A bare number or string (e.g. "443") is valid JSON on its own, so parse_json_arg's "must be
    # valid JSON" check alone doesn't catch it - confirmed against the live API: passing e.g.
    # protocols=443 doesn't error, it just silently fails to create anything. Require the parsed
    # value to actually be a list of objects, matching what these arguments are documented to take.
    value = parse_json_arg(args, name, required=required)
    if value is not None and not (isinstance(value, list) and all(isinstance(item, dict) for item in value)):
        raise DemistoException(f'"{name}" argument must be a JSON array of objects, e.g. {example}: got {value!r}')
    return value


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type Client: ``client``
    :param client: Netskope client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client._http_request(method="GET", url_suffix="/api/v2/policy/urllist")
    except DemistoException as e:
        if "Unauthorized" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def get_lists(client: Client, args: dict[str, Any]) -> CommandResults:
    r = client.get_lists()

    markdown = tableToMarkdown("Retrieved all applied and pending lists", r)

    return CommandResults(readable_output=markdown, outputs_prefix="Netskope", outputs_key_field="", outputs={"URLList": r})


def get_list(client: Client, args: dict[str, Any]) -> CommandResults:
    list_name = args.get("list_name")

    list_id = get_list_id_from_name(client, list_name)

    r = client.get_list(list_id)

    markdown = tableToMarkdown(f'Retrieved "{list_name}" list', r)

    return CommandResults(readable_output=markdown, outputs_prefix="Netskope", outputs_key_field="", outputs={"URLList": r})


def add_url(client: Client, args: dict[str, Any]) -> CommandResults:
    list_name = args.get("list_name")
    url = argToList(args.get("url"))

    if len(url) == 0:
        raise Exception("received an empty list of URLs")

    list_id = get_list_id_from_name(client, list_name)

    # create 'urls' list
    urls = []
    for u in url:
        urls.append(u)

    # append urls to list
    url_list_object = create_url_list_object(urls)
    r = client.patch_list(list_id, url_list_object, "append")

    # apply pending changes
    client.deploy_lists()

    # Summarize rather than dump the full list (which can be very large) into the War Room table -
    # the complete list content is still available in context via the outputs below.
    summary = {
        "id": r.get("id"),
        "name": r.get("name"),
        "added": urls,
        "total_urls_in_list": len(r.get("data", {}).get("urls", [])),
        "type": r.get("data", {}).get("type"),
        "pending": r.get("pending"),
    }
    markdown = tableToMarkdown(f'Added {len(urls)} URL(s) to "{r.get("name")}" list', summary)

    return CommandResults(readable_output=markdown, outputs_prefix="Netskope", outputs_key_field="", outputs={"URLList": r})


def remove_url(client: Client, args: dict[str, Any]) -> CommandResults:
    list_name = args.get("list_name")
    url = argToList(args.get("url"))

    if len(url) == 0:
        raise Exception("received an empty list of URLs")

    list_id = get_list_id_from_name(client, list_name)

    # get urls from list
    r = client.get_list(list_id)
    urls = r.get("data").get("urls")

    # remove urls
    urls_found = []
    urls_not_found = []
    for u in url:
        if u in urls:
            urls_found.append(u)
        else:
            urls_not_found.append(u)
    for u in urls_found:
        urls.remove(u)

    # write urls to list
    url_list_object = create_url_list_object(urls, r.get("data").get("type"))
    r = client.patch_list(list_id, url_list_object, "replace")

    # apply pending changes
    client.deploy_lists()

    message = f'Remove URLs from "{r.get("name")}" list'
    if urls_found:
        message += f"\nRemoved: {urls_found}"
    if urls_not_found:
        message += f"\nNot found: {urls_not_found}"

    # Summarize rather than dump the full list (which can be very large) into the War Room table -
    # the complete list content is still available in context via the outputs below.
    summary = {
        "id": r.get("id"),
        "name": r.get("name"),
        "removed": urls_found,
        "not_found": urls_not_found,
        "total_urls_in_list": len(r.get("data", {}).get("urls", [])),
        "type": r.get("data", {}).get("type"),
        "pending": r.get("pending"),
    }
    markdown = tableToMarkdown(message, summary)

    return CommandResults(readable_output=markdown, outputs_prefix="Netskope", outputs_key_field="", outputs={"URLList": r})


def list_device_classification_tags(client: Client, args: dict[str, Any]) -> CommandResults:
    r = client.list_device_classification_tags()

    markdown = tableToMarkdown("Device Classification Tags", r)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.DeviceClassificationTag", outputs_key_field="id", outputs=r
    )


def create_device_classification_tag(client: Client, args: dict[str, Any]) -> CommandResults:
    name = args.get("name")
    description = args.get("description", "")

    validate_tag_name(name)
    validate_description(description)

    r = client.create_device_classification_tags([{"name": name, "description": description}])

    outputs = {"name": name, "description": description, "ids": r.get("data")}
    markdown = tableToMarkdown(f'Created device classification tag "{name}"', outputs)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Netskope.DeviceClassificationTag",
        outputs_key_field="ids",
        outputs=outputs,
        raw_response=r,
    )


def create_device_classification_rule(client: Client, args: dict[str, Any]) -> CommandResults:
    name = args.get("name")
    label = args.get("label")
    os_ = args.get("os")
    conditions = args.get("conditions")

    if isinstance(conditions, str):
        try:
            conditions = json.loads(conditions)
        except json.JSONDecodeError as e:
            raise DemistoException(f"conditions argument must be valid JSON: {e}")

    rule = {"name": name, "label": label, "os": os_, "conditions": conditions}
    response = client.create_device_classification_rules([rule])

    # A successful create returns 201 with an empty body on this API - only try to read an ID if a body is present.
    try:
        body = response.json()
        ids = body.get("data")
    except ValueError:
        body = None
        ids = None

    outputs = {"name": name, "label": label, "os": os_, "ids": ids}
    markdown = tableToMarkdown(f'Created device classification rule "{name}"', outputs)
    if ids is None:
        markdown += "\nNote: the API did not return a rule ID for this create call."

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Netskope.DeviceClassificationRule",
        outputs_key_field="ids",
        outputs=outputs,
        raw_response=body,
    )


def find_device(client: Client, args: dict[str, Any]) -> CommandResults:
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    fields = args.get("fields") or "nsdeviceuid,hostname,os,client_version"

    r = client.find_devices(start_time, end_time, fields)
    devices = r.get("result", [])

    markdown = tableToMarkdown("Devices found", devices)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.Device", outputs_key_field="nsdeviceuid", outputs=devices,
        raw_response=r,
    )


def create_device_tag(client: Client, args: dict[str, Any]) -> CommandResults:
    name = args.get("name")
    description = args.get("description")

    validate_tag_name(name)
    validate_description(description)

    r = client.create_device_tag(name, description)
    data = r.get("data", {})

    markdown = tableToMarkdown(f'Created device tag "{name}"', data)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.DeviceTag", outputs_key_field="id", outputs=data, raw_response=r
    )


def list_device_tags(client: Client, args: dict[str, Any]) -> CommandResults:
    device_id = args.get("device_id")

    r = client.get_device_tags(device_id)
    tags = r.get("data", [])

    markdown = tableToMarkdown(f'Device tags for "{device_id}"', tags)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.DeviceTag", outputs_key_field="id", outputs=tags, raw_response=r
    )


def apply_device_tags(client: Client, args: dict[str, Any]) -> CommandResults:
    tag_ids = argToList(args.get("tag_id"))
    if not tag_ids:
        raise DemistoException("received an empty list of tag IDs")
    if len(tag_ids) > MAX_TAGS_PER_DEVICE:
        raise DemistoException(f"a device supports at most {MAX_TAGS_PER_DEVICE} tags, received {len(tag_ids)}")
    tag_ids = [int(t) for t in tag_ids]

    nsdeviceuids = argToList(args.get("nsdeviceuid"))
    if not nsdeviceuids:
        raise DemistoException("received an empty list of device UIDs")
    hostname = args.get("hostname", "")
    userkey = args.get("userkey")

    devices = [{"nsdeviceuid": uid, "userkey": userkey or uid, "hostname": hostname} for uid in nsdeviceuids]

    results = []
    for batch in chunk_list(devices, TAG_DEVICE_BATCH_SIZE):
        r = client.apply_device_tags(tag_ids, batch)
        results.append(r.get("data", {}))

    markdown = tableToMarkdown(f"Applied tags {tag_ids} to {len(devices)} device(s)", results)

    return CommandResults(
        readable_output=markdown,
        outputs_prefix="Netskope.DeviceTagApplication",
        outputs_key_field="",
        outputs=results,
        raw_response=results,
    )


def _list_profiles(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    params = build_list_profiles_params(args)

    r = client.list_profiles(profile_type, params)
    elements = r.get("elements", [])

    markdown = tableToMarkdown(f"{config.outputs_prefix.split('.')[-1]}s", elements)

    return CommandResults(
        readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=elements,
        raw_response=r,
    )


def _create_profile(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]

    name = args.get("name")
    validate_profile_name(name)
    description = args.get("description")
    validate_profile_description(description)
    values = argToList(args.get("values"))

    body: dict[str, Any] = {"name": name}
    if description:
        body["description"] = description
    if values:
        body["values"] = values
    if config.supports_type:
        type_ = (args.get("type") or "").lower()
        if not type_ or type_ not in DESTINATION_PROFILE_TYPES:
            raise DemistoException(f'type is required and must be one of {DESTINATION_PROFILE_TYPES}: "{args.get("type")}"')
        body["type"] = type_
        label_ids = argToList(args.get("label_ids"))
        if label_ids:
            body["label_ids"] = label_ids
    profile_id = args.get("id")
    if profile_id:
        body["id"] = profile_id

    params = {"interactive": bool_query_param(args.get("interactive", False))}
    if args.get("details") is not None:
        params["details"] = bool_query_param(args.get("details"))

    r = client.create_profile(profile_type, body, params)
    markdown = tableToMarkdown(f'Created profile "{name}"', r)

    return CommandResults(
        readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r, raw_response=r
    )


def _get_profile(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")

    params = {"details": bool_query_param(args.get("details"))} if args.get("details") is not None else None
    r = client.get_profile(profile_type, profile_id, params)

    markdown = tableToMarkdown(f'Profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def _update_profile(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")

    body: dict[str, Any] = {}
    if args.get("name") is not None:
        validate_profile_name(args.get("name"))
        body["name"] = args.get("name")
    if args.get("description") is not None:
        validate_profile_description(args.get("description"))
        body["description"] = args.get("description")
    if args.get("values") is not None:
        body["values"] = argToList(args.get("values"))
    if config.supports_type and args.get("type") is not None:
        type_ = (args.get("type") or "").lower()
        if type_ not in DESTINATION_PROFILE_TYPES:
            raise DemistoException(f'type must be one of {DESTINATION_PROFILE_TYPES}: "{args.get("type")}"')
        body["type"] = type_
        if "values" not in body:
            raise DemistoException('the "values" argument is required when changing "type"')
    if config.supports_type and args.get("label_ids") is not None:
        body["label_ids"] = argToList(args.get("label_ids"))

    params = {"interactive": bool_query_param(args.get("interactive", False))}

    r = client.update_profile(profile_type, profile_id, body, params)
    markdown = tableToMarkdown(f'Updated profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def _update_profile_values(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")
    op = args.get("operation")
    if op not in ("append", "remove"):
        raise DemistoException(f'operation must be "append" or "remove": "{op}"')

    values = argToList(args.get("values"))
    indexes = argToList(args.get("indexes"))
    operation: dict[str, Any] = {"op": op}

    if op == "append":
        if not values:
            raise DemistoException("append requires at least one value")
        if len(values) > VALUES_OP_MAX_ITEMS:
            raise DemistoException(f"at most {VALUES_OP_MAX_ITEMS} values are allowed per call")
        operation["values"] = values
    else:
        if indexes:
            if not config.supports_index_removal:
                raise DemistoException(f'index-based removal is not supported for "{profile_type}" profiles')
            if len(indexes) > VALUES_OP_MAX_ITEMS:
                raise DemistoException(f"at most {VALUES_OP_MAX_ITEMS} indexes are allowed per call")
            operation["indexes"] = [int(i) for i in indexes]
        elif values:
            if len(values) > VALUES_OP_MAX_ITEMS:
                raise DemistoException(f"at most {VALUES_OP_MAX_ITEMS} values are allowed per call")
            operation["values"] = values
        else:
            raise DemistoException("remove requires either values or indexes")

    r = client.update_profile_values(profile_type, profile_id, operation)
    markdown = tableToMarkdown(f'Updated values for profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def _delete_profile(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")

    params = {"interactive": bool_query_param(args.get("interactive", False))}
    r = client.delete_profile(profile_type, profile_id, params)

    markdown = tableToMarkdown(f'Deleted profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def _deploy_profiles(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    ids = argToList(args.get("ids"))
    all_ = argToBoolean(args.get("all", False))

    if len(ids) > DEPLOY_MAX_IDS:
        raise DemistoException(f"at most {DEPLOY_MAX_IDS} profile IDs are allowed per deploy call")

    body: dict[str, Any] = {}
    if all_:
        body["all"] = True
    elif ids:
        body["ids"] = ids
    else:
        raise DemistoException('either "ids" or "all" must be provided')

    change_note = args.get("change_note")
    if change_note:
        if len(change_note) > CHANGE_NOTE_MAX_LENGTH:
            raise DemistoException(f"change_note must be at most {CHANGE_NOTE_MAX_LENGTH} characters")
        body["change_note"] = change_note

    r = client.deploy_profiles(profile_type, body)
    markdown = tableToMarkdown("Deployed profiles", r)

    return CommandResults(
        readable_output=markdown, outputs_prefix=f"{config.outputs_prefix}Deploy", outputs_key_field="", outputs=r
    )


def _revert_profile(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")

    params = {"details": bool_query_param(args.get("details"))} if args.get("details") is not None else None
    r = client.revert_profile(profile_type, profile_id, params)

    markdown = tableToMarkdown(f'Reverted profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def _get_profile_applied_version(client: Client, profile_type: str, args: dict[str, Any]) -> CommandResults:
    config = PROFILE_RESOURCE_CONFIG[profile_type]
    profile_id = args.get("id")

    r = client.get_profile_applied_version(profile_type, profile_id)
    markdown = tableToMarkdown(f'Applied version of profile "{profile_id}"', r)

    return CommandResults(readable_output=markdown, outputs_prefix=config.outputs_prefix, outputs_key_field="id", outputs=r)


def list_destination_profiles(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_profiles(client, "destinations", args)


def create_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _create_profile(client, "destinations", args)


def get_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _get_profile(client, "destinations", args)


def update_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _update_profile(client, "destinations", args)


def update_destination_profile_values(client: Client, args: dict[str, Any]) -> CommandResults:
    return _update_profile_values(client, "destinations", args)


def delete_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _delete_profile(client, "destinations", args)


def deploy_destination_profiles(client: Client, args: dict[str, Any]) -> CommandResults:
    return _deploy_profiles(client, "destinations", args)


def revert_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _revert_profile(client, "destinations", args)


def get_destination_profile_applied_version(client: Client, args: dict[str, Any]) -> CommandResults:
    return _get_profile_applied_version(client, "destinations", args)


def migrate_url_list_to_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    url_list_id = args.get("url_list_id")
    destination_profile_name = args.get("destination_profile_name")

    r = client.migrate_url_list_to_profile(url_list_id, destination_profile_name)
    markdown = tableToMarkdown(f'Migrated URL List "{url_list_id}" to a new destination profile', r)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.DestinationProfile", outputs_key_field="id", outputs=r
    )


def migrate_url_list_into_destination_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    profile_id = args.get("id")
    url_list_id = args.get("url_list_id")

    r = client.migrate_url_list_into_profile(profile_id, url_list_id)
    markdown = tableToMarkdown(f'Migrated URL List "{url_list_id}" into destination profile "{profile_id}"', r)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.DestinationProfile", outputs_key_field="id", outputs=r
    )


def list_network_profiles(client: Client, args: dict[str, Any]) -> CommandResults:
    return _list_profiles(client, "networks", args)


def create_network_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _create_profile(client, "networks", args)


def get_network_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _get_profile(client, "networks", args)


def update_network_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _update_profile(client, "networks", args)


def update_network_profile_values(client: Client, args: dict[str, Any]) -> CommandResults:
    return _update_profile_values(client, "networks", args)


def delete_network_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _delete_profile(client, "networks", args)


def deploy_network_profiles(client: Client, args: dict[str, Any]) -> CommandResults:
    return _deploy_profiles(client, "networks", args)


def revert_network_profile(client: Client, args: dict[str, Any]) -> CommandResults:
    return _revert_profile(client, "networks", args)


def get_network_profile_applied_version(client: Client, args: dict[str, Any]) -> CommandResults:
    return _get_profile_applied_version(client, "networks", args)


def update_file_hash_list(client: Client, args: dict[str, Any]) -> CommandResults:
    name = args.get("name", "")
    # Filter out blank entries (e.g. from joining an empty "existing hashes" input with a comma)
    # before validating, so a leading/trailing/duplicate comma doesn't turn into a bogus entry.
    hashes = [h.strip() for h in argToList(args.get("hash")) if h.strip()]

    if not hashes:
        raise DemistoException("received an empty list of hashes")

    invalid = [h for h in hashes if not (MD5_PATTERN.match(h) or SHA256_PATTERN.match(h))]
    if invalid:
        raise DemistoException(f"only MD5 (32 hex chars) or SHA256 (64 hex chars) hashes are accepted, got: {invalid}")

    response = client.update_file_hash_list(name, hashes)
    # This API returns HTTP 200 even on failure (e.g. duplicate/no-op requests) - the real
    # success/failure is only in the response body, so it must be checked explicitly.
    if response.get("status") == "error":
        errors = response.get("errors", [])
        # "Duplicate request, no change" means the desired state (these hashes being in the
        # list) is already true - for this idempotent, replace-style operation that's a success,
        # not a failure. Treating it as an error is what breaks playbooks that re-run with the
        # same hash set (e.g. after a prior client-side timeout whose request actually succeeded).
        if any("duplicate request" in e.lower() for e in errors):
            outputs = {"name": name, "hash": hashes}
            readable_output = f'Hash List "{name}" already contains: {", ".join(hashes)} (no change needed)'
            return CommandResults(
                readable_output=readable_output,
                outputs_prefix="Netskope.FileHashList",
                outputs_key_field="name",
                outputs=outputs,
                raw_response=response,
            )
        error_text = "; ".join(errors) or response.get("errorCode", "unknown error")
        raise DemistoException(f'Failed to update file hash list "{name}": {error_text}')

    outputs = {"name": name, "hash": hashes}
    readable_output = f'Hash List "{name}" updated with: {", ".join(hashes)}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="Netskope.FileHashList",
        outputs_key_field="name",
        outputs=outputs,
        raw_response=response,
    )


def list_private_apps(client: Client, args: dict[str, Any]) -> CommandResults:
    r = client.list_private_apps()
    apps = r.get("data", {}).get("private_apps", [])

    markdown = tableToMarkdown("Private Apps", apps)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=apps,
        raw_response=r,
    )


def list_publishers(client: Client, args: dict[str, Any]) -> CommandResults:
    params = {"fields": args.get("fields")} if args.get("fields") else None
    r = client.list_publishers(params)
    publishers = r.get("data", {}).get("publishers", [])

    markdown = tableToMarkdown("Publishers", publishers)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.Publisher", outputs_key_field="publisher_id",
        outputs=publishers, raw_response=r,
    )


def create_private_app(client: Client, args: dict[str, Any]) -> CommandResults:
    app_name = args.get("app_name")
    host = args.get("host")
    protocols = parse_json_object_list_arg(args, "protocols", '[{"type": "tcp", "port": "443"}]', required=True)
    publishers = parse_json_object_list_arg(
        args, "publishers", '[{"publisher_id": "15", "publisher_name": "AWS-NPA"}]', required=True
    )

    body: dict[str, Any] = {
        "app_name": app_name,
        "host": host,
        "protocols": protocols,
        "publishers": publishers,
    }

    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = [{"tag_name": tag} for tag in tags]

    for bool_arg in ("use_publisher_dns", "clientless_access", "allow_unauthenticated_cors", "trust_self_signed_certs"):
        if args.get(bool_arg) is not None:
            body[bool_arg] = argToBoolean(args.get(bool_arg))

    r = client.create_private_app(body)
    data = r.get("data", {})

    markdown = tableToMarkdown(f'Created private app "{app_name}"', data)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=data,
        raw_response=r,
    )


def update_private_app(client: Client, args: dict[str, Any]) -> CommandResults:
    app_id = args.get("app_id")

    body: dict[str, Any] = {}
    if args.get("app_name") is not None:
        body["app_name"] = args.get("app_name")
    if args.get("host") is not None:
        body["host"] = args.get("host")
    protocols = parse_json_object_list_arg(args, "protocols", '[{"type": "tcp", "port": "443"}]')
    if protocols is not None:
        body["protocols"] = protocols
    publishers = parse_json_object_list_arg(args, "publishers", '[{"publisher_id": "15", "publisher_name": "AWS-NPA"}]')
    if publishers is not None:
        body["publishers"] = publishers
    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = [{"tag_name": tag} for tag in tags]
    for bool_arg in ("use_publisher_dns", "clientless_access", "allow_unauthenticated_cors", "trust_self_signed_certs"):
        if args.get(bool_arg) is not None:
            body[bool_arg] = argToBoolean(args.get(bool_arg))

    if not body:
        raise DemistoException("at least one field to update must be provided")

    r = client.update_private_app(app_id, body)
    data = r.get("data", {})

    markdown = tableToMarkdown(f'Updated private app "{app_id}"', data)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=data,
        raw_response=r,
    )


def replace_private_app(client: Client, args: dict[str, Any]) -> CommandResults:
    app_id = args.get("app_id")
    if not app_id:
        raise DemistoException("app_id is required")

    host = args.get("host")
    if not host:
        raise DemistoException("host is required")

    protocols = parse_json_object_list_arg(args, "protocols", '[{"type": "tcp", "port": "443"}]', required=True)
    publishers = parse_json_object_list_arg(
        args, "publishers", '[{"publisher_id": "15", "publisher_name": "AWS-NPA"}]', required=True
    )

    body: dict[str, Any] = {"host": host, "protocols": protocols, "publishers": publishers}
    if args.get("app_name"):
        body["app_name"] = args.get("app_name")

    tags = argToList(args.get("tags"))
    if tags:
        body["tags"] = [{"tag_name": tag} for tag in tags]

    for bool_arg in ("use_publisher_dns", "clientless_access", "allow_unauthenticated_cors", "trust_self_signed_certs"):
        if args.get(bool_arg) is not None:
            body[bool_arg] = argToBoolean(args.get(bool_arg))

    r = client.replace_private_app(app_id, body)
    data = r.get("data", {})

    markdown = tableToMarkdown(f'Replaced private app "{app_id}"', data)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=data,
        raw_response=r,
    )


def update_private_app_tags(client: Client, args: dict[str, Any]) -> CommandResults:
    app_ids = [int(i) for i in argToList(args.get("app_id"))]
    if not app_ids:
        raise DemistoException("received an empty list of app IDs")

    tag_names = argToList(args.get("tags"))
    if not tag_names:
        raise DemistoException("received an empty list of tags")
    tags = [{"tag_name": tag} for tag in tag_names]

    r = client.update_private_app_tags(app_ids, tags)
    # Confirmed against the live API: "data" is the list of full app objects directly, not
    # nested under "private_apps" as the reference doc's example response shows. Handle both
    # shapes defensively rather than trusting either as the sole source of truth.
    data = r.get("data", [])
    apps = data if isinstance(data, list) else data.get("private_apps", [])

    markdown = tableToMarkdown("Updated private app tags", apps)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=apps,
        raw_response=r,
    )


def delete_private_app(client: Client, args: dict[str, Any]) -> CommandResults:
    app_id = args.get("app_id")

    r = client.delete_private_app(app_id)
    data = r.get("data", {})

    markdown = tableToMarkdown(f'Deleted private app "{app_id}"', data)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.PrivateApp", outputs_key_field="app_id", outputs=data,
        raw_response=r,
    )


def submit_file_scan(client: Client, args: dict[str, Any]) -> CommandResults:
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required")

    file_info = demisto.getFilePath(entry_id)
    file_path = file_info["path"]
    file_name = file_info["name"]

    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    if ext not in ALLOWED_FILE_SCAN_EXTENSIONS:
        raise DemistoException(
            f'Unsupported file type ".{ext}" for "{file_name}": Netskope sandbox scan only accepts '
            f"{ALLOWED_FILE_SCAN_EXTENSIONS} (submitted as a password-protected .zip per the API spec)."
        )

    r = client.submit_file_scan(file_path, file_name)

    outputs = {
        "jobid": r.get("jobid"),
        "md5": r.get("md5"),
        "sha256": r.get("sha256"),
        "status": r.get("status"),
    }
    markdown = tableToMarkdown(f'Submitted "{file_name}" for sandbox scan', outputs)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.FileScan", outputs_key_field="jobid", outputs=outputs,
        raw_response=r,
    )


def get_scan_report(client: Client, args: dict[str, Any]) -> CommandResults:
    jobid = args.get("jobid")
    if not jobid:
        raise DemistoException("jobid is required")

    r = client.get_scan_report(jobid)

    summary = {k: v for k, v in r.items() if k not in ("dropped", "network", "observed_behavior", "process_tree")}
    markdown = tableToMarkdown(f'Scan report for job "{jobid}" (status: {r.get("status")})', summary)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.FileScanReport", outputs_key_field="jobid", outputs=r,
        raw_response=r,
    )


def url_lookup(client: Client, args: dict[str, Any]) -> CommandResults:
    urls = argToList(args.get("urls"))
    if not urls:
        raise DemistoException("urls must not be empty")
    if len(urls) > URL_LOOKUP_MAX_URLS:
        raise DemistoException(f"at most {URL_LOOKUP_MAX_URLS} urls are allowed per call, got {len(urls)}")

    category = args.get("category")
    if category and category not in URL_LOOKUP_CATEGORIES:
        raise DemistoException(f'category must be one of {URL_LOOKUP_CATEGORIES}: "{category}"')

    query: dict[str, Any] = {"urls": urls}
    if args.get("disable_dns_lookup") is not None:
        query["disable_dns_lookup"] = argToBoolean(args.get("disable_dns_lookup"))
    if category:
        query["category"] = category

    r = client.url_lookup(query)
    results = r.get("result", [])

    markdown = tableToMarkdown("URL Lookup Results", results)

    return CommandResults(
        readable_output=markdown, outputs_prefix="Netskope.URLLookup", outputs_key_field="url", outputs=results,
        raw_response=r,
    )


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get("api_key_credentials", {}).get("password") or demisto.params().get("api_key")
    if not api_key:
        return_error("Please provide a valid API Key")
    api_v1_token = demisto.params().get("api_v1_token_credentials", {}).get("password") or demisto.params().get(
        "api_v1_token"
    )
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    headers = {"Netskope-Api-Token": api_key}

    commands = {
        "netskopev2-get-lists": get_lists,
        "netskopev2-get-list": get_list,
        "netskopev2-add-url": add_url,
        "netskopev2-remove-url": remove_url,
        "netskopev2-list-device-classification-tags": list_device_classification_tags,
        "netskopev2-create-device-classification-tag": create_device_classification_tag,
        "netskopev2-create-device-classification-rule": create_device_classification_rule,
        "netskopev2-find-device": find_device,
        "netskopev2-create-device-tag": create_device_tag,
        "netskopev2-list-device-tags": list_device_tags,
        "netskopev2-apply-device-tags": apply_device_tags,
        "netskopev2-list-destination-profiles": list_destination_profiles,
        "netskopev2-create-destination-profile": create_destination_profile,
        "netskopev2-get-destination-profile": get_destination_profile,
        "netskopev2-update-destination-profile": update_destination_profile,
        "netskopev2-update-destination-profile-values": update_destination_profile_values,
        "netskopev2-delete-destination-profile": delete_destination_profile,
        "netskopev2-deploy-destination-profiles": deploy_destination_profiles,
        "netskopev2-revert-destination-profile": revert_destination_profile,
        "netskopev2-get-destination-profile-applied-version": get_destination_profile_applied_version,
        "netskopev2-migrate-url-list-to-destination-profile": migrate_url_list_to_destination_profile,
        "netskopev2-migrate-url-list-into-destination-profile": migrate_url_list_into_destination_profile,
        "netskopev2-list-network-profiles": list_network_profiles,
        "netskopev2-create-network-profile": create_network_profile,
        "netskopev2-get-network-profile": get_network_profile,
        "netskopev2-update-network-profile": update_network_profile,
        "netskopev2-update-network-profile-values": update_network_profile_values,
        "netskopev2-delete-network-profile": delete_network_profile,
        "netskopev2-deploy-network-profiles": deploy_network_profiles,
        "netskopev2-revert-network-profile": revert_network_profile,
        "netskopev2-get-network-profile-applied-version": get_network_profile_applied_version,
        "netskopev2-update-file-hash-list": update_file_hash_list,
        "netskopev2-list-private-apps": list_private_apps,
        "netskopev2-list-publishers": list_publishers,
        "netskopev2-create-private-app": create_private_app,
        "netskopev2-update-private-app": update_private_app,
        "netskopev2-replace-private-app": replace_private_app,
        "netskopev2-update-private-app-tags": update_private_app_tags,
        "netskopev2-delete-private-app": delete_private_app,
        "netskopev2-submit-file-scan": submit_file_scan,
        "netskopev2-get-scan-report": get_scan_report,
        "netskopev2-url-lookup": url_lookup,
    }

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        client = Client(
            base_url=demisto.params()["url"],
            verify=verify_certificate,
            proxy=proxy,
            headers=headers,
            api_key=api_key,
            api_v1_token=api_v1_token,
        )

        if command == "test-module":
            return_results(test_module(client))
        if command in commands:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
