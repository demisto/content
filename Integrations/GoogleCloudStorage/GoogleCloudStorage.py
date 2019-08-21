import traceback

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from google.cloud import storage

import datetime
import json
import re
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

RFC3339_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

PROJECT_ID = demisto.params().get('project_id')
SERVICE_ACCOUNT_JSON = demisto.params().get('service_account_json')
USE_PROXY = demisto.params().get('use_proxy')


def safe_del(dictionary, key):
    if key in dictionary:
        del dictionary[key]


# Remove proxy if not set to true in params
if not USE_PROXY:
    safe_del(os.environ, "HTTP_PROXY")
    safe_del(os.environ, "HTTPS_PROXY")
    safe_del(os.environ, "http_proxy")
    safe_del(os.environ, "https_proxy")


''' HELPER FUNCTIONS '''


def init_storage_client():

    cur_directory_path = os.getcwd()
    credentials_file_name = "{}.json".format(demisto.uniqueFile())
    credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)

    with open(credentials_file_path, "w") as creds_file:
        json_object = json.loads(SERVICE_ACCOUNT_JSON)
        json.dump(json_object, creds_file)

    return storage.Client.from_service_account_json(credentials_file_path)


def ec_key(path, *merge_by):

    if len(merge_by) == 0:
        return path

    js_condition = ""
    for key in merge_by:
        if js_condition:
            js_condition += " && "
        js_condition += "val.{0} && val.{0} === obj.{0}".format(key)

    return "{}({})".format(path, js_condition)


def bucket2dict(bucket):
    """
    Converts a google.cloud.storage.Bucket object to context format (GCP.Bucket).
    """
    return {
        "Name": bucket.name,
        "TimeCreated": reformat_datetime_str(bucket._properties.get("timeCreated", "")),
        "TimeUpdated": reformat_datetime_str(bucket._properties.get("updated", "")),
        "OwnerID": "" if not bucket.owner else bucket.owner.get("entityId", "")
    }


def blob2dict(blob):
    """
    Converts a google.cloud.storage.Blob to context format (GCP.BucketObject).
    Note: "blob" is the client API name for what is normally called an "object" in Google Cloud Storage.
    """
    return {
        "Name": blob.name,
        "Bucket": blob.bucket.name,
        "ContentType": blob.content_type,
        "TimeCreated": datetime2str(blob.time_created),
        "TimeUpdated": datetime2str(blob.updated),
        "TimeDeleted": datetime2str(blob.time_deleted),
        "Size": blob.size,
        "MD5": blob.md5_hash,
        "OwnerID": "" if not blob.owner else blob.owner.get("entityId", ""),
        "CRC32c": blob.crc32c,
        "EncryptionAlgorithm": blob._properties.get("customerEncryption", {}).get("encryptionAlgorithm", ""),
        "EncryptionKeySHA256": blob._properties.get("customerEncryption", {}).get("keySha256", ""),
    }


def acl2dict(acl_entry, for_blob=False):
    """
    Converts an ACL entry from its raw JSON form to context format (either GCP.BucketPolicy or GCP.BucketObjectPolicy).
    """
    dict_for_blob = {"object": acl_entry.get("object", "")} if for_blob else {}
    return {
        "Bucket": acl_entry.get("bucket", ""),
        **dict_for_blob,
        "Entity": acl_entry.get("entity", ""),
        "Email": acl_entry.get("email", ""),
        "Role": acl_entry.get("role", ""),
        "Team": acl_entry.get("projectTeam", {}).get("team", "")
    }


def reformat_datetime_str(dt_str):
    dt = None if not dt_str else datetime.datetime.strptime(dt_str, RFC3339_DATETIME_FORMAT)
    return datetime2str(dt)


def datetime2str(dt):
    return "" if not dt else dt.strftime(DEMISTO_DATETIME_FORMAT)


def human_readable_table(title, contents):

    def header_transform(header):
        return re.sub(r"([a-z])([A-Z])", "\\1 \\2", header)

    first_dict = {}
    if type(contents) is list and len(contents) > 0:
        first_dict = contents[0]
    elif type(contents) is dict:
        first_dict = contents

    ordered_headers = None if not first_dict else list(first_dict.keys())

    return tableToMarkdown(title, contents, ordered_headers, header_transform)


def format_error(ex):

    msg = "Error occurred in the Google Cloud Storage Integration"

    if hasattr(ex, "__class__"):
        class_name = ex.__class__.__name__
        if hasattr(ex, "message"):
            msg = "{}: {}".format(class_name, ex.message)
        else:
            msg += " ({})".format(class_name)

    return msg


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    client = init_storage_client()
    list(client.list_buckets())


def gcs_list_buckets():

    client = init_storage_client()
    buckets = client.list_buckets()
    result = [bucket2dict(bucket) for bucket in buckets]

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": human_readable_table("Buckets in project " + client.project, result),
        "EntryContext": {ec_key("GCP.Bucket", "Name"): result}
    })


def gcs_get_bucket():
    bucket_name = demisto.args()["bucket_name"]

    client = init_storage_client()
    bucket = client.get_bucket(bucket_name)
    result = bucket2dict(bucket)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": human_readable_table("Bucket " + bucket_name, result),
        "EntryContext": {ec_key("GCP.Bucket", "Name"): result}
    })


def gcs_list_bucket_objects():
    bucket_name = demisto.args()["bucket_name"]

    client = init_storage_client()
    blobs = client.list_blobs(bucket_name)
    result = [blob2dict(blob) for blob in blobs]

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": human_readable_table("Objects in bucket " + bucket_name, result),
        "EntryContext": {ec_key("GCP.BucketObject", "Name", "Bucket"): result}
    })


def gcs_download_file():
    bucket_name = demisto.args()["bucket_name"]
    blob_name = demisto.args()["object_name"]

    client = init_storage_client()
    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)

    cur_directory_path = os.getcwd()
    file_name = blob_name.split("/")[-1] or demisto.uniqueFile()
    file_path = os.path.join(cur_directory_path, file_name)
    with open(file_path, "w") as file:
        client.download_blob_to_file(blob, file)

    demisto.results(file_result_existing_file(file_name))


def gcs_create_bucket():
    bucket_name = demisto.args()["bucket_name"]
    bucket_acl = demisto.args().get("bucket_acl", "")
    default_object_acl = demisto.args().get("default_object_acl", "")

    client = init_storage_client()
    bucket = client.create_bucket(bucket_name)
    if bucket_acl:
        bucket.acl.save_predefined(bucket_acl)
    if default_object_acl:
        bucket.default_object_acl.save_predefined(default_object_acl)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Bucket {} was successfully created.".format(bucket_name)
    })


def gcs_delete_bucket():
    bucket_name = demisto.args()["bucket_name"]
    force = demisto.args().get("force", "") == "True"

    client = init_storage_client()
    bucket = client.get_bucket(bucket_name)
    bucket.delete(force)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Bucket {} was successfully deleted.".format(bucket_name)
    })


def gcs_upload_file():
    entry_id = demisto.args()["entry_id"]
    bucket_name = demisto.args()["bucket_name"]
    object_name = demisto.args()["object_name"]
    object_acl = demisto.args().get("object_acl", "")

    context_file = demisto.getFilePath(entry_id)
    file_path = context_file["path"]
    file_name = context_file["name"]
    blob = upload_file(file_path, bucket_name, object_name)
    if object_acl:
        blob.acl.save_predefined(object_acl)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "File {} was successfully uploaded to {}.".format(file_name, object_name)
    })


def upload_file(file_path, bucket_name, object_name):
    client = init_storage_client()
    bucket = client.get_bucket(bucket_name)
    blob = bucket.blob(object_name)
    blob.upload_from_filename(file_path)
    return blob


def gcs_list_bucket_policy():
    bucket_name = demisto.args()["bucket_name"]

    client = init_storage_client()
    acl = client.get_bucket(bucket_name).acl

    acl_entries = get_acl_entries(acl)
    result = [acl2dict(entry) for entry in acl_entries]

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": human_readable_table("ACL policy for bucket " + bucket_name, result),
        "EntryContext": {ec_key("GCP.BucketPolicy", "Bucket", "Entity"): result}
    })


def get_acl_entries(acl):
    client = acl.client
    path = acl.reload_path
    query_params = {}
    parsed_json = client._connection.api_request(method="GET", path=path, query_params=query_params)
    return parsed_json.get("items", ())


def gcs_create_bucket_policy():
    bucket_name = demisto.args()["bucket_name"]
    entity = demisto.args()["entity"]
    role = demisto.args()["role"]

    client = init_storage_client()
    acl = client.get_bucket(bucket_name).acl
    if acl.has_entity(entity):
        return_error(
            "Entity {} already exists in the ACL of bucket {} (use gcs-put-bucket-policy to update it)"
            .format(entity, bucket_name))

    set_acl_entry(acl, entity, role)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Added entity {} to ACL of bucket {} with role {}".format(entity, bucket_name, role)
    })


def gcs_put_bucket_policy():
    bucket_name = demisto.args()["bucket_name"]
    entity = demisto.args()["entity"]
    role = demisto.args()["role"]

    client = init_storage_client()
    acl = client.get_bucket(bucket_name).acl
    if not acl.has_entity(entity):
        return_error(
            "Entity {} does not exist in the ACL of bucket {} (use gcs-create-bucket-policy to create it)"
            .format(entity, bucket_name))

    set_acl_entry(acl, entity, role)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Updated ACL entity {} in bucket {} to role {}".format(entity, bucket_name, role)
    })


def set_acl_entry(acl, entity, role):
    acl_entry = acl.entity_from_dict({"entity": entity, "role": role})
    acl.add_entity(acl_entry)
    acl.save()


def gcs_delete_bucket_policy():
    bucket_name = demisto.args()["bucket_name"]
    entity = demisto.args()["entity"]

    client = init_storage_client()
    acl = client.get_bucket(bucket_name).acl
    if not acl.has_entity(entity):
        return_error("Entity {} does not exist in the ACL of bucket {}".format(entity, bucket_name))

    delete_acl_entry(acl, entity)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Removed entity {} from ACL of bucket {}".format(entity, bucket_name)
    })


def delete_acl_entry(acl, entity):
    del acl.entities[str(entity)]
    acl.save()


def gcs_list_bucket_object_policy():
    bucket_name = demisto.args()["bucket_name"]
    blob_name = demisto.args()["object_name"]

    acl = get_blob_acl(bucket_name, blob_name)
    acl_entries = get_acl_entries(acl)
    result = [acl2dict(entry, for_blob=True) for entry in acl_entries]

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": result,
        "HumanReadable": human_readable_table("ACL policy for object " + blob_name, result),
        "EntryContext": {ec_key("GCP.BucketObjectPolicy", "Bucket", "Object", "Entity"): result}
    })


def get_blob_acl(bucket_name, blob_name):
    client = init_storage_client()
    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)
    return blob.acl


def gcs_create_bucket_object_policy():
    bucket_name = demisto.args()["bucket_name"]
    blob_name = demisto.args()["object_name"]
    entity = demisto.args()["entity"]
    role = demisto.args()["role"]

    acl = get_blob_acl(bucket_name, blob_name)
    if acl.has_entity(entity):
        return_error(
            "Entity {} already exists in the ACL of object {} (use gcs-put-bucket-object-policy to update it)"
            .format(entity, blob_name))

    set_acl_entry(acl, entity, role)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Added entity {} to ACL of object {} with role {}".format(entity, blob_name, role)
    })


def gcs_put_bucket_object_policy():
    bucket_name = demisto.args()["bucket_name"]
    blob_name = demisto.args()["object_name"]
    entity = demisto.args()["entity"]
    role = demisto.args()["role"]

    acl = get_blob_acl(bucket_name, blob_name)
    if not acl.has_entity(entity):
        return_error(
            "Entity {} does not exist in the ACL of object {} (use gcs-create-bucket-object-policy to create it)"
            .format(entity, blob_name))

    set_acl_entry(acl, entity, role)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Updated ACL entity {} in object {} to role {}".format(entity, blob_name, role)
    })


def gcs_delete_bucket_object_policy():
    bucket_name = demisto.args()["bucket_name"]
    blob_name = demisto.args()["object_name"]
    entity = demisto.args()["entity"]

    acl = get_blob_acl(bucket_name, blob_name)
    if not acl.has_entity(entity):
        return_error("Entity {} does not exist in the ACL of object {}".format(entity, blob_name))

    delete_acl_entry(acl, entity)

    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["text"],
        "Contents": "Removed entity {} from ACL of object {}".format(entity, blob_name)
    })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG("Command being called is " + demisto.command())

try:
    if demisto.command() == "test-module":
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results("ok")

    elif demisto.command() == "gcs-list-buckets":
        gcs_list_buckets()

    elif demisto.command() == "gcs-get-bucket":
        gcs_get_bucket()

    elif demisto.command() == "gcs-list-bucket-objects":
        gcs_list_bucket_objects()

    elif demisto.command() == "gcs-download-file":
        gcs_download_file()

    elif demisto.command() == "gcs-create-bucket":
        gcs_create_bucket()

    elif demisto.command() == "gcs-delete-bucket":
        gcs_delete_bucket()

    elif demisto.command() == "gcs-upload-file":
        gcs_upload_file()

    elif demisto.command() == "gcs-list-bucket-policy":
        gcs_list_bucket_policy()

    elif demisto.command() == "gcs-create-bucket-policy":
        gcs_create_bucket_policy()

    elif demisto.command() == "gcs-put-bucket-policy":
        gcs_put_bucket_policy()

    elif demisto.command() == "gcs-delete-bucket-policy":
        gcs_delete_bucket_policy()

    elif demisto.command() == "gcs-list-bucket-object-policy":
        gcs_list_bucket_object_policy()

    elif demisto.command() == "gcs-create-bucket-object-policy":
        gcs_create_bucket_object_policy()

    elif demisto.command() == "gcs-put-bucket-object-policy":
        gcs_put_bucket_object_policy()

    elif demisto.command() == "gcs-delete-bucket-object-policy":
        gcs_delete_bucket_object_policy()

except Exception as e:
    LOG(traceback.format_exc())
    return_error(format_error(e))
