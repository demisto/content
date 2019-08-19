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
# from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBALS/PARAMS '''

RFC3339_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
DEMISTO_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

PROJECT_ID = demisto.params().get('project_id')
SERVICE_ACCOUNT_JSON = demisto.params().get('service_account_json')
USE_PROXY = demisto.params().get('use_proxy')

# USERNAME = demisto.params().get('credentials').get('identifier')
# PASSWORD = demisto.params().get('credentials').get('password')
# TOKEN = demisto.params().get('token')
# # Remove trailing slash to prevent wrong URL path to service
# SERVER = demisto.params()['url'][:-1] \
#     if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# # Should we use SSL
# USE_SSL = not demisto.params().get('insecure', False)
# # How many time before the first fetch to retrieve incidents
# FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# # Service base URL
# BASE_URL = SERVER + '/api/v2.0/'
# # Headers to be sent in requests
# HEADERS = {
#     'Authorization': 'Token ' + TOKEN + ':' + USERNAME + PASSWORD,
#     'Content-Type': 'application/json',
#     'Accept': 'application/json'
# }


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
    return {
        "Name": bucket.name,
        "TimeCreated": reformat_datetime_str(bucket._properties.get("timeCreated", "")),
        "TimeUpdated": reformat_datetime_str(bucket._properties.get("updated", "")),
        "OwnerID": "" if not bucket.owner else bucket.owner.get("entityId", "")
    }


def blob2dict(blob):
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


# def http_request(method, url_suffix, params=None, data=None):
#     # A wrapper for requests lib to send our requests and handle requests and responses better
#     res = requests.request(
#         method,
#         BASE_URL + url_suffix,
#         verify=USE_SSL,
#         params=params,
#         data=data,
#         headers=HEADERS
#     )
#     # Handle error responses gracefully
#     if res.status_code not in {200}:
#         return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))
#
#     return res.json()
#
#
# def item_to_incident(item):
#     incident = {}
#     # Incident Title
#     incident['name'] = 'Example Incident: ' + item.get('name')
#     # Incident occurrence time, usually item creation date in service
#     incident['occurred'] = item.get('createdDate')
#     # The raw response from the service, providing full info regarding the item
#     incident['rawJSON'] = json.dumps(item)
#     return incident


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


# def get_items_command():
#     """
#     Gets details about a items using IDs or some other filters
#     """
#     # Init main vars
#     headers = []
#     contents = []
#     context = {}
#     context_entries = []
#     title = ''
#     # Get arguments from user
#     item_ids = argToList(demisto.args().get('item_ids', []))
#     is_active = bool(strtobool(demisto.args().get('is_active', 'false')))
#     limit = int(demisto.args().get('limit', 10))
#     # Make request and get raw response
#     items = get_items_request(item_ids, is_active)
#     # Parse response into context & content entries
#     if items:
#         if limit:
#             items = items[:limit]
#         title = 'Example - Getting Items Details'
#
#         for item in items:
#             contents.append({
#                 'ID': item.get('id'),
#                 'Description': item.get('description'),
#                 'Name': item.get('name'),
#                 'Created Date': item.get('createdDate')
#             })
#             context_entries.append({
#                 'ID': item.get('id'),
#                 'Description': item.get('description'),
#                 'Name': item.get('name'),
#                 'CreatedDate': item.get('createdDate')
#             })
#
#         context['Example.Item(val.ID && val.ID === obj.ID)'] = context_entries
#
#     demisto.results({
#         'Type': entryTypes['note'],
#         'ContentsFormat': formats['json'],
#         'Contents': contents,
#         'ReadableContentsFormat': formats['markdown'],
#         'HumanReadable': tableToMarkdown(title, contents, removeNull=True),
#         'EntryContext': context
#     })
#
#
# def get_items_request(item_ids, is_active):
#     # The service endpoint to request from
#     endpoint_url = 'items'
#     # Dictionary of params for the request
#     params = {
#         'ids': item_ids,
#         'isActive': is_active
#     }
#     # Send a request using our http_request wrapper
#     response = http_request('GET', endpoint_url, params)
#     # Check if response contains errors
#     if response.get('errors'):
#         return_error(response.get('errors'))
#     # Check if response contains any data to parse
#     if 'data' in response:
#         return response.get('data')
#     # If neither was found, return back empty results
#     return {}
#
#
# def fetch_incidents():
#     last_run = demisto.getLastRun()
#     # Get the last fetch time, if exists
#     last_fetch = last_run.get('time')
#
#     # Handle first time fetch, fetch incidents retroactively
#     if last_fetch is None:
#         last_fetch, _ = parse_date_range(FETCH_TIME, to_timestamp=True)
#
#     incidents = []
#     items = get_items_request()
#     for item in items:
#         incident = item_to_incident(item)
#         incident_date = date_to_timestamp(incident['occurred'], '%Y-%m-%dT%H:%M:%S.%fZ')
#         # Update last run and add incident if the incident is newer than last fetch
#         if incident_date > last_fetch:
#             last_fetch = incident_date
#             incidents.append(incident)
#
#     demisto.setLastRun({'time' : last_fetch})
#     demisto.incidents(incidents)


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

except Exception as e:
    LOG(traceback.format_exc())
    return_error(format_error(e))
