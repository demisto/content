from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''

from google.cloud import storage
from typing import Any, Dict
import requests
import traceback
import urllib3


''' GLOBALS/PARAMS '''

RFC3339_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'

SERVICE_ACCOUNT_JSON = demisto.params().get('service_account_json', '')
INSECURE = demisto.params().get('insecure', False)

client: storage.Client


''' HELPER FUNCTIONS '''


def initialize_module():
    global client

    # Allow an un-initialized client for the sake of unit tests
    if SERVICE_ACCOUNT_JSON:
        client = init_storage_client()

    if INSECURE:
        disable_tls_verification()

    # Remove proxy if not set to true in params
    handle_proxy()


def init_storage_client():
    """Creates the Python API client for Google Cloud Storage."""
    cur_directory_path = os.getcwd()
    credentials_file_name = demisto.uniqueFile() + '.json'
    credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)

    with open(credentials_file_path, 'w') as creds_file:
        json_object = json.loads(SERVICE_ACCOUNT_JSON)
        json.dump(json_object, creds_file)

    return storage.Client.from_service_account_json(credentials_file_path)


def disable_tls_verification():

    original_method = requests.Session.merge_environment_settings

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = original_method(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings

    # noinspection PyTypeHints
    requests.Session.merge_environment_settings = merge_environment_settings  # type: ignore

    urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)


def ec_key(path, *merge_by):
    """Returns the context key and merge logic for the given context path and ID field name(s)."""

    if len(merge_by) == 0:
        return path

    js_condition = ''
    for key in merge_by:
        if js_condition:
            js_condition += ' && '
        js_condition += 'val.{0} && val.{0} === obj.{0}'.format(key)

    return '{}({})'.format(path, js_condition)


def reformat_datetime_str(dt_str):
    """Reformats a date/time string from Google's RFC 3339 format to our format."""
    dt = None if not dt_str else datetime.strptime(dt_str, RFC3339_DATETIME_FORMAT)
    return datetime2str(dt)


def datetime2str(dt):
    """Converts a datetime object to string."""
    return '' if not dt else dt.strftime(DEMISTO_DATETIME_FORMAT)


def human_readable_table(title, contents):
    """Creates a human-readable table for the given contents, preserving header order and adding spaces to headers."""

    def header_transform(header):
        return re.sub(r'([a-z])([A-Z])', '\\1 \\2', header)

    first_dict: Dict[str, Any] = {}
    if isinstance(contents, list) and contents:
        first_dict = contents[0]
    elif isinstance(contents, dict):
        first_dict = contents

    ordered_headers = None if not first_dict else list(first_dict.keys())

    return tableToMarkdown(title, contents, ordered_headers, header_transform)


def format_error(ex):
    """Creates a human-readable error message for the given raised error."""
    msg = 'Error occurred in the Google Cloud Storage Integration'

    if hasattr(ex, '__class__'):
        class_name = ex.__class__.__name__
        details = str(ex)
        if isinstance(ex, BaseException) and details:
            msg = '{}: {}'.format(class_name, details)
        else:
            msg += ' ({})'.format(details if details else class_name)

    return msg


''' COMMANDS + REQUESTS FUNCTIONS '''


def module_test():
    next(client.list_buckets().pages)


''' Bucket management '''


def bucket2dict(bucket):
    """Converts a google.cloud.storage.Bucket object to context format (GCS.Bucket)."""
    return {
        'Name': bucket.name,
        'TimeCreated': reformat_datetime_str(bucket._properties.get('timeCreated', '')),
        'TimeUpdated': reformat_datetime_str(bucket._properties.get('updated', '')),
        'OwnerID': '' if not bucket.owner else bucket.owner.get('entityId', '')
    }


def gcs_list_buckets():
    buckets = client.list_buckets()
    result = [bucket2dict(bucket) for bucket in buckets]

    return_outputs(
        readable_output=human_readable_table('Buckets in project ' + client.project, result),
        outputs={ec_key('GCS.Bucket', 'Name'): result},
        raw_response=result,
    )


def gcs_get_bucket():
    bucket_name = demisto.args()['bucket_name']

    bucket = client.get_bucket(bucket_name)
    result = bucket2dict(bucket)

    return_outputs(
        readable_output=human_readable_table('Bucket ' + bucket_name, result),
        outputs={ec_key('GCS.Bucket', 'Name'): result},
        raw_response=result,
    )


def gcs_create_bucket():
    bucket_name = demisto.args()['bucket_name']
    bucket_acl = demisto.args().get('bucket_acl', '')
    default_object_acl = demisto.args().get('default_object_acl', '')

    bucket = client.create_bucket(bucket_name)
    if bucket_acl:
        bucket.acl.save_predefined(bucket_acl)
    if default_object_acl:
        bucket.default_object_acl.save_predefined(default_object_acl)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Bucket {bucket_name} was created successfully.'
    })


def gcs_delete_bucket():
    bucket_name = demisto.args()['bucket_name']
    force = demisto.args().get('force', '') == 'true'

    bucket = client.get_bucket(bucket_name)
    bucket.delete(force)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Bucket {bucket_name} was deleted successfully.'
    })


''' Object operations '''


def blob2dict(blob):
    """Converts a google.cloud.storage.Blob (which represents a storage object) to context format (GCS.BucketObject)."""
    return {
        'Name': blob.name,
        'Bucket': blob.bucket.name,
        'ContentType': blob.content_type,
        'TimeCreated': datetime2str(blob.time_created),
        'TimeUpdated': datetime2str(blob.updated),
        'TimeDeleted': datetime2str(blob.time_deleted),
        'Size': blob.size,
        'MD5': blob.md5_hash,
        'OwnerID': '' if not blob.owner else blob.owner.get('entityId', ''),
        'CRC32c': blob.crc32c,
        'EncryptionAlgorithm': blob._properties.get('customerEncryption', {}).get('encryptionAlgorithm', ''),
        'EncryptionKeySHA256': blob._properties.get('customerEncryption', {}).get('keySha256', ''),
    }


def download_blob(blob, file_name=''):
    cur_directory_path = os.getcwd()
    file_name = file_name or blob.name.replace('\\', '/').split('/')[-1] or demisto.uniqueFile()
    file_path = os.path.join(cur_directory_path, file_name)

    with open(file_path, 'wb') as file:
        client.download_blob_to_file(blob, file)

    return file_name


def upload_blob(file_path, bucket_name, object_name):
    bucket = client.get_bucket(bucket_name)
    blob = bucket.blob(object_name)

    blob.upload_from_filename(file_path)

    return blob


def gcs_list_bucket_objects():
    bucket_name = demisto.args()['bucket_name']

    blobs = client.list_blobs(bucket_name)
    result = [blob2dict(blob) for blob in blobs]

    return_outputs(
        readable_output=human_readable_table('Objects in bucket ' + bucket_name, result),
        outputs={ec_key('GCS.BucketObject', 'Name', 'Bucket'): result},
        raw_response=result,
    )


def gcs_download_file():
    bucket_name = demisto.args()['bucket_name']
    blob_name = demisto.args()['object_name']
    saved_file_name = demisto.args().get('saved_file_name', '')

    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)
    saved_file_name = download_blob(blob, saved_file_name)

    demisto.results(file_result_existing_file(saved_file_name))


def gcs_upload_file():
    entry_id = demisto.args()['entry_id']
    bucket_name = demisto.args()['bucket_name']
    object_name = demisto.args()['object_name']
    object_acl = demisto.args().get('object_acl', '')

    context_file = demisto.getFilePath(entry_id)
    file_path = context_file['path']
    file_name = context_file['name']
    blob = upload_blob(file_path, bucket_name, object_name)
    if object_acl:
        blob.acl.save_predefined(object_acl)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'File {file_name} was successfully uploaded to bucket {bucket_name} as {object_name}'
    })


''' Bucket policy (ACL) '''


def acl2dict(acl_entry, include_object_name=False):
    """Converts an ACL entry from its raw JSON form to context format (GCS.BucketPolicy or GCS.BucketObjectPolicy)."""
    result = {
        'Bucket': acl_entry.get('bucket', ''),
        'Object': acl_entry.get('object', ''),
        'Entity': acl_entry.get('entity', ''),
        'Email': acl_entry.get('email', ''),
        'Role': acl_entry.get('role', ''),
        'Team': acl_entry.get('projectTeam', {}).get('team', '')
    }

    # Check if we need to adapt from GCS.BucketObjectPolicy to GCS.BucketPolicy
    if not include_object_name:
        del result['Object']

    return result


def get_acl_entries(acl):
    """Retrieves the entries of the given ACL (access control list) in their raw dictionary form."""
    path = acl.reload_path
    parsed_json = client._connection.api_request(method='GET', path=path)
    return parsed_json.get('items', ())


def set_acl_entry(acl, entity, role):
    acl_entry = acl.entity_from_dict({'entity': entity, 'role': role.upper()})
    acl.add_entity(acl_entry)
    acl.save()


def delete_acl_entry(acl, entity):
    del acl.entities[str(entity)]
    acl.save()


def gcs_list_bucket_policy():
    bucket_name = demisto.args()['bucket_name']

    acl = client.get_bucket(bucket_name).acl

    acl_entries = get_acl_entries(acl)
    result = [acl2dict(entry) for entry in acl_entries]

    return_outputs(
        readable_output=human_readable_table('ACL policy for bucket ' + bucket_name, result),
        outputs={ec_key('GCS.BucketPolicy', 'Bucket', 'Entity'): result},
        raw_response=result,
    )


def gcs_create_bucket_policy():
    bucket_name = demisto.args()['bucket_name']
    entity = demisto.args()['entity']
    role = demisto.args()['role']

    acl = client.get_bucket(bucket_name).acl
    if acl.has_entity(entity):
        raise ValueError(f'Entity {entity} already exists in the ACL of bucket {bucket_name}'
                         ' (use gcs-put-bucket-policy to update it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Added entity {entity} to ACL of bucket {bucket_name} with role {role}'
    })


def gcs_put_bucket_policy():
    bucket_name = demisto.args()['bucket_name']
    entity = demisto.args()['entity']
    role = demisto.args()['role']

    acl = client.get_bucket(bucket_name).acl
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of bucket {bucket_name}'
                         ' (use gcs-create-bucket-policy to create it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Updated ACL entity {entity} in bucket {bucket_name} to role {role}'
    })


def gcs_delete_bucket_policy():
    bucket_name = demisto.args()['bucket_name']
    entity = demisto.args()['entity']

    acl = client.get_bucket(bucket_name).acl
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of bucket {bucket_name}')

    delete_acl_entry(acl, entity)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Removed entity {entity} from ACL of bucket {bucket_name}'
    })


''' Object policy (ACL) '''


def get_blob_acl(bucket_name, blob_name):
    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)
    return blob.acl


def gcs_list_bucket_object_policy():
    bucket_name = demisto.args()['bucket_name']
    blob_name = demisto.args()['object_name']

    acl = get_blob_acl(bucket_name, blob_name)
    acl_entries = get_acl_entries(acl)
    result = [acl2dict(entry, include_object_name=True) for entry in acl_entries]

    return_outputs(
        readable_output=human_readable_table('ACL policy for object ' + blob_name, result),
        outputs={ec_key('GCS.BucketObjectPolicy', 'Bucket', 'Object', 'Entity'): result},
        raw_response=result,
    )


def gcs_create_bucket_object_policy():
    bucket_name = demisto.args()['bucket_name']
    blob_name = demisto.args()['object_name']
    entity = demisto.args()['entity']
    role = demisto.args()['role']

    acl = get_blob_acl(bucket_name, blob_name)
    if acl.has_entity(entity):
        raise ValueError(f'Entity {entity} already exists in the ACL of object {blob_name}'
                         ' (use gcs-put-bucket-object-policy to update it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Added entity {entity} to ACL of object {blob_name} with role {role}'
    })


def gcs_put_bucket_object_policy():
    bucket_name = demisto.args()['bucket_name']
    blob_name = demisto.args()['object_name']
    entity = demisto.args()['entity']
    role = demisto.args()['role']

    acl = get_blob_acl(bucket_name, blob_name)
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of object {blob_name}'
                         ' (use gcs-create-bucket-object-policy to create it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Updated ACL entity {entity} in object {blob_name} to role {role}'
    })


def gcs_delete_bucket_object_policy():
    bucket_name = demisto.args()['bucket_name']
    blob_name = demisto.args()['object_name']
    entity = demisto.args()['entity']

    acl = get_blob_acl(bucket_name, blob_name)
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of object {blob_name}')

    delete_acl_entry(acl, entity)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Removed entity {entity} from ACL of object {blob_name}'
    })


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is ' + demisto.command())

try:
    initialize_module()

    if demisto.command() == 'test-module':
        module_test()
        demisto.results('ok')

    #
    # Bucket management
    #
    elif demisto.command() == 'gcs-list-buckets':
        gcs_list_buckets()

    elif demisto.command() == 'gcs-get-bucket':
        gcs_get_bucket()

    elif demisto.command() == 'gcs-create-bucket':
        gcs_create_bucket()

    elif demisto.command() == 'gcs-delete-bucket':
        gcs_delete_bucket()

    #
    # Object operations
    #
    elif demisto.command() == 'gcs-list-bucket-objects':
        gcs_list_bucket_objects()

    elif demisto.command() == 'gcs-download-file':
        gcs_download_file()

    elif demisto.command() == 'gcs-upload-file':
        gcs_upload_file()

    #
    # Bucket policy (ACL)
    #
    elif demisto.command() == 'gcs-list-bucket-policy':
        gcs_list_bucket_policy()

    elif demisto.command() == 'gcs-create-bucket-policy':
        gcs_create_bucket_policy()

    elif demisto.command() == 'gcs-put-bucket-policy':
        gcs_put_bucket_policy()

    elif demisto.command() == 'gcs-delete-bucket-policy':
        gcs_delete_bucket_policy()

    #
    # Object policy (ACL)
    #
    elif demisto.command() == 'gcs-list-bucket-object-policy':
        gcs_list_bucket_object_policy()

    elif demisto.command() == 'gcs-create-bucket-object-policy':
        gcs_create_bucket_object_policy()

    elif demisto.command() == 'gcs-put-bucket-object-policy':
        gcs_put_bucket_object_policy()

    elif demisto.command() == 'gcs-delete-bucket-object-policy':
        gcs_delete_bucket_object_policy()

except Exception as e:
    LOG(traceback.format_exc())
    return_error(format_error(e))
