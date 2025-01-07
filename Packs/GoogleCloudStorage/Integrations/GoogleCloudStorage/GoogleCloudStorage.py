import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

from google.cloud import storage  # type: ignore[attr-defined]
from typing import Any
import requests
import traceback
import urllib3


''' GLOBALS/PARAMS '''

RFC3339_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'


''' HELPER FUNCTIONS '''


def initialize_module(service_account, insecure):
    # Allow an un-initialized client for the sake of unit tests
    client = None
    if service_account:
        client = init_storage_client(service_account)

    if insecure:
        disable_tls_verification()

    # Remove proxy if not set to true in params
    handle_proxy()

    return client


def init_storage_client(service_account):
    """Creates the Python API client for Google Cloud Storage."""
    cur_directory_path = os.getcwd()
    credentials_file_name = demisto.uniqueFile() + '.json'
    credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)

    with open(credentials_file_path, 'w') as creds_file:
        json_object = json.loads(service_account)
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


def get_bucket_name(args, default_bucket):
    bucket_name = args.get('bucket_name') or default_bucket

    if not bucket_name:
        raise DemistoException('Missing argument: "bucket_name"\nSpecify a bucket name in the command argument or'
                               ' set a default bucket name as an integration parameter.')
    return bucket_name


def ec_key(path, *merge_by):
    """Returns the context key and merge logic for the given context path and ID field name(s)."""

    if len(merge_by) == 0:
        return path

    js_condition = ''
    for key in merge_by:
        if js_condition:
            js_condition += ' && '
        js_condition += 'val.{0} && val.{0} === obj.{0}'.format(key)

    return f'{path}({js_condition})'


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

    first_dict: dict[str, Any] = {}
    if isinstance(contents, list) and contents:
        first_dict = contents[0]
    elif isinstance(contents, dict):
        first_dict = contents

    ordered_headers = None if not first_dict else list(first_dict.keys())

    return tableToMarkdown(title, contents, ordered_headers, header_transform)


def format_error(exc):
    """Creates a human-readable error message for the given raised error."""
    msg = 'Error occurred in the Google Cloud Storage Integration'

    if hasattr(exc, '__class__'):
        class_name = exc.__class__.__name__
        details = str(exc)
        if isinstance(exc, BaseException) and details:
            msg = f'{class_name}: {details}'
        else:
            msg += f' ({details if details else class_name})'

    return msg


''' COMMANDS + REQUESTS FUNCTIONS '''


def module_test(client, default_bucket):
    if default_bucket:
        client.get_bucket(default_bucket)
    else:
        # in case default bucket was not specified in the instance parameters
        demisto.debug('default bucket was not specified, querying bucket list instead.')
        try:
            next(client.list_buckets().pages)
        except Exception as exc:
            if 'does not have storage.buckets.list access' in str(exc):
                raise DemistoException('Either specify a default bucket or add storage.buckets.list access '
                                       'to the service account.', exception=exc)

            raise


''' Bucket management '''


def bucket2dict(bucket):
    """Converts a google.cloud.storage.Bucket object to context format (GCS.Bucket)."""
    return {
        'Name': bucket.name,
        'TimeCreated': reformat_datetime_str(bucket._properties.get('timeCreated', '')),
        'TimeUpdated': reformat_datetime_str(bucket._properties.get('updated', '')),
        'OwnerID': '' if not bucket.owner else bucket.owner.get('entityId', '')
    }


def gcs_list_buckets(client):
    buckets = client.list_buckets()
    result = [bucket2dict(bucket) for bucket in buckets]

    return_outputs(
        readable_output=human_readable_table('Buckets in project ' + client.project, result),
        outputs={ec_key('GCS.Bucket', 'Name'): result},
        raw_response=result,
    )


def gcs_get_bucket(client, default_bucket, args):
    bucket_name = get_bucket_name(args, default_bucket)

    bucket = client.get_bucket(bucket_name)
    result = bucket2dict(bucket)

    return_outputs(
        readable_output=human_readable_table('Bucket ' + bucket_name, result),
        outputs={ec_key('GCS.Bucket', 'Name'): result},
        raw_response=result,
    )


def gcs_create_bucket(client, args):
    bucket_name = args['bucket_name']
    bucket_acl = args.get('bucket_acl', '')
    default_object_acl = args.get('default_object_acl', '')
    location = args.get('location')
    uniform_bucket_level_access = argToBoolean(args.get('uniform_bucket_level_access'))

    bucket = client.create_bucket(bucket_name, location=location)
    if uniform_bucket_level_access:
        bucket.iam_configuration.uniform_bucket_level_access_enabled = True
        bucket.patch()
    if bucket_acl:
        bucket.acl.save_predefined(bucket_acl)
    if default_object_acl:
        bucket.default_object_acl.save_predefined(default_object_acl)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Bucket {bucket_name} was created successfully.'
    })


def gcs_delete_bucket(client, args):
    bucket_name = args['bucket_name']
    force = args.get('force', '') == 'true'

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


def download_blob(client, blob, file_name=''):
    cur_directory_path = os.getcwd()
    file_name = file_name or blob.name.replace('\\', '/').split('/')[-1] or demisto.uniqueFile()
    file_path = os.path.join(cur_directory_path, file_name)

    with open(file_path, 'wb') as file:
        client.download_blob_to_file(blob, file)

    return file_name


def upload_blob(client, file_path, bucket_name, object_name):
    bucket = client.get_bucket(bucket_name)
    blob = bucket.blob(object_name)

    blob.upload_from_filename(file_path)

    return blob


def copy_blob(client, source_bucket_name, destination_bucket_name, source_object_name, destination_object_name):
    source_bucket = client.get_bucket(source_bucket_name)
    destination_bucket = client.get_bucket(destination_bucket_name)
    source_blob = source_bucket.blob(source_object_name)
    destination_blob_name = destination_object_name

    blob_copy = source_bucket.copy_blob(source_blob, destination_bucket, destination_blob_name)

    return blob_copy


def gcs_list_bucket_objects(client, default_bucket, args):
    bucket_name = get_bucket_name(args, default_bucket)
    prefix = args.get('prefix', None)
    delimiter = args.get('delimiter', None)

    blobs = client.list_blobs(bucket_name, prefix=prefix, delimiter=delimiter)
    result = [blob2dict(blob) for blob in blobs]

    return_outputs(
        readable_output=human_readable_table('Objects in bucket ' + bucket_name, result),
        outputs={ec_key('GCS.BucketObject', 'Name', 'Bucket'): result},
        raw_response=result,
    )


def gcs_download_file(client, default_bucket, args):
    blob_name = args['object_name']
    saved_file_name = args.get('saved_file_name', '')
    bucket_name = get_bucket_name(args, default_bucket)

    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)
    saved_file_name = download_blob(client, blob, saved_file_name)

    demisto.results(file_result_existing_file(saved_file_name))


def gcs_upload_file(client, default_bucket, args):
    entry_id = args['entry_id']
    object_name = args['object_name']
    object_acl = args.get('object_acl', '')
    bucket_name = get_bucket_name(args, default_bucket)

    context_file = demisto.getFilePath(entry_id)
    file_path = context_file['path']
    file_name = context_file['name']
    blob = upload_blob(client, file_path, bucket_name, object_name)
    if object_acl:
        blob.acl.save_predefined(object_acl)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'File {file_name} was successfully uploaded to bucket {bucket_name} as {object_name}'
    })


def gcs_copy_file(client, default_bucket, args):
    source_object_name = args['source_object_name']
    source_bucket_name = args.get('source_bucket_name', default_bucket)
    destination_bucket_name = args['destination_bucket_name']
    destination_object_name = args.get('destination_object_name', source_object_name)

    copy_blob(client, source_bucket_name, destination_bucket_name, source_object_name, destination_object_name)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'File was successfully copied to bucket {destination_bucket_name} as {destination_object_name}'
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


def get_acl_entries(client, acl):
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


def gcs_list_bucket_policy(client, default_bucket, args):
    bucket_name = get_bucket_name(args, default_bucket)

    acl = client.get_bucket(bucket_name).acl

    acl_entries = get_acl_entries(client, acl)
    result = [acl2dict(entry) for entry in acl_entries]

    return_outputs(
        readable_output=human_readable_table('ACL policy for bucket ' + bucket_name, result),
        outputs={ec_key('GCS.BucketPolicy', 'Bucket', 'Entity'): result},
        raw_response=result,
    )


def gcs_create_bucket_policy(client, default_bucket, args):
    entity = args['entity']
    role = args['role']
    bucket_name = get_bucket_name(args, default_bucket)

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


def gcs_put_bucket_policy(client, default_bucket, args):
    entity = args['entity']
    role = args['role']
    bucket_name = get_bucket_name(args, default_bucket)

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


def gcs_delete_bucket_policy(client, default_bucket, args):
    entity = args['entity']
    bucket_name = get_bucket_name(args, default_bucket)

    acl = client.get_bucket(bucket_name).acl
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of bucket {bucket_name}')

    delete_acl_entry(acl, entity)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Removed entity {entity} from ACL of bucket {bucket_name}'
    })


def gcs_block_public_access_bucket(client, default_bucket, args):
    public_access_prevention = args.get('public_access_prevention', 'enforced')

    if public_access_prevention not in ['enforced', 'inherited']:
        raise ValueError('Invalid value for public_access_prevention. Accepted values are "enforced" and "inherited".')

    bucket_name = get_bucket_name(args, default_bucket)
    bucket = client.get_bucket(bucket_name)
    bucket.iam_configuration.public_access_prevention = public_access_prevention
    bucket.patch()

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Public access prevention is set to {public_access_prevention} for {bucket_name}.'
    })


''' Object policy (ACL) '''


def get_blob_acl(client, bucket_name, blob_name):
    bucket = client.get_bucket(bucket_name)
    blob = storage.Blob(blob_name, bucket)
    return blob.acl


def gcs_list_bucket_object_policy(client, default_bucket, args):
    blob_name = args['object_name']
    bucket_name = get_bucket_name(args, default_bucket)

    acl = get_blob_acl(client, bucket_name, blob_name)
    acl_entries = get_acl_entries(client, acl)
    result = [acl2dict(entry, include_object_name=True) for entry in acl_entries]

    return_outputs(
        readable_output=human_readable_table('ACL policy for object ' + blob_name, result),
        outputs={ec_key('GCS.BucketObjectPolicy', 'Bucket', 'Object', 'Entity'): result},
        raw_response=result,
    )


def gcs_create_bucket_object_policy(client, default_bucket, args):
    blob_name = args['object_name']
    entity = args['entity']
    role = args['role']
    bucket_name = get_bucket_name(args, default_bucket)

    acl = get_blob_acl(client, bucket_name, blob_name)
    if acl.has_entity(entity):
        raise ValueError(f'Entity {entity} already exists in the ACL of object {blob_name}'
                         ' (use gcs-put-bucket-object-policy to update it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Added entity {entity} to ACL of object {blob_name} with role {role}'
    })


def gcs_put_bucket_object_policy(client, default_bucket, args):
    blob_name = args['object_name']
    entity = args['entity']
    role = args['role']
    bucket_name = get_bucket_name(args, default_bucket)

    acl = get_blob_acl(client, bucket_name, blob_name)
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of object {blob_name}'
                         ' (use gcs-create-bucket-object-policy to create it)')

    set_acl_entry(acl, entity, role)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Updated ACL entity {entity} in object {blob_name} to role {role}'
    })


def gcs_delete_bucket_object_policy(client, default_bucket, args):
    blob_name = args['object_name']
    entity = args['entity']
    bucket_name = get_bucket_name(args, default_bucket)

    acl = get_blob_acl(client, bucket_name, blob_name)
    if not acl.has_entity(entity):
        raise ValueError(f'Entity {entity} does not exist in the ACL of object {blob_name}')

    delete_acl_entry(acl, entity)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': f'Removed entity {entity} from ACL of object {blob_name}'
    })


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    service_account = params.get('credentials_service_account_json', {}).get('password') or params.get('service_account_json', '')
    if not service_account:
        raise DemistoException('Service Account Private Key file contents must be provided.')
    default_bucket = params.get('default_bucket')
    insecure = params.get('insecure', False)

    LOG(f'Command being called is {command}')

    try:
        client: storage.Client = initialize_module(service_account, insecure)

        if command == 'test-module':
            module_test(client, default_bucket)
            demisto.results('ok')

        #
        # Bucket management
        #
        elif command == 'gcs-list-buckets':
            gcs_list_buckets(client)

        elif command == 'gcs-get-bucket':
            gcs_get_bucket(client, default_bucket, args)

        elif command == 'gcs-create-bucket':
            gcs_create_bucket(client, args)

        elif command == 'gcs-delete-bucket':
            gcs_delete_bucket(client, args)

        #
        # Object operations
        #
        elif command == 'gcs-list-bucket-objects':
            gcs_list_bucket_objects(client, default_bucket, args)

        elif command == 'gcs-download-file':
            gcs_download_file(client, default_bucket, args)

        elif command == 'gcs-upload-file':
            gcs_upload_file(client, default_bucket, args)

        elif command == 'gcs-copy-file':
            gcs_copy_file(client, default_bucket, args)

        #
        # Bucket policy (ACL)
        #
        elif command == 'gcs-list-bucket-policy':
            gcs_list_bucket_policy(client, default_bucket, args)

        elif command == 'gcs-create-bucket-policy':
            gcs_create_bucket_policy(client, default_bucket, args)

        elif command == 'gcs-put-bucket-policy':
            gcs_put_bucket_policy(client, default_bucket, args)

        elif command == 'gcs-delete-bucket-policy':
            gcs_delete_bucket_policy(client, default_bucket, args)

        elif command == 'gcs-block-public-access-bucket':
            gcs_block_public_access_bucket(client, default_bucket, args)

        #
        # Object policy (ACL)
        #
        elif command == 'gcs-list-bucket-object-policy':
            gcs_list_bucket_object_policy(client, default_bucket, args)

        elif command == 'gcs-create-bucket-object-policy':
            gcs_create_bucket_object_policy(client, default_bucket, args)

        elif command == 'gcs-put-bucket-object-policy':
            gcs_put_bucket_object_policy(client, default_bucket, args)

        elif command == 'gcs-delete-bucket-object-policy':
            gcs_delete_bucket_object_policy(client, default_bucket, args)

        else:
            raise NotImplementedError(f'Command not implemented: {command}')

    except Exception as e:
        LOG(traceback.format_exc())
        return_error(format_error(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
