from CommonServerPython import *
import urllib3
from minio import Minio
import io


class Client(Minio):
    def __init__(self, endpoint, access_key, secret_key, secure=False):
        super().__init__(endpoint=endpoint, access_key=access_key, secret_key=secret_key, secure=secure)


def make_bucket_command(client, args):

    response = []

    name = str(args.get('name', ''))

    client.make_bucket(bucket_name=name)

    response.append({
        'bucket': name,
        'status': 'created'
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Buckets',
        outputs_key_field='bucket',
        outputs=response,
        raw_response=response,
    )

    return command_results


def remove_bucket_command(client, args):

    response = []
    name = str(args.get('name', ''))

    client.remove_bucket(bucket_name=name)
    response.append({
        'bucket': name,
        'status': 'removed'
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Buckets',
        outputs_key_field='bucket',
        outputs=response,
        raw_response=response,
    )

    return command_results


def list_buckets_command(client, args):
    response = []
    buckets = client.list_buckets()

    for bucket in buckets:
        response.append({
            'bucket': bucket.name,
            'creation_date': str(bucket.creation_date)
        })

    command_results = CommandResults(
        outputs_prefix='MinIO.Buckets',
        outputs_key_field='bucket',
        outputs=response,
        raw_response=response,
    )

    return command_results


def list_objects_command(client, args):
    response = []

    bucket_name = str(args.get('bucket_name'))
    prefix = args.get('prefix')
    start_after = args.get('start_after')
    include_user_meta = args.get('include_user_meta', False)

    objects = client.list_objects(bucket_name=bucket_name, prefix=prefix, start_after=start_after,
                                  include_user_meta=include_user_meta)

    for stored_object in objects:
        response.append({
            'bucket': bucket_name,
            'object': stored_object.object_name,
            'is_dir': stored_object.is_dir,
            'size': stored_object.size,
            'etag': stored_object.etag,
            'last_modified': str(stored_object.last_modified)
        })

    command_results = CommandResults(
        outputs_prefix='MinIO.Objects',
        outputs_key_field='bucket,object',
        outputs=response,
        raw_response=response,
    )

    return command_results


def get_object_command (client, args):
    response = []

    bucket_name = str(args.get('bucket_name'))
    object_name = str(args.get('name'))
    offset = int(args.get('offset', 0))
    length = int(args.get('length', 0))
    extra_query_params = args.get('extra_query_params', None)
    request_headers = args.get('request_headers', None)
    try:
        response = client.get_object(bucket_name=bucket_name, object_name=object_name, offset=offset,
                                     length=length, extra_query_params=extra_query_params,
                                     request_headers=request_headers)
        object_bytes = response.read()
    finally:
        try:
            response.close()
            response.release_conn()
        except Exception as e:
            return_error(f"Failed to get object: {object_name}")

    return fileResult(filename=object_name, data=object_bytes)


def stat_object_command(client, args):

    response = []
    bucket_name = str(args.get('bucket_name'))
    object_name = str(args.get('name'))
    extra_query_params = args.get('extra_query_params', None)

    object_stats = client.stat_object(bucket_name=bucket_name, object_name=object_name,
                                      extra_query_params=extra_query_params)

    response.append({
        'bucket': bucket_name,
        'object': object_name,
        'content-type': object_stats.metadata.get('Content-Type'),
        'etag': object_stats.metadata.get('ETag'),
        'size': object_stats.size
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Objects',
        outputs_key_field='bucket,object',
        outputs=response,
        raw_response=response,
    )

    return command_results


def remove_object_command(client, args):

    response = []
    name = str(args.get('name', ''))
    bucket_name = str(args.get('bucket_name', ''))

    client.remove_object(object_name=name, bucket_name=bucket_name)
    response.append({
        'bucket': bucket_name,
        'object': name,
        'status': 'removed'
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Objects',
        outputs_key_field='bucket,object',
        outputs=response,
        raw_response=response,
    )

    return command_results


def fput_object_command(client, args):

    response = []
    bucket_name = str(args.get('bucket_name', ''))
    entry_id = args.get('entry_id', '')
    content_type = args.get('content_type', 'application/octet-stream')
    metadata = args.get('metadata', None)

    get_file_path_res = demisto.getFilePath(entry_id)
    object_path = get_file_path_res["path"]
    object_name = get_file_path_res["name"]

    client.fput_object(object_name=object_name, bucket_name=bucket_name,
                       file_path=object_path, content_type=content_type,
                       metadata=metadata)

    response.append({
        'bucket': bucket_name,
        'object': object_name,
        'status': 'uploaded'
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Objects',
        outputs_key_field='bucket,object',
        outputs=response,
        raw_response=response,
    )

    return command_results


def put_object_command(client, args):

    response = []
    bucket_name = str(args.get('bucket_name', ''))
    object_name = str(args.get('name'))
    data_bytes = args.get('data').encode('utf-8')
    content_type = args.get('content_type', 'application/octet-stream')
    metadata = args.get('metadata', None)

    data = io.BytesIO(data_bytes)

    client.put_object(object_name=object_name, bucket_name=bucket_name,
                      data=data, content_type=content_type,
                      metadata=metadata, length=len(data_bytes))

    response.append({
        'bucket': bucket_name,
        'object': object_name,
        'status': 'uploaded'
    })

    command_results = CommandResults(
        outputs_prefix='MinIO.Objects',
        outputs_key_field='bucket,object',
        outputs=response,
        raw_response=response,
    )

    return command_results


def test_module(client):
    # Test functions here
    client.list_buckets()
    demisto.results('ok')


def main():

    params = demisto.params()
    args = demisto.args()

    server = params.get('server')
    port = params.get('port', '9000')
    access_key = params.get('access_key')
    access_secret = params.get('access_secret')
    secure_connection = params.get('ssl', False)

    endpoint = f"{server}:{port}"

    command = demisto.command()

    LOG(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client = Client(
            endpoint=endpoint,
            access_key=access_key,
            secret_key=access_secret,
            secure=secure_connection
        )
        commands = {
            'minio-make-bucket': make_bucket_command,
            'minio-remove-bucket': remove_bucket_command,
            'minio-list-buckets': list_buckets_command,
            'minio-list-objects': list_objects_command,
            'minio-get-object': get_object_command,
            'minio-stat-object': stat_object_command,
            'minio-remove-object': remove_object_command,
            'minio-fput-object': fput_object_command,
            'minio-put-object': put_object_command
        }

        if command == 'test-module':
            test_module(client)

        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
