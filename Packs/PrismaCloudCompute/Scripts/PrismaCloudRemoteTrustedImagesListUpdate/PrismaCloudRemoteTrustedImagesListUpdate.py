import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


def get_xsoar_list(list_name: str) -> dict:
    """
    Gets a list from XSOAR if it exists.
    """
    res = demisto.executeCommand('getList', {'listName': list_name})
    if 'Item not found' in res[0]['Contents']:
        raise DemistoException(f'List {list_name} was not found.')
    if is_error(res):
        raise DemistoException(get_error(res))

    current_list = json.loads(res[0]['Contents']) or {}
    return current_list


def current_remote_images_same_as_local(remote_images: list, local_images: list):
    """
    Compares remote images to local trusted images list and returns True if same, False otherwise.
    """
    return set(remote_images) == set(local_images)


def update_group_from_images(remote_trusted_images: Dict[str, Any], current_trusted_images: list, trusted_group_id: str) -> \
        tuple[bool, str]:
    """
    Update the remote trusted images group with latest images from local source.
    """
    for group in remote_trusted_images['groups']:
        if group['_id'] == trusted_group_id:
            if current_remote_images_same_as_local(group['images'], current_trusted_images):
                return False, 'Local and remote lists were equal, not updating list.'
            group['images'] = current_trusted_images
            return True, ''

    return False, f'Group {trusted_group_id} was not found in the given trusted images groups list.'


def update_remote_list(current_dict: dict):
    """
    Updates the remote trusted images list with the latest images from the local trusted images list.
    """
    res = demisto.executeCommand('prisma-cloud-compute-trusted-images-update', {'images_list_json': json.dumps(current_dict)})
    if is_error(res):
        raise DemistoException(get_error(res))

    return res[0]['HumanReadable']


def update_remote_trusted_images(args: Dict[str, Any]):
    """
    Updates the remote trusted images list from the local trusted images list.
    """
    list_name = args['list_name']
    local_trusted_images = list((get_xsoar_list(list_name)).keys())

    remote_trusted_images = args.get('current_trusted_images')
    if isinstance(remote_trusted_images, str):
        remote_trusted_images = json.loads(remote_trusted_images)

    trusted_group_id = str(args.get('trusted_group_id'))

    update_remote, result = update_group_from_images(remote_trusted_images, local_trusted_images, trusted_group_id)
    if update_remote:
        result = update_remote_list(remote_trusted_images)
    return CommandResults(readable_output=result)


def main():
    try:
        args = demisto.args()
        result = update_remote_trusted_images(args)
        return_results(result)

    except Exception as e:
        return_error(f'Failed to execute PrismaCloudLocalTrustedImagesListUpdate. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
