import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


def get_list_if_exist(list_name: str) -> tuple[bool, dict]:
    """
    Gets a list from XSOAR if it exists.
    """
    res = demisto.executeCommand('getList', {'listName': list_name})
    if is_error(res) or "Item not found" in res[0]['Contents']:
        return False, {}

    current_list = json.loads(res[0]['Contents']) or {}
    return True, current_list


def get_list_from_args(list_from_args: Optional[Union[str, dict, list]] = None):
    """
    Gets an input and returns it in a list format.
    """
    if not list_from_args:
        return []

    if isinstance(list_from_args, str):
        list_from_args = json.loads(list_from_args)
    if isinstance(list_from_args, dict):
        list_from_args = [list_from_args]
    return list_from_args


def update_dict_from_images(current_dict: Dict[str, str], deployed_images: list, passed_ci_scan_images: list) -> Dict[str, str]:
    """
    Update the trusted images dict with the latest images from Prisma Cloud Compute commands outputs provided.
    """
    now = (datetime.now()).strftime(DATE_FORMAT)

    for image in deployed_images + passed_ci_scan_images:
        if not image.get('repoTag'):
            continue
        registry = image['repoTag'].get('registry')
        repo = image['repoTag']['repo']
        image_name = f'{(registry + "/") if registry else ""}{repo}:*'

        current_dict[image_name] = now

    return current_dict


def remove_expired_images(current_dict: Dict[str, str], time_frame: datetime) -> dict:
    """
    Return only images that haven't expired from the trusted images dict.
    """
    updated_dict = {image: updated_time
                    for image, updated_time in current_dict.items()
                    if parse_date_string(updated_time) >= time_frame}
    return updated_dict


def create_update_list(list_name: str, list_content: Dict[str, str], is_list_exist: bool) -> str:
    """
    Creates or updates a list on XSOAR.
    """
    if is_list_exist:
        res = demisto.executeCommand('setList', {'listName': list_name, 'listData': list_content})
    else:
        res = demisto.executeCommand('createList', {'listName': list_name, 'listData': list_content})

    if is_error(res):
        raise get_error(res)

    return f'List {list_name} {"Updated" if is_list_exist else "Created"} Successfully.'


def update_local_trusted_images(args: Dict[str, Any]) -> CommandResults:
    """
    Updates the local trusted images list with latest images from Prisma Cloud Compute.
    """
    list_name = args['list_name']
    is_list_exist, current_dict = get_list_if_exist(list_name)

    deployed_images = get_list_from_args(args.get('deployed_images'))
    passed_ci_scan_images = get_list_from_args(args.get('passed_ci_scan_images'))
    current_dict = update_dict_from_images(current_dict, deployed_images, passed_ci_scan_images)

    time_frame: datetime = dateparser.parse(args.get('time_frame', '24 hours'))  # type: ignore[assignment]
    updated_dict = remove_expired_images(current_dict, time_frame)

    result = create_update_list(list_name, updated_dict, is_list_exist)
    return CommandResults(readable_output=result)


def main():
    try:
        args = demisto.args()
        result = update_local_trusted_images(args)
        return_results(result)

    except Exception as e:
        return_error(f'Failed to execute PrismaCloudLocalTrustedImagesListUpdate. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
