import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from base64 import b64encode
from typing import Any, Dict
from distutils.version import LooseVersion



def is_machine_saas() -> bool:
    demisto_version = demisto.demistoVersion()
    if demisto_version["platform"] == "x2":
        return True
    else:
        return LooseVersion(demisto_version["version"]) >= LooseVersion("8.0.0")


def generate_url(server_url: str, encoded_task: str, encoded_user: str) -> str:
    if is_machine_saas():
        try:
            otp = execute_command("generateOTP", {})
        except Exception:
            return f'{server_url}/#/external/form/{encoded_task}/{encoded_user}'
        return f'{server_url}/external/form/{encoded_task}/{encoded_user}?otp={otp}'
    return f'{server_url}/#/external/form/{encoded_task}/{encoded_user}'


def warning_message_for_unsupported_versions(urls: list[dict[str, str]]) -> CommandResults:
    if is_machine_saas() and urls and "#" in urls[0]["url"]:
        return CommandResults(
            readable_output="In the current version, the url output is not properly supported, full support will be provided from version 8.4.0 and above.",
        )
def encode_string(value: str) -> str:
    b64 = b64encode(value.encode('ascii'))
    return b64.hex()


def get_data_collection_url(task_id: str, users: List[str]) -> List[Dict[str, str]]:
    demisto_urls = demisto.demistoUrls()
    server_url = demisto_urls.get('server', '')
    incident_id = demisto.incident().get('id')
    task = f'{incident_id}@{task_id}'
    encoded_task = encode_string(task)
    urls = []

    for user in users:
        encoded_user = encode_string(user)
        urls.append({
            'user': user,
            'task': task,
            'url': generate_url(server_url, encoded_task, encoded_user)
        })
    return urls


def get_data_collection_url_command(args: Dict[str, Any]) -> CommandResults:  # pragma: no cover
    task_id = args.get('task_id', None)
    if not task_id:
        raise ValueError('task_id not specified')

    users = argToList(args.get('users', []))
    if not users:
        raise ValueError('users not specified')

    result = get_data_collection_url(task_id, users)

    return [CommandResults(
        outputs_prefix='DataCollectionURL',
        outputs_key_field='user',
        outputs=result,
        ignore_auto_extract=True
    )].extend(warning_message_for_unsupported_versions(result))


def main():  # pragma: no cover
    try:
        return_results(get_data_collection_url_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute GetDataCollectionLink. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
