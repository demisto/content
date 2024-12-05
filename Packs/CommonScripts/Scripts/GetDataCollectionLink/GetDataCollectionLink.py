import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from base64 import b64encode
from typing import Any
from distutils.version import LooseVersion


def is_machine_saas() -> bool:
    """
    Checks if the instance is SaaS by checking the demistoVersion.
    """
    demisto_version = demisto.demistoVersion()
    if demisto_version["platform"] == "x2":
        return True
    else:
        return LooseVersion(demisto_version["version"]) >= LooseVersion("8.0.0")


def generate_url(server_url: str, encoded_task: str, encoded_user: str) -> str:
    """Generates a data collection URL.

    Args:
        server_url: The Demisto server URL.
        encoded_task: The encoded task ID.
        encoded_user: The encoded user ID.

    Returns:
        The data collection URL.
    """
    if is_machine_saas():
        try:
            otp = execute_command("generateOTP", {})
        except Exception as err:
            if "Unsupported Command" in str(err):
                return f"{server_url}/#/external/form/{encoded_task}/{encoded_user}"
            raise err
        return f"{server_url}/external/form/{encoded_task}/{encoded_user}?otp={otp}"
    return f"{server_url}/#/external/form/{encoded_task}/{encoded_user}"


def encode_string(value: str) -> str:
    b64 = b64encode(value.encode('ascii'))
    return b64.hex()


def get_data_collection_url(task_id: str, users: List[str]) -> List[dict[str, str]]:
    demisto_urls = demisto.demistoUrls()
    server_url = demisto_urls.get('server', '')
    incident_id = demisto.incident().get('id')
    task = f'{incident_id}@{task_id}'
    encoded_task = encode_string(task)
    urls = []

    for user in users:
        encoded_user = encode_string(user)
        urls.append(
            {
                "user": user,
                "task": task,
                "url": generate_url(server_url, encoded_task, encoded_user),
            }
        )
    return urls


def get_data_collection_url_command(args: dict[str, Any]) -> CommandResults:  # pragma: no cover
    task_id = args.get('task_id')
    if not task_id:
        raise ValueError('task_id not specified')

    users = argToList(args.get('users', []))
    if not users:
        raise ValueError('users not specified')

    result = get_data_collection_url(task_id, users)

    return CommandResults(
        outputs_prefix='DataCollectionURL',
        outputs_key_field='user',
        outputs=result,
        ignore_auto_extract=True
    )


def main():  # pragma: no cover
    try:
        return_results(get_data_collection_url_command(demisto.args()))
    except Exception as ex:
        return_error(f'Failed to execute GetDataCollectionLink. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
