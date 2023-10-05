import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from base64 import b64encode
from typing import Any, Dict


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
            'url': f'{server_url}/#/external/form/{encoded_task}/{encoded_user}'
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
