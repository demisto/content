import json

import asana
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

ASANA_ACCESS_TOKEN = demisto.getParams('accesstoken')


def get_asana_client():
    try:
        client = asana.Client.access_token(ASANA_ACCESS_TOKEN)
        me = client.users.me()

    except Exception as err:
        return_error(str(err))
    return client


def get_project(pid: str):
    client = get_asana_client()
    project = client.projects.find_by_id(pid)
    return json.dumps(project)


def create_task_in_project(pid: str, name: str):
    client = get_asana_client()
    task = client.tasks.create({'projects': pid,
                                'name': name
                                })


def test_module() -> str:
    req_client = get_asana_client()

    return 'ok'


def main():
    try:
        if demisto.command() == 'test-module':
            demisto.results(test_module())

        elif demisto.command() == 'asana-get-project':
            pid = demisto.args()['project_id']
            res = get_project(pid)
            demisto.results(res)
        elif demisto.command() == 'asana-create-task':
            pid = demisto.args()['project_id']
            name = demisto.args()['name']
            res = create_task_in_project(pid, name)
    except Exception as err:
        if isinstance(err, NotImplementedError) and COMMAND_NOT_IMPELEMENTED_MSG in str(err):
            raise
        return_error(str(err))

    finally:
        LOG.print_log()


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
