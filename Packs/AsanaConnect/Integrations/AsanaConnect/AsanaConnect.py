import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import asana


def get_asana_client(token):
    try:
        client = asana.Client.access_token(token)
    except Exception as err:
        return_error(str(err))
    return client


def get_projects_in_workspace(wid, client):
    res = []
    projects = client.projects.get_projects({"workspace": wid}, opt_pretty=True)

    for project in projects:
        res.append(project)
    return res


def get_all_projects(token):
    """Gets all projects of the user in Asana'

    :type token: ``str``
    :param token: PAT of the account used in this integration

    :return: list of the projects on Asana
    :rtype: ``list``
    """
    res = []
    try:
        client = get_asana_client(token)
        workspaces = client.workspaces.find_all()  # pylint: disable=no-member
        for workspace in workspaces:
            projects = get_projects_in_workspace(workspace["gid"], client)
            res.extend(projects)
        return CommandResults(outputs_prefix="asana", outputs_key_field="projects", outputs=res)
    except Exception:
        demisto.results("Request failed")


def get_project(pid, token):
    """Retrieves metadata of the particular project'

    :type id: ``str``
    :param id: project id in Asana

    :type name: ``str``
    :param name: name for the task to be created

    :type token: ``str``
    :param token: PAT of the account used in this integration

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    project = {}
    try:
        client = get_asana_client(token)
        project = client.projects.find_by_id(pid)  # pylint: disable=no-member
        return CommandResults(outputs_prefix="asana", outputs_key_field="project", outputs=project)
    except Exception:
        demisto.results("Request failed")


def create_task_in_project(pid, name, token):
    """Creates a task in the specific Asana project'

    :type id: ``str``
    :param id: project id in Asana

    :type name: ``str``
    :param name: name for the task to be created

    :type token: ``str``
    :param token: PAT of the account used in this integration

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client = get_asana_client(token)
        client.tasks.create({"projects": pid, "name": name})  # pylint: disable=no-member
        demisto.results(f"Task {name} successfully added to project")
    except Exception:
        demisto.results("Task creation failed")


def test_module(token):
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Shows the http error 'No Authorization' if it fails.

    :type token: ``str``
    :param token: PAT of the Asana account used in this integration

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    get_asana_client(token)

    return "ok"


def main():
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    access_token = params.get("accesstoken")
    try:
        if demisto.command() == "test-module":
            demisto.results(test_module(access_token))

        elif demisto.command() == "asana-get-project":
            pid = demisto.args()["project_id"]
            res = get_project(pid, access_token)
            return_results(res)

        elif demisto.command() == "asana-create-task":
            pid = demisto.args()["project_id"]
            name = demisto.args()["name"]
            create_task_in_project(pid, name, access_token)

        elif demisto.command() == "asana-get-all-projects":
            res = get_all_projects(access_token)
            return_results(res)
    except Exception as err:
        return_error(str(err))


if __name__ in ["__builtin__", "builtins", "__main__"]:
    main()
