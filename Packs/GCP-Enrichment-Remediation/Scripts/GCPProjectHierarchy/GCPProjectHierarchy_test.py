import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import CommandResults


def test_lookup_func(mocker):
    """Tests lookup helper function.

        Given:
            - Mocked arguments
        When:
            - Sending args to lookup helper function.
        Then:
            - Checks the output of the helpedfunction with the expected output.
    """
    from GCPProjectHierarchy import lookup
    folder_lookup = [{'Type': 1, 'Contents': {'name': "folders/111111111111", 'displayName': 'folder-name',
                                              'parent': "organizations/111111111111"}}]

    mocker.patch.object(demisto, "executeCommand", return_value=folder_lookup)
    args = {"parent_obj": "folders/111111111111", "level": 1}
    result = lookup(**args)
    assert result == ('organizations/111111111111', {'id': 'folders/folder-name', 'level': '1',
                                                     'number': 'folders/111111111111'})


def test_GCPProjectHierarchy_command(mocker):
    """Tests GCPProjectHierarchy function.

        Given:
            - Mocked arguments
        When:
            - Sending args to GCPProjectHierarchy function.
        Then:
            - Checks the output of the function with the expected output.
    """
    from GCPProjectHierarchy import gcp_project_heirarchy

    def executeCommand(name, args):
        if name == "gcp-iam-projects-get":
            return [{'Type': 1, 'Contents': {'name': "projects/111111111111", 'displayName': 'project-name',
                                             'parent': "folders/111111111111"}}]
        elif name == "gcp-iam-folders-get":
            return [{'Type': 1, 'Contents': {'name': "folders/111111111111", 'displayName': 'folder-name',
                                             'parent': "organizations/111111111111"}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"project_id": "project-name"}
    result = gcp_project_heirarchy(args)
    assert result.outputs == [{'id': 'projects/project-name', 'level': 'project', 'number': 'projects/111111111111'},
                              {'id': 'folders/folder-name', 'level': '1', 'number': 'folders/111111111111'},
                              {'id': 'organizations/111111111111', 'level': '2', 'number': 'organizations/111111111111'}]


def test_GCPProjectHierarchy_command_empty_folder(mocker):
    """Tests GCPProjectHierarchy function.

        Given:
            - Null mocked arguments
        When:
            - Sending args to GCPProjectHierarchy function.
        Then:
            - Checks the output of the function with the expected output.
    """
    from GCPProjectHierarchy import gcp_project_heirarchy

    def executeCommand(name, args):
        if name == "gcp-iam-projects-get":
            return [{'Type': 1, 'Contents': {'name': "projects/111111111111", 'displayName': 'project-name',
                                             'parent': "folders/111111111111"}}]
        elif name == "gcp-iam-folders-get":
            return [{'Type': 1, 'Contents': {'name': '', 'displayName': '',
                                             'parent': ''}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"project_id": "project-name"}
    with pytest.raises(ValueError, match=r"unexpected object type"):
        gcp_project_heirarchy(args)


def test_GCPProjectHierarchy_command_no_folder_name(mocker):
    """Tests GCPProjectHierarchy function.

        Given:
            - Null mocked arguments
        When:
            - Sending args to GCPProjectHierarchy function.
        Then:
            - Checks the output of the function with the expected output.
    """
    from GCPProjectHierarchy import gcp_project_heirarchy

    def executeCommand(name, args):
        if name == "gcp-iam-projects-get":
            return [{'Type': 1, 'Contents': {'name': "projects/111111111111", 'displayName': 'project-name',
                                             'parent': "folders/111111111111"}}]
        elif name == "gcp-iam-folders-get":
            return [{'Type': 1, 'Contents': {'name': None, 'displayName': 'folder-name',
                                             'parent': "organizations/111111111111"}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"project_id": "project-name"}
    results = gcp_project_heirarchy(args)
    expected_hierachy = [
        {"id": "projects/project-name", "level": "project", "number": "projects/111111111111"},
        {"id": "folders/folder-name", "level": "1", "number": None},
        {"id": "organizations/111111111111", "level": "2", "number": "organizations/111111111111"}
    ]
    expected_result = CommandResults(outputs_prefix='GCPHierarchy',
                                     outputs_key_field='level',
                                     outputs=expected_hierachy)
    assert results.to_context() == expected_result.to_context()


def test_GCPProjectHierarchy_command_no_folder_parent(mocker):
    """Tests GCPProjectHierarchy function.

        Given:
            - Null mocked arguments
        When:
            - Sending args to GCPProjectHierarchy function.
        Then:
            - Checks the output of the function with the expected output.
    """
    from GCPProjectHierarchy import gcp_project_heirarchy

    def executeCommand(name, args):
        if name == "gcp-iam-projects-get":
            return [{'Type': 1, 'Contents': {'name': "projects/111111111111", 'displayName': 'project-name',
                                             'parent': "folders/111111111111"}}]
        elif name == "gcp-iam-folders-get":
            return [{'Type': 1, 'Contents': {'name': "folders/111111111111", 'displayName': 'folder-name',
                                             'parent': None}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"project_id": "project-name"}
    results = gcp_project_heirarchy(args)
    expected_result = CommandResults('could not find specified folder/organization info')
    assert results.to_context() == expected_result.to_context()


def test_GCPProjectHierarchy_command_no_folder_displayname(mocker):
    """Tests GCPProjectHierarchy function.

        Given:
            - Null mocked arguments
        When:
            - Sending args to GCPProjectHierarchy function.
        Then:
            - Checks the output of the function with the expected output.
    """
    from GCPProjectHierarchy import gcp_project_heirarchy

    def executeCommand(name, args):
        if name == "gcp-iam-projects-get":
            return [{'Type': 1, 'Contents': {'name': "projects/111111111111", 'displayName': 'project-name',
                                             'parent': "folders/111111111111"}}]
        elif name == "gcp-iam-folders-get":
            return [{'Type': 1, 'Contents': {'name': "folders/111111111111", 'displayName': None,
                                             'parent': "organizations/111111111111"}}]

    mocker.patch.object(demisto, "executeCommand", side_effect=executeCommand)
    args = {"project_id": "project-name"}
    results = gcp_project_heirarchy(args)
    expected_result = CommandResults('could not find specified folder/organization info')
    assert results.to_context() == expected_result.to_context()
