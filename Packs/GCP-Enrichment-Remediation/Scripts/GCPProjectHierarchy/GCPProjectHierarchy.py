import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Dict, Any
import traceback


''' STANDALONE FUNCTION '''


def lookup(parent_obj: str, level: int) -> tuple[str, dict]:
    """
    Lookup information on a folder or organization object. Unless the current lookup
    is a organization object, it returns parent object to lookup and results of current lookup.
    Args:
        parent_obj (str): organization/folder object in number format.
        level (int): the current level that the object is (ascending).

    Returns:
        str: parent object to look up next or "NONE" for error handling and "stop" if no parent.
        dict: dictionary of id, name and level of the lookup object.

    """
    temp: Dict[str, str] = {}
    try:
        if "folder" in parent_obj:
            folder_info = execute_command("gcp-iam-folders-get", {"folder_name": parent_obj})
            if not folder_info:
                return "NONE", temp
            name = "folders/" + folder_info.get('displayName', '')
            temp["level"] = str(level)
            temp["id"] = name
            temp["number"] = folder_info.get('name', '')
            next_one = folder_info.get('parent', '')
        elif "organization" in parent_obj:
            next_one = "stop"
            temp["level"] = str(level)
            temp["id"] = parent_obj
            temp["number"] = parent_obj
        else:
            raise ValueError('unexpected object type')
    except TypeError:
        return "NONE", temp
    else:
        return next_one, temp


''' COMMAND FUNCTION '''


def gcp_project_heirarchy(args: Dict[str, Any]) -> CommandResults:
    """
    Determine GCP project hierarchy by looking up parent objects until the organization level is reached.
    Args:
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """

    project_id = args.get('project_id')

    if not project_id:
        raise ValueError('project_id not specified')
    full_project = "projects/" + project_id
    project_info = execute_command("gcp-iam-projects-get", {"project_name": full_project})
    if not project_info:
        return CommandResults('could not find specified project info')
    level = 1
    hierarchy = [{"level": "project", "id": full_project, "number": project_info.get('name', '')}]
    next_one, to_append = lookup(project_info.get('parent', ''), level)
    if next_one == "NONE":
        return CommandResults('could not find specified folder/organization info')
    hierarchy.append(to_append)
    try:
        while 'stop' not in next_one:
            level += 1
            next_one, to_append = lookup(next_one, level)
            if next_one == "NONE" or next_one is None:
                return CommandResults('could not find specified folder/organization info')
            hierarchy.append(to_append)
    except TypeError:
        return CommandResults('could not find specified folder/organization info')

    return CommandResults(
        outputs_prefix='GCPHierarchy',
        outputs_key_field='level',
        outputs=hierarchy,
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(gcp_project_heirarchy(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute GCPProjectHierarchy. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
