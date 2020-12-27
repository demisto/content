import urllib3

import cloudshare
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

''' CLIENT CLASS '''


class Client():
    def __init__(self, hostname: str, api_id: str = None, api_key: str = None):
        self.hostname = hostname
        self.apiId = api_id
        self.apiKey = api_key

    def send_request(self, method: str, path: str, queryParams: dict = None, content: dict = None):
        res = cloudshare.req(
            hostname=self.hostname,
            method=method,
            path=path,
            apiId=self.apiId,
            apiKey=self.apiKey,
            queryParams=queryParams,
            content=content
        )
        return res


''' HELPER FUNCTIONS '''


def test_module_command(client, args):
    res = client.send_request(
        'GET',
        'ping'
    )
    if res.status == 200:
        if "result" in res.content and res.content['result'] == "Pong":
            return_results('ok')
        else:
            return_error(res.content)
    else:
        return_error(res.content)


def get_projects_command(client, args):
    queryParams = {
        "WhereUserIsProjectManager": True if args.get('WhereUserIsProjectManager', 'false') == 'true' else False,
        "WhereUserIsProjectMember": True if args.get('WhereUserIsProjectMember', 'false') == 'true' else False,
        "WhereUserCanCreateClass": True if args.get('WhereUserCanCreateClass', 'false') == 'true' else False
    }
    res = client.send_request(
        'GET',
        'projects',
        queryParams=queryParams
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Projects:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Projects",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting projects - {res.content}")


def get_project_command(client, args):
    projectId = args.get('projectId')
    res = client.send_request(
        'GET',
        f'projects/{projectId}'
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare Project {projectId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Projects",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting project - {res.content}")


def get_project_policies_command(client, args):
    projectId = args.get('projectId')
    res = client.send_request(
        'GET',
        f'projects/{projectId}/policies'
    )
    if res.status == 200:
        policies = {
            "id": projectId,
            "Policies": res.content
        }
        md = tableToMarkdown(f'CloudShare Project Policies for {projectId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Projects",
            outputs_key_field='id',
            outputs=policies if policies else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting project policies - {res.content}")


def get_project_blueprints_command(client, args):
    projectId = args.get('projectId')
    queryParams = {k: v for k, v in args.items() if k != 'projectId'}
    res = client.send_request(
        'GET',
        f'projects/{projectId}/blueprints',
        queryParams=queryParams
    )
    if res.status == 200:
        blueprints = {
            "id": projectId,
            "Blueprints": res.content if res.content else None
        }
        md = tableToMarkdown(f'CloudShare Project Blueprints for {projectId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Projects",
            outputs_key_field='id',
            outputs=blueprints if blueprints else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting project blueprints - {res.content}")


def get_project_blueprint_command(client, args):
    projectId = args.get('projectId')
    blueprintId = args.get('blueprintId', None)
    res = client.send_request(
        'GET',
        f'projects/{projectId}/blueprints/{blueprintId}'
    )
    if res.status == 200:
        blueprints = {
            "id": projectId,
            "Blueprints": res.content if res.content else None
        }
        md = tableToMarkdown(f'CloudShare Blueprint ID {blueprintId} for Project {projectId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Projects",
            outputs_key_field='id',
            outputs=blueprints if blueprints else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting project blueprint - {res.content}")


def get_classes_command(client, args):
    res = client.send_request(
        'GET',
        'class'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare classes:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving classes - {res.content}")


def get_class_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'GET',
        f'class/{classId}'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare classes:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error finding class - {res.content}")


def delete_class_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'DELETE',
        f'class/{classId}'
    )
    if res.status == 200:
        return_results("Class {classId} deleted successfully")
    else:
        return_error(f"Error deleteing class {classId} - {res.content}")


def delete_class_environments_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'DELETE',
        'class/actions/deleteallenvironments',
        content={"id": classId}
    )
    if res.status == 200:
        results = {
            "failed": res[0].get('failed', []),
            "succeed": res[0].get('succeed', [])
        }
        for k, v in results.items():
            md = tableToMarkdown(f'CloudShare class {classId} environments deletion ({k}):', v)
            command_results = CommandResults(
                outputs_prefix="CloudShare.Classes.Actions.Delete.{k}",
                outputs_key_field='id',
                outputs=v if v else None,
                readable_output=md
            )
            return_results(command_results)
    else:
        return_error(f"Error deleteing class {classId} environments - {res.content}")


def get_classes_countries_command(client, args):
    res = client.send_request(
        'GET',
        'class/actions/countries',
        queryParams={"fullCountriesList": True}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare classes countries:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes.Countries",
            outputs_key_field='code',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving countries - {res.content}")


def get_classes_customfields_command(client, args):
    projectId = args.get('projectId')
    res = client.send_request(
        'GET',
        'class/actions/customfields',
        queryParams={"projectId": projectId}
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare project {projectId} classes custom fields:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes.CustomFields",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving custom fields - {res.content}")


def get_classes_detailed_command(client, args):
    classId = args.get('classId')
    res = client.get_classes_detailed(
        'GET',
        'class/actions/getdetailed',
        queryParams={"classId": classId}
    )
    if res.status == 200:
        res.content['id'] = classId
        md = tableToMarkdown(f'CloudShare class {classId} details:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving details - {res.content}")


def get_classes_instructors_command(client, args):
    policyId = args.get('policyId')
    res = client.send_request(
        'GET',
        'class/actions/instructors',
        queryParams={"policyId": policyId}
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare class instructors under policy {policyId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes.Instructors",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving details - {res.content}")


def create_class_command(client, args):
    res = client.send_request(
        'POST',
        'class',
        content={k: True if v == 'true' else False if v == 'false' else v for k, v in args.items()}
    )
    if res.status == 200:
        res.content.extend(args)
        md = tableToMarkdown('CloudShare create new class:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error creating new class - {res.content}")


def send_class_invitations_command(client, args):
    classId = args.get('classId')
    studentIds = args.get('studentIds').replace(" ", "").split(",")
    res = client.send_request(
        'POST',
        'class/actions/sendinvitations',
        queryParams={"isMultiple": True},
        content={
            "classId": classId,
            "studentIds": studentIds
        }
    )
    if res.status == 200:
        return_results(f"Invitations sent for class {classId} successfully.")
    else:
        return_error(f"Error sending invitations - {res.content}")


def suspend_class_environments_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'PUT',
        'class/actions/suspendallenvironments',
        content={"id": classId}
    )
    if res.status == 200:
        results = {
            "failed": res[0].get('failed', []),
            "succeed": res[0].get('succeed', [])
        }
        for k, v in results.items():
            md = tableToMarkdown(f'CloudShare class {classId} environments suspension ({k}):', v)
            command_results = CommandResults(
                outputs_prefix="CloudShare.Classes.Actions.Suspend.{k}",
                outputs_key_field='id',
                outputs=v if v else None,
                readable_output=md
            )
            return_results(command_results)
    else:
        return_error(f"Error suspending class {classId} environments - {res.content}")


def modify_class_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'PUT',
        f'class/{classId}',
        content={k: True if v == 'true' else False if v == 'false' else v for k, v in args.items() if k != 'classId'}
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare modify class {classId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Classes",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error modifying class {classId} - {res.content}")


def get_students_command(client, args):
    classId = args.get('classId')

    res = client.send_request(
        'GET',
        f'class/{classId}/students',
        queryParams={
            "isFull": True if args.get('isFull', 'false') == 'true' else False
        }
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare students for class {classId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Students",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving students for class {classId} - {res.content}")


def get_student_command(client, args):
    classId = args.get('classId')
    studentId = args.get('studentId')
    res = client.send_request(
        'GET',
        f'class/{classId}/students/{studentId}'
    )
    if res.status == 200:
        md = tableToMarkdown(f'CloudShare student {studentId} for class {classId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Students",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving students for class {classId} - {res.content}")


def delete_student_command(client, args):
    classId = args.get('classId')
    studentId = args.get('studentId')
    res = client.send_request(
        'DELETE',
        f'class/{classId}/students/{studentId}'
    )
    if res.status == 200:
        return_results("Successfully deleted student {studentId} from class {classId}")
    else:
        return_error(f"Error deleting student {studentId} from class {classId} - {res.content}")


def register_student_command(client, args):
    classId = args.get('classId')
    res = client.send_request(
        'POST',
        f'class/{classId}/students',
        content={k: v for k, v in args.items() if k != 'classId'}
    )
    if res.status == 200:
        results = {"id": v for k, v in res.contents.items() if k == 'studentId'}
        md = tableToMarkdown(f'CloudShare registered student for class {classId}:', results)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Students",
            outputs_key_field='id',
            outputs=results if results else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving students for class {classId} - {res.content}")


def modify_student_command(client, args):
    classId = args.get('classId')
    studentId = args.get('studentId')
    res = client.send_request(
        'PUT',
        f'class/{classId}/students/{studentId}',
        content={k: v for k, v in args.items() if k != 'classId' and k != 'studentId'}
    )
    if res.status == 200:
        return_results(f"Student {studentId} modified in class {classId} successfully")
    else:
        return_error(f"Error modifying student {studentId} for class {classId} - {res.content}")


def get_regions_command(client, args):
    res = client.send_request(
        'GET',
        'regions'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare regions:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Regions",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving regions - {res.content}")


def get_timezones_command(client, args):
    res = client.send_request(
        'GET',
        'timezones'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare timezones:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Timezones",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving timezones - {res.content}")


def get_envs_command(client, args):
    owned = True if args.get('owned', 'false') == 'true' else False
    visible = True if args.get('visible', 'false') == 'true' else False
    owner_email = args.get('ownerEmail', None)
    class_id = args.get('classId', None)
    brief = args.get('brief', 'false')
    queryParams = dict()
    if owned or visible:
        owned_visible = list()
        if owned:
            owned_visible.append('allowned')
        if visible:
            owned_visible.append('allvisible')
        queryParams['criteria'] = ','.join(owned_visible) if owned_visible else None
    if owner_email:
        queryParams['ownerEmail'] = owner_email
    if class_id:
        queryParams['classId'] = class_id
    if brief:
        queryParams['brief'] = brief
    res = client.send_request(
        'GET',
        'envs',
        queryParams=queryParams
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environments:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting environments - {res.content}")


def get_env_resources_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'GET',
        'envs/actions/getextended',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment {envId} Resources:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.EnvironmentResources",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting environments - {res.content}")


def get_env_extended_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'GET',
        'envs/actions/getenvresources',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment {envId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting extended environment {envId} - {res.content}")


def get_env_extended_vanity_command(client, args):
    machineVanity = args.get('machineVanity')
    res = client.send_request(
        'GET',
        'envs/actions/getextendedbymachinevanity',
        queryParams={"machineVanity": machineVanity}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment {envId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting extended environment - {res.content}")


def get_env_extended_token_command(client, args):
    sponsoredLoginToken = args.get('sponsoredLoginToken')
    res = client.send_request(
        'GET',
        'envs/actions/getextendedbytoken',
        queryParams={"sponsoredLoginToken": sponsoredLoginToken}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting extended environment - {res.content}")


def get_env_multiple_resources_command(client, args):
    res = client.send_request(
        'GET',
        'envs/actions/getmultipleenvsresources',
        queryParams={k: v for k, v in args.items()}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment Resources from {args.starttime} to {args.endtime}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.EnvironmentResources",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error getting environment resources - {res.content}")


def extend_env_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'PUT',
        'envs/actions/extend',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        return_results(f"Postpone environment {envId} suspend successful")
    else:
        return_error(f"Error postponing environment {envId} suspension- {res.content}")


def postpone_env_suspend_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'PUT',
        'envs/actions/postponeinactivity',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        return_results(f"Extend environment {envId} successful")
    else:
        return_error(f"Error extended environment {envId} - {res.content}")


def resume_env_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'PUT',
        'envs/actions/resume',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        return_results(f"Environment {envId} resumed successfully")
    else:
        return_error(f"Error resuming environment {envId} - {res.content}")


def revert_env_command(client, args):
    envId = args.get('envId')
    snapshotId = args.get('snapshotId')
    res = client.send_request(
        'PUT',
        'envs/actions/revert',
        queryParams={"envId": envId, "snapshotId": snapshotId}
    )
    if res.status == 200:
        return_results(f"Environment {envId} reverted to snapshot {snapshotId} successfully")
    else:
        return_error(f"Error reverting environment {envId} to snapshot {snapshotId} - {res.content}")


def suspend_env_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'PUT',
        'envs/actions/suspend',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        return_results(f"Environment {envId} suspended successfully")
    else:
        return_error(f"Error suspending environment {envId} - {res.content}")


def get_env_command(client, args):
    envID = args.get('envID')
    res = client.send_request(
        'GET',
        f'envs/{envID}',
        queryParams={k: v for k, v in args.items()}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare Environment {envID}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error suspending environment {envID} - {res.content}")


def delete_env_command(client, args):
    envID = args.get('envID')
    res = client.send_request(
        'DELETE',
        f'envs/{envID}'
    )
    if res.status == 200:
        return_results(f"CloudShare Environment {envID} deleted successfully")
    else:
        return_error(f"Error deleting environment {envID} - {res.content}")


def create_env_command(client, args):
    res = client.send_request(
        'POST',
        'envs',
        content={k: v for k, v in args.items()}
    )
    if res.status == 200:
        res.content['id'] = res.content.get('environmentId')
        md = tableToMarkdown('CloudShare Environment Created:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error creating environment - {res.content}")


def modify_env_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'PUT',
        'envs',
        content={"envId": envId}
    )
    if res.status == 200:
        res.content['id'] = res.content.get('environmentId')
        md = tableToMarkdown('CloudShare Environment {envId} Modified:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Environments",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error creating environment - {res.content}")


def delete_vm_command(client, args):
    VmID = args.get('VmID')
    res = client.send_request(
        'DELETE',
        f'vms/{VmID}'
    )
    if res.status == 200:
        res.content['id'] = res.content.get('environmentId')
        return_results(f"CloudShare VM {VmID} deleted successfully")
    else:
        return_error(f"Error deleting VM {VmID} - {res.content}")


def vm_check_execution_status_command(client, args):
    vmID = args.get('vmID')
    executionId = args.get('executionId')
    res = client.send_request(
        'GET',
        'vms/actions/checkexecutionstatus',
        queryParams={"vmID": vmID, "executionId": executionId}
    )
    if res.status == 200:
        md = tableToMarkdown('VM {vmID} execution {executionId} status:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.VM.Executions",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving {vmID} execution {executionId} status - {res.content}")


def vm_get_remote_command(client, args):
    VmID = args.get('VmID')
    res = client.send_request(
        'GET',
        'vms/actions/getremoteaccessfile',
        queryParams={k: v for k, v in args.items()}
    )
    if res.status == 200:
        res.content['VmID'] = VmID
        md = tableToMarkdown('VM {VmID} remote file:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.VM.Remote",
            outputs_key_field='VmID',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving {VmID} remote file - {res.content}")


def vm_execute_command(client, args):
    vmId = args.get('vmId')
    res = client.send_request(
        'POST',
        'vms/actions/executepath',
        content={"vmId": vmId}
    )
    if res.status == 200:
        md = tableToMarkdown('VM {vmId} execute task:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.VM.Execute",
            outputs_key_field='executionId',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error executing command on VM {vmId} - {res.content}")


def vm_modify_hardware_command(client, args):
    vmID = args.get('vmID')
    res = client.send_request(
        'PUT',
        'vms/actions/editvmhardware',
        content={"vmID": vmID}
    )
    if res.status == 200:
        res.content['id'] = vmID
        md = tableToMarkdown('Modify VM {vmID} hardware:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.VM.Modify",
            outputs_key_field='vmID',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error modifying VM {vmID} - {res.content}")


def reboot_vm_command(client, args):
    VmID = args.get('VmID')
    res = client.send_request(
        'PUT',
        'vms/actions/reboot',
        queryParams={"VmID": VmID}
    )
    if res.status == 200:
        return_results(f"Revert of VM {VmID} successful")
    else:
        return_error(f"Error reverting VM {VmID} - {res.content}")


def revert_vm_command(client, args):
    VmID = args.get('VmID')
    res = client.send_request(
        'PUT',
        'vms/actions/revert',
        queryParams={"VmID": VmID}
    )
    if res.status == 200:
        return_results(f"Reboot of VM {VmID} successful")
    else:
        return_error(f"Error reverting VM {VmID} - {res.content}")


def get_cloud_folders_command(client, args):
    res = client.send_request(
        'GET',
        'cloudfolders/actions/getall'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare folders:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Folders",
            outputs_key_field=['host', 'path'],
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving folders - {res.content}")


def get_env_cloud_folders_command(client, args):
    EnvId = args.get('EnvId')
    res = client.send_request(
        'PUT',
        'cloudfolders/actions/mount',
        queryParams={"EnvId": EnvId}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare folders for env {EnvId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.EnvFolders",
            outputs_key_field=['name', 'token'],
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving env {EnvId} folders - {res.content}")


def generate_password_folder_command(client, args):
    res = client.send_request(
        'PUT',
        'cloudfolders/actions/regeneratecloudfolderspassword'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare password for folders:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.FoldersPassword",
            outputs_key_field='newFtpUri',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error generating password - {res.content}")


def unmount_env_folders_command(client, args):
    EnvId = args.get('EnvId')
    res = client.send_request(
        'PUT',
        'cloudfolders/actions/unmount',
        queryParams={"EnvId": EnvId}
    )
    if res.status == 200:
        return_results(f"Unmounted env {EnvId} folders successfully")
    else:
        return_error(f"Error unmounting env {EnvId} folders - {res.content}")


def get_templates_command(client, args):
    queryParams = {k: v for k, v in args.items()}
    if "skip" in queryParams:
        queryParams['skip'] = int(queryParams['skip'])
    if "take" in queryParams:
        queryParams['take'] = int(queryParams['take'])
    res = client.send_request(
        'GET',
        'templates',
        queryParams=queryParams
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare env templates:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Templates",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving templates - {res.content}")


def get_snapshot_command(client, args):
    snapshotID = args.get('snapshotID')
    res = client.send_request(
        'GET',
        f'snapshots/{snapshotID}'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare snapshot {snapshotID}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Snapshots",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving snapshot {snapshotID} - {res.content}")


def get_env_snapshots_command(client, args):
    envId = args.get('envId')
    res = client.send_request(
        'GET',
        'snapshots/actions/getforenv',
        queryParams={"envId": envId}
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare snapshots for env {envId}:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Snapshots",
            outputs_key_field='id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving snapshots for env {envId} - {res.content}")


def mark_default_snapshot_command(client, args):
    snapshotID = args.get('snapshotID')
    res = client.send_request(
        'PUT',
        'snapshots/actions/markdefault',
        queryParams={"id": snapshotID}
    )
    if res.status == 200:
        return_results("Snapshot {snapshotID} set as default successfully")
    else:
        return_error(f"Error setting snapshot {snapshotID} as default - {res.content}")


def take_snapshot_env_command(client, args):
    envId = args.get('envId')
    content = {k: v for k, v in args.items()}
    res = client.send_request(
        method='GET',
        path='snapshots/actions/takesnapshot',
        content=content
    )
    if res.status == 200:
        return_results("Snapshot of env {envId} taken successfully")
    else:
        return_error(f"Error taking snapshot of {envId} - {res.content}")


def get_teams_command(client, args):
    res = client.send_request(
        'GET',
        'teams'
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare teams:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Teams",
            outputs_key_field='Id',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving teams - {res.content}")


def invite_user_poc_command(client, args):
    content = {k: True if v == 'true' else False if v == 'false' else v for k, v in args.items()}
    res = client.send_request(
        method='POST',
        path='invitations/actions/invitetopoc',
        content=content
    )
    if res.status == 200:
        md = tableToMarkdown('CloudShare invite:', res.content)
        command_results = CommandResults(
            outputs_prefix="CloudShare.Invites",
            outputs_key_field='invitationDetailsUrl',
            outputs=res.content if res.content else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving teams - {res.content}")


def get_poc_invitations_command(client, args):
    res = client.send_request(
        method='GET',
        path='ProofOfConceptInvitations/Rows',
        queryParams={k: v for k, v in args.items()}
    )
    if res.status == 200:
        rows = res.content.get('rows')
        md = tableToMarkdown('CloudShare POC invites:', rows)
        command_results = CommandResults(
            outputs_prefix="CloudShare.POCInvites",
            outputs_key_field='id',
            outputs=rows if rows else None,
            readable_output=md
        )
        return_results(command_results)
    else:
        return_error(f"Error retrieving invitations - {res.content}")


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    hostname = params.get('hostname')
    api_id = params.get('api_id')
    api_key = params.get('api_key')
    handle_proxy()

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        commands = {
            'cloudshare-get-envs': get_envs_command,
            'cloudshare-get-projects': get_projects_command,
            'cloudshare-get-project': get_project_command,
            'cloudshare-get-project-policies': get_project_policies_command,
            'cloudshare-get-project-blueprints': get_project_blueprints_command,
            'cloudshare-get-project-blueprint': get_project_blueprint_command,
            'cloudshare-get-classes': get_classes_command,
            'cloudshare-get-class': get_class_command,
            'cloudshare-delete-class': delete_class_command,
            'cloudshare-delete-class-environemtns': delete_class_environments_command, # This is here for maintaining BC
            'cloudshare-delete-class-environemnts': delete_class_environments_command,
            'cloudshare-get-classes-countries': get_classes_countries_command,
            'cloudshare-get-classes-customfields': get_classes_customfields_command,
            'cloudshare-get-classes-detailed': get_classes_detailed_command,
            'cloudshare-get-classes-instructors': get_classes_instructors_command,
            'cloudshare-create-class': create_class_command,
            'cloudshare-send-class-invitations': send_class_invitations_command,
            'cloudshare-suspend-class-environments': suspend_class_environments_command,
            'cloudshare-modify-class': modify_class_command,
            'cloudshare-get-students': get_students_command,
            'cloudshare-get-student': delete_student_command,
            'cloudshare-register-student': register_student_command,
            'cloudshare-modify-student': modify_student_command,
            'cloudshare-get-regions': get_regions_command,
            'cloudshare-get-timezones': get_timezones_command,
            'cloudshare-get-env-resource': get_env_resources_command,
            'cloudshare-get-env-extended': get_env_extended_command,
            'cloudshare-get-env-extended-vanity': get_env_extended_vanity_command,
            'cloudshare-get-env-extended-token': get_env_extended_token_command,
            'cloudshare-get-env-multiple-resources': get_env_multiple_resources_command,
            'cloudshare-extend-env': extend_env_command,
            'cloudshare-postpone-env-suspend': postpone_env_suspend_command,
            'cloudshare-resume-env': resume_env_command,
            'cloudshare-revert-env': revert_env_command,
            'cloudshare-suspend-env': suspend_env_command,
            'cloudshare-get-env': get_env_command,
            'cloudshare-delete-env': delete_env_command,
            'cloudshare-create-env': create_env_command,
            'cloudshare-modify-env': modify_env_command,
            'cloudshare-delete-vm': delete_vm_command,
            'cloudshare-check-vm-execution-status': vm_check_execution_status_command,
            'cloudshare-get-vm-remote-access-file': vm_get_remote_command,
            'cloudshare-execute-vm-command': vm_execute_command,
            'cloudshare-modify-vm-hardware': vm_modify_hardware_command,
            'cloudshare-reboot-vm': reboot_vm_command,
            'cloudshare-revert-vm': revert_vm_command,
            'cloudshare-get-cloud-folders': get_cloud_folders_command,
            'cloudshare-get-env-cloud-folders': get_env_cloud_folders_command,
            'cloudshare-generate-cloud-folder-password': generate_password_folder_command,
            'cloudshare-unmount-env-folders': unmount_env_folders_command,
            'cloudshare-get-templates': get_templates_command,
            'cloudshare-get-snapshot': get_snapshot_command,
            'cloudshare-get-env-snapshots': get_env_snapshots_command,
            'cloudshare-mark-default-snapshot': mark_default_snapshot_command,
            'cloudshare-take-snapshot-env': take_snapshot_env_command,
            'cloudshare-get-teams': get_teams_command,
            'cloudshare-invite-user-poc': invite_user_poc_command,
            'cloudshare-get-poc-invitations': get_poc_invitations_command

        }
        client = Client(
            hostname,
            api_id=api_id,
            api_key=api_key
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module_command(client, args)

        else:
            commands[command](client, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
