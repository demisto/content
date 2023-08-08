from pathlib import Path

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# type: ignore
from MicrosoftApiModule import *  # noqa: E402
import copy
from requests import Response
from typing import Callable
from collections import namedtuple
from datetime import datetime


PARAMETERS_ERROR_MSG = "One or more arguments are missing." \
      "Please pass with the command: {arguments}" \
      "You can also re-configure the instance and set them as parameters."

PARAMETERS_ERROR_MSG_2 = "One or more arguments are missing." \
      "Please pass with the command: repository and project." \
      "You can also re-configure the instance and set them as parameters."

INCIDENT_TYPE_NAME = "Azure DevOps"
OUTGOING_MIRRORED_FIELDS = {'status': 'The status of the pull request.',
                            'title': 'The title of the pull request.',
                            'description': 'The description of the pull request.',
                            'project': 'The name of the project.',
                            'repository_id': 'The repository ID of the pull request target branch.',
                            'pull_request_id': 'the ID of the pull request'}

GRANT_BY_CONNECTION = {'Device Code': DEVICE_CODE, 'Authorization Code': AUTHORIZATION_CODE}
AZURE_DEVOPS_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/user_impersonation offline_access"
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # ISO8601 format with UTC, default in XSOAR

class OrgRepoProject(namedtuple('OrgRepoProject', field_names='organization repository project')):
    organization: str
    repository: str
    project: str


class Client:
    """
    API Client to communicate with AzureDevOps.
    """

    def __init__(self, client_id: str, organization: str, verify: bool, proxy: bool, auth_type: str,
                 tenant_id: str = None, enc_key: str = None, auth_code: str = None, redirect_uri: str = None):
        if '@' in client_id:  # for use in test-playbook
            client_id, refresh_token = client_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        client_args = assign_params(
            self_deployed=True,
            auth_id=client_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=GRANT_BY_CONNECTION[auth_type],
            base_url=f'https://dev.azure.com/{organization}',
            verify=verify,
            proxy=proxy,
            scope=AZURE_DEVOPS_SCOPE,
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_code=auth_code,
            redirect_uri=redirect_uri)
        self.ms_client = MicrosoftClient(**client_args)
        self.organization = organization
        self.connection_type = auth_type

    def pipeline_run_request(self, project: str, pipeline_id: str, branch_name: str) -> dict:
        """
        Run a pipeline.
        Args:
            project (str): The name or the ID of the project.
            pipeline_id (str): The ID of the pipeline.
            branch_name (str): The name of the repository branch which run the pipeline.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        data = {"resources": {"repositories": {"self": {"refName": f'refs/heads/{branch_name}'}}}}

        url_suffix = f"{project}/_apis/pipelines/{pipeline_id}/runs"

        response = self.ms_client.http_request(method='POST',
                                               url_suffix=url_suffix,
                                               params=params,
                                               json_data=data,
                                               resp_type='json')

        return response

    def user_add_request(self, user_email: str, account_license_type: str, group_type: str, project_id: str) -> dict:
        """
        Add a user, assign license and extensions and make them a member of a project group in an account.
        Args:
            user_email (str): The Email of the user to add to the organization.
            account_license_type (str): The type of account license (e.g. Express, Stakeholder etc.).
            group_type (str): Project Group (e.g. Contributor, Reader etc.).
            project_id (str): The ID of the project.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.3'}
        data = {
            "accessLevel": {
                "accountLicenseType": account_license_type
            },
            "projectEntitlements": [
                {
                    "group": {
                        "groupType": group_type
                    },
                    "projectRef": {
                        "id": project_id}
                }
            ],
            "user": {
                "principalName": user_email,
                "subjectKind": "user"
            }
        }

        full_url = f"https://vsaex.dev.azure.com/{self.organization}/_apis/UserEntitlements"

        response = self.ms_client.http_request(method='POST',
                                               full_url=full_url,
                                               params=params,
                                               json_data=data,
                                               resp_type='json')

        return response

    def user_remove_request(self, user_id: str) -> Response:
        """
        Delete a user from the account.
        Args:
            user_id (str): The ID of the user to remove from the account.

        Returns:
            Response: API response from Azure.

        """
        params = {'api-version': '6.1-preview.3'}

        full_url = f'https://vsaex.dev.azure.com/{self.organization}/_apis/userentitlements/{user_id}'

        response = self.ms_client.http_request(method='DELETE',
                                               full_url=full_url,
                                               params=params,
                                               resp_type='response')

        return response

    def pull_request_create_request(self, project: str, repository_id: str, source_branch: str,
                                    target_branch: str, title: str, description: str, reviewers: list) -> dict:
        """
        Create a new pull request in Azure DevOps.

        Args:
            project (str): The name or the ID of the project.
            repository_id (str): The repository ID of the pull request's target branch.
            source_branch (str): The name of the source branch of the pull request.
            target_branch (str): The name of the target branch of the pull request.
            title (str): The title of the pull request.
            description (str): The description of the pull request.
            reviewers (list): Pull-request reviewers IDs.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}
        data = {
            "sourceRefName": source_branch,
            "targetRefName": target_branch,
            "description": description,
            "reviewers": reviewers,
            "title": title
        }

        url_suffix = f'{project}/_apis/git/repositories/{repository_id}/pullrequests'

        response = self.ms_client.http_request(method='POST',
                                               url_suffix=url_suffix,
                                               params=params,
                                               json_data=data,
                                               resp_type='json')

        return response

    def pull_request_update_request(self, project: str, repository_id: str, pull_request_id: str,
                                    title: str = None, description: str = None, status: str = None,
                                    last_merge_source_commit: dict = None) -> dict:
        """
        Update a pull request.
        Args:
            project (str): The name or the ID of the project.
            repository_id (str): The repository ID of the pull request's target branch.
            pull_request_id (str): The ID of the pull-request.
            title (str): The updated pull-request title.
            description (str): The updated pull-request description.
            status (str): The updated pull-request status.
            last_merge_source_commit (dict): Commit object at the head of the source branch
                                             at the time of the last pull request merge.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}
        data = remove_empty_elements({"description": description, "status": status,
                                      "title": title, "LastMergeSourceCommit": last_merge_source_commit})

        url_suffix = f'{project}/_apis/git/repositories/{repository_id}/pullrequests/{pull_request_id}'

        response = self.ms_client.http_request(method='PATCH',
                                               url_suffix=url_suffix,
                                               params=params,
                                               json_data=data,
                                               resp_type='json')

        return response

    def pull_requests_get_request(self, project: str, repository_id: str, pull_request_id: str) -> dict:
        """
        Retrieve pull request information request.
        Args:
            project (str): The name or the ID of the project.
            repository_id (str): The repository ID of the pull request's target branch.
            pull_request_id (str): The ID of the pull-request.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        url_suffix = f'{project}/_apis/git/repositories/{repository_id}/pullrequests/{pull_request_id}'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='json')

        return response

    def pull_requests_list_request(self, project: str, repository: str, skip: int = None, limit: int = None) -> dict:
        """
        Retrieve pull requests in repository.
        Args:
            project (str): The name or the ID of the project.
            repository (str): The repository name of the pull request's target branch.
            skip (int): The number of results to skip.
            limit (int): The number of results to retrieve.

        Returns:
            dict: API response from Azure.

        """
        params = remove_empty_elements({'api-version': '6.1-preview.1', "$skip": skip, "$top": limit})

        url_suffix = f'{project}/_apis/git/repositories/{repository}/pullrequests/'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='json')

        return response

    def project_list_request(self, skip: int = None, limit: int = None) -> dict:
        """
        Retrieve all projects in the organization that the authenticated user has access to.
        Args:
            skip (int): The number of results to skip.
            limit (int): The number of results to retrieve.

        Returns:
            dict: API response from Azure.

        """

        params = remove_empty_elements({'api-version': '6.1-preview.4', "$skip": skip, "$top": limit})

        response = self.ms_client.http_request(method='GET',
                                               url_suffix='_apis/projects',
                                               params=params,
                                               resp_type='json')

        return response

    def repository_list_request(self, project: str) -> dict:
        """
        Retrieve git repositories in the organization project.
        Args:
            project (str): The name of the project to which the repositories belong to.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        url_suffix = f'{project}/_apis/git/repositories'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='json')

        return response

    def users_query_request(self, query: str) -> dict:
        """
        Query users  in the organization.
        Args:
            query (str): Users or organization query prefix.
                         For example, If we want to retrieve information about the user 'Tom'
                         we can enter the value of this argument as 'Tom'.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        url_suffix = '_apis/IdentityPicker/Identities'

        data = {"query": query, "identityTypes": ["user", "group"], "operationScopes": ["ims", "source"],
                "properties": ["DisplayName", "IsMru", "ScopeName", "SamAccountName", "Active", "SubjectDescriptor",
                               "Department", "JobTitle", "Mail", "MailNickname", "PhysicalDeliveryOfficeName",
                               "SignInAddress", "Surname", "Guest", "TelephoneNumber", "Manager", "Description"]}

        response = self.ms_client.http_request(method='POST',
                                               url_suffix=url_suffix,
                                               params=params,
                                               json_data=data,
                                               resp_type='json')

        return response

    def get_pipeline_run_request(self, project: str, pipeline_id: str, run_id: str) -> dict:
        """
        Retrieve pipeline run information.
        Args:
            project (str): The name of the project.
            pipeline_id (str): The ID of the pipeline to retrieve.
            run_id (str): The ID of the pipeline run to retrieve.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        url_suffix = f'{project}/_apis/pipelines/{pipeline_id}/runs/{run_id}'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='json')

        return response

    def pipeline_run_list_request(self, project: str, pipeline_id: str) -> dict:
        """
        Retrieve project pipeline runs list.
        Args:
            project (str): The name of the project.
            pipeline_id (str): The ID of the pipeline to retrieve.

        Returns:
            dict: API response from Azure.

        """
        params = {'api-version': '6.1-preview.1'}

        url_suffix = f'{project}/_apis/pipelines/{pipeline_id}/runs'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='json')

        return response

    def pipeline_list_request(self, project: str, limit: int = None,
                              continuation_token: str = None) -> Response:
        """
        Retrieve project pipelines list.
        Args:
            project (str): The name of the project.
            limit (int): The number of results to retrieve.
            continuation_token (str): A continuation token from a previous request, to retrieve the next page of results.

        Returns:
            Response: API response from Azure.

        """
        params = remove_empty_elements({'api-version': '6.1-preview.1',
                                        '$top': limit,
                                        'continuationToken': continuation_token})

        url_suffix = f'{project}/_apis/pipelines'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='response')

        return response

    def branch_list_request(self, project: str, repository: str, limit: int = None,
                            continuation_token: str = None) -> Response:
        """
        Retrieve repository branches list.
        Args:
            project (str): The name of the project.
            repository (str): The name of the project repository.
            limit (int): The number of results to retrieve.
            continuation_token (str): A continuation token from a previous request, to retrieve the next page of results.

        Returns:
            Response: API response from Azure.

        """
        params = remove_empty_elements({'api-version': '6.1-preview.1',
                                        '$top': limit,
                                        'continuationToken': continuation_token,
                                        'filter': 'heads'})

        url_suffix = f'{project}/_apis/git/repositories/{repository}/refs'

        response = self.ms_client.http_request(method='GET',
                                               url_suffix=url_suffix,
                                               params=params,
                                               resp_type='response')

        return response

    def pull_requests_reviewer_list_request(self, org_repo_project_tuple: namedtuple, pull_request_id: int):

        params = {"api-version": 7.0}
        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{pull_request_id}/reviewers'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def pull_requests_reviewer_add_request(self, org_repo_project_tuple: namedtuple, pull_request_id: int,
                                           reviewer_user_id: str, is_required: bool):
        params = {"api-version": 7.0}
        data = {"id": reviewer_user_id, "isRequired": is_required, "vote": 0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{pull_request_id}/reviewers/{reviewer_user_id}'

        return self.ms_client.http_request(method='PUT',
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type='json')

    def pull_requests_commit_list_request(self, org_repo_project_tuple: namedtuple, pull_request_id: int, limit: int):

        params = {"api-version": 7.0, "$top": limit}
        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{pull_request_id}/commits'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def commit_list_request(self, org_repo_project_tuple: namedtuple, limit: int, offset: int):

        params = {"api-version": 7.0, "searchCriteria.$skip": offset, "searchCriteria.$top": limit}
        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/commits'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def commit_get_request(self, org_repo_project_tuple: namedtuple, commit_id: str):

        params = {"api-version": 7.0}
        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/commits/{commit_id}'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def work_item_get_request(self, org_repo_project_tuple: namedtuple, item_id: str):

        params = {"api-version": 7.0}
        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/wit/workitems/{item_id}'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def work_item_create_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):
        arguments_list = ['title', 'iteration_path', 'description', 'priority', 'tag']

        data = work_item_pre_process_data(args, arguments_list)

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/wit/workitems/${args["type"]}'

        return self.ms_client.http_request(method='POST',
                                           headers={"Content-Type": "application/json-patch+json"},
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def work_item_update_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):
        arguments_list = ['title', 'assignee_display_name', 'state', 'iteration_path', 'description', 'priority', 'tag']

        data = work_item_pre_process_data(args, arguments_list)

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/wit/workitems/{args["item_id"]}'

        return self.ms_client.http_request(method='PATCH',
                                           headers={"Content-Type": "application/json-patch+json"},
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def file_request(self, org_repo_project_tuple: namedtuple, change_type: str, args: Dict[str, Any]):

        data = file_pre_process_body_request(change_type, args)

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/git/repositories/{org_repo_project_tuple.repository}/pushes'

        return self.ms_client.http_request(method='POST',
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def file_list_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):

        params = {"api-version": 7.0, "versionDescriptor.version": args["branch_name"],
                  "versionDescriptor.versionType": "branch", "recursionLevel": args["recursion_level"],
                  "includeContentMetadata": True}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/git/repositories/{org_repo_project_tuple.repository}/items'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def file_get_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):

        params = {"path": args["file_name"], "api-version": 7.0, "$format": args["format"],
                  "includeContent": args["include_content"], "versionDescriptor.versionType": "branch",
                  "versionDescriptor.version": args["branch_name"]}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/git/repositories/{org_repo_project_tuple.repository}/items'

        headers = {"Content-Type": "application/json"} if args["format"] == 'json' else {"Content-Type": "application/zip"}

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           headers=headers,
                                           params=params,
                                           resp_type='response' if args["format"] == 'zip' else 'json')

    def branch_create_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):

        # initialize new branch - this is the syntax if no reference was given
        args["branch_id"] = args["branch_id"] if args.get("branch_id") else "0000000000000000000000000000000000000000"

        data = file_pre_process_body_request("add", args)
        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/' \
                   f'_apis/git/repositories/{org_repo_project_tuple.repository}/pushes'

        return self.ms_client.http_request(method='POST',
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def pull_request_thread_create_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):

        data = {
                  "comments": [
                    {
                      "parentCommentId": 0,
                      "content": args["comment_text"],
                      "commentType": 1
                    }
                  ],
                  "status": 1
                }

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{args["pull_request_id"]}/threads'

        return self.ms_client.http_request(method='POST',
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def pull_request_thread_update_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any]):

        data = {
                  "comments": [
                    {
                      "parentCommentId": 0,
                      "content": args["comment_text"],
                      "commentType": 1
                    }
                  ],
                  "status": 1
                }

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{args["pull_request_id"]}/' \
                   f'threads/{args["thread_id"]}'

        return self.ms_client.http_request(method='PATCH',
                                           full_url=full_url,
                                           params=params,
                                           json_data=data,
                                           resp_type='json')

    def pull_request_thread_list_request(self, org_repo_project_tuple: namedtuple, pull_request_id: str):

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/pullRequests/{pull_request_id}/threads'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def project_team_list_request(self, org_repo_project_tuple: namedtuple):

        params = {"api-version": 7.0}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/_apis/projects/' \
                   f'{org_repo_project_tuple.project}/teams'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def team_member_list_request(self, org_repo_project_tuple: namedtuple, args: Dict[str, Any], limit: int, skip: int):

        params = {"api-version": 7.0, "$skip": skip, "$top": limit}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/_apis/projects/' \
                   f'{org_repo_project_tuple.project}/teams/{args["team_id"]}/members'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='json')

    def blob_zip_get_request(self, org_repo_project_tuple: namedtuple, file_object_id: str):

        params = {"api-version": 7.0, "$format": "zip"}

        full_url = f'https://dev.azure.com/{org_repo_project_tuple.organization}/{org_repo_project_tuple.project}/_apis/git/' \
                   f'repositories/{org_repo_project_tuple.repository}/blobs/{file_object_id}'

        return self.ms_client.http_request(method='GET',
                                           full_url=full_url,
                                           params=params,
                                           resp_type='response')


def generate_pipeline_run_output(response: dict, project: str) -> dict:
    """
    Create XSOAR context output for retrieving pipeline run information.
    Args:
        response (dict): API response from Azure.
        project (str): The name of the pipeline project.

    Returns:
        dict: XSOAR command outputs.

    """
    outputs = copy.deepcopy(response)
    outputs['createdDate'] = arg_to_datetime(outputs.get('createdDate')).isoformat()
    outputs['run_id'] = outputs.pop('id')
    outputs['project'] = project
    outputs['result'] = outputs.get('result', 'unknown')

    return outputs


def filter_pipeline_run_table(run: dict) -> dict:
    """
    Filter pipeline-run required information for representing to the user.
    Args:
        run (dict): Pipeline-run information.

    Returns:
        dict: Filtered pipeline-run information.

    """

    return {
        "pipeline_id": dict_safe_get(run, ['pipeline', 'id']),
        "run_state": run.get('state'),
        "creation_date": run.get('createdDate'),
        "run_id": run.get('run_id'),
        "result": run.get('result', 'unknown')
    }


def generate_pipeline_run_readable_information(outputs: Union[dict, list],
                                               message: str = "Pipeline Run Information:") -> str:
    """
    Create XSOAR readable output for retrieving pipe-line information.
    Args:
        outputs (dict/list): API response from Azure.
        message (str): XSOAR readable outputs table message.

    Returns:
        str: XSOAR readable outputs.

    """

    if not isinstance(outputs, list):
        outputs = [outputs]

    readable_table = []
    for run in outputs:
        readable_table.append(filter_pipeline_run_table(run))

    readable_output = tableToMarkdown(
        message,
        readable_table,
        headers=['pipeline_id', 'run_state', 'creation_date', 'run_id', 'result'],
        headerTransform=string_to_table_header
    )

    return readable_output


def pipeline_run_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Run a pipeline.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args['project']
    pipeline_id = args['pipeline_id']
    branch_name = args['branch_name']
    should_poll = argToBoolean(args.get('polling', False))

    # create new pipeline-run.
    response = client.pipeline_run_request(project, pipeline_id, branch_name)
    state = response.get('state')

    # Running polling flow
    if should_poll and state != 'completed':
        interval = arg_to_number(args.get('interval', 30))
        timeout = arg_to_number(args.get('timeout', 60))
        run_id = response.get('id')
        polling_args = {
            'run_id': run_id,
            'interval': interval,
            'scheduled': True,
            'timeout': timeout,
            **args
        }
        # Schedule poll for the piplenine status
        scheduled_command = ScheduledCommand(
            command='azure-devops-pipeline-run-get',
            next_run_in_seconds=interval,
            timeout_in_seconds=timeout,
            args=polling_args)

        # Result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command)

    # Polling flow is done or user did not trigger the polling flow (should_poll = False)
    else:

        outputs = generate_pipeline_run_output(response, project)
        readable_output = generate_pipeline_run_readable_information(outputs)

        command_results = CommandResults(
            readable_output=readable_output,
            outputs_prefix='AzureDevOps.PipelineRun',
            outputs_key_field='run_id',
            outputs=outputs,
            raw_response=response
        )

    return command_results


def user_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add a user, assign license and extensions and make them a member of a project group in an account.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    user_email = args['user_email']
    account_license_type = args['account_license_type']
    group_type = args['group_type']
    project_id = args['project_id']

    response = client.user_add_request(user_email, account_license_type, group_type, project_id)

    if not dict_safe_get(response, ['operationResult', 'isSuccess']):
        error = dict_safe_get(response, ['operationResult', 'errors'])
        if not isinstance(error, list) or not error or len(error) == 0:
            raise ValueError('Error occurred. API response is not in the appropriate format.')

        error_message = error[0].get('value')
        raise DemistoException(error_message)

    user_information = {
        "id": dict_safe_get(response, ['userEntitlement', 'id']),
        "accountLicenseType": dict_safe_get(response,
                                            ['userEntitlement', 'accessLevel', 'accountLicenseType']),
        "lastAccessedDate": dict_safe_get(response, ['userEntitlement', 'lastAccessedDate']),
    }

    readable_output = tableToMarkdown(
        "User Information:",
        user_information,
        headers=['id', 'accountLicenseType', 'lastAccessedDate'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.User',
        outputs_key_field='id',
        outputs=response.get('userEntitlement'),
        raw_response=response
    )

    return command_results


def user_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Remove the user from all project memberships.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    user_id = args['user_id']

    client.user_remove_request(user_id)

    readable_output = f'User {user_id} was successfully removed from the organization.'
    command_results = CommandResults(
        readable_output=readable_output
    )

    return command_results


def filter_pull_request_table(pull_request: dict) -> dict:
    """
    Filter pull-request required information for representing to the user.
    Args:
        pull_request (dict): Pull-request information.

    Returns:
        dict: Filtered pull-request information.

    """

    return {
        "repository_id": dict_safe_get(pull_request, ['repository', 'id']),
        "repository_name": dict_safe_get(pull_request, ['repository', 'name']),
        "project_id": dict_safe_get(pull_request, ['repository', 'project', 'id']),
        "project_name": dict_safe_get(pull_request, ['repository', 'project', 'name']),
        "pull_request_id": pull_request.get('pullRequestId'),
        "status": pull_request.get('status'),
        "title": pull_request.get('title'),
        "description": pull_request.get('description'),
        "created_by": dict_safe_get(pull_request, ['createdBy', 'displayName']),
        "creation_date": pull_request.get('creationDate')
    }


def generate_pull_request_readable_information(response: Union[dict, list],
                                               message: str = "Pull Request Information:") -> str:
    """
    Create XSOAR readable output for retrieving pull-request information.
    Args:
        response (dict/list): API response from Azure.
        message (str): XSOAR readable outputs table message.

    Returns:
        str: XSOAR readable outputs.

    """

    if not isinstance(response, list):
        response = [response]

    readable_table = []
    for pr in response:
        readable_table.append(filter_pull_request_table(pr))

    readable_output = tableToMarkdown(
        message,
        readable_table,
        headers=['title', 'description', 'created_by', 'pull_request_id',
                 'repository_name', 'repository_id', 'project_name', 'project_id', 'creation_date'],
        headerTransform=string_to_table_header
    )

    return readable_output


def pull_request_create_command(client: Client, args: Dict[str, Any], repository: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Create a new pull-request.
    Args:
        project: Azure DevOps project.
        repository: Azure DevOps repository.
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    org_repo_project_tuple = organization_repository_project_preprocess(args=args, organization=None, repository_id=repository,
                                                                        project=project, is_organization_required=False)
    project, repository_id = org_repo_project_tuple.project, org_repo_project_tuple.repository

    source_branch = args['source_branch']
    target_branch = args['target_branch']
    title = args['title']
    description = args['description']
    reviewers_ids = argToList(args.get('reviewers_ids'))
    reviewers = [{"id": reviewer} for reviewer in reviewers_ids]

    source_branch = source_branch if source_branch.startswith('refs/') else f'refs/heads/{source_branch}'
    target_branch = target_branch if target_branch.startswith('refs/') else f'refs/heads/{target_branch}'

    response = client.pull_request_create_request(
        project, repository_id, source_branch, target_branch, title, description, reviewers)

    outputs = copy.deepcopy(response)
    outputs['creationDate'] = arg_to_datetime(response.get('creationDate')).isoformat()

    readable_output = generate_pull_request_readable_information(outputs)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequest',
        outputs_key_field='pullRequestId',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def pull_request_update_command(client: Client, args: Dict[str, Any], repository: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Update a pull request.
    Args:
        project: Azure DevOps project.
        repository: Azure DevOps repository.
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    org_repo_project_tuple = organization_repository_project_preprocess(args=args, repository_id=repository, project=project,
                                                                        is_organization_required=False, organization=None)
    project, repository = org_repo_project_tuple.project, org_repo_project_tuple.repository

    pull_request_id = args['pull_request_id']
    title = args.get('title')
    description = args.get('description')
    status = args.get('status')

    if not (title or description or status):
        raise Exception('At least one of the arguments: title, description, or status must be provided.')

    last_merge_source_commit = None
    if status == "completed":
        pr_data = client.pull_requests_get_request(project, repository, pull_request_id)
        last_merge_source_commit = pr_data.get("lastMergeSourceCommit")

    response = client.pull_request_update_request(
        project, repository, pull_request_id, title, description, status, last_merge_source_commit)

    outputs = copy.deepcopy(response)
    outputs['creationDate'] = arg_to_datetime(response.get('creationDate')).isoformat()

    readable_output = generate_pull_request_readable_information(outputs)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequest',
        outputs_key_field='pullRequestId',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def pull_request_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve pull-request information.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args['project']
    repository_id = args['repository_id']
    pull_request_id = args['pull_request_id']

    response = client.pull_requests_get_request(project, repository_id, pull_request_id)

    outputs = copy.deepcopy(response)
    outputs['creationDate'] = arg_to_datetime(response.get('creationDate')).isoformat()

    readable_output = generate_pull_request_readable_information(outputs)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequest',
        outputs_key_field='pullRequestId',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def pull_requests_list_command(client: Client, args: Dict[str, Any], repository: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Retrieve pull requests in repository.
    Args:
        project: Azure DevOps project.
        repository: Azure DevOps repository.
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args.get('project') or project
    repository = args.get('repository') or repository
    if not (repository and project):
        raise DemistoException(PARAMETERS_ERROR_MSG_2)

    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    offset = (page - 1) * limit

    response = client.pull_requests_list_request(project, repository, offset, limit)

    readable_message = f'Pull Request List:\n Current page size: {limit}\n Showing page {page} out of ' \
                       f'others that may exist.'

    outputs = copy.deepcopy(response.get('value'))
    for pr in outputs:
        pr['creationDate'] = arg_to_datetime(pr.get('creationDate')).isoformat()

    readable_output = generate_pull_request_readable_information(outputs, message=readable_message)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequest',
        outputs_key_field='pullRequestId',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def project_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve all projects in the organization that the authenticated user has access to.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    offset = (page - 1) * limit
    response = client.project_list_request(offset, limit)
    readable_message = f'Project List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    outputs = copy.deepcopy(response.get('value', []))
    output_headers = ['name', 'id', 'state', 'revision', 'visibility', 'lastUpdateTime']

    for project in outputs:
        project['lastUpdateTime'] = arg_to_datetime(project.get('lastUpdateTime')).isoformat()

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=output_headers,
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Project',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def repository_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve git repositories in the organization project.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args['project']

    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    start = (page - 1) * limit
    end = start + limit

    readable_message = f'Repositories List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    response = client.repository_list_request(project)

    outputs = []

    if response.get('count') and response.get('count') >= start:
        min_index = min(response.get('count'), end)
        for repo in response.get('value')[start:min_index]:
            outputs.append(repo)

    readable_data = copy.deepcopy(outputs)
    for repo in readable_data:
        repo["size (Bytes)"] = repo.pop("size")

    readable_output = tableToMarkdown(
        readable_message,
        readable_data,
        headers=['id', 'name', 'webUrl', 'size (Bytes)'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Repository',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def users_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Query users in the organization.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    query = args['query']
    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    start = (page - 1) * limit
    end = start + limit

    readable_message = f'Users List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    response = client.users_query_request(query)

    outputs = []
    results = response.get('results')
    readable_user_information = []
    if results and len(results) > 0:
        identities = results[0].get('identities')
        if len(identities) >= start:
            min_index = min(len(identities), end)
            for identity in identities[start:min_index]:
                # Updating the id key as well.
                identity["id"] = identity.get("localId")
                outputs.append(identity)
                if identity.get("localDirectory") == "vsd":
                    readable_user_information.append(
                        {"entityType": identity.get("entityType"), "id": identity.get("localId"),
                         "email": identity.get("signInAddress")})

    readable_output = tableToMarkdown(
        readable_message,
        readable_user_information,
        headers=['email', 'entityType', 'id'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.User',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def pipeline_run_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve pipeline run information.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    project = args['project']
    pipeline_id = args['pipeline_id']
    run_id = args['run_id']
    scheduled = argToBoolean(args.get('scheduled', False))
    response = client.get_pipeline_run_request(project, pipeline_id, run_id)

    # This is part of a scheduled command run
    state = response.get("state")

    if scheduled and state != 'completed':
        # schedule next poll
        scheduled_command = ScheduledCommand(
            command='azure-devops-pipeline-run-get',
            next_run_in_seconds=arg_to_number(args.get('interval', 30)),
            timeout_in_seconds=arg_to_number(args.get('timeout', 60)),
            args=args,
        )

        # result with scheduled_command only - no update to the war room
        command_results = CommandResults(scheduled_command=scheduled_command)

    else:
        outputs = generate_pipeline_run_output(response, project)
        readable_output = generate_pipeline_run_readable_information(outputs)

        command_results = CommandResults(
            readable_output=readable_output,
            outputs_prefix='AzureDevOps.PipelineRun',
            outputs_key_field='run_id',
            outputs=outputs,
            raw_response=response
        )

    return command_results


def pipeline_run_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve project pipeline runs list. The command retrieves up to the top 10000 runs for a particular pipeline.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args['project']
    pipeline_id = args['pipeline_id']

    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    start = (page - 1) * limit
    end = start + limit

    readable_message = f'Pipeline runs List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'
    readable_output = readable_message
    response = client.pipeline_run_list_request(project, pipeline_id)

    outputs = []
    if response.get('count') and response.get('count') >= start:
        min_index = min(response.get('count'), end)
        for run in response.get('value')[start:min_index]:
            data = generate_pipeline_run_output(run, project)
            outputs.append(data)

        readable_output = generate_pipeline_run_readable_information(outputs, message=readable_message)

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PipelineRun',
        outputs_key_field='run_id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def get_pagination_continuation_token(limit: int, page: int, client_request: Callable, args: dict) -> str:
    """
    Get next continuation token for request pagination.
    Args:
        limit (): Number of elements to retrieve.
        page (): Page number.
        client_request (Callable): Client request function.
        args (dict): Request function arguments.

    Returns:
        str: Continuation token

    """
    offset = limit * (page - 1)
    response = client_request(limit=offset, **args)
    return response.headers.get('x-ms-continuationtoken')


def pipeline_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve project pipelines list.
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    project = args['project']

    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')
    readable_message = f'Pipelines List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    continuation_token = None
    if page > 1:
        continuation_token = get_pagination_continuation_token(limit=limit, page=page,
                                                               client_request=client.pipeline_list_request,
                                                               args={"project": project})

        if not continuation_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureDevOps.Pipeline',
                outputs=[],
                raw_response=[]
            )

    response = client.pipeline_list_request(project, limit, continuation_token).json()

    outputs = copy.deepcopy(response.get("value"))
    for pipeline in outputs:
        pipeline['project'] = project

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=['id', 'name', 'revision', 'folder'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Pipeline',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )


def branch_list_command(client: Client, args: Dict[str, Any], repository: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Retrieve repository branches list.
    Args:
        project: Azure DevOps project.
        repository: Azure DevOps repository.
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    project = args.get('project') or project
    repository = args.get('repository') or repository
    if not (repository and project):
        raise DemistoException(PARAMETERS_ERROR_MSG_2)

    page = arg_to_number(args.get('page') or '1')
    limit = arg_to_number(args.get('limit') or '50')
    readable_message = f'Branches List:\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 1.')

    continuation_token = None
    if page > 1:
        continuation_token = get_pagination_continuation_token(limit=limit, page=page,
                                                               client_request=client.branch_list_request,
                                                               args={"project": project, "repository": repository})

        if not continuation_token:
            return CommandResults(
                readable_output=readable_message,
                outputs_prefix='AzureDevOps.Branch',
                outputs_key_field='name',
                outputs=[],
                raw_response=[]
            )

    response = client.branch_list_request(project, repository, limit, continuation_token).json()
    outputs = copy.deepcopy(response.get("value", []))

    for branch in outputs:
        branch['project'] = project
        branch['repository'] = repository

    readable_output = tableToMarkdown(
        readable_message,
        outputs,
        headers=['name', 'objectId'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Branch',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )


# --Mirroring Commands--
def get_update_args(delta: dict, data: dict) -> dict:
    """
    Change the updated field names to fit the pull-request update command.
    Args:
        delta (dict): Updated fields from XSOAR incident mirroring.
        data (dict): Incident source fields from XSOAR incident mirroring.

    Returns:
        dict: Updated argument information.

    """
    arguments = {'project': data.get('project'), 'repository_id': data.get('repository_id'),
                 'pull_request_id': data.get('pull_request_id'), 'title': delta.get('title'),
                 'description': delta.get('description'), 'status': delta.get('status')}

    return arguments


def update_remote_system_command(client: Client, args: Dict[str, Any]) -> str:
    """
    Pushes local changes to the remote system
    Args:
        client (Client): Azure DevOps API client.
        args (dict): Command arguments from XSOAR.
                        args['data']: the data to send to the remote system
                        args['entries']: the entries to send to the remote system
                        args['incident_changed']: boolean telling us if the local incident indeed changed or not
                        args['remote_incident_id']: the remote incident id

    Returns:
        str: The new ID of the updated incident.

    """

    remote_args = UpdateRemoteSystemArgs(args)

    if remote_args.delta:
        demisto.debug(f'Got the following delta keys {str(list(remote_args.delta.keys()))} to update Azure DevOps '
                      f'incident {remote_args.remote_incident_id}')
    else:
        demisto.debug('There is no delta fields in Azure DevOps\n')
    try:
        if remote_args.incident_changed:
            update_args = get_update_args(remote_args.delta, remote_args.data)
            demisto.debug(f'Sending incident with remote ID [{remote_args.remote_incident_id}] to Azure DevOps\n')
            pull_request_update_command(client, update_args)

        else:
            demisto.debug(f'Skipping updating remote incident fields [{remote_args.remote_incident_id}] '
                          f'as it is not new nor changed')

    except Exception as e:
        demisto.info(f"Error in Azure DevOps outgoing mirror for incident {remote_args.remote_incident_id} \n"
                     f"Error message: {str(e)}")

    finally:
        return remote_args.remote_incident_id


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Returns the list of fields for an incident type.
    """

    incident_type_scheme = SchemeTypeMapping(type_name=INCIDENT_TYPE_NAME)

    demisto.debug(f'Collecting incident mapping for incident type - "{INCIDENT_TYPE_NAME}"')

    for argument, description in OUTGOING_MIRRORED_FIELDS.items():
        incident_type_scheme.add_field(name=argument, description=description)

    mapping_response = GetMappingFieldsResponse()

    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


# --Authorization Commands--

def start_auth(client) -> CommandResults:
    result = client.ms_client.start_auth('!azure-devops-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client) -> str:
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_connection(client) -> str:
    try:
        client.ms_client.get_access_token()
    except Exception as err:
        return f'Authorization Error: \n{err}'
    return 'Success!'


def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. Run **!azure-devops-auth-start** to '
                                          'start the authentication process.')


def parse_incident(pull_request: dict, integration_instance: str) -> dict:
    """
    Parse pull request to XSOAR Incident.
    Args:
        pull_request (dict): Pull-request information.
        integration_instance (str): The name of the integration instance.

    Returns:
        dict: XSOAR Incident.

    """
    incident_data = filter_pull_request_table(pull_request)

    incident_data['mirror_direction'] = 'Out'
    incident_data['mirror_instance'] = integration_instance

    incident = {'name': "Azure DevOps - Pull request ID: " + str(incident_data.get('pull_request_id')),
                'rawJSON': json.dumps(incident_data)}

    return incident


def count_active_pull_requests(project: str, repository: str, client: Client, first_fetch: datetime = None) -> int:
    """
    Count the number of active pull-requests in the repository.
    Args:
        project (str): The name of the project which the pull requests belongs to.
        repository (str): The repository name of the pull request's target branch.
        client (Client): Azure DevOps API client.
        first_fetch (datetime): Indicated the oldest pull-request time.

    Returns:
        int: Pull-requests number.

    """
    count = 0
    limit = 100
    max_iterations = 100

    while max_iterations > 0:
        max_iterations -= 1
        response = client.pull_requests_list_request(project, repository, skip=count, limit=limit)
        if response.get("count") == 0:
            break
        if first_fetch:
            last_pr_date = arg_to_datetime(
                response.get("value")[response.get("count") - 1].get('creationDate').replace('Z', ''))
            if last_pr_date < first_fetch:  # If the oldest pr in the result is older than 'first_fetch' argument.
                for pr in response.get("value"):
                    if arg_to_datetime(pr.get('creationDate').replace('Z', '')) > first_fetch:
                        count += 1
                    else:  # Stop counting
                        max_iterations = -1
                        break
            else:
                count += response.get("count")
        else:
            count += response.get("count")

    return count


def get_last_fetch_incident_index(project: str, repository: str, client: Client, last_id: int):
    """
    Retrieve the index of the last fetched pull-request.
    index if the pull request is no active anymore - return -1.
    Args:
        project (str): The name of the project which the pull requests belongs to.
        repository (str): The repository name of the pull request's target branch.
        client (Client): Azure DevOps API client.
        last_id (int): Last fetch pull-request ID.

    Returns:
        int: Last fetched pull-request.

    """
    count = 0
    limit = 100
    max_iterations = 100

    while max_iterations > 0:
        response = client.pull_requests_list_request(project, repository, skip=count, limit=limit)
        if response.get("count") == 0:
            break

        pr_ids = [pr.get('pullRequestId') for pr in response.get('value')]
        if last_id in pr_ids:
            return pr_ids.index(last_id) + count
        else:
            if max(pr_ids) < last_id:
                break
            count += response.get("count")
            max_iterations -= 1

    return -1


def get_closest_index(project: str, repository: str, client: Client, last_id: int) -> int:
    """
    This method used for find the closest index to the last fetched pull-request ID.
    This method is used to find the ID of the next pull-request after the last_id.
    The correctness of the method stems from the fact that the pull-request ID is an incremental number,
    and from the way the pull-requests are retrieved from the API.
    Args:
        project (str): The name of the project which the pull requests belongs to.
        repository (str): The repository name of the pull request's target branch.
        client (Client): Azure DevOps API client.
        last_id (int): Last fetch pull-request ID.

    Returns:
        int: Closest index to the last fetched pull-request ID.
    """
    count = 0
    limit = 100
    max_iterations = 100

    while max_iterations > 0:
        response = client.pull_requests_list_request(project, repository, skip=count, limit=limit)

        if response.get("count") == 0:
            break

        pr_ids = [pr.get('pullRequestId') for pr in response.get('value')]
        min_id = min(pr_ids)
        max_id = max(pr_ids)

        if min_id < last_id < max_id:  # The closest index is in this page.
            closest_id = -1
            for pr_id in pr_ids:
                if pr_id < last_id:
                    break
                closest_id = pr_id

            return pr_ids.index(closest_id) + count

        elif max_id < last_id:  # The closest index is in the previous page.
            return count - 1
        else:
            count += response.get("count")
            max_iterations -= 1

        if response.get("count") == 0:
            break

    return -1


def is_new_pr(project: str, repository: str, client: Client, last_id: int) -> bool:
    """
    Validate if there is new pull-request in the repository.
    Args:
        project (str): The name of the project which the pull requests belongs to.
        repository (str): The repository name of the pull request's target branch.
        client (Client): Azure DevOps API client.
        last_id (int): Last fetch pull-request ID.

    Returns:
        bool: True if there is new pull-request in the repository, otherwise False.

    """
    response = client.pull_requests_list_request(project, repository, skip=0, limit=1)
    num_prs = response.get("count", 0)
    last_pr_id = response.get('value')[0].get('pullRequestId', 0) if len(response.get('value')) > 0 else None
    if num_prs == 0 or last_pr_id <= last_id:
        demisto.debug(f'Number of PRs is: {num_prs}. Last fetched PR id: {last_pr_id}')
        return False

    return True


def file_pre_process_body_request(change_type: str, args: Dict[str, Any]) -> dict:
    # pre-process branch
    branch_name = args["branch_name"]  # required
    branch_id = args["branch_id"]  # required
    branch_details = [{"name": branch_name, "oldObjectId": branch_id}]

    # pre-process commit
    comment = args["commit_comment"]  # required
    file_path = args.get("file_path", "")
    file_content = args.get("file_content", "")

    # validate file_path exists (explicitly or entry_id), file_content can be empty
    entry_id = args.get("entry_id", "")
    if not (entry_id or file_path):
        raise DemistoException('You must specify either the "file_path" or the "entry_id" of the file.')
    elif entry_id:
        file_path = demisto.getFilePath(entry_id)["path"]
        file_content = Path(file_path).read_text()

    changes = {"changeType": change_type, "item": {"path": file_path}}

    # in case of add/edit (create/update), add another key with the new content
    if change_type != "delete":
        changes["newContent"] = {"content": file_content, "contentType": "rawtext"}

    commits = [{"comment": comment, "changes": [changes]}]

    data = {"refUpdates": branch_details, "commits": commits}

    return data


def pagination_preprocess_and_validation(args: Dict[str, Any]) -> Tuple[int, int]:
    """
    Ensure the pagination values are valid.
    """
    limit = arg_to_number(args.get('limit') or '50')
    page = arg_to_number(args.get('page') or '1')

    if page < 1 or limit < 1:
        raise ValueError('Page and limit arguments must be greater than 1.')

    return limit, (page - 1) * limit


def organization_repository_project_preprocess(args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                                               project: Optional[str], is_repository_id_required: bool = True,
                                               is_organization_required: bool = True) -> namedtuple:
    """
    The organization, repository and project are preprocessed by this function.
    """

    # Those arguments are already set as parameters, but the user can override them.
    organization = args.get('organization_name') or organization
    repository_id = args.get('repository_id') or repository_id
    project = args.get('project_name') or project
    missing_arguments = []

    # validate those arguments exist
    if is_organization_required and not organization:
        missing_arguments.append("organization name")

    if is_repository_id_required and not repository_id:
        missing_arguments.append("repository_id / repository")

    if not project:
        missing_arguments.append("project")

    if missing_arguments:
        raise DemistoException(PARAMETERS_ERROR_MSG.format(args=", ".join(missing_arguments)))

    return OrgRepoProject(organization=organization, repository=repository_id, project=project)


def pull_request_reviewer_list_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                       repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Retrieve the reviewers for a pull request.
    """

    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    organization, repository_id, project = \
        org_repo_project_tuple.organization,  org_repo_project_tuple.repository, org_repo_project_tuple.project
    pull_request_id = arg_to_number(args.get('pull_request_id'))

    response = client.pull_requests_reviewer_list_request(org_repo_project_tuple, pull_request_id)
    mapping = {'displayName': 'Reviewer(s)'}
    readable_output = tableToMarkdown('Reviewers List', response["value"], headers=['displayName'],
                                      headerTransform=lambda header: mapping.get(header, header))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequestReviewer',
        outputs_key_field='displayName',
        outputs=response,
        raw_response=response
    )


def pull_request_reviewer_add_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                      repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Add a reviewer to a pull request.
    """

    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    pull_request_id = arg_to_number(args.get('pull_request_id'))

    reviewer_user_id = args["reviewer_user_id"]  # reviewer_user_id is required
    is_required = args.get('is_required', False)

    response = client.pull_requests_reviewer_add_request(org_repo_project_tuple, pull_request_id,
                                                            reviewer_user_id, is_required)

    readable_output = f'{response.get("displayName")} ({response.get("id")}) was created successfully as a reviewer for' \
                      f' Pull Request ID {pull_request_id}.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequestReviewer',
        outputs=response,
        raw_response=response
    )


def pull_request_commit_list_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                     repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Get the commits for the specified pull request.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    pull_request_id = arg_to_number(args.get('pull_request_id'))

    # pagination
    limit, offset = pagination_preprocess_and_validation(args)

    response = client.pull_requests_commit_list_request(org_repo_project_tuple, pull_request_id, limit)

    mapping = {'commitId': 'Commit ID', 'committer': 'Committer', 'comment': 'Comment'}
    readable_output = tableToMarkdown('Commits List', response.get('value'), headers=['comment', 'commitId', 'committer'],
                                      headerTransform=lambda header: mapping.get(header, header))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Commit',
        outputs=response,
        raw_response=response
    )


def commit_list_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                        project: Optional[str]) -> CommandResults:
    """
    Get the commits for the specified pull request.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    # pagination
    limit, offset = pagination_preprocess_and_validation(args)

    response = client.commit_list_request(org_repo_project_tuple, limit, offset)

    mapping = {'commitId': 'Commit ID', 'committer': 'Committer', 'comment': 'Comment'}
    readable_output = tableToMarkdown('Commits List', response.get('value'), headers=['comment', 'commitId', 'committer'],
                                      headerTransform=lambda header: mapping.get(header, header))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Commit',
        outputs=response,
        raw_response=response
    )


def commit_get_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                       project: Optional[str]) -> CommandResults:
    """
    Retrieve a particular commit.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    # a required argument
    commit_id = args.get('commit_id')

    response = client.commit_get_request(org_repo_project_tuple, commit_id)

    mapping = {'commitId': 'Commit ID', 'committer': 'Committer', 'comment': 'Comment'}
    readable_output = tableToMarkdown('Commit Details', response, headers=['comment', 'commitId', 'committer'],
                                      headerTransform=lambda header: mapping.get(header, header))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Commit',
        outputs=response,
        raw_response=response
    )


def work_item_get_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                          project: Optional[str]) -> CommandResults:
    """
    Returns a single work item.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    # a required argument
    item_id = args.get('item_id')

    response = client.work_item_get_request(org_repo_project_tuple, item_id)

    response_for_hr = {"ID": response.get("id"),
                       "Title": response.get("fields", {}).get("System.Title"),
                       "Assigned To": response.get("fields", {}).get("System.AssignedTo", {}).get("displayName"),
                       "State": response.get("fields", {}).get("System.State"),
                       "Area Path": response.get("fields", {}).get("System.AreaPath"),
                       "Tags": response.get("fields", {}).get("System.Tags"),
                       "Activity Date": response.get("fields", {}).get("System.ChangedDate")}

    readable_output = tableToMarkdown('Work Item Details', response_for_hr, headers=["ID", "Title", "Assigned To", "State",
                                                                                     "Area Path", "Tags", "Activity Date"])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.WorkItem',
        outputs=response,
        raw_response=response
    )


def work_item_pre_process_data(args: Dict[str, Any], arguments_list: List[str]) -> List[dict]:
    """
    This function pre-processes the data before sending it to the body.
    """
    mapping = {"title": "System.Title",
               "iteration_path": "System.IterationPath",
               "description": "System.Description",
               "priority": "Microsoft.VSTS.Common.Priority",
               "tag": "System.Tags",
               "assignee_display_name": "System.AssignedTo",
               "state": "System.State"}

    data = []

    data.extend(
        {
            "op": "add",
            "path": f'/fields/{mapping[argument]}',
            "from": None,
            "value": f'{args.get(argument)}',
        }
        for argument in arguments_list
        if args.get(argument)
    )
    return data


def work_item_create_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                             project: Optional[str]) -> CommandResults:
    """
    Creates a single work item.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.work_item_create_request(org_repo_project_tuple, args)

    readable_output = f'Work Item {response.get("id")} was created successfully.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.WorkItem',
        outputs=response,
        raw_response=response
    )


def work_item_update_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                             project: Optional[str]) -> CommandResults:
    """
    Updates a single work item.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.work_item_update_request(org_repo_project_tuple, args)

    readable_output = f'Work Item {response.get("id")} was updated successfully.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.WorkItem',
        outputs=response,
        raw_response=response
    )


def file_create_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                        project: Optional[str]) -> CommandResults:
    """
    Add a file to the repository.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.file_request(org_repo_project_tuple, change_type="add", args=args)

    readable_output = f'Commit "{response.get("commits", [])[0].get("comment")}" was created and pushed successfully by ' \
                      f'"{response.get("pushedBy", {}).get("displayName")}" to branch "{args.get("branch_name")}".'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.File',
        outputs=response,
        raw_response=response
    )


def file_update_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                        project: Optional[str]) -> CommandResults:
    """
    Update a file in the repository.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.file_request(org_repo_project_tuple, change_type="edit", args=args)

    readable_output = f'Commit "{response.get("commits", [])[0].get("comment")}" was updated successfully by ' \
                      f'"{response.get("pushedBy", {}).get("displayName")}" in branch "{args.get("branch_name")}".'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.File',
        outputs=response,
        raw_response=response
    )


def file_delete_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                        project: Optional[str]) -> CommandResults:
    """
    Delete a file in the repository.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.file_request(org_repo_project_tuple, change_type="delete", args=args)

    readable_output = f'Commit "{response.get("commits", [])[0].get("comment")}" was deleted successfully by ' \
                      f'"{response.get("pushedBy", {}).get("displayName")}" in branch "{args.get("branch_name")}".'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.File',
        outputs=response,
        raw_response=response
    )


def file_list_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                      project: Optional[str]) -> CommandResults:
    """
    Retrieve repository files (items) list.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.file_list_request(org_repo_project_tuple, args=args)

    mapping = {"path": "File Name(s)", "objectId": "Object ID"}
    readable_output = tableToMarkdown('Files', response.get("value"), headers=["path", "objectId"],
                                      headerTransform=lambda header: mapping.get(header, header))

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.File',
        outputs=response,
        raw_response=response
    )


def file_get_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                     project: Optional[str]) -> dict:
    """
    Getting the file.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.file_get_request(org_repo_project_tuple, args=args)
    file_name = Path(args["file_name"]).name

    if args["format"] == 'json':
        data = response["content"]
        file_type = EntryType.ENTRY_INFO_FILE

    else:  # args["format"] == 'zip'
        data = response.content
        file_type = EntryType.FILE

    return fileResult(filename=file_name, data=data, file_type=file_type)


def mapping_branch_name_to_branch_id(client: Client, args: Dict[str, Any], org_repo_project_tuple: namedtuple):
    """
    This function converts a branch name to branch id. If the given branch does not exist, returns None.
    """
    branch_list = branch_list_command(client, args, org_repo_project_tuple.repository, org_repo_project_tuple.project)
    for branch in branch_list.outputs:
        if branch.get("name").endswith(args["reference_branch_name"]):
            return branch.get("objectId")


def branch_create_command(client: Client, args: Dict[str, Any], organization: Optional[str], repository_id: Optional[str],
                          project: Optional[str]) -> CommandResults:
    """
    Create a branch.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)
    # convert reference_branch_name to branch id
    if args.get("reference_branch_name"):
        args["branch_id"] = mapping_branch_name_to_branch_id(client, args, org_repo_project_tuple)

    response = client.branch_create_request(org_repo_project_tuple, args=args)

    readable_output = f'Branch {response.get("refUpdates", [])[0].get("name")} was created successfully by' \
                      f' {response.get("pushedBy", {}).get("displayName")}.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Branch',
        outputs=response,
        raw_response=response
    )


def pull_request_thread_create_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                       repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Create a thread in a pull request.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.pull_request_thread_create_request(org_repo_project_tuple, args=args)

    readable_output = f'Thread {response.get("id")} was created successfully by' \
                      f' {response.get("comments", [])[0].get("author", {}).get("displayName")}.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequestThread',
        outputs=response,
        raw_response=response
    )


def pull_request_thread_update_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                       repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Update a thread in a pull request.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.pull_request_thread_update_request(org_repo_project_tuple, args=args)

    readable_output = f'Thread {response.get("id")} was updated successfully by' \
                      f' {response.get("comments", [])[0].get("author", {}).get("displayName")}.'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequestThread',
        outputs=response,
        raw_response=response
    )


def pull_request_thread_list_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                                     repository_id: Optional[str], project: Optional[str]) -> CommandResults:
    """
    Retrieve all threads in a pull request.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.pull_request_thread_list_request(org_repo_project_tuple, args["pull_request_id"])

    list_to_table = []
    for thread in response.get("value"):
        thread_id = thread.get("id")
        list_to_table.extend(
            {
                "Thread ID": thread_id,
                "Content": comment.get("content"),
                "Name": comment.get("author").get("displayName"),
                "Date": comment.get("publishedDate"),
            }
            for comment in thread.get("comments")
        )

    readable_output = tableToMarkdown(
        "Threads",
        list_to_table,
        headers=["Thread ID", "Content", "Name", "Date"]
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.PullRequestThread',
        outputs=response,
        raw_response=response
    )


def project_team_list_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                              project: Optional[str]) -> CommandResults:
    """
    Get a list of teams.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id=None, project=project,
                                                                        is_repository_id_required=False)

    response = client.project_team_list_request(org_repo_project_tuple)

    mapping = {"name": "Name"}
    readable_output = tableToMarkdown(
        "Teams",
        response.get("value"),
        headers=["name"],
        headerTransform=lambda header: mapping.get(header, header),
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.Team',
        outputs=response,
        raw_response=response
    )


def team_member_list_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                             project: Optional[str]) -> CommandResults:
    """
    Get a list of members for a specific team.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id=None, project=project,
                                                                        is_repository_id_required=False)
    # pagination
    limit, offset = pagination_preprocess_and_validation(args)

    response = client.team_member_list_request(org_repo_project_tuple, args, limit, offset)

    list_for_hr = []
    list_for_hr.extend(
        {"Name": member.get("identity").get("displayName")}
        for member in response.get("value")
    )
    readable_output = tableToMarkdown(
        "Team Members",
        list_for_hr,
        headers=["Name"],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureDevOps.TeamMember',
        outputs=response,
        raw_response=response
    )


def blob_zip_get_command(client: Client, args: Dict[str, Any], organization: Optional[str],
                         repository_id: Optional[str], project: Optional[str]) -> dict:
    """
    Get a single blob.
    """
    # pre-processing inputs
    org_repo_project_tuple = organization_repository_project_preprocess(args, organization, repository_id, project)

    response = client.blob_zip_get_request(org_repo_project_tuple, args["file_object_id"])

    return fileResult(filename=f'{args["file_object_id"]}.zip', data=response.content, file_type=EntryType.FILE)


def fetch_incidents(client, project: str, repository: str, integration_instance: str, max_fetch: int = 50,
                    first_fetch: str = None) -> None:
    """
    Fetch new active pull-requests from repository.
    Args:
        client (Client): Azure DevOps API client.
        project (str): The name of the project which the pull requests belongs to.
        repository (str): The repository name of the pull request's target branch.
        integration_instance (str): The name of the integration instance.
        max_fetch (int): Maximum incidents for one fetch.
        first_fetch (str): Indicated the date from which to start fetching pull-requests.

    """
    last_run = demisto.getLastRun()

    last_id = last_run.get("last_id", None)

    if last_id:
        if not is_new_pr(project, repository, client, last_id):  # There is no new pr
            demisto.incidents([])
            return

        last_id_index = get_last_fetch_incident_index(project, repository, client, last_id)

        if last_id_index == -1:  # Last pull-request state is no-active
            last_id_index = get_closest_index(project, repository, client, last_id) + 1

    else:  # In the first iteration of fetch-incident ,
        # we have to find the oldest active pull-request index.
        if first_fetch:
            first_fetch = arg_to_datetime(first_fetch)
        last_id_index = count_active_pull_requests(project, repository, client, first_fetch)

    skip = last_id_index - max_fetch
    if skip <= 0:
        skip = 0
        max_fetch = last_id_index

    response = client.pull_requests_list_request(project, repository, skip=skip, limit=max_fetch)

    pr_data = reversed(response.get("value"))

    last = None
    incidents = []
    for pr in pr_data:
        incidents.append(parse_incident(pr, integration_instance))
        last = pr.get('pullRequestId')

    if last:
        demisto.setLastRun({
            'last_id': last
        })

    demisto.incidents(incidents)


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if "Device" in client.connection_type:
        raise DemistoException("Please enable the integration and run `!azure-devops-auth-start`"
                               "and `!azure-deops-auth-complete` to log in."
                               "You can validate the connection by running `!azure-devops-auth-test`\n"
                               "For more details press the (?) button.")

    else:
        raise Exception("When using user auth flow configuration, "
                        "Please enable the integration and run the !azure-devops-auth-test command in order to test it")


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    client_id = params['client_id']
    organization = params['organization']
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    is_mirroring = params.get('is_mirroring', False)
    tenant_id = params.get('tenant_id')
    auth_type = params.get('auth_type', 'Device')
    auth_code = params.get('auth_code', {}).get('password', '')
    redirect_uri = params.get('redirect_uri')
    enc_key = params.get('credentials', {}).get('password', '')

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(
            client_id=client_id,
            organization=organization,
            verify=verify_certificate,
            proxy=proxy, auth_type=auth_type, tenant_id=tenant_id,
            enc_key=enc_key, auth_code=auth_code, redirect_uri=redirect_uri)

        if command == 'azure-devops-generate-login-url':
            return_results(generate_login_url(client.ms_client))

        elif command == 'azure-devops-auth-start':
            return_results(start_auth(client))

        elif command == 'azure-devops-auth-complete':
            return_results(complete_auth(client))

        elif command == 'azure-devops-auth-test':
            return_results(test_connection(client))

        elif command == 'azure-devops-user-add':
            return_results(user_add_command(client, args))

        elif command == 'azure-devops-user-remove':
            return_results(user_remove_command(client, args))

        elif command == 'azure-devops-pull-request-create':
            return_results(pull_request_create_command(client, args, params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-get':
            return_results(pull_request_get_command(client, args))

        elif command == 'azure-devops-pull-request-update':
            return_results(pull_request_update_command(client, args, params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-list':
            return_results(pull_requests_list_command(client, args, params.get('repository'), params.get('project')))

        elif command == 'azure-devops-project-list':
            return_results(project_list_command(client, args))

        elif command == 'azure-devops-repository-list':
            return_results(repository_list_command(client, args))

        elif command == 'azure-devops-user-list':
            return_results(users_query_command(client, args))

        elif command == 'azure-devops-pipeline-run-get':
            return_results(pipeline_run_get_command(client, args))

        elif command == 'azure-devops-pipeline-run-list':
            return_results(pipeline_run_list_command(client, args))

        elif command == 'azure-devops-pipeline-list':
            return_results(pipeline_list_command(client, args))

        elif command == 'azure-devops-branch-list':
            return_results(branch_list_command(client, args, params.get('repository'), params.get('project')))

        elif command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            integration_instance = demisto.integrationInstance()
            fetch_incidents(client, params.get('project'), params.get('repository'), integration_instance,
                            arg_to_number(params.get('max_fetch', 50)), params.get('first_fetch'))

        elif command == 'azure-devops-auth-reset':
            return_results(reset_auth())

        elif command == 'azure-devops-pipeline-run':
            return_results(pipeline_run_command(client, args))

        elif command == 'get-mapping-fields':
            return_results(get_mapping_fields_command())

        elif command == 'update-remote-system':
            if is_mirroring:
                return_results(update_remote_system_command(client, args))

        elif command == 'azure-devops-pull-request-reviewer-list':
            return_results(pull_request_reviewer_list_command(client, args, params.get('organization'),
                                                              params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-reviewer-add':
            return_results(pull_request_reviewer_add_command(client, args, params.get('organization'),
                                                             params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-commit-list':
            return_results(pull_request_commit_list_command(client, args, params.get('organization'),
                                                            params.get('repository'), params.get('project')))

        elif command == 'azure-devops-commit-list':
            return_results(commit_list_command(client, args, params.get('organization'),
                                               params.get('repository'), params.get('project')))

        elif command == 'azure-devops-commit-get':
            return_results(commit_get_command(client, args, params.get('organization'),
                                              params.get('repository'), params.get('project')))

        elif command == 'azure-devops-work-item-get':
            return_results(work_item_get_command(client, args, params.get('organization'),
                                                 params.get('repository'), params.get('project')))

        elif command == 'azure-devops-work-item-create':
            return_results(work_item_create_command(client, args, params.get('organization'),
                                                    params.get('repository'), params.get('project')))

        elif command == 'azure-devops-work-item-update':
            return_results(work_item_update_command(client, args, params.get('organization'),
                                                    params.get('repository'), params.get('project')))

        elif command == 'azure-devops-file-create':
            return_results(file_create_command(client, args, params.get('organization'),
                                               params.get('repository'), params.get('project')))

        elif command == 'azure-devops-file-update':
            return_results(file_update_command(client, args, params.get('organization'),
                                               params.get('repository'), params.get('project')))

        elif command == 'azure-devops-file-delete':
            return_results(file_delete_command(client, args, params.get('organization'),
                                               params.get('repository'), params.get('project')))

        elif command == 'azure-devops-file-list':
            return_results(file_list_command(client, args, params.get('organization'),
                                             params.get('repository'), params.get('project')))

        elif command == 'azure-devops-file-get':
            return_results(file_get_command(client, args, params.get('organization'),
                                            params.get('repository'), params.get('project')))

        elif command == 'azure-devops-branch-create':
            return_results(branch_create_command(client, args, params.get('organization'),
                                                 params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-thread-create':
            return_results(pull_request_thread_create_command(client, args, params.get('organization'),
                                                              params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-thread-update':
            return_results(pull_request_thread_update_command(client, args, params.get('organization'),
                                                              params.get('repository'), params.get('project')))

        elif command == 'azure-devops-pull-request-thread-list':
            return_results(pull_request_thread_list_command(client, args, params.get('organization'),
                                                            params.get('repository'), params.get('project')))

        elif command == 'azure-devops-project-team-list':
            return_results(project_team_list_command(client, args, params.get('organization'), params.get('project')))

        elif command == 'azure-devops-team-member-list':
            return_results(team_member_list_command(client, args, params.get('organization'), params.get('project')))

        elif command == 'azure-devops-blob-zip-get':
            return_results(blob_zip_get_command(client, args, params.get('organization'),
                                                params.get('repository'), params.get('project')))

        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        demisto.error(traceback.format_exc())
        if type(e) == NotFoundError:
            return_error(f"{str(e)}. There is a possibility that the organization's name is incorrect")
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
