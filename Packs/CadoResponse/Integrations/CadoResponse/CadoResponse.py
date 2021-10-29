''' Cado Response API Integration for the Cortex XSOAR Platform '''

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any, Optional
import time

''' Module Level Declarations '''

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DATE_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'

''' Cado Response API Client Code '''


class Client(BaseClient):
    ''' Client that makes HTTP requests to the Cado Response API '''

    def heartbeat(self) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/system/status endpoint to verify
            everything is working

            :return JSON response from /system/status endpoint
            :rtype Dict[str, Any]
        '''

        return self._http_request(
            method='GET',
            url_suffix='/system/status'
        )

    def create_project(self, project_name: str, project_description: Optional[str]) -> Dict[str, Any]:
        ''' Calls the POST /api/v2/projects endpoint to create a new
            project with given parameters

            :param str project_name: Name of the project
            :param Optional[str] project_description: Description for the project

            :return JSON response from /projects endpoint
            :rtype Dict[str, Any]
        '''

        if not project_name.endswith('_XSOAR'):
            project_name += '_XSOAR'

        if not project_description:
            project_description = 'This is a project in Cado Response created through Cortex XSOAR!'

        payload: Dict[str, Any] = {
            'caseName': project_name,
            'description': project_description
        }

        return self._http_request(
            method='POST',
            url_suffix='/projects',
            json_data=payload
        )

    def get_project(self, project_id: Optional[int]) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/projects endpoint to retrieve a
            project with given parameters

            :param Optional[int] project_id: ID of the project to retrieve

            :return JSON response from /projects endpoint
            :rtype Dict[str, Any]
        '''
        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        return self._http_request(
            method='GET',
            url_suffix=f'/projects/{project_id}'
        )

    def list_projects(self) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/projects endpoint to retrieve a list
            of created projects

            :return JSON response from /projects endpoint
            :rtype Dict[str, Any]
        '''

        return self._http_request(
            method='GET',
            url_suffix='/projects'
        )

    def get_pipeline(self, pipeline_id: Optional[int], project_id: Optional[int]) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/tasks/pipelines endpoint to
            retrieve details about a given pipeline

            :param Optional[int] pipeline_id: The id of the pipeline to retrieve
            :param Optional[int] project_id: The id of the project the pipeline belongs to

            :return JSON response from /tasks/pipelines endpoint
            :rtype Dict[str, Any]
        '''

        if not pipeline_id:
            return {}

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        return self._http_request(
            method='GET',
            url_suffix='/tasks/pipelines',
            params={
                'project_id': project_id,
                'pipeline_id': pipeline_id
            }
        )

    def list_pipelines(self, project_id: Optional[int]) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/tasks/pipelines endpoint to
            retrieve details about all of a projects pipelines

            :param Optional[int] project_id: The id of the project the pipeline belongs to

            :return JSON response from /tasks/pipelines endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        return self._http_request(
            method='GET',
            url_suffix='/tasks/pipelines',
            params={
                'project_id': project_id,
            }
        )

    def list_instances(self, project_id: Optional[int], region: Optional[str]) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/projects/{id}/imports/ec2 endpoint to
            retrieve details about a regions EC2 instances

            :param Optional[int] project_id: The id of the project to query available instances in
            :param Optional[str] region: The AWS region to search instances in

            :return JSON response from /projects/{id}/imports/ec2 endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        if not region:
            region = demisto.params().get('CadoResponse_DefaultRegion', 'us-east-1')

        return self._http_request(
            method='GET',
            url_suffix=f'/projects/{project_id}/imports/ec2',
            params={
                'region': region
            }
        )

    def list_buckets(self, project_id: Optional[int]) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/projects/{id}/imports/s3 endpoint to
            retrieve details about all the available S3 buckets

            :param Optional[int] project_id: The id of the project to query available buckets in

            :return JSON response from /projects/{id}/imports/s3 endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        return self._http_request(
            method='GET',
            url_suffix=f'/projects/{project_id}/imports/s3'
        )

    def trigger_instance_acquisition(self, project_id: Optional[int], instance_id: str, region: Optional[str],
                                     bucket: Optional[str], compress: bool = True, include_disks: bool = True,
                                     include_hash: bool = False, include_logs: bool = True,
                                     include_screenshot: bool = True) -> Dict[str, Any]:
        ''' Calls the POST /api/v2/projects/{id}/imports/ec2 endpoint to
            trigger an acquisition of a given instance

            :param Optional[int] project_id: The ID of the project you wish to attach the acquisition to
            :param str instance_id: ID of the EC2 instance to acquire
            :param Optional[str] region: AWS region in which the EC2 instance is located
            :param Optional[str] bucket: S3 bucket where the uploaded disk image resides
            :param bool compress: Flag indicating if disk compression is enabled
            :param bool include_disks: Flag indicating if we include disk image in the acquisition
            :param bool include_hash: Flag indicating if we calculate the hash of the disk
            :param bool include_logs: Flag indicating if we include system logs in the acquisition
            :param bool include_screenshot: Flag indicating if we include a screenshot of the system in the acquisition

            :return JSON response from /projects/{id}/imports/ec2 endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        if not region:
            region = demisto.params().get('CadoResponse_DefaultRegion', 'us-east-1')

        if not bucket:
            bucket = demisto.params().get('CadoResponse_DefaultBucket', 'cado-default-bucket')

        payload: Dict[str, Any] = {
            'bucket': bucket,
            'compress': compress,
            'include_disks': include_disks,
            'include_hash': include_hash,
            'include_logs': include_logs,
            'include_screenshot': include_screenshot,
            'instance_id': instance_id,
            'region': region
        }

        return self._http_request(
            method='POST',
            url_suffix=f'/projects/{project_id}/imports/ec2',
            json_data=payload
        )

    def trigger_bucket_acquisition(self, project_id: Optional[int], bucket: Optional[str],
                                   file_name: Optional[str]) -> Dict[str, Any]:
        ''' Calls the POST /api/v2/projects/{id}/imports/s3 endpoint to
            trigger an acquisition of a given bucket or file

            :param Optional[int] project_id: The ID of the project you wish to attach the acquisition to
            :param Optional[str] bucket: The S3 bucket name containing the file
            :param Optional[str] file_name: The name of the file to process

            :return JSON response from /projects/{id}/imports/ec2 endpoint
            :rtype Dict[str, Any]
        '''
        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        if not bucket:
            bucket = demisto.params().get('CadoResponse_DefaultBucket', 'cado-default-bucket')

        payload: Dict[str, Any] = {
            'bucket': bucket
        }

        if not file_name:
            payload['file_name'] = file_name

        return self._http_request(
            method='POST',
            url_suffix=f'/projects/{project_id}/imports/s3',
            json_data=payload
        )


''' Command Line Handlers '''


def test_module(client: Client) -> str:
    ''' Command handler for !test-module '''
    result: Dict[str, Any] = client.heartbeat()

    if result['status']:
        if result['status'] == 'Running':
            return 'ok'

    return 'Cado Response is not running'


def create_project_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-create-project '''
    unix_timestamp: str = str(int(time.time()))
    project_name: str = args.get('project_name', unix_timestamp)
    project_description: Optional[str] = args.get('project_description', None)

    result: Dict[str, Any] = client.create_project(project_name, project_description)

    return CommandResults(
        outputs_prefix='CadoResponse.Project',
        outputs_key_field='id',
        outputs=result
    )


def get_project_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-get-project '''
    project_id: Optional[int] = args.get('project_id', None)

    result: Dict[str, Any] = client.get_project(project_id)

    return CommandResults(
        outputs_prefix='CadoResponse.Project',
        outputs_key_field='id',
        outputs=result
    )


def list_projects_command(client: Client) -> CommandResults:
    ''' Command handler for cado-list-project '''
    result: Dict[str, Any] = client.list_projects()

    return CommandResults(
        outputs_prefix='CadoResponse.Projects',
        outputs_key_field='id',
        outputs=result
    )


def get_pipeline_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-get-pipeline '''
    pipeline_id: Optional[int] = args.get('pipeline_id', None)
    project_id: Optional[int] = args.get('project_id', None)

    if not pipeline_id:
        raise DemistoException('pipeline_id is a required parameter!')

    result: Dict[str, Any] = client.get_pipeline(pipeline_id, project_id)

    return CommandResults(
        outputs_prefix='CadoResponse.Pipeline',
        outputs_key_field='pipeline_id',
        outputs=result
    )


def get_pipelines_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-get-pipelines '''
    project_id: Optional[int] = args.get('project_id', None)

    result: Dict[str, Any] = client.list_pipelines(project_id)

    return CommandResults(
        outputs_prefix='CadoResponse.Pipelines',
        outputs_key_field='pipeline_id',
        outputs=result.get('pipelines', {})
    )


''' Helper Functions '''


def enrich_errors(message: str, command: str) -> str:
    ''' Helper function to return better error messages.

        :param str message: Error message
        :param str command: Calling command

        :return: A better error message
        :rtype str
    '''
    if command == 'cado-create-project' and 'Project name already exists' in message:
        return f'Project name {demisto.args().get("project_name")} already exists!'
    else:
        return f'Failed to execute {demisto.command()} command.\nError:\n{message}'


''' Entrypoint '''


def main() -> None:
    api_key: str = demisto.params().get('apikey')
    base_url: str = urljoin(demisto.params()['url'], '/api/v2')
    verify_certificate: bool = not demisto.params().get('insecure', False)
    proxy: bool = demisto.params().get('proxy', False)
    command: str = demisto.command()
    args: Dict[str, Any] = demisto.args()
    headers: Dict[str, Any] = {
        'Authorization': f'Bearer {api_key}'
    }

    try:
        client: Client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'cado-create-project':
            return_results(create_project_command(client, args))
        elif command == 'cado-get-project':
            return_results(get_project_command(client, args))
        elif command == 'cado-list-projects':
            return_results(list_projects_command(client))
        elif command == 'cado-get-pipeline':
            return_results(get_pipeline_command(client, args))
        elif command == 'cado-get-pipelines':
            return_results(get_pipelines_command(client, args))

    except Exception as e:
        message: str = str(e)
        demisto.error(traceback.format_exc())
        return_error(enrich_errors(message, command), error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
