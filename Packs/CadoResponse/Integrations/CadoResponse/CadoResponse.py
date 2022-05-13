''' Cado Response API Integration for the Cortex XSOAR Platform '''

import time
import traceback
from typing import Any, Dict, Optional

from CommonServerPython import *

from CommonServerUserPython import *

import demistomock as demisto

import requests


''' Module Level Declarations '''

requests.packages.urllib3.disable_warnings()
CadoResponseCombinedOutput = Union[Dict[str, Any], List[Dict[str, Any]]]

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

    def list_projects(self, limit: int) -> List[Dict[str, Any]]:
        ''' Calls the GET /api/v2/projects endpoint to retrieve a list
            of created projects

            :return JSON response from /projects endpoint
            :rtype Dict[str, Any]
        '''

        data: List[Dict[str, Any]] = self._http_request(
            method='GET',
            url_suffix='/projects'
        )

        return data[:limit]

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

    def list_pipelines(self, project_id: Optional[int], limit: int) -> List[Dict[str, Any]]:
        ''' Calls the GET /api/v2/tasks/pipelines endpoint to
            retrieve details about all of a projects pipelines

            :param Optional[int] project_id: The id of the project the pipeline belongs to

            :return JSON response from /tasks/pipelines endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        data: Dict[str, Any] = self._http_request(
            method='GET',
            url_suffix='/tasks/pipelines',
            params={
                'project_id': project_id,
            }
        )

        pipelines: List[Dict[str, Any]] = data['pipelines']

        return pipelines[:limit]

    def list_instances(self, project_id: Optional[int], region: Optional[str], limit: int) -> List[Dict[str, Any]]:
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

        data: Dict[str, Any] = self._http_request(
            method='GET',
            url_suffix=f'/projects/{project_id}/imports/ec2',
            params={
                'region': region
            }
        )

        instances: List[Dict[str, Any]] = data['instances']

        return instances[:limit]

    def list_buckets(self, project_id: Optional[int], limit: int) -> Dict[str, Any]:
        ''' Calls the GET /api/v2/projects/{id}/imports/s3 endpoint to
            retrieve details about all the available S3 buckets

            :param Optional[int] project_id: The id of the project to query available buckets in

            :return JSON response from /projects/{id}/imports/s3 endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        data: Dict[str, Any] = self._http_request(
            method='GET',
            url_suffix=f'/projects/{project_id}/imports/s3'
        )

        data['buckets'] = data['buckets'][:limit]

        return data

    def trigger_instance_acquisition(self, project_id: Optional[int], instance_id: Optional[str], region: Optional[str],
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
            :param str file_name: The name of the file to process

            :return JSON response from /projects/{id}/imports/ec2 endpoint
            :rtype Dict[str, Any]
        '''

        if not project_id:
            project_id = demisto.params().get('CadoResponse_DefaultProject', 1)

        if not bucket:
            bucket = demisto.params().get('CadoResponse_DefaultBucket', 'cado-default-bucket')

        payload: Dict[str, Any] = {
            'bucket': bucket,
            'file_name': file_name
        }

        return self._http_request(
            method='POST',
            url_suffix=f'/projects/{project_id}/imports/s3',
            json_data=payload
        )


''' Command Line Handlers '''


def test_module(client: Client) -> str:
    ''' Command handler for !test-module '''

    result: Dict[str, Any] = client.heartbeat()
    status: Optional[str] = result['status']

    if status is not None and status == 'Running':
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


def list_project_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-list-project '''

    project_id: Optional[int] = args.get('project_id', None)
    limit: int = int(args.get('limit', 50))

    if project_id:
        result: Any = client.get_project(project_id)
    else:
        result = client.list_projects(limit)

    return CommandResults(
        outputs_prefix='CadoResponse.Projects',
        outputs_key_field='id',
        outputs=result
    )


def get_pipeline_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-get-pipeline '''

    project_id: Optional[int] = args.get('project_id', None)
    limit: int = int(args.get('limit', 50))
    pipeline_id: Optional[int] = args.get('pipeline_id', None)

    if pipeline_id:
        result: CadoResponseCombinedOutput = client.get_pipeline(pipeline_id, project_id)
    else:
        result = client.list_pipelines(project_id, limit)

    return CommandResults(
        outputs_prefix='CadoResponse.Pipelines',
        outputs_key_field='pipeline_id',
        outputs=result
    )


def list_ec2_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-list-ec2 '''

    project_id: Optional[int] = args.get('project_id', None)
    region: Optional[str] = args.get('region', None)
    limit: int = int(args.get('limit', 100))
    result: List[Dict[str, Any]] = client.list_instances(project_id, region, limit)

    return CommandResults(
        outputs_prefix='CadoResponse.EC2Instances',
        outputs_key_field='id',
        outputs=result
    )


def list_s3_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-list-s3 '''

    project_id: Optional[int] = args.get('project_id', None)
    limit: int = int(args.get('limit', 100))
    result: Dict[str, Any] = client.list_buckets(project_id, limit)

    return CommandResults(
        outputs_prefix='CadoResponse.S3Buckets',
        outputs=result
    )


def trigger_ec2_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-trigger-ec2 '''

    project_id: Optional[int] = args.get('project_id', None)
    instance_id: Optional[str] = args.get('instance_id', None)
    region: Optional[str] = args.get('region', None)
    bucket: Optional[str] = args.get('bucket', None)
    compress: bool = args.get('compress', True)
    include_disks: bool = args.get('include_disks', True)
    include_hash: bool = args.get('include_hash', False)
    include_logs: bool = args.get('include_logs', True)
    include_screenshot: bool = args.get('include_screenshot', True)

    if not instance_id:
        raise DemistoException('region is a required parameter!')

    result: Dict[str, Any] = client.trigger_instance_acquisition(
        project_id, instance_id, region, bucket, compress,
        include_disks, include_hash, include_logs, include_screenshot
    )

    return CommandResults(
        outputs_prefix='CadoResponse.EC2Acquistion',
        outputs_key_field='pipeline_id',
        outputs=result
    )


def trigger_s3_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    ''' Command handler for cado-trigger-s3 '''

    project_id: Optional[int] = args.get('project_id', None)
    bucket: Optional[str] = args.get('bucket', None)
    file_name: Optional[str] = args.get('file_name', None)

    if not bucket:
        raise DemistoException('bucket is a required parameter!')

    if not file_name:
        raise DemistoException('file_name is a required parameter!')

    result: Dict[str, Any] = client.trigger_bucket_acquisition(project_id, bucket, file_name)

    return CommandResults(
        outputs_prefix='CadoResponse.S3Acquisition',
        outputs_key_field='pipeline_id',
        outputs=result.get('pipelines')
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
        elif command == 'cado-list-project':
            return_results(list_project_command(client, args))
        elif command == 'cado-get-pipeline':
            return_results(get_pipeline_command(client, args))
        elif command == 'cado-list-ec2':
            return_results(list_ec2_command(client, args))
        elif command == 'cado-list-s3':
            return_results(list_s3_command(client, args))
        elif command == 'cado-trigger-ec2':
            return_results(trigger_ec2_command(client, args))
        elif command == 'cado-trigger-s3':
            return_results(trigger_s3_command(client, args))

    except Exception as e:
        message: str = str(e)

        if '404' in message:
            return_results(f'Nothing found for {command}')
        else:
            demisto.error(traceback.format_exc())
            return_error(enrich_errors(message, command), error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
