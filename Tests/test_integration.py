from __future__ import print_function

import ast
import copy
import json
import logging
import re
import time
from typing import Optional, Tuple
import urllib.parse
import uuid
from pprint import pformat
from subprocess import PIPE, Popen

import demisto_client
import requests.exceptions
import urllib3
from demisto_client.demisto_api import DefaultApi
from demisto_client.demisto_api.rest import ApiException
from demisto_client.demisto_api.models.incident import Incident
from demisto_sdk.commands.common.constants import PB_Status

from Tests.tools import update_server_configuration

# Disable insecure warnings
urllib3.disable_warnings()

# ----- Constants ----- #
DEFAULT_TIMEOUT = 60
DEFAULT_INTERVAL = 20
ENTRY_TYPE_ERROR = 4


# ----- Docker class ----- #
class Docker:
    """ Client for running docker commands on remote machine using ssh connection.

    """
    PYTHON_INTEGRATION_TYPE = 'python'
    JAVASCRIPT_INTEGRATION_TYPE = 'javascript'
    DEFAULT_PYTHON2_IMAGE = 'demisto/python'
    DEFAULT_PYTHON3_IMAGE = 'demisto/python3'
    COMMAND_FORMAT = '{{json .}}'
    MEMORY_USAGE = 'MemUsage'
    PIDS_USAGE = 'PIDs'
    CONTAINER_NAME = 'Name'
    CONTAINER_ID = 'ID'
    DEFAULT_CONTAINER_MEMORY_USAGE = 75
    DEFAULT_CONTAINER_PIDS_USAGE = 3
    REMOTE_MACHINE_USER = 'ec2-user'
    SSH_OPTIONS = 'ssh -o StrictHostKeyChecking=no'

    @classmethod
    def _build_ssh_command(cls, server_ip, remote_command, force_tty=False):
        """Add and returns ssh prefix and escapes remote command

            Args:
                server_ip (str): remote machine ip to connect using ssh.
                remote_command (str): command to execute in remote machine.
                force_tty (bool): adds -t flag in order to force tty allocation.

            Returns:
                str: full ssh command

        """
        remote_server = '{}@{}'.format(cls.REMOTE_MACHINE_USER, server_ip)
        ssh_prefix = '{} {}'.format(cls.SSH_OPTIONS, remote_server)
        if force_tty:
            ssh_prefix += ' -t'
        # escaping the remote command with single quotes
        cmd = "{} '{}'".format(ssh_prefix, remote_command)

        return cmd

    @classmethod
    def _build_stats_cmd(cls, server_ip, docker_images):
        """ Builds docker stats and grep command string.

        Example of returned value:
        ssh -o StrictHostKeyChecking=no ec2-user@server_ip
        'sudo docker stats --no-stream --no-trunc --format "{{json .}}" | grep -Ei "demistopython33.7.2.214--"'
        Grep is based on docker images names regex.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                docker_images (set): Set of docker images.

            Returns:
                str: String command to run later as subprocess.

        """
        # docker stats command with json output
        docker_command = 'sudo docker stats --no-stream --no-trunc --format "{}"'.format(cls.COMMAND_FORMAT)
        # replacing : and / in docker images names in order to grep the stats by container name
        docker_images_regex = ['{}--'.format(re.sub('[:/]', '', docker_image)) for docker_image in docker_images]
        pipe = ' | '
        grep_command = 'grep -Ei "{}"'.format('|'.join(docker_images_regex))
        remote_command = docker_command + pipe + grep_command
        cmd = cls._build_ssh_command(server_ip, remote_command)

        return cmd

    @classmethod
    def _build_kill_cmd(cls, server_ip, container_name):
        """ Constructs docker kll command string to run on remote machine.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                container_name (str): Docker container name to kill.

            Returns:
                str: String of docker kill command on remote machine.
        """
        remote_command = 'sudo docker kill {}'.format(container_name)
        cmd = cls._build_ssh_command(server_ip, remote_command)

        return cmd

    @classmethod
    def _build_pid_info_cmd(cls, server_ip, container_id):
        """Constructs docker exec ps command string to run on remote machine.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                container_id (str): Docker container id.

            Returns:
                str: String of docker exec ps command on remote machine.

        """
        remote_command = 'sudo docker exec -it {} ps -fe'.format(container_id)
        cmd = cls._build_ssh_command(server_ip, remote_command, force_tty=True)

        return cmd

    @classmethod
    def _parse_stats_result(cls, stats_lines, logging_module=logging):
        """Parses the docker statics str and converts to Mib.

            Args:
                stats_lines (str): String that contains docker stats.
                logging_module: The logging module that should be used.
            Returns:
                list: List of dictionaries with parsed docker container statistics.

        """
        stats_result = []
        try:
            containers_stats = [json.loads(c) for c in stats_lines.splitlines()]

            for container_stat in containers_stats:
                memory_usage_stats = container_stat.get(cls.MEMORY_USAGE, '').split('/')[0].lower()

                if 'kib' in memory_usage_stats:
                    mib_usage = float(memory_usage_stats.replace('kib', '').strip()) / 1024
                elif 'gib' in memory_usage_stats:
                    mib_usage = float(memory_usage_stats.replace('kib', '').strip()) * 1024
                else:
                    mib_usage = float(memory_usage_stats.replace('mib', '').strip())

                stats_result.append({
                    'memory_usage': mib_usage,
                    'pids': int(container_stat.get(cls.PIDS_USAGE)),
                    'container_name': container_stat.get(cls.CONTAINER_NAME),
                    'container_id': container_stat.get(cls.CONTAINER_ID)
                })
        except Exception:
            logging_module.exception("Failed in parsing docker stats result, returned empty list.")
        finally:
            return stats_result

    @classmethod
    def run_shell_command(cls, cmd):
        """Executes shell command and returns outputs of the process.

            Args:
                cmd (str): command to execute.

            Returns:
                str: stdout of the executed command.
                str: stderr of the executed command.

        """
        process = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
        stdout, stderr = process.communicate()

        return stdout, stderr

    @classmethod
    def get_image_for_container_id(cls, server_ip, container_id, logging_module=logging):
        cmd = cls._build_ssh_command(server_ip, "sudo docker inspect -f {{.Config.Image}} " + container_id,
                                     force_tty=False)
        stdout, stderr = cls.run_shell_command(cmd)
        if stderr:
            logging_module.warning(f"Received stderr from docker inspect command. Additional information: {stderr}")
        res = stdout or ""
        return res.strip()

    @classmethod
    def get_integration_image(cls, integration_config):
        """ Returns docker image of integration that was configured using rest api call via demisto_client

            Args:
                integration_config (dict): Integration config that included script section.
            Returns:
                list: List that includes integration docker image name. If no docker image was found,
                      default python2 and python3 images are returned.

        """
        integration_script = integration_config.get('configuration', {}).get('integrationScript', {}) or {}
        integration_type = integration_script.get('type')
        docker_image = integration_script.get('dockerImage')

        if integration_type == cls.JAVASCRIPT_INTEGRATION_TYPE:
            return None
        elif integration_type == cls.PYTHON_INTEGRATION_TYPE and docker_image:
            return [docker_image]
        else:
            return [cls.DEFAULT_PYTHON2_IMAGE, cls.DEFAULT_PYTHON3_IMAGE]

    @classmethod
    def docker_stats(cls, server_ip, docker_images, logging_module=logging):
        """ Executes docker stats command and greps all containers with prefix of docker images names.

            Args:
                server_ip (str): Remote machine ip to connect using ssh.
                docker_images (set): Set of docker images to check their resource usage.
                logging_module: The logging module that should be used.

            Returns:
                list: List of dictionaries with parsed container memory statistics.
        """
        cmd = cls._build_stats_cmd(server_ip, docker_images)
        stdout, stderr = cls.run_shell_command(cmd)

        if stderr:
            logging_module.warning(f"Failed running docker stats command. Additional information: {stderr}")
            return []

        return cls._parse_stats_result(stdout, logging_module)

    @classmethod
    def kill_container(cls, server_ip, container_name, logging_module):
        """ Executes docker kill command on remote machine using ssh.

            Args:
                server_ip (str): The remote server ip address.
                container_name (str): The container name to kill
                logging_module: The logging module to use

        """
        cmd = cls._build_kill_cmd(server_ip, container_name)
        _, stderr = cls.run_shell_command(cmd)

        if stderr:
            logging_module.debug(f"Failed killing container: {container_name}\nAdditional information: {stderr}")

    @classmethod
    def get_docker_pid_info(cls, server_ip, container_id, logging_module):
        """Executes docker exec ps command on remote machine using ssh.

            Args:
                server_ip (str): The remote server ip address.
                container_id (str): Docker container id.
                logging_module: The logging module to use

            Returns:
                str: output of executed command.
        """
        cmd = cls._build_pid_info_cmd(server_ip, container_id)
        stdout, stderr = cls.run_shell_command(cmd)

        if stderr:
            ignored_warning_message = "Connection to {} closed".format(server_ip)
            if ignored_warning_message not in stderr:
                logging_module.debug(f"Failed getting pid info for container id: {container_id}.\n"
                                     f"Additional information: {stderr}")

        return stdout

    @classmethod
    def check_resource_usage(cls,
                             server_url,
                             docker_images,
                             def_memory_threshold,
                             def_pid_threshold,
                             docker_thresholds,
                             logging_module):
        """
        Executes docker stats command on remote machine and returns error message in case of exceeding threshold.

        Args:
            server_url (str): Target machine full url.
            docker_images (set): Set of docker images to check their resource usage.
            def_memory_threshold (int): Memory threshold of specific docker container, in Mib.
            def_pids_threshold (int): PIDs threshold of specific docker container, in Mib.
            docker_thresholds: thresholds per docker image
            logging_module: The logging module that should be used.

        Returns:
            str: The error message. Empty in case that resource check passed.

        """
        server_ip = server_url.lstrip("https://")
        containers_stats = cls.docker_stats(server_ip, docker_images, logging_module)
        error_message = ""

        for container_stat in containers_stats:
            failed_memory_test = False
            container_name = container_stat['container_name']
            container_id = container_stat['container_id']
            memory_usage = container_stat['memory_usage']
            pids_usage = container_stat['pids']
            image_full = cls.get_image_for_container_id(server_ip,
                                                        container_id,
                                                        logging_module)  # get full name (ex: demisto/slack:1.0.0.4978)
            image_name = image_full.split(':')[0]  # just the name such as demisto/slack

            memory_threshold = (docker_thresholds.get(image_full, {}).get('memory_threshold') or docker_thresholds.get(
                image_name, {}).get('memory_threshold') or def_memory_threshold)
            pid_threshold = (docker_thresholds.get(image_full, {}).get('pid_threshold')
                             or docker_thresholds.get(image_name, {}).get('pid_threshold') or def_pid_threshold)
            logging_module.debug(
                f"Checking container: {container_name} "
                f"(image: {image_full}) for memory: {memory_threshold} pid: {pid_threshold} thresholds ...")
            if memory_usage > memory_threshold:
                error_message += ('Failed docker resource test. Docker container {} exceeded the memory threshold, '
                                  'configured: {} MiB and actual memory usage is {} MiB.\n'
                                  'Fix container memory usage or add `memory_threshold` key to failed test '
                                  'in conf.json with value that is greater than {}\n'
                                  .format(container_name, memory_threshold, memory_usage, memory_usage))
                failed_memory_test = True
            if pids_usage > pid_threshold:
                error_message += ('Failed docker resource test. Docker container {} exceeded the pids threshold, '
                                  'configured: {} and actual pid number is {}.\n'
                                  'Fix container pid usage or add `pid_threshold` key to failed test '
                                  'in conf.json with value that is greater than {}\n'
                                  .format(container_name, pid_threshold, pids_usage, pids_usage))
                additional_pid_info = cls.get_docker_pid_info(server_ip, container_id, logging_module)
                if additional_pid_info:
                    error_message += 'Additional pid information:\n{}'.format(additional_pid_info)
                failed_memory_test = True

            if failed_memory_test:
                # killing current container in case of memory resource test failure
                cls.kill_container(server_ip, container_name, logging_module)

        return error_message


# ----- Functions ----- #

# get integration configuration
def __get_integration_config(client, integration_name, logging_module=logging):
    body = {
        'page': 0, 'size': 100, 'query': 'name:' + integration_name
    }
    try:
        res_raw = demisto_client.generic_request_func(self=client, path='/settings/integration/search',
                                                      method='POST', body=body)
    except ApiException:
        logging_module.exception(f'failed to get integration {integration_name} configuration')
        return None

    res = ast.literal_eval(res_raw[0])
    TIMEOUT = 180
    SLEEP_INTERVAL = 5
    total_sleep = 0
    while 'configurations' not in res:
        if total_sleep == TIMEOUT:
            logging_module.error(f"Timeout - failed to get integration {integration_name} configuration. Error: {res}")
            return None

        time.sleep(SLEEP_INTERVAL)
        total_sleep += SLEEP_INTERVAL

    all_configurations = res['configurations']
    match_configurations = [x for x in all_configurations if x['name'] == integration_name]

    if not match_configurations or len(match_configurations) == 0:
        logging_module.error('integration was not found')
        return None

    return match_configurations[0]


# __test_integration_instance
def __test_integration_instance(client, module_instance, logging_module=logging):
    connection_retries = 3
    response_code = 0
    integration_of_instance = module_instance.get('brand', '')
    instance_name = module_instance.get('name', '')
    logging_module.info(
        f'Running "test-module" for instance "{instance_name}" of integration "{integration_of_instance}".')
    for i in range(connection_retries):
        try:
            response_data, response_code, _ = demisto_client.generic_request_func(self=client, method='POST',
                                                                                  path='/settings/integration/test',
                                                                                  body=module_instance,
                                                                                  _request_timeout=120)
            break
        except ApiException:
            logging_module.exception(
                'Failed to test integration instance, error trying to communicate with demisto server')
            return False, None
        except urllib3.exceptions.ReadTimeoutError:
            logging_module.warning(f"Could not connect. Trying to connect for the {i + 1} time")

    if int(response_code) != 200:
        logging_module.error(f'Integration-instance test ("Test" button) failed. Bad status code: {response_code}')
        return False, None

    result_object = ast.literal_eval(response_data)
    success, failure_message = bool(result_object.get('success')), result_object.get('message')
    if not success:
        server_url = client.api_client.configuration.host
        test_failed_msg = f'Test integration failed - server: {server_url}.'
        test_failed_msg += f'\nFailure message: {failure_message}' if failure_message else ' No failure message.'
        logging_module.error(test_failed_msg)
    return success, failure_message


def __set_server_keys(client, logging_manager, integration_params, integration_name):
    """Adds server configuration keys using the demisto_client.

    Args:
        client (demisto_client): The configured client to use.
        logging_manager (ParallelLoggingManager): logging manager object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.
        integration_name (str): The name of the integration which the server configurations keys are related to.

    """
    if 'server_keys' not in integration_params:
        return

    logging_manager.debug(f'Setting server keys for integration: {integration_name}')

    data = {
        'data': {},
        'version': -1
    }

    for key, value in integration_params.get('server_keys').items():
        data['data'][key] = value

    update_server_configuration(
        client=client,
        server_configuration=integration_params.get('server_keys'),
        error_msg='Failed to set server keys',
        logging_manager=logging_manager
    )


def __delete_integration_instance_if_determined_by_name(client, instance_name, logging_manager):
    """Deletes integration instance by it's name.

    Args:
        client (demisto_client): The configured client to use.
        instance_name (str): The name of the instance to delete.
        logging_manager (ParallelLoggingManager): logging manager object.

    Notes:
        This function is needed when the name of the instance is pre-defined in the tests configuration, and the test
        itself depends on the instance to be called as the `instance name`.
        In case we need to configure another instance with the same name, the client will throw an error, so we
        will call this function first, to delete the instance with this name.

    """
    try:
        int_resp = demisto_client.generic_request_func(self=client, method='POST',
                                                       path='/settings/integration/search',
                                                       body={'size': 1000})
        int_instances = ast.literal_eval(int_resp[0])
    except ApiException:
        logging_manager.exception(
            'Failed to delete integrations instance, error trying to communicate with demisto server')
        return
    if int(int_resp[1]) != 200:
        logging_manager.error(f'Get integration instance failed with status code: {int_resp[1]}')
        return
    if 'instances' not in int_instances:
        logging_manager.info('No integrations instances found to delete')
        return

    for instance in int_instances['instances']:
        if instance.get('name') == instance_name:
            logging_manager.info(f'Deleting integration instance {instance_name} since it is defined by name')
            __delete_integration_instance(client, instance.get('id'), logging_manager)


# return instance name if succeed, None otherwise
def __create_integration_instance(server, username, password, integration_name, integration_instance_name,
                                  integration_params, is_byoi, logging_manager=logging, validate_test=True):

    # get configuration config (used for later rest api
    integration_conf_client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
    configuration = __get_integration_config(integration_conf_client, integration_name, logging_manager)
    if not configuration:
        return None, 'No configuration', None

    module_configuration = configuration['configuration']
    if not module_configuration:
        module_configuration = []

    if 'integrationInstanceName' in integration_params:
        instance_name = integration_params['integrationInstanceName']
        __delete_integration_instance_if_determined_by_name(integration_conf_client, instance_name, logging_manager)
    else:
        instance_name = f'{integration_instance_name.replace(" ", "_")}_test_{uuid.uuid4()}'

    logging_manager.info(
        f'Configuring instance for {integration_name} (instance name: {instance_name}, validate "Test": {validate_test})'
    )
    # define module instance
    module_instance = {
        'brand': configuration['name'],
        'category': configuration['category'],
        'configuration': configuration,
        'data': [],
        'enabled': "true",
        'engine': '',
        'id': '',
        'isIntegrationScript': is_byoi,
        'name': instance_name,
        'passwordProtected': False,
        'version': 0
    }

    # set server keys
    __set_server_keys(integration_conf_client, logging_manager, integration_params, configuration['name'])

    # set module params
    for param_conf in module_configuration:
        if param_conf['display'] in integration_params or param_conf['name'] in integration_params:
            # param defined in conf
            key = param_conf['display'] if param_conf['display'] in integration_params else param_conf['name']
            if key == 'credentials':
                credentials = integration_params[key]
                param_value = {
                    'credential': '',
                    'identifier': credentials['identifier'],
                    'password': credentials['password'],
                    'passwordChanged': False
                }
            else:
                param_value = integration_params[key]

            param_conf['value'] = param_value
            param_conf['hasvalue'] = True
        elif param_conf['defaultValue']:
            # param is required - take default value
            param_conf['value'] = param_conf['defaultValue']
        module_instance['data'].append(param_conf)
    try:
        res = demisto_client.generic_request_func(self=integration_conf_client, method='PUT',
                                                  path='/settings/integration',
                                                  body=module_instance)
    except ApiException:
        error_message = f'Error trying to create instance for integration: {integration_name}'
        logging_manager.exception(error_message)
        return None, error_message, None

    if res[1] != 200:
        error_message = f'create instance failed with status code  {res[1]}'
        logging_manager.error(error_message)
        logging_manager.error(pformat(res[0]))
        return None, error_message, None

    integration_config = ast.literal_eval(res[0])
    module_instance['id'] = integration_config['id']

    # test integration
    refreshed_client = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
    if validate_test:
        test_succeed, failure_message = __test_integration_instance(refreshed_client, module_instance, logging_manager)
    else:
        logging_manager.debug(
            f"Skipping test validation for integration: {integration_name} (it has test_validate set to false)"
        )
        test_succeed = True

    if not test_succeed:
        __disable_integrations_instances(refreshed_client, [module_instance], logging_manager)
        return None, failure_message, None

    docker_image = Docker.get_integration_image(integration_config)

    return module_instance, '', docker_image


def __disable_integrations_instances(client, module_instances, logging_module=logging):
    for configured_instance in module_instances:
        # tested with POSTMAN, this is the minimum required fields for the request.
        module_instance = {
            key: configured_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "false"
        module_instance['version'] = -1
        logging.debug(f'Disabling integration {module_instance.get("name")}')
        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException:
            logging_module.exception('Failed to disable integration instance')
            return

        if res[1] != 200:
            logging_module.error(f'disable instance failed, Error: {pformat(res)}')


# create incident with given name & playbook, and then fetch & return the incident
def __create_incident_with_playbook(client: DefaultApi,
                                    name,
                                    playbook_id,
                                    integrations,
                                    logging_manager,
                                    ) -> Tuple[Optional[Incident], int]:
    # create incident
    create_incident_request = demisto_client.demisto_api.CreateIncidentRequest()
    create_incident_request.create_investigation = True
    create_incident_request.playbook_id = playbook_id
    create_incident_request.name = name

    try:
        response = client.create_incident(create_incident_request=create_incident_request)
    except ApiException:
        logging_manager.exception(f'Failed to create incident with name {name} for playbook {playbook_id}')

    try:
        inc_id = response.id
    except:  # noqa: E722
        inc_id = 'incCreateErr'
    # inc_id = response_json.get('id', 'incCreateErr')
    if inc_id == 'incCreateErr':
        integration_names = [integration['name'] for integration in integrations if
                             'name' in integration]
        error_message = f'Failed to create incident for integration names: {integration_names} ' \
                        f'and playbookID: {playbook_id}.' \
                        'Possible reasons are:\nMismatch between playbookID in conf.json and ' \
                        'the id of the real playbook you were trying to use,' \
                        'or schema problems in the TestPlaybook.'
        logging_manager.error(error_message)
        return None, -1

    # get incident
    search_filter = demisto_client.demisto_api.SearchIncidentsData()
    inc_filter = demisto_client.demisto_api.IncidentFilter()
    inc_filter.query = 'id:' + str(inc_id)
    # inc_filter.query
    search_filter.filter = inc_filter

    incident_search_responses = []

    found_incidents = 0
    # poll the incidents queue for a max time of 300 seconds
    timeout = time.time() + 300
    while found_incidents < 1:
        try:
            incidents = client.search_incidents(filter=search_filter)
            found_incidents = incidents.total
            incident_search_responses.append(incidents)
        except ApiException:
            logging_manager.exception(f'Searching incident with id {inc_id} failed')
        if time.time() > timeout:
            logging_manager.error(f'Got timeout for searching incident with id {inc_id}')
            logging_manager.error(f'Incident search responses: {incident_search_responses}')
            return None, -1

        time.sleep(10)

    return incidents.data[0], inc_id


# returns current investigation playbook state - 'inprogress'/'failed'/'completed'
def __get_investigation_playbook_state(client, inv_id, logging_manager):
    try:
        investigation_playbook_raw = demisto_client.generic_request_func(self=client, method='GET',
                                                                         path='/inv-playbook/' + inv_id)
        investigation_playbook = ast.literal_eval(investigation_playbook_raw[0])
    except ApiException:
        logging_manager.exception(
            'Failed to get investigation playbook state, error trying to communicate with demisto server'
        )
        return PB_Status.FAILED

    try:
        state = investigation_playbook['state']
        return state
    except:  # noqa: E722
        return PB_Status.NOT_SUPPORTED_VERSION


# return True if delete-incident succeeded, False otherwise
def __delete_incident(client: DefaultApi, incident: Incident, logging_manager):
    try:
        body = {
            'ids': [incident.id],
            'filter': {},
            'all': False
        }
        res = demisto_client.generic_request_func(self=client, method='POST',
                                                  path='/incident/batchDelete', body=body)
    except ApiException:
        logging_manager.exception('Failed to delete incident, error trying to communicate with demisto server')
        return False

    if int(res[1]) != 200:
        logging_manager.error(f'delete incident failed with Status code {res[1]}')
        logging_manager.error(pformat(res))
        return False

    return True


# return True if delete-integration-instance succeeded, False otherwise
def __delete_integration_instance(client, instance_id, logging_manager=logging):
    try:
        res = demisto_client.generic_request_func(self=client, method='DELETE',
                                                  path='/settings/integration/' + urllib.parse.quote(
                                                      instance_id))
    except ApiException:
        logging_manager.exception('Failed to delete integration instance, error trying to communicate with demisto.')
        return False
    if int(res[1]) != 200:
        logging_manager.error(f'delete integration instance failed\nStatus code {res[1]}')
        logging_manager.error(pformat(res))
        return False
    return True


# delete all integration instances, return True if all succeed delete all
def __delete_integrations_instances(client, module_instances, logging_manager=logging):
    succeed = True
    for module_instance in module_instances:
        succeed = __delete_integration_instance(client, module_instance['id'], logging_manager) and succeed
    return succeed


def __print_investigation_error(client, playbook_id, investigation_id, logging_manager):
    try:
        empty_json = {"pageSize": 1000}
        res = demisto_client.generic_request_func(self=client, method='POST',
                                                  path='/investigation/' + urllib.parse.quote(
                                                      investigation_id), body=empty_json)
        if res and int(res[1]) == 200:
            resp_json = ast.literal_eval(res[0])
            entries = resp_json['entries']
            logging_manager.error(f'Playbook {playbook_id} has failed:')
            for entry in entries:
                if entry['type'] == ENTRY_TYPE_ERROR and entry['parentContent']:
                    logging_manager.error(f'- Task ID: {entry["taskId"]}')
                    # Checks for passwords and replaces them with "******"
                    parent_content = re.sub(
                        r' (P|p)assword="[^";]*"', ' password=******', entry['parentContent'])
                    logging_manager.error(f'  Command: {parent_content}')
                    logging_manager.error(f'  Body:\n{entry["contents"]}')
        else:
            logging_manager.error(f'Failed getting entries for investigation: {investigation_id}. Res: {res}')
    except ApiException:
        logging_manager.exception(
            'Failed to print investigation error, error trying to communicate with demisto server')


# Configure integrations to work with mock
def configure_proxy_unsecure(integration_params):
    """Copies the integration parameters dictionary.
        Set proxy and insecure integration parameters to true.

    Args:
        integration_params: dict of the integration parameters.
    """
    integration_params_copy = copy.deepcopy(integration_params)
    for param in ('proxy', 'useProxy', 'insecure', 'unsecure'):
        integration_params[param] = True

    return integration_params_copy


# 1. create integrations instances
# 2. create incident with playbook
# 3. wait for playbook to finish run
# 4. if test pass - delete incident & instance
# return playbook status
def check_integration(client, server_url, demisto_user, demisto_pass, integrations, playbook_id,
                      logging_module=logging, options=None, is_mock_run=False):
    options = options if options is not None else {}
    # create integrations instances
    module_instances = []
    test_docker_images = set()

    with open("./Tests/conf.json", 'r') as conf_file:
        docker_thresholds = json.load(conf_file).get('docker_thresholds', {}).get('images', {})

    for integration in integrations:
        integration_name = integration.get('name', None)
        integration_instance_name = integration.get('instance_name', '')
        integration_params = integration.get('params', None)
        is_byoi = integration.get('byoi', True)
        validate_test = integration.get('validate_test', False)

        if is_mock_run:
            configure_proxy_unsecure(integration_params)

        module_instance, failure_message, docker_image = __create_integration_instance(server_url,
                                                                                       demisto_user,
                                                                                       demisto_pass,
                                                                                       integration_name,
                                                                                       integration_instance_name,
                                                                                       integration_params,
                                                                                       is_byoi, logging_module,
                                                                                       validate_test=validate_test)
        if module_instance is None:
            failure_message = failure_message if failure_message else 'No failure message could be found'
            logging_module.error(f'Failed to create instance: {failure_message}')
            __delete_integrations_instances(client, module_instances, logging_module)
            return False, -1

        module_instances.append(module_instance)
        if docker_image:
            test_docker_images.update(docker_image)

        logging_module.info(f'Create integration {integration_name} succeed')

    # create incident with playbook
    incident, inc_id = __create_incident_with_playbook(client,
                                                       f'inc_{playbook_id}',
                                                       playbook_id,
                                                       integrations,
                                                       logging_module)

    if not incident:
        return False, -1

    investigation_id = incident.investigation_id
    if investigation_id is None or len(investigation_id) == 0:
        logging.error(f'Failed to get investigation id of incident: {incident}')
        return False, -1

    logging_module.info(f'Investigation URL: {server_url}/#/WorkPlan/{investigation_id}')

    timeout_amount = options['timeout'] if 'timeout' in options else DEFAULT_TIMEOUT
    timeout = time.time() + timeout_amount

    i = 1
    # wait for playbook to finish run
    while True:
        # give playbook time to run
        time.sleep(1)

        try:
            # fetch status
            playbook_state = __get_investigation_playbook_state(client, investigation_id, logging_module)
        except demisto_client.demisto_api.rest.ApiException:
            playbook_state = 'Pending'
            client = demisto_client.configure(base_url=client.api_client.configuration.host,
                                              api_key=client.api_client.configuration.api_key, verify_ssl=False)

        if playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION):
            break
        if playbook_state == PB_Status.FAILED:
            logging_module.error(f'{playbook_id} failed with error/s')
            __print_investigation_error(client, playbook_id, investigation_id, logging_module)
            break
        if time.time() > timeout:
            logging_module.error(f'{playbook_id} failed on timeout')
            break

        if i % DEFAULT_INTERVAL == 0:
            logging_module.info(f'loop no. {i / DEFAULT_INTERVAL}, playbook state is {playbook_state}')
        i = i + 1

    __disable_integrations_instances(client, module_instances, logging_module)

    if test_docker_images:
        memory_threshold = options.get('memory_threshold', Docker.DEFAULT_CONTAINER_MEMORY_USAGE)
        pids_threshold = options.get('pid_threshold', Docker.DEFAULT_CONTAINER_PIDS_USAGE)
        error_message = Docker.check_resource_usage(server_url=server_url,
                                                    docker_images=test_docker_images,
                                                    def_memory_threshold=memory_threshold,
                                                    def_pid_threshold=pids_threshold,
                                                    docker_thresholds=docker_thresholds,
                                                    logging_module=logging_module)

        if error_message:
            logging_module.error(error_message)
            return PB_Status.FAILED_DOCKER_TEST, inc_id
    else:
        logging_module.debug(f"Skipping docker container memory resource check for test {playbook_id}")

    test_pass = playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)
    if test_pass:
        # delete incident
        __delete_incident(client, incident, logging_module)

        # delete integration instance
        __delete_integrations_instances(client, module_instances, logging_module)

    return playbook_state, inc_id


def disable_all_integrations(dem_client, logging_manager=logging):
    """
    Disable all enabled integrations. Should be called at start of test loop to start out clean

    Arguments:
        client -- demisto py client
    """
    try:
        body = {'size': 1000}
        int_resp = demisto_client.generic_request_func(self=dem_client, method='POST',
                                                       path='/settings/integration/search',
                                                       body=body)
        int_instances = ast.literal_eval(int_resp[0])
    except requests.exceptions.RequestException:
        logging_manager.exception('Failed to disable all integrations, error trying to communicate with demisto server')
        return
    if int(int_resp[1]) != 200:
        logging_manager.error(f'Get all integration instances failed with status code: {int_resp[1]}')
        return
    if 'instances' not in int_instances:
        logging_manager.info("No integrations instances found to disable all")
        return
    to_disable = []
    for instance in int_instances['instances']:
        if instance.get('enabled') == 'true' and instance.get("isIntegrationScript"):
            logging_manager.debug(
                f'Adding to disable list. Name: {instance.get("name")}. Brand: {instance.get("brand")}')
            to_disable.append(instance)
    if len(to_disable) > 0:
        __disable_integrations_instances(dem_client, to_disable, logging_manager)
