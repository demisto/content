import ast
import json
import re
import subprocess
import time
import urllib.parse
import uuid
from distutils.version import LooseVersion
from pprint import pformat
from queue import Queue, Empty
from typing import List, Dict, Tuple, Optional, Union, Any, Callable

import demisto_client
import prettytable
import requests
import urllib3
from demisto_client.demisto_api import DefaultApi, Incident
from demisto_client.demisto_api.rest import ApiException
from slack import WebClient as SlackClient

from Tests.Common.IntegrationsLock import acquire_test_lock
from Tests.mock_server import MITMProxy, run_with_mock, RESULT
from Tests.scripts.utils.log_util import *
from Tests.test_integration import Docker
from Tests.tools import update_server_configuration
from demisto_sdk.commands.common.constants import FILTER_CONF, PB_Status

ENV_RESULTS_PATH = './env_results.json'
FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using " \
                            "the instance_name argument in conf.json. The options are:\n{}"
ENTRY_TYPE_ERROR = 4
DEFAULT_INTERVAL = 20
SLACK_MEM_CHANNEL_ID = 'CM55V7J8K'

__all__ = ['BuildContext',
           'Conf',
           'Integration',
           'IntegrationConfiguration',
           'SecretConf',
           'TestConfiguration',
           'TestContext',
           'TestPlaybook',
           'TestResults',
           'TestsExecution']


class IntegrationConfiguration:
    def __init__(self, integration_configuration):
        self.raw_dict = integration_configuration
        self.name: str = integration_configuration.get('name', '')
        self.instance_name: str = integration_configuration.get('instance_name', self.name)
        self.is_byoi: bool = integration_configuration.get('byoi', True)
        self.should_validate_test_module: bool = integration_configuration.get('validate_test', True)
        self.has_integration: bool = integration_configuration.get('has_integration', True)
        self.params: dict = integration_configuration.get('params', {})

    def __str__(self):
        return json.dumps(self.raw_dict)

    def __repr__(self):
        return str(self)


class SecretConf:
    def __init__(self, secret_conf: dict):
        """
        Args:
            secret_conf: The contents of the content-test-conf conf.json file.
        """
        self.server_username = secret_conf['username']
        self.server_password = secret_conf['userPassword']
        self.integrations = [
            IntegrationConfiguration(integration_configuration=configuration) for configuration in
            secret_conf['integrations']
        ]


class TestConfiguration:
    def __init__(self, test_configuration: dict, default_test_timeout: int):
        """
        Args:
            test_configuration: A record of a test from 'tests' list in conf.json file in content repo..
            default_test_timeout: The default timeout to use in case no timeout is specified in the configuration
        """
        self.raw_dict = test_configuration
        self.playbook_id = test_configuration.get('playbookID', '')
        self.nightly_test = test_configuration.get('nightly', False)
        self.from_version = test_configuration.get('fromversion', '0.0.0')
        self.to_version = test_configuration.get('toversion', '99.99.99')
        self.timeout = test_configuration.get('timeout', default_test_timeout)
        self.memory_threshold = test_configuration.get('memory_threshold', Docker.DEFAULT_CONTAINER_MEMORY_USAGE)
        self.pid_threshold = test_configuration.get('pid_threshold', Docker.DEFAULT_CONTAINER_PIDS_USAGE)
        self.docker_thresholds = test_configuration.get('docker_thresholds', {}).get('images', {})
        self.test_integrations: List[str] = self._parse_integrations_conf(test_configuration)
        self.test_instance_names: List[str] = self._parse_instance_names_conf(test_configuration)

    @staticmethod
    def _parse_integrations_conf(test_configuration):
        integrations_conf = test_configuration.get('integrations', [])
        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf]
        return integrations_conf

    @staticmethod
    def _parse_instance_names_conf(test_configuration):
        instance_names_conf = test_configuration.get('instance_names', [])
        if not isinstance(instance_names_conf, list):
            instance_names_conf = [instance_names_conf]
        return instance_names_conf


class Conf:
    def __init__(self, conf: dict):
        """
        Args:
            conf: The contents of the content conf.json file.
        """
        self.default_timeout: int = conf.get('testTimeout', 30)
        self.tests: list = [
            TestConfiguration(test_configuration, self.default_timeout) for test_configuration in conf.get('tests', [])
        ]
        self.skipped_tests: Dict[str, str] = conf.get('skipped_tests')
        self.skipped_integrations: Dict[str, str] = conf.get('skipped_integrations')
        self.nightly_integrations: List[str] = conf['nightly_integrations']
        self.unmockable_integrations: Dict[str, str] = conf.get('unmockable_integrations')
        self.parallel_integrations: List[str] = conf['parallel_integrations']
        self.docker_thresholds: dict = conf['docker_thresholds']


class TestPlaybook:

    def __init__(self,
                 build_context,
                 test_configuration: TestConfiguration):
        """
        This class has all the info related to a test playbook during test execution
        Args:
            build_context (BuildContext): The build context to use in the build
            test_configuration: The configuration from content conf.json file
        """
        self.build_context = build_context
        self.configuration: TestConfiguration = test_configuration
        self.is_mockable: bool = self.configuration.playbook_id not in build_context.unmockable_test_ids
        self.integrations: List[Integration] = [
            Integration(self.build_context, integration_name, self.configuration.test_instance_names)
            for integration_name in self.configuration.test_integrations]
        self.integrations_to_lock = [
            integration for integration in self.integrations if
            integration.name not in self.build_context.conf.parallel_integrations]

    def __str__(self):
        return f'"{self.configuration.playbook_id}"'

    def __repr__(self):
        return str(self)

    def should_test_run(self):
        skipped_tests_collected = self.build_context.tests_data_keeper.skipped_tests
        # If There are a list of filtered tests and the playbook is in in them
        if self.build_context.filtered_tests and self.configuration.playbook_id not in self.build_context.filtered_tests:
            self.build_context.logging_module.debug(f'Skipping {self} because it\'s not in filtered tests')
            skipped_tests_collected[self.configuration.playbook_id] = 'not in filtered tests'
            return False
        # nightly test in a non nightly build
        if self.configuration.nightly_test and not self.build_context.is_nightly:
            self.build_context.logging_module.debug(
                f'Skipping {self} because it\'s a nightly test in a non nightly build')
            skipped_tests_collected[self.configuration.playbook_id] = \
                'nightly test in a non nightly build'
            return False

        # skipped test
        if self.configuration.playbook_id in self.build_context.conf.skipped_tests:
            # If the playbook supposed to run according to the filters but it's skipped - warning log
            if self.build_context.filtered_tests and self.configuration.playbook_id not in self.build_context.filtered_tests:
                self.build_context.logging_module.warning(f'Skipping test {self} because it\'s in skipped test list')
            else:
                self.build_context.logging_module.debug(f'Skipping test {self} because it\'s in skipped test list')
            reason = self.build_context.conf.skipped_tests[self.configuration.playbook_id]
            skipped_tests_collected[self.configuration.playbook_id] = reason
            return False
        # Version mismatch
        if not (LooseVersion(self.configuration.from_version) <= LooseVersion(
                self.build_context.server_numeric_version) <= LooseVersion(self.configuration.to_version)):
            self.build_context.logging_module.warning(
                f'Test {self} ignored due to version mismatch '
                f'(test versions: {self.configuration.from_version}-{self.configuration.to_version})\n')
            skipped_tests_collected[self.configuration.playbook_id] = \
                f'(test versions: {self.configuration.from_version}-{self.configuration.to_version})'
            return False
        # Test has skipped integration
        for integration in self.configuration.test_integrations:
            # So now we know that the test is in the filtered tests
            if integration in self.build_context.conf.skipped_integrations:
                self.build_context.logging_module.debug(
                    f'Skipping {self} because it has a skipped integration "{integration}"')
                # The playbook should be run but has a skipped integration
                reason = self.build_context.conf.skipped_integrations[integration]
                if self.build_context.filtered_tests and self.configuration.playbook_id in self.build_context.filtered_tests:
                    # Adding the playbook ID to playbook_skipped_integration so that we can send a PR comment about it
                    skip_reason = self.build_context.conf.skipped_integrations[integration]
                    self.build_context.tests_data_keeper.playbook_skipped_integration.add(
                        f'{self.configuration.playbook_id} - reason: {skip_reason}')
                    self.build_context.logging_module.warning(
                        f'The integration "{integration}" is skipped and critical for the test {self}.')
                    skipped_tests_collected[self.configuration.playbook_id] = \
                        f'The integration "{integration}" is skipped'
                return False
            if integration in self.build_context.conf.nightly_integrations and not self.build_context.is_nightly:
                self.build_context.logging_module.debug(
                    f'Skipping {self} because it has a nightly integration {integration} in a non nightly build')
                skipped_tests_collected[self.configuration.playbook_id] = \
                    f'The integration {integration} is a nightly integration'
                return False

        return True

    def configure_integrations(self, client: DefaultApi) -> bool:
        """
        Configures all integrations that the playbook uses and return a boolean indicating the result
        Args:
            client: The demisto_client to use

        Returns:
            True if all integrations were configured else False
        """
        configured_integrations: List[Integration] = []
        for integration in self.integrations:
            instance_created = integration.create_integration_instance(client,
                                                                       self.configuration.playbook_id,
                                                                       self.is_mockable)
            if not instance_created:
                self.build_context.logging_module.error(
                    f'Cannot run playbook {self}, integration {integration} failed to configure')
                # Deleting all the already configured integrations
                for configured_integration in configured_integrations:
                    configured_integration.delete_integration_instance(client)
                return False
            configured_integrations.append(integration)
        return True

    def disable_integrations(self, client: DefaultApi) -> None:
        """
        Disables all integrations that the playbook uses
        Args:
            client: The demisto_client to use
        """
        for integration in self.integrations:
            integration.disable_integrations_instances(client)

    def delete_integration_instances(self, client: DefaultApi):
        """
        Deletes all integrations that the playbook uses
        Args:
            client: The demisto_client to use
        """
        for integration in self.integrations:
            integration.delete_integration_instance(client)

    def create_incident(self, client: DefaultApi) -> Optional[Incident]:
        """
        Creates an incident with the current playbook ID
        Args:
            client: The demisto_client to use

        Returns:
            - The created incident or None
        """
        incident_name = f'inc-{self.configuration.playbook_id}'
        create_incident_request = demisto_client.demisto_api.CreateIncidentRequest()
        create_incident_request.create_investigation = True
        create_incident_request.playbook_id = self.configuration.playbook_id
        create_incident_request.name = incident_name

        try:
            response = client.create_incident(create_incident_request=create_incident_request)
        except ApiException:
            self.build_context.logging_module.exception(
                f'Failed to create incident with name {incident_name} for playbook {self}')
        try:
            inc_id = response.id
        except:  # noqa: E722
            inc_id = 'incCreateErr'
        # inc_id = response_json.get('id', 'incCreateErr')
        if inc_id == 'incCreateErr':
            error_message = f'Failed to create incident for playbookID: {self}.' \
                            'Possible reasons are:\nMismatch between playbookID in conf.json and ' \
                            'the id of the real playbook you were trying to use,' \
                            'or schema problems in the TestPlaybook.'
            self.build_context.logging_module.error(error_message)
            return None

        # get incident
        search_filter = demisto_client.demisto_api.SearchIncidentsData()
        inc_filter = demisto_client.demisto_api.IncidentFilter()
        inc_filter.query = f'id: {inc_id}'
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
                self.build_context.logging_module.exception(f'Searching incident with id {inc_id} failed')
            if time.time() > timeout:
                self.build_context.logging_module.error(f'Got timeout for searching incident with id {inc_id}')
                self.build_context.logging_module.error(f'Incident search responses: {incident_search_responses}')
                return None

            time.sleep(10)

        return incidents.data[0]

    def delete_incident(self, client: DefaultApi, incident: Incident) -> bool:
        """
        Deletes a Demisto incident
        Args:
            client: demisto_client instance to use
            incident: Incident to delete

        Returns:
            True if incident was deleted else False
        """
        try:
            body = {
                'ids': [incident.id],
                'filter': {},
                'all': False
            }
            res = demisto_client.generic_request_func(self=client, method='POST',
                                                      path='/incident/batchDelete', body=body)
        except ApiException:
            self.build_context.logging_module.exception(
                'Failed to delete incident, error trying to communicate with demisto server')
            return False

        if int(res[1]) != 200:
            self.build_context.logging_module.error(f'delete incident failed with Status code {res[1]}')
            self.build_context.logging_module.error(pformat(res))
            return False

        return True


class BuildContext:
    def __init__(self, options, logging_module):
        self.logging_module: ParallelLoggingManager = logging_module
        self.api_key = options.apiKey
        self.server = options.server
        self.conf_path = options.conf
        self.secret_conf_path = options.secret
        self.conf, self.secret_conf = self._load_conf_files(self.conf_path, self.secret_conf_path)
        self.env_json = self._load_env_results_json()
        self.is_nightly = options.nightly
        self.slack_client = SlackClient(options.slack)
        self.circleci_token = options.circleci
        self.build_number = options.buildNumber
        self.build_name = options.buildName
        self.isAMI = options.isAMI
        self.memCheck = options.memCheck
        self.server_version = options.serverVersion
        self.specific_tests_to_run = self._parse_tests_list_arg(options.testsList)
        self.is_local_run = (self.server is not None)
        self.server_numeric_version = self._get_server_numeric_version()
        self.instances_ips = self._get_instances_ips()
        self.filtered_tests = self._extract_filtered_tests()
        self.tests_data_keeper = TestResults(self.conf.unmockable_integrations)
        self.conf_unmockable_tests = self._get_unmockable_tests_from_conf()
        self.unmockable_test_ids = {}
        self.mockable_tests_to_run, self.unmockable_tests_to_run = self._get_tests_to_run()
        self.slack_user_id = self._retrieve_slack_user_id()

    def _generate_tests_queue(self, tests_to_run: List[TestConfiguration]) -> Queue:
        """
        Generates a queue containing test playbooks to run
        Args:
            tests_to_run: A list containing playbook names
        """
        queue = Queue()
        for test in tests_to_run:
            playbook = TestPlaybook(self, test)
            if playbook.should_test_run():
                queue.put(playbook)
        return queue

    def _get_tests_to_run(self) -> Tuple[Queue, Queue]:
        """
        Gets tests to run in the current build and updates the unmockable tests ids set
        Returns:
            - A queue with mockable TestPlaybook instances to run in the current build
            - A queue with unmockable TestPlaybook instances to run in the current build
        """
        unmockable_tests = []
        all_tests = self._get_all_tests()
        if self.server or not self.isAMI:
            unmockable_tests = all_tests
            self.unmockable_test_ids = [test.playbook_id for test in all_tests]
        elif self.isAMI:
            unmockable_tests = self.conf_unmockable_tests
            self.unmockable_test_ids = {test.playbook_id for test in self.conf_unmockable_tests}
        self.logging_module.debug(f'Unmockable tests selected: {pformat(self.unmockable_test_ids)}')
        mockable_tests = [test for test in all_tests if test.playbook_id not in self.unmockable_test_ids]
        self.logging_module.debug(f'Mockable tests selected: {pformat([test.playbook_id for test in mockable_tests])}')
        mockable_tests_queue = self._generate_tests_queue(mockable_tests)
        unmockable_tests_queue = self._generate_tests_queue(unmockable_tests)
        return mockable_tests_queue, unmockable_tests_queue

    @staticmethod
    def _extract_filtered_tests() -> list:
        """
        Reads the content from ./Tests/filter_file.txt and parses it into a list of test playbook IDs that should be run
        in the current build
        Returns:
            A list of playbook IDs that should be run in the current build
        """
        with open(FILTER_CONF, 'r') as filter_file:
            filtered_tests = [line.strip('\n') for line in filter_file.readlines()]

        return filtered_tests

    def _get_unmockable_tests_from_conf(self) -> list:
        """
        Extracts the unmockable test playbook by looking at all playbooks that has unmockable integrations
        Returns:
            A with unmockable playbook names
        """
        unmockable_integrations = self.conf.unmockable_integrations
        tests = self.conf.tests
        unmockable_tests = []
        for test_record in tests:
            test_name = test_record.playbook_id
            unmockable_integrations_used = [integration_name for integration_name in test_record.test_integrations if
                                            integration_name in unmockable_integrations]
            if test_name and (not test_record.test_integrations or unmockable_integrations_used) or not self.isAMI:
                unmockable_tests.append(test_record)

        return unmockable_tests

    @staticmethod
    def _get_used_integrations(test_configuration: dict) -> list:
        """
        Gets the integration used in a test playbook configurations
        Args:
            test_configuration: A test configuration from content conf.json file.

        Returns:
            A list with integration names
        """
        tested_integrations = test_configuration.get("integrations", [])
        if isinstance(tested_integrations, list):
            return tested_integrations
        else:
            return [tested_integrations]

    def _get_all_tests(self) -> List[TestConfiguration]:
        """
        Gets a list of all playbooks configured in content conf.json
        Returns:
            A list with playbook names
        """
        tests_records = self.conf.tests
        return [test for test in tests_records if test.playbook_id]

    def _get_instances_ips(self) -> List[Tuple[str, str]]:
        """
        Parses the env_results.json and extracts the instance ip from each server configured in it.
        Returns:
            A list containing tuple with the following:
                - The server IP
        """
        if self.server:
            return [self.server]
        instances_ips = [env.get('InstanceDNS') for env in self.env_json if env.get('Role') == self.server_version]
        return instances_ips

    @staticmethod
    def _parse_tests_list_arg(tests_list: str):
        """
        Parses the test list arguments if present.

        :param tests_list: CSV string of tests to run.
        :return: List of tests if there are any, otherwise empty list.
        """
        tests_to_run = tests_list.split(",") if tests_list else []
        return tests_to_run

    @staticmethod
    def _load_env_results_json():
        if not os.path.isfile(ENV_RESULTS_PATH):
            return {}

        with open(ENV_RESULTS_PATH, 'r') as json_file:
            return json.load(json_file)

    def _get_server_numeric_version(self) -> str:
        """
        Gets the current server version

        Returns:
            Server numeric version
        """
        default_version = '99.99.98'
        if self.is_local_run:
            self.logging_module.info(f'Local run, assuming server version is {default_version}', real_time=True)
            return default_version

        if not self.env_json:
            self.logging_module.warning(
                f'Did not find {ENV_RESULTS_PATH} file, assuming server version is {default_version}.',
                real_time=True)
            return default_version

        instances_ami_names = {env.get('AmiName') for env in self.env_json if
                               self.server_version in env.get('Role', '')}
        if len(instances_ami_names) != 1:
            self.logging_module.warning(f'Did not get one AMI Name, got {instances_ami_names}.'
                                        f' Assuming server version is {default_version}',
                                        real_time=True)
            return default_version

        instances_ami_name = list(instances_ami_names)[0]

        return self._extract_server_numeric_version(instances_ami_name, default_version)

    def _extract_server_numeric_version(self, instances_ami_name, default_version):
        # regex doesn't catch Server Master execution
        extracted_version = re.findall(r'Demisto-(?:Circle-CI|Marketplace)-Content-AMI-[A-Za-z]*[-_](\d[._]\d)-[\d]{5}',
                                       instances_ami_name)
        extracted_version = [match.replace('_', '.') for match in extracted_version]

        if extracted_version:
            server_numeric_version = extracted_version[0]
        else:
            if 'Master' in instances_ami_name:
                self.logging_module.info('Server version: Master', real_time=True)
                return default_version
            else:
                server_numeric_version = default_version

        # make sure version is three-part version
        if server_numeric_version.count('.') == 1:
            server_numeric_version += ".0"

        self.logging_module.info(f'Server version: {server_numeric_version}', real_time=True)
        return server_numeric_version

    @staticmethod
    def _load_conf_files(conf_path, secret_conf_path):
        with open(conf_path) as data_file:
            conf = Conf(json.load(data_file))

        secret_conf = None
        if secret_conf_path:
            with open(secret_conf_path) as data_file:
                secret_conf = SecretConf(json.load(data_file))

        return conf, secret_conf

    def _get_user_name_from_circle(self):
        url = f"https://circleci.com/api/v1.1/project/github/demisto/content/{self.build_number}?" \
              f"circle-token={self.circleci_token}"
        res = self._http_request(url)

        user_details = res.get('user', {})
        return user_details.get('name', '')

    @staticmethod
    def _http_request(url, params_dict=None):
        try:
            res = requests.request("GET",
                                   url,
                                   verify=True,
                                   params=params_dict,
                                   )
            res.raise_for_status()

            return res.json()

        except Exception as e:
            raise e

    def _retrieve_slack_user_id(self):
        """
        Gets the user id of the circle user who triggered the current build
        Args:
            slack_client (SlackClient): The slack client

        Returns:

        """
        circle_user_name = self._get_user_name_from_circle()
        user_id = ''
        res = self.slack_client.api_call('users.list')

        user_list = res.get('members', [])
        for user in user_list:
            profile = user.get('profile', {})
            name = profile.get('real_name_normalized', '')
            if name == circle_user_name:
                user_id = user.get('id', '')

        return user_id


class TestResults:

    def __init__(self, unmockable_integrations):
        self.succeeded_playbooks = []
        self.failed_playbooks = set()
        self.skipped_tests = dict()
        self.skipped_integrations = dict()
        self.rerecorded_tests = []
        self.empty_files = []
        self.unmockable_integrations = unmockable_integrations
        self.playbook_skipped_integration = set()

    def add_proxy_related_test_data(self, proxy):
        # Using multiple appends and not extend since append is guaranteed to be thread safe
        for playbook_id in proxy.rerecorded_tests:
            self.rerecorded_tests.append(playbook_id)
        for playbook_id in proxy.empty_files:
            self.empty_files.append(playbook_id)

    def create_result_files(self):
        with open("./Tests/failed_tests.txt", "w") as failed_tests_file:
            failed_tests_file.write('\n'.join(self.failed_playbooks))
        with open('./Tests/skipped_tests.txt', "w") as skipped_tests_file:
            skipped_tests_file.write('\n'.join(self.skipped_tests))
        with open('./Tests/skipped_integrations.txt', "w") as skipped_integrations_file:
            skipped_integrations_file.write('\n'.join(self.skipped_integrations))

    def print_test_summary(self,
                           is_ami: bool = True,
                           logging_module: Union[Any, ParallelLoggingManager] = logging) -> None:
        """
        Takes the information stored in the tests_data_keeper and prints it in a human readable way.
        Args:
            is_ami: indicating if the server running the tests is an AMI or not.
            logging_module: Logging module to use for test_summary
        """
        succeed_playbooks = self.succeeded_playbooks
        failed_playbooks = self.failed_playbooks
        skipped_tests = self.skipped_tests
        unmocklable_integrations = self.unmockable_integrations
        skipped_integration = self.skipped_integrations
        rerecorded_tests = self.rerecorded_tests
        empty_files = self.empty_files

        succeed_count = len(succeed_playbooks)
        failed_count = len(failed_playbooks)
        rerecorded_count = len(rerecorded_tests) if is_ami else 0
        empty_mocks_count = len(empty_files) if is_ami else 0
        logging_module.real_time_logs_only = True
        logging_module.info('TEST RESULTS:')
        logging_module.info(f'Number of playbooks tested - {succeed_count + failed_count}')
        if failed_count:
            logging_module.error(f'Number of failed tests - {failed_count}:')
            logging_module.error('Failed Tests: {}'.format(
                ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in failed_playbooks])))
        if succeed_count:
            logging_module.success(f'Number of succeeded tests - {succeed_count}')
            logging_module.success('Successful Tests: {}'.format(
                ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in succeed_playbooks])))
        if rerecorded_count > 0:
            logging_module.debug(
                f'Number of tests with failed playback and successful re-recording - {rerecorded_count}')
            logging_module.debug('Tests with failed playback and successful re-recording: {}'.format(
                ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in rerecorded_tests])))

        if empty_mocks_count > 0:
            logging_module.debug(f'Successful tests with empty mock files count- {empty_mocks_count}:\n')
            proxy_explanation = \
                '\t\t\t\t\t\t\t (either there were no http requests or no traffic is passed through the proxy.\n' \
                '\t\t\t\t\t\t\t Investigate the playbook and the integrations.\n' \
                '\t\t\t\t\t\t\t If the integration has no http traffic, add to unmockable_integrations in conf.json)'
            logging_module.debug(proxy_explanation)
            logging_module.debug('Successful tests with empty mock files: {}'.format(
                ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in empty_files])))

        if skipped_integration:
            self.print_table("Skipped Integrations", skipped_integration, logging_module.debug)

        if skipped_tests:
            self.print_table("Skipped Tests", skipped_tests, logging_module.debug)

        if unmocklable_integrations:
            self.print_table("Unmockable Integrations", unmocklable_integrations, logging_module.debug)

    @staticmethod
    def print_table(table_name: str, table_data: dict, logging_method: Callable) -> None:
        table = prettytable.PrettyTable()
        table.field_names = ['Index', 'Name', 'Reason']
        for index, record in enumerate(table_data, start=1):
            row = [index, record, table_data[record]]
            table.add_row(row)
        logging_method(f'{table_name}:\n{table}', real_time=True)


class Integration:
    def __init__(self, build_context: BuildContext, integration_name: str, potential_integration_instance_names: list):
        """
        An integration class that should represent the integrations during the build
        Args:
            build_context: The context of the build
            integration_name: The name of the integration
            potential_integration_instance_names: A list of instance names, one of those names should be the actual reason
            but we won't know for sure until we will try to filter it with conf.json from content-test-conf repo
        """
        self.build_context = build_context
        self.name = integration_name
        self.instance_names = potential_integration_instance_names
        self.instance_name = ''
        self.configuration: Optional[IntegrationConfiguration] = IntegrationConfiguration(
            {'name': self.name,
             'params': {}})
        self.docker_image: list = []
        self.integration_instance: dict = {}

    @staticmethod
    def _change_placeholders_to_values(server_url: str,
                                       config_item: IntegrationConfiguration) -> IntegrationConfiguration:
        """Replaces placeholders in the object to their real values

        Args:
            server_url: (dict)
                 The server url that should be inserted instead of the placeholder in the configuration params
            config_item: (json object)
                Integration configuration object.

        Returns:
            IntegrationConfiguration class with the modified params
        """
        placeholders_map = {'%%SERVER_HOST%%': server_url}
        item_as_string = json.dumps(config_item.params)
        for key, value in placeholders_map.items():
            item_as_string = item_as_string.replace(key, value)
        config_item.params = json.loads(item_as_string)
        return config_item

    def _set_integration_params(self, server_url: str, playbook_id: str, is_mockable: bool) -> bool:
        """
        Finds the matching configuration for the integration in content-test-data conf.json file
        in accordance with the configured instance name if exist and configures the proxy parameter if needed
        Args:
            server_url: The url of the demisto server to configure the integration in
            playbook_id: The ID of the playbook for which the integration should be configured
            is_mockable: Should the proxy parameter be set to True or not

        Returns:
            True if found a matching configuration else False if found more that one configuration candidate returns False
        """
        self.build_context.logging_module.debug(f'Searching integration configuration for {self}')
        integration_params: List[IntegrationConfiguration] = [
            self._change_placeholders_to_values(server_url, conf) for
            conf in self.build_context.secret_conf.integrations if conf.name == self.name]

        if integration_params:
            if len(integration_params) != 1:
                found_matching_instance = False
                for item in integration_params:
                    if item.instance_name in self.instance_names:
                        self.configuration = item
                        found_matching_instance = True
                        break

                if not found_matching_instance:
                    optional_instance_names = [optional_integration.instance_name
                                               for optional_integration in integration_params]
                    error_msg = FAILED_MATCH_INSTANCE_MSG.format(playbook_id,
                                                                 len(integration_params),
                                                                 self.name,
                                                                 '\n'.join(optional_instance_names))
                    self.build_context.logging_module.error(error_msg)
                    return False
            else:
                self.configuration = integration_params[0]

        elif self.name == 'Demisto REST API':
            self.configuration.params = {
                'url': 'https://localhost',
                'apikey': self.build_context.api_key,
                'insecure': True,
            }
        if is_mockable:
            self.build_context.logging_module.debug(f'configuring {self} with proxy params')
            for param in ('proxy', 'useProxy', 'insecure', 'unsecure'):
                self.configuration.params[param] = True
        return True

    def _get_integration_config(self, client: DefaultApi) -> Optional[dict]:
        """
        Gets integration configuration as it exists on the demisto server
        Args:
            client: Demisto client instance

        Returns:
            A dict containing the configuration for the integration if found, else None
        """
        body = {
            'page': 0, 'size': 100, 'query': f'name:{self.name}'
        }
        try:
            res_raw = demisto_client.generic_request_func(self=client, path='/settings/integration/search',
                                                          method='POST', body=body)
        except ApiException:
            self.build_context.logging_module.exception(f'failed to get integration {self} configuration')
            return None

        res = ast.literal_eval(res_raw[0])
        TIMEOUT = 180
        SLEEP_INTERVAL = 5
        total_sleep = 0
        while 'configurations' not in res:
            if total_sleep == TIMEOUT:
                self.build_context.logging_module.error(
                    f"Timeout - failed to get integration {self} configuration. Error: {res}")
                return None

            time.sleep(SLEEP_INTERVAL)
            total_sleep += SLEEP_INTERVAL

        all_configurations = res['configurations']
        match_configurations = [x for x in all_configurations if x['name'] == self.name]

        if not match_configurations or len(match_configurations) == 0:
            self.build_context.logging_module.error('integration was not found')
            return None

        return match_configurations[0]

    def _delete_integration_instance_if_determined_by_name(self, client: DefaultApi, instance_name: str) -> None:
        """Deletes integration instance by it's name.

        Args:
            client (demisto_client): The configured client to use.
            instance_name (str): The name of the instance to delete.

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
            self.build_context.logging_module.exception(
                f'Failed to delete integration {self} instance, error trying to communicate with demisto server')
            return
        if int(int_resp[1]) != 200:
            self.build_context.logging_module.error(f'Get integration {self} instance failed with status code: {int_resp[1]}')
            return
        if 'instances' not in int_instances:
            self.build_context.logging_module.info(f'No integrations instances found to delete for {self}')
            return

        for instance in int_instances['instances']:
            if instance.get('name') == instance_name:
                self.build_context.logging_module.info(
                    f'Deleting integration instance {instance_name} since it is defined by name')
                self.delete_integration_instance(client, instance.get('id'))

    def _set_server_keys(self, client: DefaultApi) -> None:
        """In case the the params of the test in the content-test-conf repo has 'server_keys' key:
            Adds server configuration keys using the demisto_client.

        Args:
            client (demisto_client): The configured client to use.
        """
        if 'server_keys' not in self.configuration.params:
            return

        self.build_context.logging_module.debug(f'Setting server keys for integration: {self}')

        data = {
            'data': {},
            'version': -1
        }

        for key, value in self.configuration.params.get('server_keys').items():
            data['data'][key] = value

        update_server_configuration(
            client=client,
            server_configuration=self.configuration.params.get('server_keys'),
            error_msg='Failed to set server keys',
            logging_manager=self.build_context.logging_module
        )

    def create_integration_instance(self, client: DefaultApi, playbook_id: str, is_mockable: bool) -> Optional[dict]:
        """
        Create an instance of the integration in the server specified in the demisto client instance.
        Args:
            client: The demisto_client instance to use
            playbook_id: The playbook id for which the instance should be created
            is_mockable: Indicates whether the integration should be configured with proxy=True or not

        Returns:
            The integration configuration as it exists on the server after it was configured
        """
        self._set_integration_params(client.api_client.configuration.host, playbook_id, is_mockable)
        configuration = self._get_integration_config(client)
        if not configuration:
            self.build_context.logging_module.error(f'Could not find configuration for integration {self}')
            return

        module_configuration = configuration['configuration']
        if not module_configuration:
            module_configuration = []

        if 'integrationInstanceName' in self.configuration.params:
            instance_name = self.configuration.params['integrationInstanceName']
            self._delete_integration_instance_if_determined_by_name(client, instance_name)
        else:
            instance_name = f'{self.configuration.instance_name.replace(" ", "_")}_test_{uuid.uuid4()}'

        self.build_context.logging_module.info(
            f'Configuring instance for {self} (instance name: {instance_name}, '
            f'validate "test-module": {self.configuration.should_validate_test_module})'
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
            'isIntegrationScript': self.configuration.is_byoi,
            'name': instance_name,
            'passwordProtected': False,
            'version': 0
        }

        # set server keys
        self._set_server_keys(client)

        # set module params
        for param_conf in module_configuration:
            if param_conf['display'] in self.configuration.params or param_conf['name'] in self.configuration.params:
                # param defined in conf
                key = param_conf['display'] if param_conf['display'] in self.configuration.params else param_conf[
                    'name']
                if key == 'credentials':
                    credentials = self.configuration.params[key]
                    param_value = {
                        'credential': '',
                        'identifier': credentials['identifier'],
                        'password': credentials['password'],
                        'passwordChanged': False
                    }
                else:
                    param_value = self.configuration.params[key]

                param_conf['value'] = param_value
                param_conf['hasvalue'] = True
            elif param_conf['defaultValue']:
                # param is required - take default value
                param_conf['value'] = param_conf['defaultValue']
            module_instance['data'].append(param_conf)
        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException:
            self.build_context.logging_module.exception(f'Error trying to create instance for integration: {self}')
            return

        if res[1] != 200:
            self.build_context.logging_module.error(f'create instance failed with status code  {res[1]}')
            self.build_context.logging_module.error(pformat(res[0]))
            return

        integration_config = ast.literal_eval(res[0])
        self.integration_instance = integration_config
        return integration_config

    def delete_integration_instance(self, client, instance_id: Optional[str] = None) -> bool:
        """
        Deletes an integration with the given ID
        Args:
            client: Demisto client instance
            instance_id: The instance ID to Delete

        Returns:
            True if integration was deleted else False
        """
        instance_id = instance_id or self.integration_instance.get('id')
        if not instance_id:
            self.build_context.logging_module.debug(f'no instance ID for integration {self} was supplied')
            return True
        try:
            res = demisto_client.generic_request_func(self=client, method='DELETE',
                                                      path='/settings/integration/' + urllib.parse.quote(
                                                          instance_id))
        except ApiException:
            self.build_context.logging_module.exception(
                'Failed to delete integration instance, error trying to communicate with demisto.')
            return False
        if int(res[1]) != 200:
            self.build_context.logging_module.error(f'delete integration instance failed\nStatus code {res[1]}')
            self.build_context.logging_module.error(pformat(res))
            return False
        if self.integration_instance:
            self.integration_instance = {}
        return True

    def test_integration_instance(self, client: DefaultApi) -> bool:
        """Runs test module on the integration instance
        Args:
            client: The demisto_client instance to use

        Returns:
            The integration configuration as it exists on the server after it was configured
        """
        connection_retries = 3
        response_code = 0
        integration_of_instance = self.integration_instance.get('brand', '')
        instance_name = self.integration_instance.get('name', '')
        self.build_context.logging_module.info(
            f'Running "test-module" for instance "{instance_name}" of integration "{integration_of_instance}".')
        for i in range(connection_retries):
            try:
                response_data, response_code, _ = demisto_client.generic_request_func(self=client, method='POST',
                                                                                      path='/settings/integration/test',
                                                                                      body=self.integration_instance,
                                                                                      _request_timeout=120)
                break
            except ApiException:
                self.build_context.logging_module.exception(
                    f'Failed to test integration {self} instance, error trying to communicate with demisto server')
                return False
            except urllib3.exceptions.ReadTimeoutError:
                self.build_context.logging_module.warning(f"Could not connect. Trying to connect for the {i + 1} time")

        if int(response_code) != 200:
            self.build_context.logging_module.error(
                f'Integration-instance test-module failed. Bad status code: {response_code}')
            return False

        result_object = ast.literal_eval(response_data)
        success, failure_message = bool(result_object.get('success')), result_object.get('message')
        if not success:
            server_url = client.api_client.configuration.host
            test_failed_msg = f'Test integration failed - server: {server_url}.\n' \
                              f'Failure message: {failure_message}' if failure_message else ' No failure message.'
            self.build_context.logging_module.error(test_failed_msg)
        return success

    def disable_integrations_instances(self, client) -> None:
        """Disables the integration
        Args:
            client: The demisto_client instance to use

        Returns:
            The integration configuration as it exists on the server after it was configured
        """
        # tested with POSTMAN, this is the minimum required fields for the request.
        module_instance = {
            key: self.integration_instance[key] for key in ['id', 'brand', 'name', 'data', 'isIntegrationScript', ]
        }
        module_instance['enable'] = "false"
        module_instance['version'] = -1
        self.build_context.logging_module.debug(f'Disabling integration instance "{module_instance.get("name")}"')
        try:
            res = demisto_client.generic_request_func(self=client, method='PUT',
                                                      path='/settings/integration',
                                                      body=module_instance)
        except ApiException:
            self.build_context.logging_module.exception('Failed to disable integration instance')
            return

        if res[1] != 200:
            self.build_context.logging_module.error(f'disable instance failed, Error: {pformat(res)}')

    def get_docker_images(self) -> List[str]:
        """
        Gets the docker image name from the configured integration instance's body if such body exists
        Returns:

        """
        if self.integration_instance:
            return Docker.get_integration_image(self.integration_instance)
        else:
            raise Exception('Cannot get docker image - integration instance was not created yet')

    def __str__(self):
        return f'"{self.name}"'

    def __repr__(self):
        return str(self)


class TestContext:
    def __init__(self, build_context: BuildContext, playbook: TestPlaybook, client: DefaultApi):
        self.build_context = build_context
        self.playbook = playbook
        self.incident: Optional[Incident] = None
        self.test_docker_images = set()
        self.client: DefaultApi = client

    def _get_investigation_playbook_state(self) -> str:
        """
        Queried the server for the current status of the test's investigation
        Returns:
            A string representing the status of the playbook
        """
        try:
            investigation_playbook_raw = demisto_client.generic_request_func(
                self=self.client,
                method='GET',
                path='/inv-playbook/' + self.incident.investigation_id)
            investigation_playbook = ast.literal_eval(investigation_playbook_raw[0])
        except ApiException:
            self.build_context.logging_module.exception(
                'Failed to get investigation playbook state, error trying to communicate with demisto server'
            )
            return PB_Status.FAILED

        try:
            state = investigation_playbook['state']
            return state
        except Exception:  # noqa: E722
            return PB_Status.NOT_SUPPORTED_VERSION

    def _collect_docker_images(self) -> None:
        """
        Collects docker images of the playbook's integration.
        This method can be called only after the integrations were configured in the server.
        """
        for integration in self.playbook.integrations:
            docker_images = integration.get_docker_images()
            if docker_images:
                self.test_docker_images.update(docker_images)

    def _print_investigation_error(self):
        try:
            res = demisto_client.generic_request_func(
                self=self.client,
                method='POST',
                path='/investigation/' + urllib.parse.quote(self.incident.investigation_id),
                body={"pageSize": 1000})
            if res and int(res[1]) == 200:
                resp_json = ast.literal_eval(res[0])
                entries = resp_json['entries']

                self.build_context.logging_module.error(f'Playbook {self.playbook} has failed:')
                for entry in entries:
                    if entry['type'] == ENTRY_TYPE_ERROR and entry['parentContent']:
                        self.build_context.logging_module.error(f'- Task ID: {entry["taskId"]}')
                        # Checks for passwords and replaces them with "******"
                        parent_content = re.sub(
                            r' (P|p)assword="[^";]*"', ' password=******', entry['parentContent'])
                        self.build_context.logging_module.error(f'  Command: {parent_content}')
                        self.build_context.logging_module.error(f'  Body:\n{entry["contents"]}')
            else:
                self.build_context.logging_module.error(
                    f'Failed getting entries for investigation: {self.incident.investigation_id}. Res: {res}')
        except ApiException:
            self.build_context.logging_module.exception(
                'Failed to print investigation error, error trying to communicate with demisto server')

    def _poll_for_playbook_state(self) -> str:
        """
        Polls for the playbook execution in the incident and return it's state.
        Returns:
            A string representing the status of the playbook
        """
        timeout = time.time() + self.playbook.configuration.timeout
        number_of_attempts = 1
        # wait for playbook to finish run
        while True:
            # give playbook time to run
            time.sleep(1)
            try:
                # fetch status
                playbook_state = self._get_investigation_playbook_state()
            except demisto_client.demisto_api.rest.ApiException:
                playbook_state = 'Pending'
                self.client.api_client.pool.close()
                self.client.api_client.pool.terminate()
                self.client = demisto_client.configure(base_url=self.client.api_client.configuration.host,
                                                       api_key=self.client.api_client.configuration.api_key,
                                                       verify_ssl=False)

            if playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION):
                break
            if playbook_state == PB_Status.FAILED:
                self.build_context.logging_module.error(f'{self.playbook} failed with error/s')
                self._print_investigation_error()
                break
            if time.time() > timeout:
                self.build_context.logging_module.error(f'{self.playbook} failed on timeout')
                break

            if number_of_attempts % DEFAULT_INTERVAL == 0:
                self.build_context.logging_module.info(
                    f'loop no. {number_of_attempts / DEFAULT_INTERVAL}, playbook state is {playbook_state}')
            number_of_attempts = number_of_attempts + 1
        return playbook_state

    def _run_incident_test(self) -> str:
        """
        Creates an incident in demisto server and return it's status
        Returns:
            Empty string or
        """
        try:
            server_url = self.client.api_client.configuration.host
            self.playbook.configure_integrations(self.client)
            incident = self.playbook.create_incident(self.client)
            if not incident:
                return ''
            self.incident = incident
            investigation_id = incident.investigation_id
            if investigation_id is None or len(investigation_id) == 0:
                self.build_context.logging_module.error(f'Failed to get investigation id of incident: {incident}')
                return ''
            self.build_context.logging_module.info(f'Investigation URL: {server_url}/#/WorkPlan/{investigation_id}')
            playbook_state = self._poll_for_playbook_state()
            self.playbook.disable_integrations(self.client)
            return playbook_state
        except Exception:
            self.build_context.logging_module.exception(f'Failed to run incident test for {self.playbook}')
            return PB_Status.FAILED

    def _run_docker_threshold_test(self):
        self._collect_docker_images()
        if self.test_docker_images:
            error_message = Docker.check_resource_usage(
                server_url=self.client.api_client.configuration.host,
                docker_images=self.test_docker_images,
                def_memory_threshold=self.playbook.configuration.memory_threshold,
                def_pid_threshold=self.playbook.configuration.pid_threshold,
                docker_thresholds=self.build_context.conf.docker_thresholds,
                logging_module=self.build_context.logging_module)
            if error_message:
                self.build_context.logging_module.error(error_message)
                return False
        return True

    def _send_slack_message(self, channel, text, user_name, as_user):
        self.build_context.slack_client.api_call(
            "chat.postMessage",
            channel=channel,
            username=user_name,
            as_user=as_user,
            text=text,
            mrkdwn='true'
        )

    @staticmethod
    def _retrieve_slack_user_id(circle_user_name, slack_client):
        user_id = ''
        res = slack_client.api_call('users.list')

        user_list = res.get('members', [])
        for user in user_list:
            profile = user.get('profile', {})
            name = profile.get('real_name_normalized', '')
            if name == circle_user_name:
                user_id = user.get('id', '')

        return user_id

    def _notify_failed_test(self):
        if self.incident:
            text = f'{self.build_context.build_name} - {self.playbook} Failed\n' \
                   f' {self.client.api_client.configuration.host}'
        else:
            text = f'{self.build_context.build_name} - {self.playbook} Failed\n' \
                   f' {self.client.api_client.configuration.host}/#/WorkPlan/{self.incident.investigation_id}'

        if self.build_context.slack_user_id:
            self.build_context.slack_client.api_call(
                "chat.postMessage",
                channel=self.build_context.slack_user_id,
                username="Content CircleCI",
                as_user="False",
                text=text
            )

    def _add_to_succeeded_playbooks(self) -> None:
        """
        Adds the playbook to the succeeded playbooks list
        """
        self.build_context.tests_data_keeper.succeeded_playbooks.append(self.playbook.configuration.playbook_id)

    def _add_to_failed_playbooks(self) -> None:
        """
        Adds the playbook to the succeeded playbooks list
        """
        playbook_name_to_add = self.playbook.configuration.playbook_id
        if not self.playbook.is_mockable:
            playbook_name_to_add += " (Mock Disabled)"
        self.build_context.tests_data_keeper.failed_playbooks.add(playbook_name_to_add)

    @staticmethod
    def _get_docker_memory_data():
        process = subprocess.Popen(['cat', '/sys/fs/cgroup/memory/memory.usage_in_bytes'], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        return stdout, stderr

    @staticmethod
    def _get_docker_processes_data():
        process = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = process.communicate()
        return stdout, stderr

    def _send_docker_stats_on_slack(self):
        if self.build_context.is_nightly and self.build_context.memCheck and not self.build_context.is_local_run:
            stdout, stderr = self._get_docker_memory_data()
            text = 'Memory Usage: {}'.format(stdout) if not stderr else stderr
            self._send_slack_message(SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')
            stdout, stderr = self._get_docker_processes_data()
            text = stdout if not stderr else stderr
            self._send_slack_message(SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')

    def _incident_and_docker_test(self):
        playbook_state = self._run_incident_test()
        test_passed = playbook_state in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)
        if playbook_state:
            docker_test_results = self._run_docker_threshold_test()
            if not docker_test_results:
                playbook_state = PB_Status.FAILED_DOCKER_TEST
        if self.incident and test_passed:
            self.playbook.delete_incident(self.client, self.incident)
            self.playbook.delete_integration_instances(self.client)
        return playbook_state

    def _execute_unmockable_test(self) -> bool:
        """
        Executes an unmockable test
        In case the test failed to execute because one of the test's integrations were locked will return False
        as indication that the test was not done.
        Returns:
            True if test has finished it's execution else False
        """
        self.build_context.logging_module.info(f'------ Test {self} start ------ (Mock: Disabled)')
        with acquire_test_lock(self.playbook) as lock:
            if lock:
                status = self._incident_and_docker_test()
                self._handle_status(status)
            else:
                return False
        return True

    def _handle_status(self, status: str, is_playback_run: bool = False) -> None:
        """
        Handles the playbook execution run
        - Logs according to the results
        - Adds the test to the test results
        Args:
            is_playback_run:
            status:
        """
        if status == PB_Status.COMPLETED:
            self.build_context.logging_module.success(f'PASS: {self} succeed')
            self._add_to_succeeded_playbooks()

        elif status == PB_Status.NOT_SUPPORTED_VERSION:
            self.build_context.logging_module.info(f'PASS: {self} skipped - not supported version')
            self._add_to_succeeded_playbooks()

        elif status == PB_Status.FAILED_DOCKER_TEST:
            self.build_context.logging_module.error(f'Failed: {self} failed')
            self._add_to_failed_playbooks()

        else:
            if is_playback_run:
                return
            self._add_to_failed_playbooks()
            if not self.build_context.is_local_run:
                self._notify_failed_test()

    def _execute_mockable_test(self, proxy: MITMProxy):
        """
        Executes a mockable test
        In case the test failed to execute because one of the test's integrations were locked will return False
        as indication that the test was not done.
        Returns:
            True if test has finished it's execution else False
        """
        if proxy.has_mock_file(self.playbook.configuration.playbook_id):
            self.build_context.logging_module.info(f'------ Test {self} start ------ (Mock: Playback)')
            with run_with_mock(proxy, self.playbook.configuration.playbook_id) as result_holder:
                status = self._incident_and_docker_test()
                result_holder[RESULT] = status in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)
            self._handle_status(status, is_playback_run=True)
            if status in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION, PB_Status.FAILED_DOCKER_TEST):
                return True
        self.build_context.logging_module.warning("Test failed with mock, recording new mock file. (Mock: Recording)")
        self.build_context.logging_module.info(f'------ Test {self} start ------ (Mock: Recording)')
        with acquire_test_lock(self.playbook) as lock:
            if lock:
                with run_with_mock(proxy, self.playbook.configuration.playbook_id, record=True) as result_holder:
                    status = self._incident_and_docker_test()
                    self._handle_status(status)
                    succeed = status in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)
                    result_holder[RESULT] = succeed
                    return True
            return False

    def execute_test(self, proxy: Optional[MITMProxy] = None):
        self._send_docker_stats_on_slack()
        if self.playbook.is_mockable:
            test_executed = self._execute_mockable_test(proxy)
        else:
            test_executed = self._execute_unmockable_test()
        self.build_context.logging_module.info(f'------ Test {self} end ------ \n')
        self.build_context.logging_module.execute_logs()
        return test_executed

    def __str__(self):
        test_message = f'playbook: "{self.playbook}"'
        if self.playbook.integrations:
            test_message += f' with integration(s): {self.playbook.integrations}'
        else:
            test_message += ' with no integrations'
        return test_message

    def __repr__(self):
        return str(self)


class TestsExecution:

    def __init__(self, build_context: BuildContext, server_ip: str):
        self.build_context = build_context
        self.server_ip = server_ip
        self.server_url = f'https://{self.server_ip}'
        self.client: Optional[DefaultApi] = None
        self._configure_new_client()
        self.proxy = MITMProxy(server_ip,
                               self.build_context.logging_module,
                               build_number=self.build_context.build_number,
                               branch_name=self.build_context.build_name)
        self.executed_tests = set()
        self.executed_in_current_round = set()

    def _execute_unmockable_tests(self):
        """
        Iterates the mockable tests queue and executes them as long as there are tests to execute
        """
        self._execute_tests(self.build_context.unmockable_tests_to_run)

    def _execute_tests(self, queue: Queue) -> None:
        """
        Iterates the tests queue and executes them as long as there are tests to execute
        Args:
            queue: The queue to fetch tests to execute from
        """
        while queue.unfinished_tasks:
            try:
                test_playbook: TestPlaybook = queue.get(block=False)
                self.reset_tests_round_if_necessary(test_playbook, queue)
            except Empty:
                continue
            self._configure_new_client()
            test_executed = TestContext(self.build_context, test_playbook, self.client).execute_test(self.proxy)
            if test_executed:
                self.executed_tests.add(test_playbook.configuration.playbook_id)
            else:
                queue.put(test_playbook)
            queue.task_done()

    def _execute_mockable_tests(self):
        """
        Iterates the mockable tests queue and executes them as long as there are tests to execute
        """
        self.proxy.configure_proxy_in_demisto(proxy=self.proxy.ami.docker_ip + ':' + self.proxy.PROXY_PORT,
                                              username=self.build_context.secret_conf.server_username,
                                              password=self.build_context.secret_conf.server_password,
                                              server=self.server_url)
        self._execute_tests(self.build_context.mockable_tests_to_run)
        self.proxy.configure_proxy_in_demisto(proxy='',
                                              username=self.build_context.secret_conf.server_username,
                                              password=self.build_context.secret_conf.server_password,
                                              server=self.server_url)

    def reset_tests_round_if_necessary(self, test_playbook: TestPlaybook, queue_: Queue) -> None:
        """
        Checks if the string representation of the current test configuration is already in
        the executed_in_current_round set.
        If it is- it means we have already executed this test and the we have reached a round and there are tests that
        were not able to be locked by this execution..
        In that case we want to start a new round monitoring by emptying the 'executed_in_current_round' set and sleep
        in order to let the tests be unlocked
        Since this operation can be performed by multiple threads - this operaion is protected by the queue's lock
        Args:
            test_playbook: Test playbook to check if has been executed in the current round
            queue_: The queue from which the current tests are executed
        """
        queue_.mutex.acquire()
        if str(test_playbook.configuration) in self.executed_in_current_round:
            self.build_context.logging_module.info(
                'all tests in the queue were executed, sleeping for 30 seconds to let locked tests get unlocked.')
            self.executed_in_current_round = {str(test_playbook.configuration)}
            queue_.mutex.release()
            time.sleep(30)
            return
        queue_.mutex.release()

    def _configure_new_client(self):
        if self.client:
            self.client.api_client.pool.close()
            self.client.api_client.pool.terminate()
        self.client = demisto_client.configure(base_url=self.server_url,
                                               api_key=self.build_context.api_key,
                                               verify_ssl=False)

    def _reset_containers(self):
        self.build_context.logging_module.info('Resetting containers\n', real_time=True)

        body, status_code, _ = demisto_client.generic_request_func(self=self.client, method='POST',
                                                                   path='/containers/reset')
        if status_code != 200:
            self.build_context.logging_module.critical(
                f'Request to reset containers failed with status code "{status_code}"\n{body}', real_time=True)
            sys.exit(1)
        time.sleep(10)

    def execute_tests(self):

        try:
            self.build_context.logging_module.info(f'Starts tests with server url - {self.server_url}', real_time=True)
            self._execute_mockable_tests()
            self._reset_containers()
            self._execute_unmockable_tests()
            self.build_context.logging_module.info(f'Finished tests with server url - {self.server_url}',
                                                   real_time=True)
            self.build_context.tests_data_keeper.add_proxy_related_test_data(self.proxy)

            if self.build_context.isAMI:
                if self.proxy.should_update_mock_repo:
                    self.proxy.push_mock_files()
            self.build_context.logging_module.debug(f'Tests executed on server {self.server_ip}:\n'
                                                    f'{pformat(self.executed_tests)}')
        except Exception:
            self.build_context.logging_module.exception('~~ Thread failed ~~')
            raise
        finally:
            self.build_context.logging_module.execute_logs()
