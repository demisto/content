
import argparse
import ast
import json
import os
import subprocess
import sys
import uuid
import zipfile
from abc import abstractmethod, ABC
from datetime import datetime
from packaging.version import Version
from enum import IntEnum
from pprint import pformat
from threading import Thread
from time import sleep

from urllib.parse import quote_plus
import demisto_client

from demisto_sdk.commands.common.constants import FileType
from demisto_sdk.commands.common.tools import run_threads_list, run_command, get_yaml, \
    str2bool, format_version, find_type, listdir_fullpath
from demisto_sdk.commands.test_content.constants import SSH_USER
from demisto_sdk.commands.test_content.mock_server import MITMProxy, run_with_mock, RESULT
from demisto_sdk.commands.test_content.tools import update_server_configuration, is_redhat_instance
from demisto_sdk.commands.test_content.TestContentClasses import BuildContext
from demisto_sdk.commands.validate.validate_manager import ValidateManager
from ruamel import yaml

from Tests.Marketplace.search_and_install_packs import search_and_install_packs_and_their_dependencies, \
    upload_zipped_packs, install_all_content_packs_for_nightly
from Tests.Marketplace.marketplace_constants import Metadata
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging
from Tests.test_content import get_server_numeric_version
from Tests.test_integration import __get_integration_config, test_integration_instance, disable_all_integrations
from Tests.tools import run_with_proxy_configured
from Tests.update_content_data import update_content
from Tests.private_build.upload_packs_private import extract_packs_artifacts
from tempfile import mkdtemp

MARKET_PLACE_MACHINES = ('master',)
SKIPPED_PACKS = ['NonSupported', 'ApiModules']
NO_PROXY = ','.join([
    'oproxy.demisto.ninja',
    'oproxy-dev.demisto.ninja',
])
NO_PROXY_CONFIG = {'python.pass.extra.keys': f'--env##no_proxy={NO_PROXY}'}  # noqa: E501
DOCKER_HARDENING_CONFIGURATION = {
    'docker.cpu.limit': '1.0',
    'docker.run.internal.asuser': 'true',
    'limit.docker.cpu': 'true',
    'python.pass.extra.keys': f'--memory=1g##--memory-swap=-1##--pids-limit=256##--ulimit=nofile=1024:8192##--env##no_proxy={NO_PROXY}',  # noqa: E501
    'powershell.pass.extra.keys': f'--env##no_proxy={NO_PROXY}',
    'monitoring.pprof': 'true',
    'enable.pprof.memory.dump': 'true',
    'limit.memory.dump.size': '14000',
    'memdump.debug.level': '1',
}
DOCKER_HARDENING_CONFIGURATION_FOR_PODMAN = {
    'docker.run.internal.asuser': 'true'
}
MARKET_PLACE_CONFIGURATION = {
    'content.pack.verify': 'false',
    'marketplace.initial.sync.delay': '0',
    'content.pack.ignore.missing.warnings.contentpack': 'true'
}
AVOID_DOCKER_IMAGE_VALIDATION = {
    'content.validate.docker.images': 'false'
}
ID_SET_PATH = './artifacts/id_set.json'
XSOAR_BUILD_TYPE = "XSOAR"
CLOUD_BUILD_TYPE = "XSIAM"
MARKETPLACE_TEST_BUCKET = 'marketplace-ci-build/content/builds'
MARKETPLACE_XSIAM_BUCKETS = 'marketplace-v2-dist-dev/upload-flow/builds-xsiam'
ARTIFACTS_FOLDER_MPV2 = os.getenv('ARTIFACTS_FOLDER_MPV2', '/builds/xsoar/content/artifacts/marketplacev2')
ARTIFACTS_FOLDER = os.getenv('ARTIFACTS_FOLDER')
SET_SERVER_KEYS = True


class Running(IntEnum):
    CI_RUN = 0
    WITH_OTHER_SERVER = 1
    WITH_LOCAL_SERVER = 2


def get_custom_user_agent(build_number):
    return f"demisto-py/dev (Build:{build_number})"


class Server:

    def __init__(self):
        self.internal_ip = None
        self.user_name = None
        self.password = None
        self.name = ''
        self.build_number = 'unknown'


class CloudServer(Server):

    def __init__(self, api_key, server_numeric_version, base_url, xdr_auth_id, name, build_number=''):
        super().__init__()
        self.name = name
        self.api_key = api_key
        self.server_numeric_version = server_numeric_version
        self.base_url = base_url
        self.xdr_auth_id = xdr_auth_id
        self.build_number = build_number
        self.__client = None
        # we use client without demisto username
        os.environ.pop('DEMISTO_USERNAME', None)

    def __str__(self):
        return self.name

    @property
    def client(self):
        if self.__client is None:
            self.__client = self.reconnect_client()

        return self.__client

    def reconnect_client(self):
        self.__client = demisto_client.configure(base_url=self.base_url,
                                                 verify_ssl=False,
                                                 api_key=self.api_key,
                                                 auth_id=self.xdr_auth_id)
        custom_user_agent = get_custom_user_agent(self.build_number)
        logging.debug(f"Setting user-agent on client to '{custom_user_agent}'.")
        self.__client.api_client.user_agent = custom_user_agent
        return self.__client


class XSOARServer(Server):

    def __init__(self, internal_ip, user_name, password, build_number=''):
        super().__init__()
        self.__client = None
        self.internal_ip: str = internal_ip
        self.user_name = user_name
        self.password = password
        self.build_number = build_number

    def __str__(self):
        return self.internal_ip

    @property
    def client(self):
        if self.__client is None:
            self.__client = self.reconnect_client()

        return self.__client

    def reconnect_client(self):
        self.__client = demisto_client.configure(f'https://{self.internal_ip}',
                                                 verify_ssl=False,
                                                 username=self.user_name,
                                                 password=self.password)
        custom_user_agent = get_custom_user_agent(self.build_number)
        logging.debug(f"Setting user-agent on client to '{custom_user_agent}'.")
        self.__client.api_client.user_agent = custom_user_agent
        return self.__client

    def add_server_configuration(self, config_dict, error_msg, restart=False):
        update_server_configuration(self.client, config_dict, error_msg)

        if restart:
            self.exec_command('sudo systemctl restart demisto')

    def exec_command(self, command):
        subprocess.check_output(f'ssh {SSH_USER}@{self.internal_ip} {command}'.split(),
                                stderr=subprocess.STDOUT)


def get_id_set(id_set_path) -> dict | None:
    """
    Used to collect the ID set so it can be passed to the Build class on init.

    :return: ID set as a dict if it exists.
    """
    if os.path.isfile(id_set_path):
        return get_json_file(id_set_path)
    return None


class Build(ABC):
    # START CHANGE ON LOCAL RUN #
    content_path = f'{os.getenv("HOME")}/project' if os.getenv('CIRCLECI') else os.getenv('CI_PROJECT_DIR')
    test_pack_target = f'{os.getenv("HOME")}/project/Tests' if os.getenv(
        'CIRCLECI') else f'{os.getenv("CI_PROJECT_DIR")}/Tests'  # noqa
    key_file_path = 'Use in case of running with non local server'
    run_environment = Running.CI_RUN
    env_results_path = f'{ARTIFACTS_FOLDER}/env_results.json'
    DEFAULT_SERVER_VERSION = '99.99.98'

    #  END CHANGE ON LOCAL RUN  #

    def __init__(self, options):
        self._proxy = None
        self.is_cloud = False
        self.cloud_machine = None
        self.servers = []
        self.server_numeric_version = ''
        self.git_sha1 = options.git_sha1
        self.branch_name = options.branch
        self.ci_build_number = options.build_number
        self.is_nightly = options.is_nightly
        self.secret_conf = get_json_file(options.secret)
        self.username = options.user if options.user else self.secret_conf.get('username')
        self.password = options.password if options.password else self.secret_conf.get('userPassword')
        self.is_private = options.is_private
        conf = get_json_file(options.conf)
        self.tests = conf['tests']
        self.skipped_integrations_conf = conf['skipped_integrations']
        self.unmockable_integrations = conf['unmockable_integrations']
        id_set_path = options.id_set_path if options.id_set_path else ID_SET_PATH
        self.id_set = get_id_set(id_set_path)
        self.test_pack_path = options.test_pack_path if options.test_pack_path else None
        self.tests_to_run = self.fetch_tests_list(options.tests_to_run)
        self.content_root = options.content_root
        self.pack_ids_to_install = self.fetch_pack_ids_to_install(options.pack_ids_to_install)
        self.service_account = options.service_account
        self.marketplace_tag_name = None
        self.artifacts_folder = None
        self.marketplace_buckets = None

    @property
    @abstractmethod
    def marketplace_name(self) -> str:
        pass

    @staticmethod
    def fetch_tests_list(tests_to_run_path: str):
        """
        Fetches the test list from the filter. (Parses lines, all test written in the  filter.txt file)

        :param tests_to_run_path: Path to location of test filter.
        :return: List of tests if there are any, otherwise empty list.
        """
        tests_to_run = []
        with open(tests_to_run_path) as filter_file:
            tests_from_file = filter_file.readlines()
            for test_from_file in tests_from_file:
                test_clean = test_from_file.rstrip()
                tests_to_run.append(test_clean)
        return tests_to_run

    @staticmethod
    def fetch_pack_ids_to_install(packs_to_install_path: str):
        """
        Fetches the test list from the filter.

        :param packs_to_install_path: Path to location of pack IDs to install file.
        :return: List of Pack IDs if there are any, otherwise empty list.
        """
        tests_to_run = []
        with open(packs_to_install_path) as filter_file:
            tests_from_file = filter_file.readlines()
            for test_from_file in tests_from_file:
                test_clean = test_from_file.rstrip()
                tests_to_run.append(test_clean)
        return tests_to_run

    @abstractmethod
    def configure_servers_and_restart(self):
        pass

    @abstractmethod
    def install_nightly_pack(self):
        pass

    @abstractmethod
    def test_integrations_post_update(self, new_module_instances: list,
                                      modified_module_instances: list) -> tuple:
        pass

    @abstractmethod
    def configure_and_test_integrations_pre_update(self, new_integrations, modified_integrations) -> tuple:
        pass

    @abstractmethod
    def test_integration_with_mock(self, instance: dict, pre_update: bool):
        pass

    @staticmethod
    def set_marketplace_url(servers, branch_name, ci_build_number, marketplace_name=None, artifacts_folder=None,
                            marketplace_buckets=None) -> bool:
        raise NotImplementedError

    def check_if_new_to_marketplace(self, diff: str) -> bool:
        """
        Args:
            diff: the git diff for pack_metadata file, between master and branch
        Returns:
            (bool): whether new (current) marketplace was added to the pack_metadata or not
        """
        spaced_diff = " ".join(diff.split())
        return (f'+ "{self.marketplace_name}"' in spaced_diff) and f'- "{self.marketplace_name}"' not in spaced_diff

    def disable_instances(self):
        for server in self.servers:
            disable_all_integrations(server.client)

    def get_changed_integrations(self, packs_not_to_install: set[str] | None = None) -> tuple[list[str], list[str]]:
        """
        Return 2 lists - list of new integrations names and list of modified integrations names since the commit of the git_sha1.
        The modified list is exclude the packs_not_to_install and the new list is including it
        in order to ignore the turned non-hidden tests in the pre-update stage.
        Args:
            self: the build object.
            packs_not_to_install (Set[str]): The set of packs names which are turned to non-hidden.
        Returns:
            Tuple[List[str], List[str]]: The list of new integrations names and list of modified integrations names.
        """
        new_integrations_files, modified_integrations_files = get_new_and_modified_integration_files(
            self.branch_name) if not self.is_private else ([], [])
        new_integrations_names, modified_integrations_names = [], []

        if new_integrations_files:
            new_integrations_names = get_integration_names_from_files(new_integrations_files)
            logging.debug(f'New Integrations Since Last Release:\n{new_integrations_names}')

        if modified_integrations_files:
            modified_integrations_names = get_integration_names_from_files(modified_integrations_files)
            logging.debug(f'Updated Integrations Since Last Release:\n{modified_integrations_names}')
        return update_integration_lists(new_integrations_names, packs_not_to_install, modified_integrations_names)

    @abstractmethod
    def concurrently_run_function_on_servers(self, function=None, pack_path=None, service_account=None):
        pass

    def install_packs(self, pack_ids: list | None = None, multithreading=True, production_bucket: bool = True) -> bool:
        """
        Install packs using 'pack_ids' or "$ARTIFACTS_FOLDER/content_packs_to_install.txt" file, and their dependencies.
        Args:
            pack_ids (list | None, optional): Packs to install on the server.
                If no packs provided, installs packs that were provided by the previous step of the build.
            multithreading (bool): Whether to install packs in parallel or not.
            production_bucket (bool): Whether the installation is using production bucket for packs metadata. Defaults to True.

        Returns:
            bool: Whether packs installed successfully
        """
        pack_ids = self.pack_ids_to_install if pack_ids is None else pack_ids
        logging.info(f"IDs of packs to install: {pack_ids}")
        installed_content_packs_successfully = True
        for server in self.servers:
            try:
                hostname = self.cloud_machine if self.is_cloud else ''
                _, flag = search_and_install_packs_and_their_dependencies(pack_ids=pack_ids,
                                                                          client=server.client,
                                                                          hostname=hostname,
                                                                          multithreading=multithreading,
                                                                          production_bucket=production_bucket)
                if not flag:
                    raise Exception('Failed to search and install packs.')
            except Exception:
                logging.exception('Failed to search and install packs')
                installed_content_packs_successfully = False

        return installed_content_packs_successfully

    def get_tests(self) -> list[dict]:
        """
        Selects the tests from that should be run in this execution and filters those that cannot run in this server version
        Args:
            self: Build object

        Returns:
            Test configurations from conf.json that should be run in this execution
        """
        server_numeric_version: str = self.server_numeric_version
        tests: dict = self.tests
        tests_for_iteration: list[dict]
        if Build.run_environment == Running.CI_RUN:
            filtered_tests = BuildContext._extract_filtered_tests()
            if self.is_nightly:
                # skip test button testing
                logging.debug('Not running instance tests in nightly flow')
                tests_for_iteration = []
            else:
                # if not filtered_tests in cloud, we not running tests at all
                if self.is_cloud and not filtered_tests:
                    tests_for_iteration = []
                else:
                    tests_for_iteration = list(filter(lambda test: test.get('playbookID', '') in filtered_tests, tests))
            tests_for_iteration = filter_tests_with_incompatible_version(tests_for_iteration, server_numeric_version)
            return tests_for_iteration

        # START CHANGE ON LOCAL RUN #
        return [
            {
                "playbookID": "Docker Hardening Test",
                "fromversion": "5.0.0"
            },
            {
                "integrations": "SplunkPy",
                "playbookID": "SplunkPy-Test-V2",
                "memory_threshold": 500,
                "instance_names": "use_default_handler"
            }
        ]
        #  END CHANGE ON LOCAL RUN  #

    def configure_server_instances(self, tests_for_iteration, all_new_integrations, modified_integrations):
        modified_module_instances = []
        new_module_instances = []
        testing_client = self.servers[0].client
        for test in tests_for_iteration:
            integrations = get_integrations_for_test(test, self.skipped_integrations_conf)

            playbook_id = test.get('playbookID')

            new_integrations, modified_integrations, unchanged_integrations, integration_to_status = group_integrations(
                integrations, self.skipped_integrations_conf, all_new_integrations, modified_integrations
            )
            integration_to_status_string = '\n\t\t\t\t\t\t'.join(
                [f'"{key}" - {val}' for key, val in integration_to_status.items()])
            if integration_to_status_string:
                logging.info(f'All Integrations for test "{playbook_id}":\n\t\t\t\t\t\t{integration_to_status_string}')
            else:
                logging.info(f'No Integrations for test "{playbook_id}"')
            instance_names_conf = test.get('instance_names', [])
            if not isinstance(instance_names_conf, list):
                instance_names_conf = [instance_names_conf]

            integrations_to_configure = modified_integrations[:]
            integrations_to_configure.extend(unchanged_integrations)
            placeholders_map = {'%%SERVER_HOST%%': self.servers[0]}
            new_ints_params_set = set_integration_params(self,
                                                         new_integrations,
                                                         self.secret_conf['integrations'],
                                                         instance_names_conf,
                                                         placeholders_map)
            ints_to_configure_params_set = set_integration_params(self,
                                                                  integrations_to_configure,
                                                                  self.secret_conf['integrations'],
                                                                  instance_names_conf, placeholders_map)
            if not new_ints_params_set:
                logging.error(f'failed setting parameters for integrations: {new_integrations}')
            if not ints_to_configure_params_set:
                logging.error(f'failed setting parameters for integrations: {integrations_to_configure}')
            if not (new_ints_params_set and ints_to_configure_params_set):
                continue

            modified_module_instances_for_test, new_module_instances_for_test = self.configure_modified_and_new_integrations(
                integrations_to_configure,
                new_integrations,
                testing_client)

            modified_module_instances.extend(modified_module_instances_for_test)
            new_module_instances.extend(new_module_instances_for_test)
        return modified_module_instances, new_module_instances

    def configure_modified_and_new_integrations(self,
                                                modified_integrations_to_configure: list,
                                                new_integrations_to_configure: list,
                                                demisto_client_: demisto_client) -> tuple:
        """
        Configures old and new integrations in the server configured in the demisto_client.
        Args:
            self: The build object
            modified_integrations_to_configure: Integrations to configure that are already exists
            new_integrations_to_configure: Integrations to configure that were created in this build
            demisto_client_: A demisto client

        Returns:
            A tuple with two lists:
            1. List of configured instances of modified integrations
            2. List of configured instances of new integrations
        """
        modified_modules_instances = []
        new_modules_instances = []
        for integration in modified_integrations_to_configure:
            placeholders_map = {'%%SERVER_HOST%%': self.servers[0]}
            module_instance = configure_integration_instance(integration, demisto_client_, placeholders_map)
            if module_instance:
                modified_modules_instances.append(module_instance)
        for integration in new_integrations_to_configure:
            placeholders_map = {'%%SERVER_HOST%%': self.servers[0]}
            module_instance = configure_integration_instance(integration, demisto_client_, placeholders_map)
            if module_instance:
                new_modules_instances.append(module_instance)
        return modified_modules_instances, new_modules_instances

    def instance_testing(self,
                         all_module_instances: list,
                         pre_update: bool,
                         use_mock: bool = True,
                         first_call: bool = True) -> tuple[set, set]:
        """
        Runs 'test-module' command for the instances detailed in `all_module_instances`
        Args:
            self: An object containing the current build info.
            all_module_instances: The integration instances that should be tested
            pre_update: Whether this instance testing is before or after the content update on the server.
            use_mock: Whether to use mock while testing mockable integrations. Should be used mainly with
            private content build which aren't using the mocks.
            first_call: indicates if its the first time the function is called from the same place

        Returns:
            A set of the successful tests containing the instance name and the integration name
            A set of the failed tests containing the instance name and the integration name
        """
        update_status = 'Pre' if pre_update else 'Post'
        failed_tests = set()
        successful_tests = set()
        # Test all module instances (of modified + unchanged integrations) pre-updating content
        if all_module_instances:
            # only print start message if there are instances to configure
            logging.info(f'Start of Instance Testing ("Test" button) ({update_status}-update)')
        else:
            logging.info(f'No integrations to configure for the chosen tests. ({update_status}-update)')
        failed_instances = []
        for instance in all_module_instances:
            integration_of_instance = instance.get('brand', '')
            instance_name = instance.get('name', '')
            # If there is a failure, test_integration_instance will print it
            if integration_of_instance not in self.unmockable_integrations and use_mock:
                success = self.test_integration_with_mock(instance, pre_update)
            else:
                testing_client = self.servers[0].reconnect_client()
                success, _ = test_integration_instance(testing_client, instance)
            if not success:
                failed_tests.add((instance_name, integration_of_instance))
                failed_instances.append(instance)
            else:
                successful_tests.add((instance_name, integration_of_instance))

        # in case some tests failed post update, wait a 15 secs, runs the tests again
        if failed_instances and not pre_update and first_call:
            logging.info("some post-update tests failed, sleeping for 15 seconds, then running the failed tests again")
            sleep(15)
            _, failed_tests = self.instance_testing(failed_instances, pre_update=False, first_call=False)

        return successful_tests, failed_tests

    def update_content_on_servers(self) -> bool:
        """
        Changes marketplace bucket to new one that was created for current branch.
        Updates content on the build's server according to the server version.
        Args:
            self: Build object

        Returns:
            A boolean that indicates whether the content installation was successful.
            If the server version is lower then 5.9.9 will return the 'installed_content_packs_successfully' parameter as is
            If the server version is higher or equal to 6.0 - will return True if the packs installation was successful
            both before that update and after the update.
        """
        installed_content_packs_successfully = self.set_marketplace_url(self.servers, self.branch_name, self.ci_build_number,
                                                                        self.marketplace_tag_name, self.artifacts_folder,
                                                                        self.marketplace_buckets)
        installed_content_packs_successfully &= self.install_packs(production_bucket=False)
        return installed_content_packs_successfully

    def create_and_upload_test_pack(self, packs_to_install: list = None):
        """Creates and uploads a test pack that contains the test playbook of the specified packs to install list.

        Args:
            packs_to_install (list): The packs to install list from the artifacts.
        """
        packs_to_install = packs_to_install or []
        create_test_pack(packs_to_install)

        for server in self.servers:
            upload_zipped_packs(client=server.client,
                                host=server.name or server.internal_ip,
                                pack_path=f'{Build.test_pack_target}/test_pack.zip')


class XSOARBuild(Build):

    def __init__(self, options):
        super().__init__(options)
        self.ami_env = options.ami_env
        servers_list, self.server_numeric_version = self.get_servers(options.ami_env)
        self.servers = [XSOARServer(internal_ip,
                                    self.username,
                                    self.password,
                                    self.ci_build_number) for internal_ip in servers_list]

    @property
    def proxy(self) -> MITMProxy:
        """
        A property method that should create and return a single proxy instance through out the build
        Returns:
            The single proxy instance that should be used in this build.
        """
        if not self._proxy:
            self._proxy = MITMProxy(self.servers[0].internal_ip,
                                    logging_module=logging,
                                    build_number=self.ci_build_number,
                                    branch_name=self.branch_name)
        return self._proxy

    @property
    def marketplace_name(self) -> str:
        return 'xsoar'

    def configure_servers_and_restart(self):
        manual_restart = Build.run_environment == Running.WITH_LOCAL_SERVER
        for server in self.servers:
            configurations = {}
            if is_redhat_instance(server.internal_ip):
                configurations.update(DOCKER_HARDENING_CONFIGURATION_FOR_PODMAN)
                configurations.update(NO_PROXY_CONFIG)
                configurations['python.pass.extra.keys'] += "##--network=slirp4netns:cidr=192.168.0.0/16"
            else:
                configurations.update(DOCKER_HARDENING_CONFIGURATION)
            configure_types = ['docker hardening', 'marketplace']
            configurations.update(MARKET_PLACE_CONFIGURATION)

            error_msg = f"failed to set {' and '.join(configure_types)} configurations"
            server.add_server_configuration(configurations, error_msg=error_msg, restart=not manual_restart)

        if manual_restart:
            input('restart your server and then press enter.')
        else:
            logging.info('Done restarting servers. Sleeping for 1 minute')
            sleep(60)

    def install_nightly_pack(self):
        """
        Installs all existing packs in master
        Collects all existing test playbooks, saves them to test_pack.zip
        Uploads test_pack.zip to server
        Args:
            self: A build object
        """
        # Install all existing packs with latest version
        self.concurrently_run_function_on_servers(function=install_all_content_packs_for_nightly,
                                                  service_account=self.service_account)
        # creates zip file test_pack.zip witch contains all existing TestPlaybooks
        create_test_pack()
        # uploads test_pack.zip to all servers
        self.concurrently_run_function_on_servers(function=upload_zipped_packs,
                                                  pack_path=f'{Build.test_pack_target}/test_pack.zip')

        logging.info('Sleeping for 45 seconds while installing nightly packs')
        sleep(45)

    @run_with_proxy_configured
    def test_integrations_post_update(self, new_module_instances: list,
                                      modified_module_instances: list) -> tuple:
        """
        Runs 'test-module on all integrations for post-update check
        Args:
            self: A build object
            new_module_instances: A list containing new integrations instances to run test-module on
            modified_module_instances: A list containing old (existing) integrations instances to run test-module on

        Returns:
            * A list of integration names that have failed the 'test-module' execution post update
            * A list of integration names that have succeeded the 'test-module' execution post update
        """
        modified_module_instances.extend(new_module_instances)
        successful_tests_post, failed_tests_post = self.instance_testing(modified_module_instances, pre_update=False)
        return successful_tests_post, failed_tests_post

    @run_with_proxy_configured
    def configure_and_test_integrations_pre_update(self, new_integrations, modified_integrations) -> tuple:
        """
        Configures integration instances that exist in the current version and for each integration runs 'test-module'.
        Args:
            self: Build object
            new_integrations: A list containing new integrations names
            modified_integrations: A list containing modified integrations names

        Returns:
            A tuple consists of:
            * A list of modified module instances configured
            * A list of new module instances configured
            * A list of integrations that have failed the 'test-module' command execution
            * A list of integrations that have succeeded the 'test-module' command execution
            * A list of new integrations names
        """
        tests_for_iteration = self.get_tests()
        modified_module_instances, new_module_instances = self.configure_server_instances(
            tests_for_iteration,
            new_integrations,
            modified_integrations)
        successful_tests_pre, failed_tests_pre = self.instance_testing(modified_module_instances, pre_update=True)
        return modified_module_instances, new_module_instances, failed_tests_pre, successful_tests_pre

    def test_integration_with_mock(self, instance: dict, pre_update: bool):
        """
        Runs 'test-module' for given integration with mitmproxy
        In case the playback mode fails and this is a pre-update run - a record attempt will be executed.
        Args:
            instance: A dict containing the instance details
            pre_update: Whether this instance testing is before or after the content update on the server.

        Returns:
            The result of running the 'test-module' command for the given integration.
            If a record was executed - will return the result of the 'test--module' with the record mode only.
        """
        testing_client = self.servers[0].reconnect_client()
        integration_of_instance = instance.get('brand', '')
        logging.debug(f'Integration "{integration_of_instance}" is mockable, running test-module with mitmproxy')
        has_mock_file = self.proxy.has_mock_file(integration_of_instance)
        success = False
        if has_mock_file:
            with run_with_mock(self.proxy, integration_of_instance) as result_holder:
                success, _ = test_integration_instance(testing_client, instance)
                result_holder[RESULT] = success
                if not success:
                    logging.warning(f'Running test-module for "{integration_of_instance}" has failed in playback mode')
        if not success and not pre_update:
            logging.debug(f'Recording a mock file for integration "{integration_of_instance}".')
            with run_with_mock(self.proxy, integration_of_instance, record=True) as result_holder:
                success, _ = test_integration_instance(testing_client, instance)
                result_holder[RESULT] = success
                if not success:
                    logging.debug(f'Record mode for integration "{integration_of_instance}" has failed.')
        return success

    @staticmethod
    def set_marketplace_url(servers, branch_name, ci_build_number, marketplace_name=None, artifacts_folder=None,
                            marketplace_buckets=None):
        url_suffix = f'{quote_plus(branch_name)}/{ci_build_number}/xsoar'
        config_path = 'marketplace.bootstrap.bypass.url'
        config = {config_path: f'https://storage.googleapis.com/marketplace-ci-build/content/builds/{url_suffix}'}
        for server in servers:
            server.add_server_configuration(config, 'failed to configure marketplace custom url ', True)
        logging.success('Updated marketplace url and restarted servers')
        logging.info('sleeping for 120 seconds')
        sleep(120)
        return True

    @staticmethod
    def get_servers(ami_env):
        env_conf = get_env_conf()
        servers = get_servers(env_conf, ami_env)
        if Build.run_environment == Running.CI_RUN:
            server_numeric_version = get_server_numeric_version(ami_env)
        else:
            server_numeric_version = Build.DEFAULT_SERVER_VERSION
        return servers, server_numeric_version

    def concurrently_run_function_on_servers(self, function=None, pack_path=None, service_account=None):
        threads_list = []

        if not function:
            raise Exception('Install method was not provided.')

        # For each server url we install pack/ packs
        for server in self.servers:
            kwargs = {'client': server.client, 'host': server.internal_ip}
            if service_account:
                kwargs['service_account'] = service_account
            if pack_path:
                kwargs['pack_path'] = pack_path
            threads_list.append(Thread(target=function, kwargs=kwargs))
        run_threads_list(threads_list)


class CloudBuild(Build):

    def __init__(self, options):
        global SET_SERVER_KEYS
        SET_SERVER_KEYS = False
        super().__init__(options)
        self.is_cloud = True
        self.cloud_machine = options.cloud_machine
        self.api_key, self.server_numeric_version, self.base_url, self.xdr_auth_id =\
            self.get_cloud_configuration(options.cloud_machine, options.cloud_servers_path,
                                         options.cloud_servers_api_keys)
        self.servers = [CloudServer(self.api_key, self.server_numeric_version, self.base_url, self.xdr_auth_id,
                                    self.cloud_machine, self.ci_build_number)]
        self.marketplace_tag_name: str = options.marketplace_name
        self.artifacts_folder = options.artifacts_folder
        self.marketplace_buckets = options.marketplace_buckets

    @staticmethod
    def get_cloud_configuration(cloud_machine, cloud_servers_path, cloud_servers_api_keys_path):
        logging.info('getting cloud configuration')

        cloud_servers = get_json_file(cloud_servers_path)
        conf = cloud_servers.get(cloud_machine)
        cloud_servers_api_keys = get_json_file(cloud_servers_api_keys_path)
        api_key = cloud_servers_api_keys.get(cloud_machine)
        return api_key, conf.get('demisto_version'), conf.get('base_url'), conf.get('x-xdr-auth-id')

    @property
    def marketplace_name(self) -> str:
        return self.marketplace_tag_name

    def configure_servers_and_restart(self):
        # No need of this step in cloud.
        pass

    def test_integration_with_mock(self, instance: dict, pre_update: bool):
        # No need of this step in CLOUD.
        pass

    def install_nightly_pack(self):
        """
        Installs packs from content_packs_to_install.txt file
        Collects all existing test playbooks, saves them to test_pack.zip
        Uploads test_pack.zip to server
        """
        success = self.install_packs(multithreading=False, production_bucket=True)
        if not success:
            logging.error('Failed to install content packs, aborting.')
            sys.exit(1)
        # creates zip file test_pack.zip witch contains all existing TestPlaybooks
        create_test_pack()
        # uploads test_pack.zip to all servers (we have only one cloud server)
        for server in self.servers:
            upload_zipped_packs(client=server.client,
                                host=server.name,
                                pack_path=f'{Build.test_pack_target}/test_pack.zip')

        logging.info('Sleeping for 45 seconds while installing nightly packs')
        sleep(45)

    def test_integrations_post_update(self, new_module_instances: list,
                                      modified_module_instances: list) -> tuple:
        """
        Runs 'test-module on all integrations for post-update check
        Args:
            self: A build object
            new_module_instances: A list containing new integrations instances to run test-module on
            modified_module_instances: A list containing old (existing) integrations instances to run test-module on

        Returns:
            * A list of integration names that have failed the 'test-module' execution post update
            * A list of integration names that have succeeded the 'test-module' execution post update
        """
        modified_module_instances.extend(new_module_instances)
        successful_tests_post, failed_tests_post = self.instance_testing(modified_module_instances, pre_update=False,
                                                                         use_mock=False)
        return successful_tests_post, failed_tests_post

    def configure_and_test_integrations_pre_update(self, new_integrations, modified_integrations) -> tuple:
        """
        Configures integration instances that exist in the current version and for each integration runs 'test-module'.
        Args:
            self: Build object
            new_integrations: A list containing new integrations names
            modified_integrations: A list containing modified integrations names

        Returns:
            A tuple consists of:
            * A list of modified module instances configured
            * A list of new module instances configured
            * A list of integrations that have failed the 'test-module' command execution
            * A list of integrations that have succeeded the 'test-module' command execution
            * A list of new integrations names
        """
        tests_for_iteration = self.get_tests()
        modified_module_instances, new_module_instances = self.configure_server_instances(
            tests_for_iteration,
            new_integrations,
            modified_integrations)
        successful_tests_pre, failed_tests_pre = self.instance_testing(modified_module_instances,
                                                                       pre_update=True,
                                                                       use_mock=False)
        return modified_module_instances, new_module_instances, failed_tests_pre, successful_tests_pre

    @staticmethod
    def set_marketplace_url(servers, branch_name, ci_build_number, marketplace_name='marketplacev2',
                            artifacts_folder=ARTIFACTS_FOLDER_MPV2,
                            marketplace_buckets=MARKETPLACE_XSIAM_BUCKETS):
        from Tests.Marketplace.search_and_uninstall_pack import sync_marketplace
        logging.info('Copying custom build bucket to cloud_instance_bucket.')
        marketplace_name = marketplace_name
        from_bucket = f'{MARKETPLACE_TEST_BUCKET}/{branch_name}/{ci_build_number}/{marketplace_name}/content'
        output_file = f'{artifacts_folder}/Copy_custom_bucket_to_cloud_machine.log'
        success = True
        for server in servers:
            to_bucket = f'{marketplace_buckets}/{server.name}'
            cmd = f'gsutil -m cp -r gs://{from_bucket} gs://{to_bucket}/'
            with open(output_file, "w") as outfile:
                try:
                    subprocess.run(cmd.split(), stdout=outfile, stderr=outfile, check=True)
                    logging.info('Finished copying successfully.')
                except subprocess.CalledProcessError as exc:
                    logging.exception(f'Failed to copy custom build bucket to cloud_instance_bucket. {exc}')
                    success = False

            success &= sync_marketplace(server.client)

        if success:
            logging.info('Finished copying successfully.')
        else:
            logging.error('Failed to copy or sync marketplace bucket.')
        sleep_time = 120
        logging.info(f'sleeping for {sleep_time} seconds')
        sleep(sleep_time)
        return success

    def concurrently_run_function_on_servers(self, function=None, pack_path=None, service_account=None):
        # no need to run this concurrently since we have only one server
        pass


def options_handler(args=None):
    parser = argparse.ArgumentParser(description='Utility for instantiating and testing integration instances')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('--ami_env', help='The AMI environment for the current run. Options are '
                                          '"Server Master", "Server 6.0". '
                                          'The server url is determined by the AMI environment.')
    parser.add_argument('-g', '--git_sha1', help='commit sha1 to compare changes with')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-s', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--is-nightly', type=str2bool, help='Is nightly build')
    parser.add_argument('-pr', '--is_private', type=str2bool, help='Is private build')
    parser.add_argument('--branch', help='GitHub branch name', required=True)
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--test_pack_path', help='Path to where the test pack will be saved.',
                        default='/home/runner/work/content-private/content-private/content/artifacts/packs')
    parser.add_argument('--content_root', help='Path to the content root.',
                        default='/home/runner/work/content-private/content-private/content')
    parser.add_argument('--id_set_path', help='Path to the ID set.')
    parser.add_argument('-l', '--tests_to_run', help='Path to the Test Filter.',
                        default='./artifacts/filter_file.txt')
    parser.add_argument('-pl', '--pack_ids_to_install', help='Path to the packs to install file.',
                        default='./artifacts/content_packs_to_install.txt')
    parser.add_argument('--build_object_type', help='Build type running: XSOAR or XSIAM')
    parser.add_argument('--cloud_machine', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--cloud_servers_path', help='Path to secret cloud server metadata file.')
    parser.add_argument('--cloud_servers_api_keys', help='Path to file with cloud Servers api keys.')
    parser.add_argument('--marketplace_name', help='the name of the marketplace to use.')
    parser.add_argument('--artifacts_folder', help='the artifacts folder to use.')
    parser.add_argument('--marketplace_buckets', help='the path to the marketplace buckets.')
    # disable-secrets-detection-start
    parser.add_argument('-sa', '--service_account',
                        help=("Path to gcloud service account, is for circleCI usage. "
                              "For local development use your personal account and "
                              "authenticate using Google Cloud SDK by running: "
                              "`gcloud auth application-default login` and leave this parameter blank. "
                              "For more information go to: "
                              "https://googleapis.dev/python/google-api-core/latest/auth.html"),
                        required=False)
    # disable-secrets-detection-end
    options = parser.parse_args(args)

    return options


def check_test_version_compatible_with_server(test, server_version):
    """
    Checks if a given test is compatible wis the given server version.
    Arguments:
        test: (dict)
            Test playbook object from content conf.json. May contain the following fields: "playbookID",
            "integrations", "instance_names", "timeout", "nightly", "fromversion", "toversion.
        server_version: (int)
            The server numerical version.
    Returns:
        (bool) True if test is compatible with server version or False otherwise.
    """
    test_from_version = format_version(test.get('fromversion', '0.0.0'))
    test_to_version = format_version(test.get('toversion', '99.99.99'))
    server_version = format_version(server_version)

    if not Version(test_from_version) <= Version(server_version) <= Version(test_to_version):
        playbook_id = test.get('playbookID')
        logging.debug(
            f'Test Playbook: {playbook_id} was ignored in the content installation test due to version mismatch '
            f'(test versions: {test_from_version}-{test_to_version}, server version: {server_version})')
        return False
    return True


def filter_tests_with_incompatible_version(tests, server_version):
    """
    Filter all tests with incompatible version to the given server.
    Arguments:
        tests: (list)
            List of test objects.
        server_version: (int)
            The server numerical version.
    Returns:
        (lst): List of filtered tests (compatible version)
    """

    filtered_tests = [test for test in tests if
                      check_test_version_compatible_with_server(test, server_version)]
    return filtered_tests


def configure_integration_instance(integration, client, placeholders_map):
    """
    Configure an instance for an integration

    Arguments:
        integration: (dict)
            Integration object whose params key-values are set
        client: (demisto_client)
            The client to connect to
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.

    Returns:
        (dict): Configured integration instance
    """
    integration_name = integration.get('name')
    logging.info(f'Configuring instance for integration "{integration_name}"')
    integration_instance_name = integration.get('instance_name', '')
    integration_params = change_placeholders_to_values(placeholders_map, integration.get('params'))
    is_byoi = integration.get('byoi', True)
    validate_test = integration.get('validate_test', True)

    integration_configuration = __get_integration_config(client, integration_name)
    if not integration_configuration:
        return None

    # In the integration configuration in content-test-conf conf.json, the test_validate flag was set to false
    if not validate_test:
        logging.debug(f'Skipping configuration for integration: {integration_name} (it has test_validate set to false)')
        return None
    module_instance = set_integration_instance_parameters(integration_configuration, integration_params,
                                                          integration_instance_name, is_byoi, client)
    return module_instance


def filepath_to_integration_name(integration_file_path):
    """Load an integration file and return the integration name.

    Args:
        integration_file_path (str): The path to an integration yml file.

    Returns:
        (str): The name of the integration.
    """
    integration_yaml = get_yaml(integration_file_path)
    integration_name = integration_yaml.get('name')
    return integration_name


def get_integration_names_from_files(integration_files_list):
    integration_names_list = [filepath_to_integration_name(path) for path in integration_files_list]
    return [name for name in integration_names_list if name]  # remove empty values


def get_new_and_modified_integration_files(branch_name):
    """Return 2 lists - list of new integrations and list of modified integrations since the first commit of the branch.

    Args:
        branch_name: The branch name against which we will run the 'git diff' command.

    Returns:
        (tuple): Returns a tuple of two lists, the file paths of the new integrations and modified integrations.
    """
    # get changed yaml files (filter only added and modified files)
    file_validator = ValidateManager(skip_dependencies=True)
    file_validator.branch_name = branch_name
    modified_files, added_files, _, _, _ = file_validator.get_changed_files_from_git()

    new_integration_files = [
        file_path for file_path in added_files if
        find_type(file_path) in [FileType.INTEGRATION, FileType.BETA_INTEGRATION]
    ]

    modified_integration_files = [
        file_path for file_path in modified_files if
        isinstance(file_path, str) and find_type(file_path) in [FileType.INTEGRATION, FileType.BETA_INTEGRATION]
    ]
    return new_integration_files, modified_integration_files


def is_content_update_in_progress(client):
    """Make request to check if content is updating.

    Args:
        client (demisto_client): The configured client to use.

    Returns:
        (str): Returns the request response data which is 'true' if updating and 'false' if not.
    """
    host = client.api_client.configuration.host
    logging.debug(f'Making "Get" request to server - "{host}" to check if content is installing.')

    # make request to check if content is updating
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path='/content/updating',
                                                                        method='GET', accept='application/json')

    if status_code >= 300 or status_code < 200:
        result_object = ast.literal_eval(response_data)
        message = result_object.get('message', '')
        logging.error(f"Failed to check if content is installing - with status code {status_code}\n{message}")
        return 'request unsuccessful'

    return response_data


def get_content_version_details(client, ami_name):
    """Make request for details about the content installed on the demisto instance.

    Args:
        client (demisto_client): The configured client to use.
        ami_name (string): the role name of the machine

    Returns:
        (tuple): The release version and asset ID of the content installed on the demisto instance.
    """
    host = client.api_client.configuration.host
    logging.info(f'Making "POST" request to server - "{host}" to check installed content.')

    # make request to installed content details
    uri = '/content/installedlegacy' if ami_name in MARKET_PLACE_MACHINES else '/content/installed'
    response_data, status_code, _ = demisto_client.generic_request_func(self=client, path=uri,
                                                                        method='POST')

    try:
        result_object = ast.literal_eval(response_data)
        logging.debug(f'Response was {response_data}')
    except ValueError:
        logging.exception('failed to parse response from demisto.')
        return '', 0

    if status_code >= 300 or status_code < 200:
        message = result_object.get('message', '')
        logging.error(f'Failed to check if installed content details - with status code {status_code}\n{message}')
    return result_object.get('release', ''), result_object.get('assetId', 0)


def change_placeholders_to_values(placeholders_map, config_item):
    """Replaces placeholders in the object to their real values

    Args:
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.
        config_item: (json object)
            Integration configuration object.

    Returns:
        dict. json object with the real configuration.
    """
    item_as_string = json.dumps(config_item)
    for key, value in placeholders_map.items():
        item_as_string = item_as_string.replace(key, str(value))
    return json.loads(item_as_string)


def set_integration_params(build,
                           integrations,
                           secret_params,
                           instance_names,
                           placeholders_map,
                           logging_module=logging):
    """
    For each integration object, fill in the parameter values needed to configure an instance from
    the secret_params taken from our secret configuration file. Because there may be a number of
    configurations for a single integration (if there are values provided in our secret conf for
    multiple different instances of the same integration) then selects the parameter values for the
    configuration of the instance whose instance is in 'instance_names' (will take the last one listed
    in 'secret_params'). Note that this function does not explicitly return the modified 'integrations'
    object but rather it modifies the 'integrations' object since it is passed by reference and not by
    value, so the 'integrations' object that was passed to this function will have been changed once
    this function has completed execution and gone out of scope.

    Arguments:
        build: Build object
        integrations: (list of dicts)
            List of integration objects whose 'params' attribute will be populated in this function.
        secret_params: (list of dicts)
            List of secret configuration values for all of our integrations (as well as specific
            instances of said integrations).
        instance_names: (list)
            The names of particular instances of an integration to use the secret_params of as the
            configuration values.
        placeholders_map: (dict)
             Dict that holds the real values to be replaced for each placeholder.
        logging_module (Union[ParallelLoggingManager,logging]): The logging module to use

    Returns:
        (bool): True if integrations params were filled with secret configuration values, otherwise false
    """
    for integration in integrations:
        integration_params = [change_placeholders_to_values(placeholders_map, item) for item
                              in secret_params if item['name'] == integration['name']]
        if integration['name'] == "Core REST API" and build.is_cloud:
            integration_params[0]['params'] = {  # type: ignore
                "url": build.base_url,
                "creds_apikey": {
                    "identifier": str(build.xdr_auth_id),
                    "password": build.api_key,
                },
                "auth_method": "Standard",
                "insecure": True,
                "proxy": False,
            }

        if integration_params:
            matched_integration_params = integration_params[0]
            # if there are more than one integration params, it means that there are configuration
            # values in our secret conf for multiple instances of the given integration and now we
            # need to match the configuration values to the proper instance as specified in the
            # 'instance_names' list argument
            if len(integration_params) != 1:
                found_matching_instance = False
                for item in integration_params:
                    if item.get('instance_name', 'Not Found') in instance_names:
                        matched_integration_params = item
                        found_matching_instance = True

                if not found_matching_instance:
                    optional_instance_names = [optional_integration.get('instance_name', 'None')
                                               for optional_integration in integration_params]
                    failed_match_instance_msg = 'There are {} instances of {}, please select one of them by using' \
                                                ' the instance_name argument in conf.json. The options are:\n{}'
                    logging_module.error(failed_match_instance_msg.format(len(integration_params),
                                                                          integration['name'],
                                                                          '\n'.join(optional_instance_names)))
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
            integration['instance_name'] = matched_integration_params.get('instance_name', integration['name'])
            integration['validate_test'] = matched_integration_params.get('validate_test', True)
            if integration['name'] not in build.unmockable_integrations:
                integration['params'].update({'proxy': True})
                logging.debug(
                    f'Configuring integration "{integration["name"]}" with proxy=True')
            else:
                integration['params'].update({'proxy': False})
                logging.debug(
                    f'Configuring integration "{integration["name"]}" with proxy=False')

    return True


def set_module_params(param_conf, integration_params):
    """Configure a parameter object for use in a module instance.

    Each integration parameter is actually an object with many fields that together describe it. E.g. a given
    parameter will have all of the following fields - "name", "display", "value", "hasvalue", "defaultValue",
    etc. This function fills the "value" field for a parameter configuration object and returns it for use in
    a module instance.

    Args:
        param_conf (dict): The parameter configuration object.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.

    Returns:
        (dict): The configured parameter object
    """
    if param_conf['display'] in integration_params or param_conf['name'] in integration_params:
        # param defined in conf
        key = param_conf['display'] if param_conf['display'] in integration_params else param_conf['name']
        if key == 'credentials' or key == "creds_apikey":
            credentials = integration_params[key]
            param_value = {
                'credential': '',
                'identifier': credentials.get('identifier', ''),
                'password': credentials['password'],
                'passwordChanged': False
            }
        else:
            param_value = integration_params[key]

        param_conf['value'] = param_value
        param_conf['hasvalue'] = True
    elif param_conf['defaultValue']:
        # if the parameter doesn't have a value provided in the integration's configuration values
        # but does have a default value then assign it to the parameter for the module instance
        param_conf['value'] = param_conf['defaultValue']
    return param_conf


def __set_server_keys(client, integration_params, integration_name):
    """Adds server configuration keys using the demisto_client.

    Args:
        client (demisto_client): The configured client to use.
        integration_params (dict): The values to use for an integration's parameters to configure an instance.
        integration_name (str): The name of the integration which the server configurations keys are related to.

    """
    if 'server_keys' not in integration_params or not SET_SERVER_KEYS:
        return

    logging.info(f'Setting server keys for integration: {integration_name}')

    data: dict = {
        'data': {},
        'version': -1
    }

    for key, value in integration_params.get('server_keys').items():
        data['data'][key] = value

    update_server_configuration(
        client=client,
        server_configuration=data,
        error_msg='Failed to set server keys'
    )


def set_integration_instance_parameters(integration_configuration,
                                        integration_params,
                                        integration_instance_name,
                                        is_byoi,
                                        client):
    """Set integration module values for integration instance creation

    The integration_configuration and integration_params should match, in that
    they are for the same integration

    Arguments:
        integration_configuration: (dict)
            dictionary of the integration configuration parameters/keys that need
            filling to instantiate an instance of a given integration
        integration_params: (dict)
            values for a given integration taken from the configuration file in
            which the secret values are stored to configure instances of various
            integrations
        integration_instance_name: (str)
            The name of the integration instance being configured if there is one
            provided in the conf.json
        is_byoi: (bool)
            If the integration is byoi or not
        client: (demisto_client)
            The client to connect to

    Returns:
        (dict): The configured module instance to send to the Demisto server for
        instantiation.
    """
    module_configuration = integration_configuration.get('configuration', {})
    if not module_configuration:
        module_configuration = []

    if 'integrationInstanceName' in integration_params:
        instance_name = integration_params['integrationInstanceName']
    else:
        instance_name = '{}_test_{}'.format(integration_instance_name.replace(' ', '_'), str(uuid.uuid4()))

    # define module instance
    module_instance = {
        'brand': integration_configuration['name'],
        'category': integration_configuration['category'],
        'configuration': integration_configuration,
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
    __set_server_keys(client, integration_params, integration_configuration['name'])

    # set module params
    for param_conf in module_configuration:
        configured_param = set_module_params(param_conf, integration_params)
        module_instance['data'].append(configured_param)

    return module_instance


def group_integrations(integrations, skipped_integrations_conf, new_integrations_names, modified_integrations_names):
    """
    Filter integrations into their respective lists - new, modified or unchanged. if it's on the skip list, then
    skip if random tests were chosen then we may be configuring integrations that are neither new or modified.

    Args:
        integrations (list): The integrations to categorize.
        skipped_integrations_conf (dict): Integrations that are on the skip list.
        new_integrations_names (list): The names of new integrations.
        modified_integrations_names (list): The names of modified integrations.

    Returns:
        (tuple): Lists of integrations objects as well as an Integration-to-Status dictionary useful for logs.
    """
    new_integrations = []
    modified_integrations = []
    unchanged_integrations = []
    integration_to_status = {}
    for integration in integrations:
        integration_name = integration.get('name', '')
        if integration_name in skipped_integrations_conf:
            continue

        if integration_name in new_integrations_names:
            new_integrations.append(integration)
        elif integration_name in modified_integrations_names:
            modified_integrations.append(integration)
            integration_to_status[integration_name] = 'Modified Integration'
        else:
            unchanged_integrations.append(integration)
            integration_to_status[integration_name] = 'Unchanged Integration'
    return new_integrations, modified_integrations, unchanged_integrations, integration_to_status


def get_integrations_for_test(test, skipped_integrations_conf):
    """Return a list of integration objects that are necessary for a test (excluding integrations on the skip list).

    Args:
        test (dict): Test dictionary from the conf.json file containing the playbookID, integrations and
            instance names.
        skipped_integrations_conf (dict): Skipped integrations dictionary with integration names as keys and
            the skip reason as values.

    Returns:
        (list): List of integration objects to configure.
    """
    integrations_conf = test.get('integrations', [])

    if not isinstance(integrations_conf, list):
        integrations_conf = [integrations_conf]

    integrations = [
        {'name': integration, 'params': {}} for
        integration in integrations_conf if integration not in skipped_integrations_conf
    ]
    return integrations


def update_content_on_demisto_instance(client, server, ami_name):
    """Try to update the content

    Args:
        client (demisto_client): The configured client to use.
        server (str): The server url to pass to Tests/update_content_data.py
    """
    content_zip_path = 'artifacts/all_content.zip'
    update_content(content_zip_path, server=server, client=client)

    # Check if content update has finished installing
    sleep_interval = 20
    updating_content = is_content_update_in_progress(client)
    while updating_content.lower() == 'true':
        sleep(sleep_interval)
        updating_content = is_content_update_in_progress(client)

    if updating_content.lower() == 'request unsuccessful':
        # since the request to check if content update installation finished didn't work, can't use that mechanism
        # to check and just try sleeping for 30 seconds instead to allow for content update installation to complete
        logging.debug('Request to install content was unsuccessful, sleeping for 30 seconds and retrying')
        sleep(30)
    else:
        # check that the content installation updated
        # verify the asset id matches the circleci build number / asset_id in the content-descriptor.json
        release, asset_id = get_content_version_details(client, ami_name)
        logging.info(f'Content Release Version: {release}')
        with open('./artifacts/content-descriptor.json') as cd_file:
            cd_json = json.loads(cd_file.read())
            cd_release = cd_json.get('release')
            cd_asset_id = cd_json.get('assetId')
        if release == cd_release and asset_id == cd_asset_id:
            logging.success(f'Content Update Successfully Installed on server {server}.')
        else:
            logging.error(
                f'Content Update to version: {release} was Unsuccessful:\nAttempted to install content with release '
                f'"{cd_release}" and assetId "{cd_asset_id}" but release "{release}" and assetId "{asset_id}" '
                f'were retrieved from the instance post installation.')
            if ami_name not in MARKET_PLACE_MACHINES:
                sys.exit(1)


def report_tests_status(preupdate_fails, postupdate_fails, preupdate_success, postupdate_success,
                        new_integrations_names, build=None):
    """Prints errors and/or warnings if there are any and returns whether whether testing was successful or not.

    Args:
        preupdate_fails (set): List of tuples of integrations that failed the "Test" button prior to content
            being updated on the demisto instance where each tuple is comprised of the integration name and the
            name of the instance that was configured for that integration which failed.
        postupdate_fails (set): List of tuples of integrations that failed the "Test" button after content was
            updated on the demisto instance where each tuple is comprised of the integration name and the name
            of the instance that was configured for that integration which failed.
        preupdate_success (set): List of tuples of integrations that succeeded the "Test" button prior to content
            being updated on the demisto instance where each tuple is comprised of the integration name and the
            name of the instance that was configured for that integration which failed.
        postupdate_success (set): List of tuples of integrations that succeeded the "Test" button after content was
            updated on the demisto instance where each tuple is comprised of the integration name and the name
            of the instance that was configured for that integration which failed.
        new_integrations_names (list): List of the names of integrations that are new since the last official
            content release and that will only be present on the demisto instance after the content update is
            performed.
        build: Build object

    Returns:
        (bool): False if there were integration instances that succeeded prior to the content update and then
            failed after content was updated, otherwise True.
    """
    testing_status = True

    # a "Test" can be either successful both before and after content update(succeeded_pre_and_post variable),
    # fail on one of them(mismatched_statuses variable), or on both(failed_pre_and_post variable)
    succeeded_pre_and_post = preupdate_success.intersection(postupdate_success)
    if succeeded_pre_and_post:
        succeeded_pre_and_post_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"' for
             instance_name, integration_of_instance in succeeded_pre_and_post])
        logging.success(
            'Integration instances that had ("Test" Button) succeeded both before and after the content update:\n'
            f'{succeeded_pre_and_post_string}')

    failed_pre_and_post = preupdate_fails.intersection(postupdate_fails)
    mismatched_statuses = postupdate_fails - preupdate_fails
    failed_only_after_update = []
    failed_but_is_new = []
    for instance_name, integration_of_instance in mismatched_statuses:
        if integration_of_instance in new_integrations_names:
            failed_but_is_new.append((instance_name, integration_of_instance))
        else:
            failed_only_after_update.append((instance_name, integration_of_instance))

    # warnings but won't fail the build step
    if failed_but_is_new:
        failed_but_is_new_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"'
             for instance_name, integration_of_instance in failed_but_is_new])
        logging.warning(f'New Integrations ("Test" Button) Failures:\n{failed_but_is_new_string}')
    if failed_pre_and_post:
        failed_pre_and_post_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"'
             for instance_name, integration_of_instance in failed_pre_and_post])
        logging.warning(f'Integration instances that had ("Test" Button) failures '
                        f'both before and after the content update'
                        f'(No need to handle ERROR messages for these "test-module" failures):'
                        f'\n{pformat(failed_pre_and_post_string)}.')
    # fail the step if there are instances that only failed after content was updated
    if failed_only_after_update:
        failed_only_after_update_string = "\n".join(
            [f'Integration: "{integration_of_instance}", Instance: "{instance_name}"' for
             instance_name, integration_of_instance in failed_only_after_update])
        testing_status = False
        logging.critical('Integration instances that had ("Test" Button) failures only after content was updated:\n'
                         f'{pformat(failed_only_after_update_string)}.\n'
                         f'This indicates that your updates introduced breaking changes to the integration.')
    else:
        # creating this file to indicates that this instance passed post update tests,
        # uses this file in XSOAR destroy instances
        if build and build.__class__ == XSOARBuild:
            with open(f"{ARTIFACTS_FOLDER}/is_post_update_passed_{build.ami_env.replace(' ', '')}.txt", 'a'):
                pass

    return testing_status


def get_env_conf():
    if Build.run_environment == Running.CI_RUN:
        return get_json_file(Build.env_results_path)

    if Build.run_environment == Running.WITH_LOCAL_SERVER:
        # START CHANGE ON LOCAL RUN #
        return [{
            "InstanceDNS": "http://localhost:8080",
            "Role": "Server Master"  # e.g. 'Server Master'
        }]
    if Build.run_environment == Running.WITH_OTHER_SERVER:
        return [{
            "InstanceDNS": "DNS NANE",  # without http prefix
            "Role": "DEMISTO EVN"  # e.g. 'Server Master'
        }]

    #  END CHANGE ON LOCAL RUN  #
    return None


def get_servers(env_results, instance_role):
    """
    Arguments:
        env_results: (dict)
            env_results.json in server
        instance_role: (str)
            The amazon machine image environment whose IP we should connect to.

    Returns:
        (lst): The server url list to connect to
    """

    return [env.get('InstanceDNS') for env in env_results if instance_role in env.get('Role')]


def get_json_file(path):
    with open(path) as json_file:
        return json.loads(json_file.read())


def create_test_pack(packs: list = None):
    packs = packs or []
    test_pack_zip(Build.content_path, Build.test_pack_target, packs)


def test_files(content_path, packs_to_install: list = None):
    packs_root = f'{content_path}/Packs'
    packs_to_install = packs_to_install or []

    # if is given a list of packs to install then collect the test playbook only for those packs (in commit/push build)
    if packs_to_install:
        packs = filter(lambda x: x.is_dir() and x.name in packs_to_install, os.scandir(packs_root))
    else:
        # else collect the test playbooks for all content packs (in nightly)
        packs = filter(lambda x: x.is_dir(), os.scandir(packs_root))

    for pack_dir in packs:
        if pack_dir in SKIPPED_PACKS:
            continue
        playbooks_root = f'{pack_dir.path}/TestPlaybooks'
        if os.path.isdir(playbooks_root):
            for playbook_path, playbook in get_test_playbooks_in_dir(playbooks_root):
                yield playbook_path, playbook
            if os.path.isdir(f'{playbooks_root}/NonCircleTests'):
                for playbook_path, playbook in get_test_playbooks_in_dir(f'{playbooks_root}/NonCircleTests'):
                    yield playbook_path, playbook


def get_test_playbooks_in_dir(path):
    playbooks = filter(lambda x: x.is_file(), os.scandir(path))
    for playbook in playbooks:
        yield playbook.path, playbook


def test_pack_metadata():
    now = datetime.now().isoformat().split('.')[0]
    now = f'{now}Z'
    metadata = {
        "name": "test pack",
        "id": str(uuid.uuid4()),
        "description": "test pack (all test playbooks and scripts).",
        "created": now,
        "updated": now,
        "legacy": True,
        "support": "Cortex XSOAR",
        "supportDetails": {},
        "author": "Cortex XSOAR",
        "authorImage": "",
        "certification": "certified",
        "price": 0,
        "serverMinVersion": "6.0.0",
        "serverLicense": "",
        "currentVersion": "1.0.0",
        "general": [],
        "tags": [],
        "categories": [
            "Forensics & Malware Analysis"
        ],
        "contentItems": {},
        "integrations": [],
        "useCases": [],
        "keywords": [],
        "dependencies": {}
    }
    return json.dumps(metadata, indent=4)


def test_pack_zip(content_path, target, packs: list = None):
    """
    Iterates over all TestPlaybooks folders and adds all files from there to test_pack.zip' file.
    """
    packs = packs or []
    with zipfile.ZipFile(f'{target}/test_pack.zip', 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('test_pack/metadata.json', test_pack_metadata())
        for test_path, test in test_files(content_path, packs):
            if not test_path.endswith('.yml'):
                continue
            test = test.name
            with open(test_path) as test_file:
                if not (test.startswith(('playbook-', 'script-'))):
                    test_type = find_type(_dict=yaml.safe_load(test_file), file_type='yml').value
                    test_file.seek(0)
                    test_target = f'test_pack/TestPlaybooks/{test_type}-{test}'
                else:
                    test_target = f'test_pack/TestPlaybooks/{test}'
                zip_file.writestr(test_target, test_file.read())


def get_non_added_packs_ids(build: Build):
    """
    In this step we want to get only updated packs (not new packs).
    :param build: the build object
    :return: all non added packs i.e. unchanged packs (dependencies) and modified packs
    """
    compare_against = (
        'master~1' if build.branch_name == 'master' else 'origin/master'
    )
    added_files = run_command(f'git diff --name-only --diff-filter=A '
                              f'{compare_against}..refs/heads/{build.branch_name} -- Packs/*/pack_metadata.json')
    if os.getenv('CONTRIB_BRANCH'):
        added_contrib_files = run_command(
            'git status -uall --porcelain -- Packs/*/pack_metadata.json | grep "?? "').replace('?? ', '')
        added_files = added_files if not added_contrib_files else '\n'.join([added_files, added_contrib_files])

    added_files = filter(lambda x: x, added_files.split('\n'))
    added_pack_ids = (x.split('/')[1] for x in added_files)
    # build.pack_ids_to_install contains new packs and modified. added_pack_ids contains new packs only.
    return set(build.pack_ids_to_install) - set(added_pack_ids)


def run_git_diff(pack_name: str, build: Build) -> str:
    """
    Run git diff command with the specific pack id.
    Args:
        pack_name (str): The pack name.
        build (Build): The build object.
    Returns:
        (str): The git diff output.
    """
    compare_against = (
        f"origin/master{'' if build.branch_name != 'master' else '~1'}"
    )
    return run_command(f'git diff {compare_against}..{build.branch_name} -- Packs/{pack_name}/pack_metadata.json')


def check_hidden_field_changed(pack_name: str, build: Build) -> bool:
    """
    Check if pack turned from hidden to non-hidden.
    Args:
        pack_name (str): The pack name.
        build (Build): The build object.
    Returns:
        (bool): True if the pack transformed to non-hidden.
    """
    diff = run_git_diff(pack_name, build)
    return any('"hidden": false' in diff_line and diff_line.split()[0].startswith('+') for diff_line in diff.splitlines())


def get_turned_non_hidden_packs(modified_packs_names: set[str], build: Build) -> set[str]:
    """
    Return a set of packs which turned from hidden to non-hidden.
    Args:
        modified_packs_names (Set[str]): The set of packs to install.
        build (Build): The build object.
    Returns:
        (Set[str]): The set of packs names which are turned non-hidden.
    """
    hidden_packs = set()
    for pack_name in modified_packs_names:
        # check if the pack turned from hidden to non-hidden.
        if check_hidden_field_changed(pack_name, build):
            hidden_packs.add(pack_name)
    return hidden_packs


def create_build_object() -> Build:
    options = options_handler()
    logging.info(f'Build type: {options.build_object_type}')
    if options.build_object_type == XSOAR_BUILD_TYPE:
        return XSOARBuild(options)
    elif options.build_object_type == CLOUD_BUILD_TYPE:
        return CloudBuild(options)
    else:
        raise Exception(f"Wrong Build object type {options.build_object_type}.")


def packs_names_to_integrations_names(turned_non_hidden_packs_names: set[str]) -> list[str]:
    """
    Convert packs names to the integrations names contained in it.
    Args:
        turned_non_hidden_packs_names (Set[str]): The turned non-hidden pack names (e.g. "AbnormalSecurity")
    Returns:
        List[str]: The turned non-hidden integrations names list.
    """
    hidden_integrations = []
    hidden_integrations_paths = [f'Packs/{pack_name}/Integrations' for pack_name in turned_non_hidden_packs_names]
    # extract integration names within the turned non-hidden packs.
    for hidden_integrations_path in hidden_integrations_paths:
        if os.path.exists(hidden_integrations_path):
            pack_integrations_paths = listdir_fullpath(hidden_integrations_path)
            for integration_path in pack_integrations_paths:
                hidden_integrations.append(integration_path.split("/")[-1])
    hidden_integrations_names = [integration for integration in hidden_integrations if
                                 not str(integration).startswith('.')]
    return hidden_integrations_names


def update_integration_lists(new_integrations_names: list[str], packs_not_to_install: set[str] | None,
                             modified_integrations_names: list[str]) -> tuple[list[str], list[str]]:
    """
    Add the turned non-hidden integrations names to the new integrations names list and
     remove it from modified integrations names.
    Args:
        new_integrations_names (List[str]): The new integration name (e.g. "AbnormalSecurity").
        packs_not_to_install (Set[str]): The turned non-hidden packs names.
        modified_integrations_names (List[str]): The modified integration name (e.g. "AbnormalSecurity").
    Returns:
        Tuple[List[str], List[str]]: The updated lists after filtering the turned non-hidden integrations.
    """
    if not packs_not_to_install:
        return new_integrations_names, modified_integrations_names

    hidden_integrations_names = packs_names_to_integrations_names(packs_not_to_install)
    # update the new integration and the modified integration with the non-hidden integrations.
    for hidden_integration_name in hidden_integrations_names:
        if hidden_integration_name in modified_integrations_names:
            modified_integrations_names.remove(hidden_integration_name)
            new_integrations_names.append(hidden_integration_name)
    return list(set(new_integrations_names)), modified_integrations_names


def filter_new_to_marketplace_packs(build: Build, modified_pack_names: set[str]) -> set[str]:
    """
    Return a set of packs that is new to the marketplace.
    Args:
        build (Build): The build object.
        modified_pack_names (Set[str]): The set of packs to install.
    Returns:
        (Set[str]): The set of the pack names that should not be installed.
    """
    first_added_to_marketplace = set()
    for pack_name in modified_pack_names:
        diff = run_git_diff(pack_name, build)
        if build.check_if_new_to_marketplace(diff):
            first_added_to_marketplace.add(pack_name)
    return first_added_to_marketplace


def get_packs_to_install(build: Build) -> tuple[set[str], set[str]]:
    """
    Return a set of packs to install only in the pre-update, and set to install in post-update.
    Args:
        build (Build): The build object.
    Returns:
        (Set[str]): The set of the pack names that should not be installed.
        (Set[str]): The set of the pack names that should be installed only in post update. (non-hidden packs or packs
                                                that new to current marketplace)
    """
    modified_packs_names = get_non_added_packs_ids(build)

    non_hidden_packs = get_turned_non_hidden_packs(modified_packs_names, build)

    packs_with_higher_min_version = get_packs_with_higher_min_version(set(build.pack_ids_to_install),
                                                                      build.server_numeric_version)
    # packs to install used in post update
    build.pack_ids_to_install = list(set(build.pack_ids_to_install) - packs_with_higher_min_version)

    first_added_to_marketplace = filter_new_to_marketplace_packs(
        build, modified_packs_names - non_hidden_packs - packs_with_higher_min_version
    )

    packs_not_to_install_in_pre_update = set().union(*[packs_with_higher_min_version,
                                                       non_hidden_packs, first_added_to_marketplace])
    packs_to_install_in_pre_update = modified_packs_names - packs_not_to_install_in_pre_update
    return packs_to_install_in_pre_update, non_hidden_packs


def get_packs_with_higher_min_version(packs_names: set[str],
                                      server_numeric_version: str) -> set[str]:
    """
    Return a set of packs that have higher min version than the server version.

    Args:
        packs_names (Set[str]): A set of packs to install.
        server_numeric_version (str): The server version.

    Returns:
        (Set[str]): The set of the packs names that supposed to be not installed because
                    their min version is greater than the server version.
    """
    extract_content_packs_path = mkdtemp()
    packs_artifacts_path = f'{ARTIFACTS_FOLDER}/content_packs.zip'
    extract_packs_artifacts(packs_artifacts_path, extract_content_packs_path)

    packs_with_higher_version = set()
    for pack_name in packs_names:
        pack_metadata = get_json_file(f"{extract_content_packs_path}/{pack_name}/metadata.json")
        server_min_version = pack_metadata.get(Metadata.SERVER_MIN_VERSION,
                                               pack_metadata.get('server_min_version', Metadata.SERVER_DEFAULT_MIN_VERSION))

        if 'Master' not in server_numeric_version and Version(server_numeric_version) < Version(server_min_version):
            packs_with_higher_version.add(pack_name)
            logging.info(f"Found pack '{pack_name}' with min version {server_min_version} that is "
                         f"higher than server version {server_numeric_version}")

    return packs_with_higher_version


def main():
    """
    This step in the build is doing different things for branch build and nightly.
    The flow for custom branch build is:
        1. Add server config and restart servers (only in xsoar).
        2. Disable all enabled integrations.
        3. Finds only modified (not new) packs and install them, same version as in production.
            (before the update in this branch).
        4. Finds all the packs that should not be installed, like turned hidden -> non-hidden packs names
           or packs with higher min version than the server version,
           or existing packs that were added to a new marketplace.
        5. Compares master to commit_sha and return two lists - new integrations and modified in the current branch.
           Filter the lists, add the turned non-hidden to the new integrations list and remove it from the modified list
           This filter purpose is to ignore the turned-hidden integration tests in the pre-update step. (#CIAC-3009)
        6. Configures integration instances (same version as in production) for the modified packs
            and runs `test-module` (pre-update).
        7. Changes marketplace bucket to the new one that was created in create-instances workflow.
        8. Installs all (new and modified) packs from current branch.
        9. After updating packs from branch, runs `test-module` for both new and modified integrations,
            to check that modified integrations was not broken. (post-update).
        10. Upload the test playbooks of packs from the packs to install list.
        11. Prints results.
    The flow for nightly:
        1. Add server config and restart servers (only in xsoar).
        2. Disable all enabled integrations.
        3. Upload all test playbooks that currently in master.
        4. In XSOAR:Install all existing packs, in cloud: install only requested packs.
    """
    install_logging('Install_Content_And_Configure_Integrations_On_Server.log', logger=logging)
    build = create_build_object()
    logging.info(f"Build Number: {build.ci_build_number}")

    build.configure_servers_and_restart()
    build.disable_instances()

    if build.is_nightly:
        build.install_nightly_pack()
    else:
        packs_to_install_in_pre_update, packs_to_install_in_post_update = get_packs_to_install(build)
        logging.info("Installing packs in pre-update step")
        build.install_packs(pack_ids=packs_to_install_in_pre_update)  # type: ignore[arg-type]
        new_integrations_names, modified_integrations_names = build.get_changed_integrations(
            packs_to_install_in_post_update)
        pre_update_configuration_results = build.configure_and_test_integrations_pre_update(new_integrations_names,
                                                                                            modified_integrations_names)
        modified_module_instances, new_module_instances, failed_tests_pre, successful_tests_pre = pre_update_configuration_results
        logging.info("Installing packs in post-update step")
        installed_content_packs_successfully = build.update_content_on_servers()
        successful_tests_post, failed_tests_post = build.test_integrations_post_update(new_module_instances,
                                                                                       modified_module_instances)
        if not os.getenv('BUCKET_UPLOAD'):  # Don't need to upload test playbooks in upload flow
            build.create_and_upload_test_pack(packs_to_install=build.pack_ids_to_install)
        success = report_tests_status(failed_tests_pre, failed_tests_post, successful_tests_pre, successful_tests_post,
                                      new_integrations_names, build)
        if not success or not installed_content_packs_successfully:
            logging.exception('Failed to configure and test integration instances.')
            sys.exit(2)


if __name__ == '__main__':
    main()
