from __future__ import print_function

import datetime
import json
import logging
import os
import re
import sys
from contextlib import contextmanager
from queue import Queue
from typing import Union, Any

import demisto_client.demisto_api
import pytz
import requests
import urllib3
from google.api_core.exceptions import PreconditionFailed
from google.cloud import storage
from slack import WebClient as SlackClient

from Tests.test_dependencies import get_used_integrations
from demisto_sdk.commands.common.constants import FILTER_CONF
from demisto_sdk.commands.test_content.ParallelLoggingManager import ParallelLoggingManager

logging_manager: ParallelLoggingManager = None

# Disable insecure warnings
urllib3.disable_warnings()

SERVER_URL = "https://{}"
INTEGRATIONS_CONF = "./Tests/integrations_file.txt"

FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using " \
                            "the instance_name argument in conf.json. The options are:\n{}"

LOCKS_PATH = 'content-locks'
BUCKET_NAME = os.environ.get('GCS_ARTIFACTS_BUCKET')
CIRCLE_BUILD_NUM = os.environ.get('CIRCLE_BUILD_NUM')
WORKFLOW_ID = os.environ.get('CIRCLE_WORKFLOW_ID')
CIRCLE_STATUS_TOKEN = os.environ.get('CIRCLECI_STATUS_TOKEN')
ENV_RESULTS_PATH = './env_results.json'


class SettingsTester:
    def __init__(self, options):
        self.api_key = options.apiKey
        self.server = options.server
        self.conf_path = options.conf
        self.secret_conf_path = options.secret
        self.nightly = options.nightly
        self.slack = options.slack
        self.circleci = options.circleci
        self.buildNumber = options.buildNumber
        self.buildName = options.buildName
        self.isAMI = options.isAMI
        self.memCheck = options.memCheck
        self.serverVersion = options.serverVersion
        self.serverNumericVersion = None
        self.specific_tests_to_run = self.parse_tests_list_arg(options.testsList)
        self.is_local_run = (self.server is not None)

    @staticmethod
    def parse_tests_list_arg(tests_list: str):
        """
        Parses the test list arguments if present.

        :param tests_list: CSV string of tests to run.
        :return: List of tests if there are any, otherwise empty list.
        """
        tests_to_run = tests_list.split(",") if tests_list else []
        return tests_to_run


class DataKeeperTester:

    def __init__(self):
        self.succeeded_playbooks = []
        self.failed_playbooks = []
        self.skipped_tests = []
        self.skipped_integrations = []
        self.rerecorded_tests = []
        self.empty_files = []
        self.unmockable_integrations = {}

    def add_tests_data(self, succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration,
                       unmockable_integrations):
        # Using multiple appends and not extend since append is guaranteed to be thread safe
        for playbook in succeed_playbooks:
            self.succeeded_playbooks.append(playbook)
        for playbook in failed_playbooks:
            self.failed_playbooks.append(playbook)
        for playbook in skipped_tests:
            self.skipped_tests.append(playbook)
        for playbook in skipped_integration:
            self.skipped_integrations.append(playbook)
        for playbook_id, reason in unmockable_integrations.items():
            self.unmockable_integrations[playbook_id] = reason

    def add_proxy_related_test_data(self, proxy):
        # Using multiple appends and not extend since append is guaranteed to be thread safe
        for playbook_id in proxy.rerecorded_tests:
            self.rerecorded_tests.append(playbook_id)
        for playbook_id in proxy.empty_files:
            self.empty_files.append(playbook_id)


def print_test_summary(tests_data_keeper: DataKeeperTester,
                       is_ami: bool = True,
                       logging_module: Union[Any, ParallelLoggingManager] = logging) -> None:
    """
    Takes the information stored in the tests_data_keeper and prints it in a human readable way.
    Args:
        tests_data_keeper: object containing test statuses.
        is_ami: indicating if the server running the tests is an AMI or not.
        logging_module: Logging module to use for test_summary


    """
    succeed_playbooks = tests_data_keeper.succeeded_playbooks
    failed_playbooks = tests_data_keeper.failed_playbooks
    skipped_tests = tests_data_keeper.skipped_tests
    unmocklable_integrations = tests_data_keeper.unmockable_integrations
    skipped_integration = tests_data_keeper.skipped_integrations
    rerecorded_tests = tests_data_keeper.rerecorded_tests
    empty_files = tests_data_keeper.empty_files

    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)
    skipped_count = len(skipped_tests)
    rerecorded_count = len(rerecorded_tests) if is_ami else 0
    empty_mocks_count = len(empty_files) if is_ami else 0
    unmocklable_integrations_count = len(unmocklable_integrations)
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
        logging_module.warning(f'Number of tests with failed playback and successful re-recording - {rerecorded_count}')
        logging_module.warning('Tests with failed playback and successful re-recording: {}'.format(
            ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in rerecorded_tests])))

    if empty_mocks_count > 0:
        logging_module.info(f'Successful tests with empty mock files count- {empty_mocks_count}:\n')
        proxy_explanation = \
            '\t\t\t\t\t\t\t (either there were no http requests or no traffic is passed through the proxy.\n' \
            '\t\t\t\t\t\t\t Investigate the playbook and the integrations.\n' \
            '\t\t\t\t\t\t\t If the integration has no http traffic, add to unmockable_integrations in conf.json)'
        logging_module.info(proxy_explanation)
        logging_module.info('Successful tests with empty mock files: {}'.format(
            ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in empty_files])))

    if len(skipped_integration) > 0:
        logging_module.warning(f'Number of skipped integration - {len(skipped_integration):}')
        logging_module.warning('Skipped integration: {}'.format(
            ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in skipped_integration])))

    if skipped_count > 0:
        logging_module.warning(f'Number of skipped tests - {skipped_count}:')
        logging_module.warning('Skipped tests: {}'.format(
            ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id}' for playbook_id in skipped_tests])))

    if unmocklable_integrations_count > 0:
        logging_module.warning(f'Number of unmockable integrations - {unmocklable_integrations_count}:')
        logging_module.warning('Unmockable integrations: {}'.format(
            ''.join([f'\n\t\t\t\t\t\t\t - {playbook_id} - {reason}' for playbook_id, reason in
                     unmocklable_integrations.items()])))


def update_test_msg(integrations, test_message):
    if integrations:
        integrations_names = [integration['name'] for integration in
                              integrations]
        test_message = test_message + ' with integration(s): ' + ','.join(
            integrations_names)

    return test_message


def turn_off_telemetry(xsoar_client):
    """
    Turn off telemetry on the AMI instance

    :param xsoar_client: Preconfigured client for the XSOAR instance
    :return: None
    """

    body, status_code, _ = demisto_client.generic_request_func(self=xsoar_client, method='POST',
                                                               path='/telemetry?status=notelemetry')

    if status_code != 200:
        logging_manager.critical(f'Request to turn off telemetry failed with status code "{status_code}"\n{body}',
                                 real_time=True)
        sys.exit(1)


def http_request(url, params_dict=None):
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


def get_user_name_from_circle(circleci_token, build_number):
    url = "https://circleci.com/api/v1.1/project/github/demisto/content/{0}?circle-token={1}".format(build_number,
                                                                                                     circleci_token)
    res = http_request(url)

    user_details = res.get('user', {})
    return user_details.get('name', '')


def notify_failed_test(slack, circle_ci, playbook_id, build_number, inc_id, server_url, build_name):
    circle_user_name = get_user_name_from_circle(circle_ci, build_number)
    sc = SlackClient(slack)
    user_id = retrieve_id(circle_user_name, sc)

    text = "{0} - {1} Failed\n{2}".format(build_name, playbook_id, server_url) if inc_id == -1 \
        else "{0} - {1} Failed\n{2}/#/WorkPlan/{3}".format(build_name, playbook_id, server_url, inc_id)

    if user_id:
        sc.api_call(
            "chat.postMessage",
            channel=user_id,
            username="Content CircleCI",
            as_user="False",
            text=text
        )


def retrieve_id(circle_user_name, sc):
    user_id = ''
    res = sc.api_call('users.list')

    user_list = res.get('members', [])
    for user in user_list:
        profile = user.get('profile', {})
        name = profile.get('real_name_normalized', '')
        if name == circle_user_name:
            user_id = user.get('id', '')

    return user_id


def create_result_files(tests_data_keeper):
    failed_playbooks = tests_data_keeper.failed_playbooks
    skipped_integration = tests_data_keeper.skipped_integrations
    skipped_tests = tests_data_keeper.skipped_tests
    with open("./Tests/failed_tests.txt", "w") as failed_tests_file:
        failed_tests_file.write('\n'.join(failed_playbooks))
    with open('./Tests/skipped_tests.txt', "w") as skipped_tests_file:
        skipped_tests_file.write('\n'.join(skipped_tests))
    with open('./Tests/skipped_integrations.txt', "w") as skipped_integrations_file:
        skipped_integrations_file.write('\n'.join(skipped_integration))


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
        item_as_string = item_as_string.replace(key, value)
    return json.loads(item_as_string)


def set_integration_params(demisto_api_key, integrations, secret_params, instance_names, playbook_id, placeholders_map):
    for integration in integrations:
        integration_params = [change_placeholders_to_values(placeholders_map, item) for item
                              in secret_params if item['name'] == integration['name']]

        if integration_params:
            matched_integration_params = integration_params[0]
            if len(integration_params) != 1:
                found_matching_instance = False
                for item in integration_params:
                    if item.get('instance_name', 'Not Found') in instance_names:
                        matched_integration_params = item
                        found_matching_instance = True

                if not found_matching_instance:
                    optional_instance_names = [optional_integration.get('instance_name', 'None')
                                               for optional_integration in integration_params]
                    error_msg = FAILED_MATCH_INSTANCE_MSG.format(playbook_id, len(integration_params),
                                                                 integration['name'],
                                                                 '\n'.join(optional_instance_names))
                    logging_manager.error(error_msg)
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
            integration['instance_name'] = matched_integration_params.get('instance_name', integration['name'])
            integration['validate_test'] = matched_integration_params.get('validate_test', True)
        elif integration['name'] == 'Demisto REST API':
            integration['params'] = {
                'url': 'https://localhost',
                'apikey': demisto_api_key,
                'insecure': True,
            }

    return True


def collect_integrations(integrations_conf, skipped_integration, skipped_integrations_conf, nightly_integrations):
    integrations = []
    is_nightly_integration = False
    test_skipped_integration = []
    for integration in integrations_conf:
        if integration in skipped_integrations_conf.keys():
            skipped_integration.add("{0} - reason: {1}".format(integration, skipped_integrations_conf[integration]))
            test_skipped_integration.append(integration)

        if integration in nightly_integrations:
            is_nightly_integration = True

        # string description
        integrations.append({
            'name': integration,
            'params': {}
        })

    return test_skipped_integration, integrations, is_nightly_integration


def extract_filtered_tests():
    with open(FILTER_CONF, 'r') as filter_file:
        filtered_tests = [line.strip('\n') for line in filter_file.readlines()]

    return filtered_tests


def load_conf_files(conf_path, secret_conf_path):
    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    return conf, secret_conf


def load_env_results_json():
    if not os.path.isfile(ENV_RESULTS_PATH):
        return {}

    with open(ENV_RESULTS_PATH, 'r') as json_file:
        return json.load(json_file)


def get_server_numeric_version(ami_env, is_local_run=False):
    """
    Gets the current server version
    Arguments:
        ami_env: (str)
            AMI version name.
        is_local_run: (bool)
            when running locally, assume latest version.

    Returns:
        (str) Server numeric version
    """
    default_version = '99.99.98'
    if is_local_run:
        logging.info(f'Local run, assuming server version is {default_version}')
        return default_version

    env_json = load_env_results_json()
    if not env_json:
        logging.warning(f'Did not find {ENV_RESULTS_PATH} file, assuming server version is {default_version}.')
        return default_version

    instances_ami_names = {env.get('AmiName') for env in env_json if ami_env in env.get('Role', '')}
    if len(instances_ami_names) != 1:
        logging.warning(f'Did not get one AMI Name, got {instances_ami_names}.'
                        f' Assuming server version is {default_version}')
        return default_version

    instances_ami_name = list(instances_ami_names)[0]

    return extract_server_numeric_version(instances_ami_name, default_version)


def extract_server_numeric_version(instances_ami_name, default_version):
    # regex doesn't catch Server Master execution
    extracted_version = re.findall(r'Demisto-(?:Circle-CI|Marketplace)-Content-AMI-[A-Za-z]*[-_](\d[._]\d)-[\d]{5}',
                                   instances_ami_name)
    extracted_version = [match.replace('_', '.') for match in extracted_version]

    if extracted_version:
        server_numeric_version = extracted_version[0]
    else:
        if 'Master' in instances_ami_name:
            logging.info('Server version: Master')
            return default_version
        else:
            server_numeric_version = default_version

    # make sure version is three-part version
    if server_numeric_version.count('.') == 1:
        server_numeric_version += ".0"

    logging.info(f'Server version: {server_numeric_version}')
    return server_numeric_version


def get_instances_ips_and_names(tests_settings):
    if tests_settings.server:
        return [tests_settings.server]
    env_json = load_env_results_json()
    instances_ips = [(env.get('Role'), env.get('InstanceDNS')) for env in env_json]
    return instances_ips


def get_test_records_of_given_test_names(tests_settings, tests_names_to_search):
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    tests_records = conf['tests']
    test_records_with_supplied_names = []
    for test_record in tests_records:
        test_name = test_record.get("playbookID")
        if test_name and test_name in tests_names_to_search:
            test_records_with_supplied_names.append(test_record)
    return test_records_with_supplied_names


def get_json_file(path):
    with open(path, 'r') as json_file:
        return json.loads(json_file.read())


def initialize_queue_and_executed_tests_set(tests):
    tests_queue = Queue()
    already_executed_test_playbooks = set()
    for t in tests:
        tests_queue.put(t)
    return already_executed_test_playbooks, tests_queue


def get_unmockable_tests(tests_settings):
    conf, _ = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    unmockable_integrations = conf['unmockable_integrations']
    tests = conf['tests']
    unmockable_tests = []
    for test_record in tests:
        test_name = test_record.get("playbookID")
        integrations_used_in_test = get_used_integrations(test_record)
        unmockable_integrations_used = [integration_name for integration_name in integrations_used_in_test if
                                        integration_name in unmockable_integrations]
        if test_name and (not integrations_used_in_test or unmockable_integrations_used):
            unmockable_tests.append(test_name)
    return unmockable_tests


def get_all_tests(tests_settings):
    conf, _ = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    tests_records = conf['tests']
    all_tests = []
    for test_record in tests_records:
        test_name = test_record.get("playbookID")
        if test_name:
            all_tests.append(test_name)
    return all_tests


def add_pr_comment(comment):
    token = os.environ['CONTENT_GITHUB_TOKEN']
    branch_name = os.environ['CIRCLE_BRANCH']
    sha1 = os.environ['CIRCLE_SHA1']

    query = '?q={}+repo:demisto/content+org:demisto+is:pr+is:open+head:{}+is:open'.format(sha1, branch_name)
    url = 'https://api.github.com/search/issues'
    headers = {'Authorization': 'Bearer ' + token}
    try:
        res = requests.get(url + query, headers=headers, verify=False)
        res = handle_github_response(res)

        if res and res.get('total_count', 0) == 1:
            issue_url = res['items'][0].get('comments_url') if res.get('items', []) else None
            if issue_url:
                res = requests.post(issue_url, json={'body': comment}, headers=headers, verify=False)
                handle_github_response(res)
        else:
            logging_manager.warning('Add pull request comment failed: There is more then one open pull '
                                    f'request for branch {branch_name}.', real_time=True)
    except Exception:
        logging_manager.exception('Add pull request comment failed')


def handle_github_response(response):
    res_dict = response.json()
    if not res_dict.ok:
        logging_manager.error(f'Add pull request comment failed: {res_dict.get("message")}', real_time=True)
    return res_dict


@contextmanager
def acquire_test_lock(integrations_details: list,
                      test_timeout: int,
                      conf_json_path: str) -> None:
    """
    This is a context manager that handles all the locking and unlocking of integrations.
    Execution is as following:
    * Attempts to lock the test's integrations and yields the result of this attempt
    * If lock attempt has failed - yields False, if it succeeds - yields True
    * Once the test is done- will unlock all integrations
    Args:
        integrations_details: test integrations details
        test_timeout: test timeout in seconds
        conf_json_path: Path to conf.json file
    Yields:
        A boolean indicating the lock attempt result
    """
    locked = safe_lock_integrations(test_timeout,
                                    integrations_details,
                                    conf_json_path)
    try:
        yield locked
    except Exception:
        logging_manager.exception('Failed with test lock')
    finally:
        if not locked:
            return
        safe_unlock_integrations(integrations_details)


def safe_unlock_integrations(integrations_details: list):
    """
    This integration safely unlocks the test's integrations.
    If an unexpected error occurs - this method will log it's details and other tests execution will continue
    Args:
        integrations_details: Details of the currently executed test
    """
    try:
        # executing the test could take a while, re-instancing the storage client
        storage_client = storage.Client()
        unlock_integrations(integrations_details, storage_client)
    except Exception:
        logging_manager.exception('attempt to unlock integration failed for unknown reason.')


def safe_lock_integrations(test_timeout: int,
                           integrations_details: list,
                           conf_json_path: str) -> bool:
    """
    This integration safely locks the test's integrations and return it's result
    If an unexpected error occurs - this method will log it's details and return False
    Args:
        test_timeout: Test timeout in seconds
        integrations_details: test integrations details
        conf_json_path: Path to conf.json file

    Returns:
        A boolean indicating the lock attempt result
    """
    conf, _ = load_conf_files(conf_json_path, None)
    parallel_integrations_names = conf['parallel_integrations']
    filtered_integrations_details = [integration for integration in integrations_details if
                                     integration['name'] not in parallel_integrations_names]
    integration_names = get_integrations_list(filtered_integrations_details)
    if integration_names:
        print_msg = f'Attempting to lock integrations {integration_names}, with timeout {test_timeout}'
    else:
        print_msg = 'No integrations to lock'
    logging_manager.debug(print_msg)
    try:
        storage_client = storage.Client()
        locked = lock_integrations(filtered_integrations_details, test_timeout, storage_client)
    except Exception:
        logging_manager.exception('attempt to lock integration failed for unknown reason.')
        locked = False
    return locked


def workflow_still_running(workflow_id: str) -> bool:
    """
    This method takes a workflow id and checks if the workflow is still running
    If given workflow ID is the same as the current workflow, will simply return True
    else it will query circleci api for the workflow and return the status
    Args:
        workflow_id: The ID of the workflow

    Returns:
        True if the workflow is running, else False
    """
    # If this is the current workflow_id
    if workflow_id == WORKFLOW_ID:
        return True
    else:
        try:
            workflow_details_response = requests.get(f'https://circleci.com/api/v2/workflow/{workflow_id}',
                                                     headers={'Accept': 'application/json'},
                                                     auth=(CIRCLE_STATUS_TOKEN, ''))
            workflow_details_response.raise_for_status()
        except Exception:
            logging_manager.exception(f'Failed to get circleci response about workflow with id {workflow_id}.')
            return True
        return workflow_details_response.json().get('status') not in ('canceled', 'success', 'failed')


def lock_integrations(integrations_details: list,
                      test_timeout: int,
                      storage_client: storage.Client) -> bool:
    """
    Locks all the test's integrations
    Args:
        integrations_details: List of current test's integrations
        test_timeout: Test timeout in seconds
        storage_client: The GCP storage client

    Returns:
        True if all the test's integrations were successfully locked, else False
    """
    integrations = get_integrations_list(integrations_details)
    if not integrations:
        return True
    existing_integrations_lock_files = get_locked_integrations(integrations, storage_client)
    for integration, lock_file in existing_integrations_lock_files.items():
        # Each file has content in the form of <circleci-build-number>:<timeout in seconds>
        # If it has not expired - it means the integration is currently locked by another test.
        workflow_id, build_number, lock_timeout = lock_file.download_as_string().decode().split(':')
        if not lock_expired(lock_file, lock_timeout) and workflow_still_running(workflow_id):
            # there is a locked integration for which the lock is not expired - test cannot be executed at the moment
            logging_manager.warning(
                f'Could not lock integration {integration}, another lock file was exist with '
                f'build number: {build_number}, timeout: {lock_timeout}, last update at {lock_file.updated}.\n'
                f'Delaying test execution')
            return False
    integrations_generation_number = {}
    # Gathering generation number with which the new file will be created,
    # See https://cloud.google.com/storage/docs/generations-preconditions for details.
    for integration in integrations:
        if integration in existing_integrations_lock_files:
            integrations_generation_number[integration] = existing_integrations_lock_files[integration].generation
        else:
            integrations_generation_number[integration] = 0
    return create_lock_files(integrations_generation_number, storage_client, integrations_details, test_timeout)


def get_integrations_list(test_integrations: list) -> list:
    """
    Since test details can have one integration as a string and sometimes a list of integrations- this methods
    parses the test's integrations into a list of integration names.
    Args:
        test_integrations: List of current test's integrations
    Returns:
        the integration names in a list for all the integrations that takes place in the test
        specified in test details.
    """
    return [integration['name'] for integration in test_integrations]


def create_lock_files(integrations_generation_number: dict,
                      storage_client: storage.Client,
                      integrations_details: list,
                      test_timeout: int) -> bool:
    """
    This method tries to create a lock files for all integrations specified in 'integrations_generation_number'.
    Each file should contain <circle-ci-build-number>:<test-timeout>
    where the <circle-ci-build-number> part is for debugging and troubleshooting
    and the <test-timeout> part is to be able to unlock revoked test files.
    If for any of the integrations, the lock file creation will fail- the already created files will be cleaned.
    Args:
        integrations_generation_number: A dict in the form of {<integration-name>:<integration-generation>}
        storage_client: The GCP storage client
        integrations_details: List of current test's integrations
        test_timeout: The time out

    Returns:

    """
    locked_integrations = []
    bucket = storage_client.bucket(BUCKET_NAME)
    for integration, generation_number in integrations_generation_number.items():
        blob = bucket.blob(f'{LOCKS_PATH}/{integration}')
        try:
            blob.upload_from_string(f'{WORKFLOW_ID}:{CIRCLE_BUILD_NUM}:{test_timeout + 30}',
                                    if_generation_match=generation_number)
            logging_manager.debug(f'integration {integration} locked')
            locked_integrations.append(integration)
        except PreconditionFailed:
            # if this exception occurs it means that another build has locked this integration
            # before this build managed to do it.
            # we need to unlock all the integrations we have already locked and try again later
            logging_manager.warning(
                f'Could not lock integration {integration}, Create file with precondition failed.'
                f'delaying test execution.')
            unlock_integrations(integrations_details, storage_client)
            return False
    return True


def unlock_integrations(integrations_details: list,
                        storage_client: storage.Client) -> None:
    """
    Delete all integration lock files for integrations specified in 'locked_integrations'
    Args:
        integrations_details: List of current test's integrations
        storage_client: The GCP storage client
    """
    locked_integrations = get_integrations_list(integrations_details)
    locked_integration_blobs = get_locked_integrations(locked_integrations, storage_client)
    for integration, lock_file in locked_integration_blobs.items():
        try:
            # Verifying build number is the same as current build number to avoid deleting other tests lock files
            _, build_number, _ = lock_file.download_as_string().decode().split(':')
            if build_number == CIRCLE_BUILD_NUM:
                lock_file.delete(if_generation_match=lock_file.generation)
                logging_manager.debug(
                    f'Integration {integration} unlocked')
        except PreconditionFailed:
            logging_manager.error(f'Could not unlock integration {integration} precondition failure')


def get_locked_integrations(integrations: list, storage_client: storage.Client) -> dict:
    """
    Getting all locked integrations files
    Args:
        integrations: Integrations that we want to get lock files for
        storage_client: The GCP storage client

    Returns:
        A dict of the form {<integration-name>:<integration-blob-object>} for all integrations that has a blob object.
    """
    # Listing all files in lock folder
    # Wrapping in 'list' operator because list_blobs return a generator which can only be iterated once
    lock_files_ls = list(storage_client.list_blobs(BUCKET_NAME, prefix=f'{LOCKS_PATH}'))
    current_integrations_lock_files = {}
    # Getting all existing files details for integrations that we want to lock
    for integration in integrations:
        current_integrations_lock_files.update({integration: [lock_file_blob for lock_file_blob in lock_files_ls if
                                                              lock_file_blob.name == f'{LOCKS_PATH}/{integration}']})
    # Filtering 'current_integrations_lock_files' from integrations with no files
    current_integrations_lock_files = {integration: blob_files[0] for integration, blob_files in
                                       current_integrations_lock_files.items() if blob_files}
    return current_integrations_lock_files


def lock_expired(lock_file: storage.Blob, lock_timeout: str) -> bool:
    """
    Checks if the time that passed since the creation of the 'lock_file' is more then 'lock_timeout'.
    If not- it means that the integration represented by the lock file is currently locked and is tested in another build
    Args:
        lock_file: The lock file blob object
        lock_timeout: The expiration timeout of the lock in seconds

    Returns:
        True if the lock has expired it's timeout, else False
    """
    return datetime.datetime.now(tz=pytz.utc) - lock_file.updated >= datetime.timedelta(seconds=int(lock_timeout))
