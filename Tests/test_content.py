from __future__ import print_function
import re
import sys
import json
import time
import urllib3
import argparse
import requests
import threading
import subprocess
from time import sleep
from datetime import datetime

import demisto_client.demisto_api
from slackclient import SlackClient

from Tests.mock_server import MITMProxy, AMIConnection
from Tests.test_integration import test_integration, disable_all_integrations
from Tests.scripts.constants import RUN_ALL_TESTS_FORMAT, FILTER_CONF, PB_Status
from Tests.test_dependencies import get_used_integrations, get_tests_allocation_for_threads
from Tests.test_utils import print_color, print_error, print_warning, LOG_COLORS, str2bool, server_version_compare


# Disable insecure warnings
urllib3.disable_warnings()

SERVER_URL = "https://{}"
INTEGRATIONS_CONF = "./Tests/integrations_file.txt"

FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using the "\
                            "instance_name argument in conf.json. The options are:\n{}"

AMI_NAMES = ["Demisto GA", "Server Master", "Demisto one before GA", "Demisto two before GA"]

SERVICE_RESTART_TIMEOUT = 300
SERVICE_RESTART_POLLING_INTERVAL = 5

SLACK_MEM_CHANNEL_ID = 'CM55V7J8K'


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-k', '--apiKey', help='The Demisto API key for the server', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to')
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly tests')
    parser.add_argument('-t', '--slack', help='The token for slack', required=True)
    parser.add_argument('-a', '--circleci', help='The token for circleci', required=True)
    parser.add_argument('-b', '--buildNumber', help='The build number', required=True)
    parser.add_argument('-g', '--buildName', help='The build name', required=True)
    parser.add_argument('-i', '--isAMI', type=str2bool, help='is AMI build or not', default=False)
    parser.add_argument('-m', '--memCheck', type=str2bool,
                        help='Should trigger memory checks or not. The slack channel to check the data is: '
                             'dmst_content_nightly_memory_data', default=False)
    parser.add_argument('-d', '--serverVersion', help='Which server version to run the '
                                                      'tests on(Valid only when using AMI)', default="NonAMI")
    parser.add_argument('-l', '--testsList', help='List of specific, comma separated'
                                                  'tests to run')

    options = parser.parse_args()
    tests_settings = TestsSettings(options)
    return tests_settings


class TestsSettings:
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

    @ staticmethod
    def parse_tests_list_arg(tests_list):
        tests_to_run = tests_list.split(",") if tests_list else []
        return tests_to_run


class PrintJob:
    def __init__(self, message_to_print, print_function_to_execute, message_color=None):
        self.print_function_to_execute = print_function_to_execute
        self.message_to_print = message_to_print
        self.message_color = message_color

    def execute_print(self):
        if self.message_color:
            self.print_function_to_execute(self.message_to_print, self.message_color)
        else:
            self.print_function_to_execute(self.message_to_print)


class ParallelPrintsManager:

    def __init__(self, number_of_threads):
        self.threads_print_jobs = [[] for i in range(number_of_threads)]
        self.print_lock = threading.Lock()
        self.threads_last_update_times = [time.time() for i in range(number_of_threads)]

    def should_update_thread_status(self, thread_index):
        current_time = time.time()
        thread_last_update = self.threads_last_update_times[thread_index]
        return current_time - thread_last_update > 300

    def add_print_job(self, message_to_print, print_function_to_execute, thread_index, message_color=None):
        if message_color:
            print_job = PrintJob(message_to_print, print_function_to_execute, message_color)
        else:
            print_job = PrintJob(message_to_print, print_function_to_execute)
        self.threads_print_jobs[thread_index].append(print_job)
        if self.should_update_thread_status(thread_index):
            print("Thread {} is still running.".format(thread_index))
            self.threads_last_update_times[thread_index] = time.time()

    def execute_thread_prints(self, thread_index):
        self.print_lock.acquire()
        prints_to_execute = self.threads_print_jobs[thread_index]
        for print_job in prints_to_execute:
            print_job.execute_print()
        self.print_lock.release()
        self.threads_print_jobs[thread_index] = []


class TestsDataKeeper:

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


def print_test_summary(tests_data_keeper, is_ami=True):
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
    print('\nTEST RESULTS:')
    tested_playbooks_message = '\t Number of playbooks tested - ' + str(succeed_count + failed_count)
    print(tested_playbooks_message)
    succeeded_playbooks_message = '\t Number of succeeded tests - ' + str(succeed_count)
    print_color(succeeded_playbooks_message, LOG_COLORS.GREEN)

    if failed_count > 0:
        failed_tests_message = '\t Number of failed tests - ' + str(failed_count) + ':'
        print_error(failed_tests_message)
        for playbook_id in failed_playbooks:
            print_error('\t - ' + playbook_id)

    if rerecorded_count > 0:
        recording_warning = '\t Tests with failed playback and successful re-recording - ' + str(rerecorded_count) + ':'
        print_warning(recording_warning)
        for playbook_id in rerecorded_tests:
            print_warning('\t - ' + playbook_id)

    if empty_mocks_count > 0:
        empty_mock_successes_msg = '\t Successful tests with empty mock files - ' + str(empty_mocks_count) + ':'
        print(empty_mock_successes_msg)
        proxy_explanation = '\t (either there were no http requests or no traffic is passed through the proxy.\n'\
                            '\t Investigate the playbook and the integrations.\n'\
                            '\t If the integration has no http traffic, add to unmockable_integrations in conf.json)'
        print(proxy_explanation)
        for playbook_id in empty_files:
            print('\t - ' + playbook_id)

    if len(skipped_integration) > 0:
        skipped_integrations_warning = '\t Number of skipped integration - ' + str(len(skipped_integration)) + ':'
        print_warning(skipped_integrations_warning)
        for playbook_id in skipped_integration:
            print_warning('\t - ' + playbook_id)

    if skipped_count > 0:
        skipped_tests_warning = '\t Number of skipped tests - ' + str(skipped_count) + ':'
        print_warning(skipped_tests_warning)
        for playbook_id in skipped_tests:
            print_warning('\t - ' + playbook_id)

    if unmocklable_integrations_count > 0:
        unmockable_warning = '\t Number of unmockable integrations - ' + str(unmocklable_integrations_count) + ':'
        print_warning(unmockable_warning)
        for playbook_id, reason in unmocklable_integrations.items():
            print_warning('\t - ' + playbook_id + ' - ' + reason)


def update_test_msg(integrations, test_message):
    if integrations:
        integrations_names = [integration['name'] for integration in
                              integrations]
        test_message = test_message + ' with integration(s): ' + ','.join(
            integrations_names)

    return test_message


def has_unmockable_integration(integrations, unmockable_integrations):
    return list(set(x['name'] for x in integrations).intersection(unmockable_integrations.keys()))


def get_docker_limit():
    process = subprocess.Popen(['cat', '/sys/fs/cgroup/memory/memory.limit_in_bytes'], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout, stderr = process.communicate()
    return stdout, stderr


def get_docker_processes_data():
    process = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, stderr = process.communicate()
    return stdout, stderr


def get_docker_memory_data():
    process = subprocess.Popen(['cat', '/sys/fs/cgroup/memory/memory.usage_in_bytes'], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    stdout, stderr = process.communicate()
    return stdout, stderr


def send_slack_message(slack, chanel, text, user_name, as_user):
    sc = SlackClient(slack)
    sc.api_call(
        "chat.postMessage",
        channel=chanel,
        username=user_name,
        as_user=as_user,
        text=text,
        mrkdwn='true'
    )


def run_test_logic(tests_settings, c, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                   test_message, test_options, slack, circle_ci, build_number, server_url, build_name,
                   prints_manager, thread_index=0, is_mock_run=False):
    status, inc_id = test_integration(c, server_url, integrations, playbook_id, prints_manager, test_options,
                                      is_mock_run, thread_index=thread_index)
    # c.api_client.pool.close()
    if status == PB_Status.COMPLETED:
        prints_manager.add_print_job('PASS: {} succeed'.format(test_message), print_color, thread_index,
                                     message_color=LOG_COLORS.GREEN)
        succeed_playbooks.append(playbook_id)

    elif status == PB_Status.NOT_SUPPORTED_VERSION:
        not_supported_version_message = 'PASS: {} skipped - not supported version'.format(test_message)
        prints_manager.add_print_job(not_supported_version_message, print, thread_index)
        succeed_playbooks.append(playbook_id)

    else:
        error_message = 'Failed: {} failed'.format(test_message)
        prints_manager.add_print_job(error_message, print_error, thread_index)
        playbook_id_with_mock = playbook_id
        if not is_mock_run:
            playbook_id_with_mock += " (Mock Disabled)"
        failed_playbooks.append(playbook_id_with_mock)
        if not tests_settings.is_local_run:
            notify_failed_test(slack, circle_ci, playbook_id, build_number, inc_id, server_url, build_name)

    succeed = status == PB_Status.COMPLETED or status == PB_Status.NOT_SUPPORTED_VERSION
    return succeed


# run the test using a real instance, record traffic.
def run_and_record(tests_settings, c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                   test_message, test_options, slack, circle_ci, build_number, server_url, build_name,
                   prints_manager, thread_index=0):
    proxy.set_tmp_folder()
    proxy.start(playbook_id, record=True, thread_index=thread_index, prints_manager=prints_manager)
    succeed = run_test_logic(tests_settings, c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message,
                             test_options, slack, circle_ci, build_number, server_url, build_name,
                             prints_manager, thread_index=thread_index, is_mock_run=True)
    proxy.stop()
    if succeed:
        proxy.move_mock_file_to_repo(playbook_id, thread_index=thread_index, prints_manager=prints_manager)

    proxy.set_repo_folder()
    return succeed


def mock_run(tests_settings, c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name, start_message,
             prints_manager, thread_index=0):
    rerecord = False

    if proxy.has_mock_file(playbook_id):
        start_mock_message = '{} (Mock: Playback)'.format(start_message)
        prints_manager.add_print_job(start_mock_message, print, thread_index)
        proxy.start(playbook_id, thread_index=thread_index, prints_manager=prints_manager)
        # run test
        status, inc_id = test_integration(c, server_url, integrations, playbook_id, prints_manager, test_options,
                                          is_mock_run=True, thread_index=thread_index)
        # use results
        proxy.stop()
        if status == PB_Status.COMPLETED:
            succeed_message = 'PASS: {} succeed'.format(test_message)
            prints_manager.add_print_job(succeed_message, print_color, thread_index, LOG_COLORS.GREEN)
            succeed_playbooks.append(playbook_id)
            end_mock_message = '------ Test {} end ------\n'.format(test_message)
            prints_manager.add_print_job(end_mock_message, print, thread_index)

            return

        elif status == PB_Status.NOT_SUPPORTED_VERSION:
            not_supported_version_message = 'PASS: {} skipped - not supported version'.format(test_message)
            prints_manager.add_print_job(not_supported_version_message, print, thread_index)
            succeed_playbooks.append(playbook_id)
            end_mock_message = '------ Test {} end ------\n'.format(test_message)
            prints_manager.add_print_job(end_mock_message, print, thread_index)

            return

        else:
            mock_failed_message = "Test failed with mock, recording new mock file. (Mock: Recording)"
            prints_manager.add_print_job(mock_failed_message, print, thread_index)
            rerecord = True
    else:
        mock_recording_message = start_message + ' (Mock: Recording)'
        prints_manager.add_print_job(mock_recording_message, print, thread_index)

    # Mock recording - no mock file or playback failure.
    succeed = run_and_record(tests_settings, c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                             test_message, test_options, slack, circle_ci, build_number, server_url, build_name,
                             prints_manager, thread_index=thread_index)

    if rerecord and succeed:
        proxy.rerecorded_tests.append(playbook_id)
    test_end_message = '------ Test {} end ------\n'.format(test_message)
    prints_manager.add_print_job(test_end_message, print, thread_index)


def run_test(tests_settings, demisto_api_key, proxy, failed_playbooks, integrations, unmockable_integrations,
             playbook_id, succeed_playbooks, test_message, test_options, slack, circle_ci, build_number,
             server_url, build_name, prints_manager, is_ami=True, thread_index=0):
    start_message = '------ Test %s start ------' % (test_message,)
    client = demisto_client.configure(base_url=server_url, api_key=demisto_api_key, verify_ssl=False)

    if not is_ami or (not integrations or has_unmockable_integration(integrations, unmockable_integrations)):
        prints_manager.add_print_job(start_message + ' (Mock: Disabled)', print, thread_index)
        run_test_logic(tests_settings, client, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                       test_message, test_options, slack, circle_ci, build_number, server_url, build_name,
                       prints_manager, thread_index=thread_index)
        prints_manager.add_print_job('------ Test %s end ------\n' % (test_message,), print, thread_index)

        return
    mock_run(tests_settings, client, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name, start_message,
             prints_manager, thread_index=thread_index)


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


def set_integration_params(demisto_api_key, integrations, secret_params, instance_names, playbook_id,
                           prints_manager, thread_index=0):
    for integration in integrations:
        integration_params = [item for item in secret_params if item['name'] == integration['name']]

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
                    prints_manager.add_print_job(error_msg, print_error, thread_index)
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
            integration['instance_name'] = matched_integration_params.get('instance_name', integration['name'])
            integration['validate_test'] = matched_integration_params.get('validate_test', True)
        elif 'Demisto REST API' == integration['name']:
            integration['params'] = {
                'url': 'https://localhost',
                'apikey': demisto_api_key,
                'insecure': True,
            }

    return True


def collect_integrations(integrations_conf, skipped_integration, skipped_integrations_conf, nightly_integrations):
    integrations = []
    is_nightly_integration = False
    has_skipped_integration = False
    for integration in integrations_conf:
        if integration in skipped_integrations_conf.keys():
            skipped_integration.add("{0} - reason: {1}".format(integration, skipped_integrations_conf[integration]))
            has_skipped_integration = True

        if integration in nightly_integrations:
            is_nightly_integration = True

        # string description
        integrations.append({
            'name': integration,
            'params': {}
        })

    return has_skipped_integration, integrations, is_nightly_integration


def extract_filtered_tests(is_nightly):
    if is_nightly:
        # TODO: verify this response
        return [], False, False
    with open(FILTER_CONF, 'r') as filter_file:
        filtered_tests = filter_file.readlines()
        filtered_tests = [line.strip('\n') for line in filtered_tests]
        is_filter_configured = True if filtered_tests else False
        run_all = True if RUN_ALL_TESTS_FORMAT in filtered_tests else False

    return filtered_tests, is_filter_configured, run_all


def load_conf_files(conf_path, secret_conf_path):
    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    return conf, secret_conf


def run_test_scenario(tests_settings, t, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                      skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests, is_filter_configured,
                      filtered_tests, skipped_tests, secret_params, failed_playbooks,
                      unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server, build_name,
                      server_numeric_version, demisto_api_key, prints_manager, thread_index=0, is_ami=True):
    playbook_id = t['playbookID']
    nightly_test = t.get('nightly', False)
    integrations_conf = t.get('integrations', [])
    instance_names_conf = t.get('instance_names', [])

    test_message = 'playbook: ' + playbook_id

    test_options = {
        'timeout': t.get('timeout', default_test_timeout)
    }

    if not isinstance(integrations_conf, list):
        integrations_conf = [integrations_conf, ]

    if not isinstance(instance_names_conf, list):
        instance_names_conf = [instance_names_conf, ]

    has_skipped_integration, integrations, is_nightly_integration = collect_integrations(
        integrations_conf, skipped_integration, skipped_integrations_conf, nightly_integrations)

    skip_nightly_test = True if (nightly_test or is_nightly_integration) and not is_nightly else False

    # Skip nightly test
    if skip_nightly_test:
        prints_manager.add_print_job('\n------ Test {} start ------'.format(test_message), print, thread_index)
        prints_manager.add_print_job('Skip test', print, thread_index)
        prints_manager.add_print_job('------ Test {} end ------\n'.format(test_message), print, thread_index)
        return

    if not run_all_tests:
        # Skip filtered test
        if is_filter_configured and playbook_id not in filtered_tests:
            return

    # Skip bad test
    if playbook_id in skipped_tests_conf:
        skipped_tests.add("{0} - reason: {1}".format(playbook_id, skipped_tests_conf[playbook_id]))
        return

    # Skip integration
    if has_skipped_integration:
        return

    # Skip version mismatch test
    test_from_version = t.get('fromversion', '0.0.0')
    test_to_version = t.get('toversion', '99.99.99')
    if (server_version_compare(test_from_version, server_numeric_version) > 0
            or server_version_compare(test_to_version, server_numeric_version) < 0):
        prints_manager.add_print_job('\n------ Test {} start ------'.format(test_message), print, thread_index)
        warning_message = 'Test {} ignored due to version mismatch (test versions: {}-{})'.format(test_message,
                                                                                                  test_from_version,
                                                                                                  test_to_version)
        prints_manager.add_print_job(warning_message, print_warning, thread_index)
        prints_manager.add_print_job('------ Test {} end ------\n'.format(test_message), print, thread_index)
        return

    are_params_set = set_integration_params(demisto_api_key, integrations, secret_params, instance_names_conf,
                                            playbook_id, prints_manager, thread_index=thread_index)
    if not are_params_set:
        failed_playbooks.append(playbook_id)
        return

    test_message = update_test_msg(integrations, test_message)
    options = options_handler()
    stdout, stderr = get_docker_memory_data()
    text = 'Memory Usage: {}'.format(stdout) if not stderr else stderr
    if options.nightly and options.memCheck and not tests_settings.is_local_run:
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')
        stdout, stderr = get_docker_processes_data()
        text = stdout if not stderr else stderr
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')

    run_test(tests_settings, demisto_api_key, proxy, failed_playbooks, integrations, unmockable_integrations,
             playbook_id, succeed_playbooks, test_message, test_options, slack, circle_ci,
             build_number, server, build_name, prints_manager, is_ami, thread_index=thread_index)


def get_and_print_server_numeric_version(tests_settings):
    if tests_settings.is_local_run:
        # TODO: verify this logic, it's a workaround because the test_image file does not exist on local run
        return '99.99.98'  # latest
    with open('./Tests/images_data.txt', 'r') as image_data_file:
        image_data = [line for line in image_data_file if line.startswith(tests_settings.serverVersion)]
        if len(image_data) != 1:
            print('Did not get one image data for server version, got {}'.format(image_data))
            return '0.0.0'
        else:
            server_numeric_version = re.findall(r'Demisto-Circle-CI-Content-[\w-]+-([\d.]+)-[\d]{5}', image_data[0])
            if server_numeric_version:
                server_numeric_version = server_numeric_version[0]
            else:
                server_numeric_version = '99.99.98'  # latest
            print('Server image info: {}'.format(image_data[0]))
            print('Server version: {}'.format(server_numeric_version))
            return server_numeric_version


def get_instances_ips_and_names(tests_settings):
    if tests_settings.server:
        return [tests_settings.server]
    with open('./Tests/instance_ips.txt', 'r') as instance_file:
        instance_ips = instance_file.readlines()
        instance_ips = [line.strip('\n').split(":") for line in instance_ips]
        return instance_ips


def get_test_records_of_given_test_names(tests_settings, tests_names_to_search):
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    tests_records = conf['tests']
    test_records_with_supplied_names = []
    for test_record in tests_records:
        test_name = test_record.get("playbookID")
        if test_name and test_name in tests_names_to_search:
            test_records_with_supplied_names.append(test_record)
    return test_records_with_supplied_names


def execute_testing(tests_settings, server_ip, mockable_tests_names, unmockable_tests_names,
                    tests_data_keeper, prints_manager, thread_index=0, is_ami=True):
    server = SERVER_URL.format(server_ip)
    server_numeric_version = tests_settings.serverNumericVersion
    start_message = "Executing tests with the server {} - and the server ip {}".format(server, server_ip)
    prints_manager.add_print_job(start_message, print, thread_index)
    is_nightly = tests_settings.nightly
    is_memory_check = tests_settings.memCheck
    slack = tests_settings.slack
    circle_ci = tests_settings.circleci
    build_number = tests_settings.buildNumber
    build_name = tests_settings.buildName
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)

    demisto_api_key = tests_settings.api_key

    default_test_timeout = conf.get('testTimeout', 30)

    tests = conf['tests']
    skipped_tests_conf = conf['skipped_tests']
    nightly_integrations = conf['nightly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']
    unmockable_integrations = conf['unmockable_integrations']

    secret_params = secret_conf['integrations'] if secret_conf else []

    filtered_tests, is_filter_configured, run_all_tests = extract_filtered_tests(tests_settings.nightly)
    if is_filter_configured and not run_all_tests:
        is_nightly = True

    if not tests or len(tests) == 0:
        prints_manager.add_print_job('no integrations are configured for test', print, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        return

    proxy = None
    if is_ami:
        ami = AMIConnection(server_ip)
        ami.clone_mock_data()
        proxy = MITMProxy(server_ip)

    failed_playbooks = []
    succeed_playbooks = []
    skipped_tests = set([])
    skipped_integration = set([])

    disable_all_integrations(demisto_api_key, server, prints_manager, thread_index=thread_index)
    prints_manager.execute_thread_prints(thread_index)
    mockable_tests = get_test_records_of_given_test_names(tests_settings, mockable_tests_names)
    unmockable_tests = get_test_records_of_given_test_names(tests_settings, unmockable_tests_names)

    if is_nightly and is_memory_check:
        mem_lim, err = get_docker_limit()
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID,
                           'Build Number: {0}\n Server Address: {1}\nMemory Limit: {2}'.format(build_number, server,
                                                                                               mem_lim),
                           'Content CircleCI', 'False')
    # first run the mock tests to avoid mockless side effects in container
    if is_ami and mockable_tests:
        proxy.configure_proxy_in_demisto(demisto_api_key, server, proxy.ami.docker_ip + ':' + proxy.PROXY_PORT)
        for t in mockable_tests:
            run_test_scenario(tests_settings, t, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                              skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests,
                              is_filter_configured,
                              filtered_tests, skipped_tests, secret_params, failed_playbooks,
                              unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server,
                              build_name, server_numeric_version, demisto_api_key, prints_manager,
                              thread_index=thread_index)
        prints_manager.add_print_job("\nRunning mock-disabled tests", print, thread_index)
        proxy.configure_proxy_in_demisto(demisto_api_key, server, '')
        prints_manager.add_print_job('Resetting containers', print, thread_index)
        client = demisto_client.configure(base_url=server, api_key=demisto_api_key, verify_ssl=False)
        body, status_code, headers = demisto_client.generic_request_func(self=client, method='POST',
                                                                         path='/containers/reset')
        if status_code != 200:
            error_msg = 'Request to reset containers failed with status code "{}"\n{}'.format(status_code, body)
            prints_manager.add_print_job(error_msg, print_error, thread_index)
            prints_manager.execute_thread_prints(thread_index)
            sys.exit(1)
        sleep(10)
    for t in unmockable_tests:
        run_test_scenario(tests_settings, t, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                          skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests,
                          is_filter_configured,
                          filtered_tests, skipped_tests, secret_params, failed_playbooks,
                          unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server,
                          build_name, server_numeric_version, demisto_api_key,
                          prints_manager, thread_index, is_ami)

        prints_manager.execute_thread_prints(thread_index)

    tests_data_keeper.add_tests_data(succeed_playbooks, failed_playbooks, skipped_tests,
                                     skipped_integration, unmockable_integrations)
    if not tests_settings.is_local_run:
        tests_data_keeper.add_proxy_related_test_data(proxy)

    if is_ami and build_name == 'master':
        updating_mocks_msg = "Pushing new/updated mock files to mock git repo."
        prints_manager.add_print_job(updating_mocks_msg, print, thread_index)
        ami.upload_mock_files(build_name, build_number)


def get_unmockable_tests(tests_settings):
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
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
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    tests_records = conf['tests']
    all_tests = []
    for test_record in tests_records:
        test_name = test_record.get("playbookID")
        if test_name:
            all_tests.append(test_name)
    return all_tests


def manage_tests(tests_settings):
    """
    This function manages the execution of Demisto's tests.

    Args:
        tests_settings (TestsSettings): An object containing all the relevant data regarding how the tests should be ran

    """
    tests_settings.serverNumericVersion = get_and_print_server_numeric_version(tests_settings)
    instances_ips = get_instances_ips_and_names(tests_settings)
    is_nightly = tests_settings.nightly
    server_version = tests_settings.serverVersion
    number_of_instances = len(instances_ips)
    prints_manager = ParallelPrintsManager(number_of_instances)
    tests_data_keeper = TestsDataKeeper()

    if tests_settings.server:
        # If the user supplied a server - all tests will be done on that server.
        server_ip = tests_settings.server
        print_color("Starting tests for {}".format(server_ip), LOG_COLORS.GREEN)
        print("Starts tests with server url - https://{}".format(server_ip))
        all_tests = get_all_tests(tests_settings)
        mockable_tests = []
        print(tests_settings.specific_tests_to_run)
        unmockable_tests = tests_settings.specific_tests_to_run if tests_settings.specific_tests_to_run else all_tests
        execute_testing(tests_settings, server_ip, mockable_tests, unmockable_tests, tests_data_keeper, prints_manager,
                        thread_index=0, is_ami=False)
    elif tests_settings.isAMI:
        """
        Running tests in AMI configuration.
        This is the way we run most tests, including running Circle for PRs and nightly.
        """
        if is_nightly:
            """
            If the build is a nightly build, run tests in parallel.
            """
            test_allocation = get_tests_allocation_for_threads(number_of_instances, tests_settings.conf_path)
            current_thread_index = 0
            all_unmockable_tests_list = get_unmockable_tests(tests_settings)
            threads_array = []
            for ami_instance_name, ami_instance_ip in instances_ips:
                if ami_instance_name == server_version:  # Only run tests for server master
                    current_instance = ami_instance_ip
                    tests_allocation_for_instance = test_allocation[current_thread_index]

                    unmockable_tests = [test for test in all_unmockable_tests_list
                                        if test in tests_allocation_for_instance]
                    mockable_tests = [test for test in tests_allocation_for_instance if test not in unmockable_tests]
                    print_color("Starting tests for {}".format(ami_instance_name), LOG_COLORS.GREEN)
                    print("Starts tests with server url - https://{}".format(ami_instance_ip))

                    if number_of_instances == 1:
                        execute_testing(tests_settings, current_instance, mockable_tests, unmockable_tests,
                                        tests_data_keeper, prints_manager, thread_index=0, is_ami=True)
                    else:
                        thread_kwargs = {
                            "tests_settings": tests_settings,
                            "server_ip": current_instance,
                            "mockable_tests_names": mockable_tests,
                            "unmockable_tests_names": unmockable_tests,
                            "thread_index": current_thread_index,
                            "prints_manager": prints_manager,
                            "tests_data_keeper": tests_data_keeper
                        }
                        t = threading.Thread(target=execute_testing, kwargs=thread_kwargs)
                        threads_array.append(t)
                        t.start()
                        current_thread_index += 1
            for t in threads_array:
                t.join()

        else:
            for ami_instance_name, ami_instance_ip in instances_ips:
                if ami_instance_name == tests_settings.serverVersion:
                    print_color("Starting tests for {}".format(ami_instance_name), LOG_COLORS.GREEN)
                    print("Starts tests with server url - https://{}".format(ami_instance_ip))
                    all_tests = get_all_tests(tests_settings)
                    unmockable_tests = get_unmockable_tests(tests_settings)
                    mockable_tests = [test for test in all_tests if test not in unmockable_tests]
                    execute_testing(tests_settings, ami_instance_ip, mockable_tests, unmockable_tests,
                                    tests_data_keeper, prints_manager, thread_index=0, is_ami=True)
                    sleep(8)

    else:
        # TODO: understand better when this occurs and what will be the settings
        """
        This case is rare, and usually occurs on two cases:
        1. When someone from Server wants to trigger a content build on their branch.
        2. When someone from content wants to run tests on a specific build.
        """
        server_numeric_version = '99.99.98'  # assume latest
        print("Using server version: {} (assuming latest for non-ami)".format(server_numeric_version))
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ips = instance_file.readlines()
            instance_ip = [line.strip('\n').split(":")[1] for line in instance_ips][0]
        all_tests = get_all_tests(tests_settings)
        execute_testing(tests_settings, instance_ip, [], all_tests,
                        tests_data_keeper, prints_manager, thread_index=0, is_ami=False)

    print_test_summary(tests_data_keeper, tests_settings.isAMI)
    create_result_files(tests_data_keeper)

    if len(tests_data_keeper.failed_playbooks):
        tests_failed_msg = "Some tests have failed. Not destroying instances."
        print(tests_failed_msg)
        sys.exit(1)
    else:
        file_path = "./Tests/is_build_passed_{}.txt".format(tests_settings.serverVersion.replace(' ', ''))
        with open(file_path, "w") as is_build_passed_file:
            is_build_passed_file.write('Build passed')


def main():
    print("Time is: {}\n\n\n".format(datetime.now()))
    tests_settings = options_handler()

    # should be removed after solving: https://github.com/demisto/etc/issues/21383
    # -------------
    if 'master' in tests_settings.serverVersion.lower():
        sleep(100)
        print('slept for 100 secs')
        sleep(100)
        print('slept for 100 secs')
    # -------------
    manage_tests(tests_settings)


if __name__ == '__main__':
    main()
