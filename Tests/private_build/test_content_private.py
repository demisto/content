from __future__ import print_function
import os
import re
import sys
import json
import time
import argparse
import threading
import subprocess
import traceback
from time import sleep
import datetime
from distutils.version import LooseVersion

import pytz

from google.cloud import storage
from google.api_core.exceptions import PreconditionFailed
from queue import Queue
from contextlib import contextmanager

import urllib3
import requests
import demisto_client.demisto_api
from demisto_client.demisto_api.rest import ApiException
from slackclient import SlackClient

from Tests.test_integration import Docker, test_integration, disable_all_integrations
from demisto_sdk.commands.common.constants import RUN_ALL_TESTS_FORMAT, FILTER_CONF, PB_Status
from demisto_sdk.commands.common.tools import print_color, print_error, print_warning, \
    LOG_COLORS, str2bool

from Tests.test_content import TestsSettings, PrintJob, ParallelPrintsManager, TestsDataKeeper, \
    print_test_summary, update_test_msg, turn_off_telemetry, reset_containers, run_test_logic, \
    create_result_files, get_all_tests, get_instances_ips_and_names, get_server_numeric_version, \
    initialize_queue_and_executed_tests_set, get_test_records_of_given_test_names, \
    extract_filtered_tests, load_conf_files, set_integration_params, collect_integrations

# Disable insecure warnings
urllib3.disable_warnings()

SERVER_URL = "https://{}"
INTEGRATIONS_CONF = "./Tests/integrations_file.txt"

FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using " \
                            "the instance_name argument in conf.json. The options are:\n{}"

SERVICE_RESTART_TIMEOUT = 300
SERVICE_RESTART_POLLING_INTERVAL = 5
LOCKS_PATH = 'content-locks'
BUCKET_NAME = os.environ.get('GCS_ARTIFACTS_BUCKET')
CIRCLE_BUILD_NUM = os.environ.get('CIRCLE_BUILD_NUM')
WORKFLOW_ID = os.environ.get('CIRCLE_WORKFLOW_ID')
CIRCLE_STATUS_TOKEN = os.environ.get('CIRCLECI_STATUS_TOKEN')
SLACK_MEM_CHANNEL_ID = 'CM55V7J8K'
PROXY_LOG_FILE_NAME = 'proxy_metrics.csv'
ENV_RESULTS_PATH = './env_results.json'


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
    parser.add_argument('-p', '--private', help='Is the build private.', type=str2bool, required=False, default=False)
    parser.add_argument('-sa', '--service_account', help="Path to GCS service account.", required=False)
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


def run_test(tests_settings, demisto_user, demisto_pass,
             failed_playbooks, integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name,
             prints_manager, thread_index=0):
    start_message = f'------ Test {test_message} start ------'
    client = demisto_client.configure(base_url=server_url, username=demisto_user, password=demisto_pass, verify_ssl=False)
    prints_manager.add_print_job(start_message + ' (Private Build Test)', print, thread_index,
                                 include_timestamp=True)
    run_test_logic(tests_settings, client, failed_playbooks, integrations, playbook_id,
                   succeed_playbooks, test_message, test_options, slack, circle_ci, build_number,
                   server_url, demisto_user, demisto_pass, build_name, prints_manager,
                   thread_index=thread_index)
    prints_manager.add_print_job('------ Test %s end ------\n' % (test_message,), print,
                                 thread_index,
                                 include_timestamp=True)

    return


def run_private_test_scenario(tests_settings, t, default_test_timeout, skipped_tests_conf,
                      nightly_integrations, skipped_integrations_conf, skipped_integration,
                      run_all_tests, is_filter_configured, filtered_tests, skipped_tests, secret_params,
                      failed_playbooks, playbook_skipped_integration,
                      succeed_playbooks, slack, circle_ci, build_number, server, build_name,
                      server_numeric_version, demisto_user, demisto_pass, demisto_api_key,
                      prints_manager, thread_index=0):
    playbook_id = t['playbookID']
    integrations_conf = t.get('integrations', [])
    instance_names_conf = t.get('instance_names', [])

    test_message = 'playbook: ' + playbook_id

    test_options = {
        'timeout': t.get('timeout', default_test_timeout),
        'memory_threshold': t.get('memory_threshold', Docker.DEFAULT_CONTAINER_MEMORY_USAGE),
        'pid_threshold': t.get('pid_threshold', Docker.DEFAULT_CONTAINER_PIDS_USAGE)
    }

    if not isinstance(integrations_conf, list):
        integrations_conf = [integrations_conf, ]

    if not isinstance(instance_names_conf, list):
        instance_names_conf = [instance_names_conf, ]

    test_skipped_integration, integrations, is_nightly_integration = collect_integrations(
        integrations_conf, skipped_integration, skipped_integrations_conf, nightly_integrations)

    if playbook_id in filtered_tests:
        playbook_skipped_integration.update(test_skipped_integration)

    if not run_all_tests:
        # Skip filtered test
        if is_filter_configured and playbook_id not in filtered_tests:
            return

    # Skip bad test
    if playbook_id in skipped_tests_conf:
        skipped_tests.add(f'{playbook_id} - reason: {skipped_tests_conf[playbook_id]}')
        return

    # Skip integration
    if test_skipped_integration:
        return

    # Skip version mismatch test
    test_from_version = t.get('fromversion', '0.0.0')
    test_to_version = t.get('toversion', '99.99.99')

    if not (LooseVersion(test_from_version) <= LooseVersion(server_numeric_version) <= LooseVersion(test_to_version)):
        prints_manager.add_print_job(f'\n------ Test {test_message} start ------', print, thread_index,
                                     include_timestamp=True)
        warning_message = 'Test {} ignored due to version mismatch (test versions: {}-{})'.format(test_message,
                                                                                                  test_from_version,
                                                                                                  test_to_version)
        prints_manager.add_print_job(warning_message, print_warning, thread_index)
        prints_manager.add_print_job(f'------ Test {test_message} end ------\n', print, thread_index,
                                     include_timestamp=True)
        return

    placeholders_map = {'%%SERVER_HOST%%': server}
    are_params_set = set_integration_params(demisto_api_key, integrations, secret_params, instance_names_conf,
                                            playbook_id, prints_manager, placeholders_map, thread_index=thread_index)
    if not are_params_set:
        failed_playbooks.append(playbook_id)
        return

    test_message = update_test_msg(integrations, test_message)
    run_test(tests_settings, demisto_user, demisto_pass, failed_playbooks, integrations,
             playbook_id, succeed_playbooks, test_message, test_options, slack, circle_ci,
             build_number, server, build_name, prints_manager, thread_index=thread_index)


def execute_testing(tests_settings, server_ip, all_tests,
                    tests_data_keeper, prints_manager, thread_index=0):
    server = SERVER_URL.format(server_ip)
    server_numeric_version = tests_settings.serverNumericVersion
    start_message = "Executing tests with the server {} - and the server ip {}".format(server, server_ip)
    prints_manager.add_print_job(start_message, print, thread_index)
    slack = tests_settings.slack
    circle_ci = tests_settings.circleci
    build_number = tests_settings.buildNumber
    build_name = tests_settings.buildName
    conf, secret_conf = load_conf_files(tests_settings.conf_path, tests_settings.secret_conf_path)
    demisto_api_key = tests_settings.api_key
    demisto_user = secret_conf['username']
    demisto_pass = secret_conf['userPassword']

    default_test_timeout = conf.get('testTimeout', 30)

    tests = conf['tests']
    skipped_tests_conf = conf['skipped_tests']
    nightly_integrations = conf['nightly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']
    unmockable_integrations = conf['unmockable_integrations']

    secret_params = secret_conf['integrations'] if secret_conf else []

    filtered_tests, is_filter_configured, run_all_tests = extract_filtered_tests()

    if not tests or len(tests) == 0:
        prints_manager.add_print_job('no integrations are configured for test', print, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        return
    xsoar_client = demisto_client.configure(base_url=server, username=demisto_user,
                                            password=demisto_pass, verify_ssl=False)

    # turn off telemetry
    turn_off_telemetry(xsoar_client)

    failed_playbooks = []
    succeed_playbooks = []
    skipped_tests = set([])
    skipped_integration = set([])
    playbook_skipped_integration = set([])

    disable_all_integrations(xsoar_client, prints_manager, thread_index=thread_index)
    prints_manager.execute_thread_prints(thread_index)
    #  Private builds do not use mocking. Here we copy the mocked test list to the unmockable list.
    private_tests = get_test_records_of_given_test_names(tests_settings, all_tests)
    try:
        # first run the mock tests to avoid mockless side effects in container
        prints_manager.add_print_job("\nRunning private tests", print, thread_index)
        executed_in_current_round, private_tests_queue = initialize_queue_and_executed_tests_set(private_tests)
        while not private_tests_queue.empty():
            t = private_tests_queue.get()
            executed_in_current_round = update_round_set_and_sleep_if_round_completed(
                executed_in_current_round, prints_manager, t, thread_index)
            run_private_test_scenario(tests_settings, t, default_test_timeout, skipped_tests_conf,
                                      nightly_integrations, skipped_integrations_conf,
                                      skipped_integration, run_all_tests, is_filter_configured,
                                      filtered_tests, skipped_tests, secret_params,
                                      failed_playbooks, playbook_skipped_integration,
                                      succeed_playbooks, slack, circle_ci, build_number, server,
                                      build_name, server_numeric_version, demisto_user,
                                      demisto_pass, demisto_api_key, prints_manager,
                                      thread_index=thread_index)
            prints_manager.execute_thread_prints(thread_index)

    except Exception as exc:
        if exc.__class__ == ApiException:
            error_message = exc.body
        else:
            error_message = f'~~ Thread {thread_index + 1} failed ~~\n{str(exc)}\n{traceback.format_exc()}'
        prints_manager.add_print_job(error_message, print_error, thread_index)
        prints_manager.execute_thread_prints(thread_index)
        failed_playbooks.append(f'~~ Thread {thread_index + 1} failed ~~')
        raise

    finally:
        tests_data_keeper.add_tests_data(succeed_playbooks, failed_playbooks, skipped_tests,
                                         skipped_integration, unmockable_integrations)


def update_round_set_and_sleep_if_round_completed(executed_in_current_round: set,
                                                  prints_manager: ParallelPrintsManager,
                                                  t: dict,
                                                  thread_index: int) -> set:
    """
    Checks if the string representation of the current test configuration is already in
    the executed_in_current_round set.
    If it is- it means we have already executed this test and the we have reached a round and
    there are tests that
    were not able to be locked by this execution..
    In that case we want to start a new round monitoring by emptying the
    'executed_in_current_round' set and sleep
    in order to let the tests be unlocked
    Args:
        executed_in_current_round: A set containing the string representation of all tests
        configuration as they appear
        in conf.json file that were already executed in the current round
        prints_manager: ParallelPrintsManager object
        t: test configuration as it appears in conf.json file
        thread_index: Currently executing thread
        unmockable_tests_queue: The queue of remaining tests

    Returns:
        A new executed_in_current_round set which contains only the current tests configuration if a round was completed
        else it just adds the new test to the set.
    """
    if str(t) in executed_in_current_round:
        prints_manager.add_print_job(
            'all tests in the queue were executed, sleeping for 30 seconds to let locked tests get unlocked.',
            print,
            thread_index)
        executed_in_current_round = set()
        time.sleep(30)
    executed_in_current_round.add(str(t))
    return executed_in_current_round


def manage_tests(tests_settings):
    """
    This function manages the execution of Demisto's tests.

    Args:
        tests_settings (TestsSettings): An object containing all the relevant data regarding how the tests should be ran

    """
    tests_settings.serverNumericVersion = get_server_numeric_version(tests_settings.serverVersion,
                                                                     tests_settings.is_local_run)
    instances_ips = get_instances_ips_and_names(tests_settings)
    number_of_instances = len(instances_ips)
    prints_manager = ParallelPrintsManager(number_of_instances)
    tests_data_keeper = TestsDataKeeper()

    for ami_instance_name, ami_instance_ip in instances_ips:
        if ami_instance_name == tests_settings.serverVersion:
            print_color("Starting private testing for {}".format(ami_instance_name), LOG_COLORS.GREEN)
            print("Starts tests with server url - https://{}".format(ami_instance_ip))
            all_tests = get_all_tests(tests_settings)
            execute_testing(tests_settings, ami_instance_ip, all_tests, tests_data_keeper,
                            prints_manager, thread_index=0)
            sleep(8)

    print_test_summary(tests_data_keeper, tests_settings.isAMI)
    create_result_files(tests_data_keeper)

    if tests_data_keeper.failed_playbooks:
        tests_failed_msg = "Some tests have failed. Not destroying instances."
        print(tests_failed_msg)
        sys.exit(1)


def main():
    print("Time is: {}\n\n\n".format(datetime.datetime.now()))
    tests_settings = options_handler()
    manage_tests(tests_settings)


if __name__ == '__main__':
    main()
