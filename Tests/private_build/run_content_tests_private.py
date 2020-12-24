from __future__ import print_function
import sys
import time
import argparse
from time import sleep
from distutils.version import LooseVersion
from typing import Any

import logging
import urllib3
import demisto_client.demisto_api

from Tests.scripts.utils.log_util import install_logging
from Tests.test_integration import check_integration
from demisto_sdk.commands.common.constants import PB_Status
from demisto_sdk.commands.common.tools import str2bool

from Tests.test_content import SettingsTester, DataKeeperTester, \
    print_test_summary, update_test_msg, turn_off_telemetry, \
    create_result_files, get_all_tests, get_instances_ips_and_names, get_server_numeric_version, \
    initialize_queue_and_executed_tests_set, get_test_records_of_given_test_names, \
    extract_filtered_tests, load_conf_files, set_integration_params, collect_integrations, notify_failed_test, \
    SERVER_URL

# Disable insecure warnings
from demisto_sdk.commands.test_content.Docker import Docker

urllib3.disable_warnings()


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
    tests_settings = SettingsTester(options)
    return tests_settings


def run_test_logic(tests_settings: Any, c: Any, failed_playbooks: list,
                   integrations: list, playbook_id: str, succeed_playbooks: list, test_message: str,
                   test_options: dict, slack: Any, circle_ci: str, build_number: str, server_url: str,
                   demisto_user: str, demisto_pass: str, build_name: str) -> bool:
    """
    run_test_logic handles the testing of the integration by triggering check_integration. afterwards
    it will check the status of the test and report success or add the failed test to the list of
    failed integrations.

    :param tests_settings: SettingsTester object which contains the test variables
    :param c: Client for connecting to XSOAR via demisto-py
    :param failed_playbooks: List of failed playbooks, additional failed playbooks will be added if
                             they failed.
    :param integrations: List of integrations being tested.
    :param playbook_id: ID of the test playbook being tested.
    :param succeed_playbooks: List of playbooks which have passed tests.
    :param test_message: Name of the playbook/integration being tested. This is reported back in the
                         build and used to print in the console the test being ran.
    :param test_options: Options being passed to the test. PID, Docker Threshold, Timeout, etc.
    :param slack: Slack client used for notifications.
    :param circle_ci: CircleCI token. Used to get name of dev who triggered the build.
    :param build_number: The build number of the CI run. Used in slack message.
    :param server_url: The FQDN of the server tests are being ran on.
    :param demisto_user: Username of the demisto user running the tests.
    :param demisto_pass: Password of the demisto user running the tests.
    :param build_name: Name of the build. (Nightly, etc.)
    :return: Boolean indicating if the test was successful.
    """
    status, inc_id = check_integration(c, server_url, demisto_user, demisto_pass, integrations, playbook_id,
                                       options=test_options)
    if status == PB_Status.COMPLETED:
        logging.success(f'PASS: {test_message} succeed')
        succeed_playbooks.append(playbook_id)

    elif status == PB_Status.NOT_SUPPORTED_VERSION:
        logging.info(f'PASS: {test_message} skipped - not supported version')
        succeed_playbooks.append(playbook_id)

    else:
        logging.error(f'Failed: {test_message} failed')
        playbook_id_with_mock = playbook_id
        playbook_id_with_mock += " (Mock Disabled)"
        failed_playbooks.append(playbook_id_with_mock)
        if not tests_settings.is_local_run:
            notify_failed_test(slack, circle_ci, playbook_id, build_number, inc_id, server_url,
                               build_name)

    succeed = status in (PB_Status.COMPLETED, PB_Status.NOT_SUPPORTED_VERSION)

    return succeed


def run_test(tests_settings: SettingsTester, demisto_user: str, demisto_pass: str,
             failed_playbooks: list, integrations: list, playbook_id: str, succeed_playbooks: list,
             test_message: str, test_options: dict, slack: str, circle_ci: str, build_number: str,
             server_url: str, build_name: str) -> None:
    """
    Wrapper for the run_test_logic function. Helps by indicating when the test is starting and ending.

    :param tests_settings: SettingsTester object which contains the test variables
    :param demisto_user: Username of the demisto user running the tests.
    :param demisto_pass: Password of the demisto user running the tests.
    :param failed_playbooks: List of failed playbooks, additional failed playbooks will be added if
                             they failed.
    :param integrations: List of integrations being tested.
    :param playbook_id: ID of the test playbook being tested.
    :param succeed_playbooks: List of playbooks which have passed tests.
    :param test_message: Name of the playbook/integration being tested. This is reported back in the
                         build and used to print in the console the test being ran.
    :param test_options: Options being passed to the test. PID, Docker Threshold, Timeout, etc.
    :param slack: Slack client used for notifications.
    :param circle_ci: CircleCI token. Used to get name of dev who triggered the build.
    :param build_number: The build number of the CI run. Used in slack message.
    :param server_url: The FQDN of the server tests are being ran on.
    :param build_name: Name of the build. (Nightly, etc.)
    :return: No object is returned.
    """
    start_message = f'------ Test {test_message} start ------'
    client = demisto_client.configure(base_url=server_url, username=demisto_user, password=demisto_pass,
                                      verify_ssl=False)
    logging.info(start_message + ' (Private Build Test)')
    run_test_logic(tests_settings, client, failed_playbooks, integrations, playbook_id,
                   succeed_playbooks, test_message, test_options, slack, circle_ci, build_number,
                   server_url, demisto_user, demisto_pass, build_name)
    logging.info(f'------ Test {test_message} end ------\n')

    return


def run_private_test_scenario(tests_settings: SettingsTester, t: dict, default_test_timeout: int,
                              skipped_tests_conf: set, nightly_integrations: list, skipped_integrations_conf: set,
                              skipped_integration: set, filtered_tests: list, skipped_tests: set, secret_params: dict,
                              failed_playbooks: list, playbook_skipped_integration: set, succeed_playbooks: list,
                              slack: str, circle_ci: str, build_number: str, server: str, build_name: str,
                              server_numeric_version: str, demisto_user: str, demisto_pass: str, demisto_api_key: str):
    """
    Checks to see if test should run given the scenario. If the test should run, it will collect the
    integrations which are required to run the test.

    :param tests_settings: SettingsTester object which contains the test variables
    :param t: Options being passed to the test. PID, Docker Threshold, Timeout, etc.
    :param default_test_timeout: Time in seconds indicating when the test should timeout if no
                                 status is reported.
    :param skipped_tests_conf: Collection of the tests which are skipped.
    :param nightly_integrations: List of integrations which should only be tested on a nightly build.
    :param skipped_integrations_conf: Collection of integrations which are skiped.
    :param skipped_integration: Set of skipped integrations. Currently not used in private.
    :param filtered_tests: List of tests excluded from testing.
    :param skipped_tests: List of skipped tests.
    :param secret_params: Parameters found in the content-test-conf. Used to configure the instance.
    :param failed_playbooks: List of failed playbooks, additional failed playbooks will be added if
                             they failed.
    :param playbook_skipped_integration: Not used.
    :param succeed_playbooks: List of playbooks which have passed tests.
    :param slack: Slack client used for notifications.
    :param circle_ci: CircleCI token. Used to get name of dev who triggered the build.
    :param build_number: The build number of the CI run. Used in slack message.
    :param server: The FQDN of the server tests are being ran on.
    :param build_name: Name of the build. (Nightly, etc.)
    :param server_numeric_version: Version of XSOAR currently installed on the server.
    :param demisto_user: Username of the demisto user running the tests.
    :param demisto_pass: Password of the demisto user running the tests.
    :param demisto_api_key: API key for the demisto instance.
    :return:
    """
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

    # Skip tests that are missing from filtered list
    if filtered_tests and playbook_id not in filtered_tests:
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
        warning_message = f'Test {test_message} ignored due to version mismatch ' \
                          f'(test versions: {test_from_version}-{test_to_version})'
        logging.warning(warning_message)
        return

    placeholders_map = {'%%SERVER_HOST%%': server}
    are_params_set = set_integration_params(demisto_api_key, integrations, secret_params, instance_names_conf,
                                            playbook_id, placeholders_map)
    if not are_params_set:
        failed_playbooks.append(playbook_id)
        return

    test_message = update_test_msg(integrations, test_message)
    run_test(tests_settings, demisto_user, demisto_pass, failed_playbooks, integrations,
             playbook_id, succeed_playbooks, test_message, test_options, slack, circle_ci,
             build_number, server, build_name)


def execute_testing(tests_settings: SettingsTester, server_ip: str, all_tests: set,
                    tests_data_keeper: DataKeeperTester):
    """
    Main function used to handle the testing process. Starts by turning off telemetry and disabling
    any left over tests. Afterwards it will create a test queue object which then is used to run the
    specific test scenario.

    :param tests_settings: SettingsTester object which contains the test variables
    :param server_ip: IP address of the server. Will be formatted before use.
    :param all_tests: All tests currently in the test conf.
    :param tests_data_keeper: Object containing all the test results. Used by report tests function.
    :return: No object is returned, just updates the tests_data_keep object.
    """
    server = SERVER_URL.format(server_ip)
    server_numeric_version = tests_settings.serverNumericVersion
    logging.info(f"Executing tests with the server {server} - and the server ip {server_ip}")
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

    filtered_tests = extract_filtered_tests()

    if not tests or len(tests) == 0:
        logging.info('no integrations are configured for test')
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

    #  Private builds do not use mocking. Here we copy the mocked test list to the unmockable list.
    private_tests = get_test_records_of_given_test_names(tests_settings, all_tests)
    try:
        # first run the mock tests to avoid mockless side effects in container
        logging.info("\nRunning private tests")
        executed_in_current_round, private_tests_queue = initialize_queue_and_executed_tests_set(private_tests)
        while not private_tests_queue.empty():
            t = private_tests_queue.get()
            executed_in_current_round = update_round_set_and_sleep_if_round_completed(
                executed_in_current_round, t)
            run_private_test_scenario(tests_settings, t, default_test_timeout, skipped_tests_conf,
                                      nightly_integrations, skipped_integrations_conf,
                                      skipped_integration,
                                      filtered_tests, skipped_tests, secret_params,
                                      failed_playbooks, playbook_skipped_integration,
                                      succeed_playbooks, slack, circle_ci, build_number, server,
                                      build_name, server_numeric_version, demisto_user,
                                      demisto_pass, demisto_api_key)

    except Exception:
        logging.exception('~~ Thread Failed ~~')
        raise

    finally:
        tests_data_keeper.add_tests_data(succeed_playbooks, failed_playbooks, skipped_tests,
                                         skipped_integration, unmockable_integrations)


def update_round_set_and_sleep_if_round_completed(executed_in_current_round: set,
                                                  t: dict) -> set:
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
        t: test configuration as it appears in conf.json file

    Returns:
        A new executed_in_current_round set which contains only the current tests configuration if a
        round was completed else it just adds the new test to the set.
    """
    if str(t) in executed_in_current_round:
        logging.info(
            'all tests in the queue were executed, sleeping for 30 seconds to let locked tests get unlocked.')
        executed_in_current_round = set()
        time.sleep(30)
    executed_in_current_round.add(str(t))
    return executed_in_current_round


def manage_tests(tests_settings: SettingsTester):
    """
    This function manages the execution of Demisto's tests.

    Args:
        tests_settings (SettingsTester): An object containing all the relevant data regarding how the
                                        tests should be ran.

    """
    tests_settings.serverNumericVersion = get_server_numeric_version(tests_settings.serverVersion,
                                                                     tests_settings.is_local_run)
    instances_ips = get_instances_ips_and_names(tests_settings)
    tests_data_keeper = DataKeeperTester()

    for ami_instance_name, ami_instance_ip in instances_ips:
        if ami_instance_name == tests_settings.serverVersion:
            logging.info(f"Starting private testing for {ami_instance_name}")
            logging.info(f"Starts tests with server url - https://{ami_instance_ip}")
            all_tests = get_all_tests(tests_settings)
            execute_testing(tests_settings, ami_instance_ip, all_tests, tests_data_keeper)
            sleep(8)

    print_test_summary(tests_data_keeper, tests_settings.isAMI)
    create_result_files(tests_data_keeper)

    if tests_data_keeper.failed_playbooks:
        tests_failed_msg = "Some tests have failed. Not destroying instances."
        print(tests_failed_msg)
        sys.exit(1)


def main():
    install_logging('Run_Tests.log')
    tests_settings = options_handler()
    manage_tests(tests_settings)


if __name__ == '__main__':
    main()
