import re
import sys
import json
import argparse
import requests
import subprocess
from time import sleep
from datetime import datetime

import demisto_client.demisto_api
from slackclient import SlackClient

from Tests.test_integration import test_integration, disable_all_integrations
from Tests.mock_server import MITMProxy, AMIConnection
from Tests.test_utils import print_color, print_error, print_warning, LOG_COLORS, str2bool, server_version_compare
from Tests.scripts.constants import RUN_ALL_TESTS_FORMAT, FILTER_CONF, PB_Status

SERVER_URL = "https://{}"
INTEGRATIONS_CONF = "./Tests/integrations_file.txt"

FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using the " \
                            "instance_name argument in conf.json. The options are:\n{}"

AMI_NAMES = ["Demisto GA", "Server Master", "Demisto one before GA", "Demisto two before GA"]

SERVICE_RESTART_TIMEOUT = 300
SERVICE_RESTART_POLLING_INTERVAL = 5

SLACK_MEM_CHANNEL_ID = 'CM55V7J8K'


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
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

    options = parser.parse_args()

    return options


def print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration,
                       unmocklable_integrations, proxy, is_ami=True):
    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)
    skipped_count = len(skipped_tests)
    rerecorded_count = len(proxy.rerecorded_tests) if is_ami else 0
    empty_mocks_count = len(proxy.empty_files) if is_ami else 0
    unmocklable_integrations_count = len(unmocklable_integrations)

    print('\nTEST RESULTS:')
    print('\t Number of playbooks tested - ' + str(succeed_count + failed_count))
    print_color('\t Number of succeeded tests - ' + str(succeed_count), LOG_COLORS.GREEN)

    if failed_count > 0:
        print_error('\t Number of failed tests - ' + str(failed_count) + ':')
        for playbook_id in failed_playbooks:
            print_error('\t - ' + playbook_id)

    if rerecorded_count > 0:
        print_warning('\t Tests with failed playback and successful re-recording - ' + str(rerecorded_count) + ':')
        for playbook_id in proxy.rerecorded_tests:
            print_warning('\t - ' + playbook_id)

    if empty_mocks_count > 0:
        print('\t Successful tests with empty mock files - ' + str(empty_mocks_count) + ':')
        print('\t (either there were no http requests or no traffic is passed through the proxy.\n'
              '\t Investigate the playbook and the integrations.\n'
              '\t If the integration has no http traffic, add to unmockable_integrations in conf.json)')
        for playbook_id in proxy.empty_files:
            print('\t - ' + playbook_id)

    if len(skipped_integration) > 0:
        print_warning('\t Number of skipped integration - ' + str(len(skipped_integration)) + ':')
        for playbook_id in skipped_integration:
            print_warning('\t - ' + playbook_id)

    if skipped_count > 0:
        print_warning('\t Number of skipped tests - ' + str(skipped_count) + ':')
        for playbook_id in skipped_tests:
            print_warning('\t - ' + playbook_id)

    if unmocklable_integrations_count > 0:
        print_warning('\t Number of unmockable integrations - ' + str(unmocklable_integrations_count) + ':')
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


def run_test_logic(c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message, test_options, slack,
                   circle_ci, build_number, server_url, build_name, is_mock_run=False):
    status, inc_id = test_integration(c, integrations, playbook_id, test_options, is_mock_run)

    if status == PB_Status.COMPLETED:
        print_color('PASS: {} succeed'.format(test_message), LOG_COLORS.GREEN)
        succeed_playbooks.append(playbook_id)

    elif status == PB_Status.NOT_SUPPORTED_VERSION:
        print('PASS: {} skipped - not supported version'.format(test_message))
        succeed_playbooks.append(playbook_id)

    else:
        print_error('Failed: {} failed'.format(test_message))
        playbook_id_with_mock = playbook_id
        if not is_mock_run:
            playbook_id_with_mock += " (Mock Disabled)"
        failed_playbooks.append(playbook_id_with_mock)
        notify_failed_test(slack, circle_ci, playbook_id, build_number, inc_id, server_url, build_name)

    succeed = status == PB_Status.COMPLETED or status == PB_Status.NOT_SUPPORTED_VERSION
    return succeed


# run the test using a real instance, record traffic.
def run_and_record(c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                   test_message, test_options, slack, circle_ci, build_number, server_url, build_name):
    proxy.set_tmp_folder()
    proxy.start(playbook_id, record=True)
    succeed = run_test_logic(c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message,
                             test_options, slack, circle_ci, build_number, server_url, build_name, is_mock_run=True)
    proxy.stop()
    if succeed:
        proxy.move_mock_file_to_repo(playbook_id)

    proxy.set_repo_folder()
    return succeed


def mock_run(c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name, start_message):
    rerecord = False

    if proxy.has_mock_file(playbook_id):
        print('{} (Mock: Playback)'.format(start_message))
        proxy.start(playbook_id)
        # run test
        status, inc_id = test_integration(c, integrations, playbook_id, test_options, is_mock_run=True)
        # use results
        proxy.stop()
        if status == PB_Status.COMPLETED:
            print_color('PASS: {} succeed'.format(test_message), LOG_COLORS.GREEN)
            succeed_playbooks.append(playbook_id)
            print('------ Test {} end ------\n'.format(test_message))

            return

        elif status == PB_Status.NOT_SUPPORTED_VERSION:
            print('PASS: {} skipped - not supported version'.format(test_message))
            succeed_playbooks.append(playbook_id)
            print('------ Test {} end ------\n'.format(test_message))

            return

        else:
            print("Test failed with mock, recording new mock file. (Mock: Recording)")
            rerecord = True
    else:
        print(start_message + ' (Mock: Recording)')

    # Mock recording - no mock file or playback failure.
    succeed = run_and_record(c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                             test_message, test_options, slack, circle_ci, build_number, server_url, build_name)

    if rerecord and succeed:
        proxy.rerecorded_tests.append(playbook_id)
    print('------ Test {} end ------\n'.format(test_message))


def run_test(c, proxy, failed_playbooks, integrations, unmockable_integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name, is_ami=True):
    start_message = '------ Test %s start ------' % (test_message,)

    if not is_ami or (not integrations or has_unmockable_integration(integrations, unmockable_integrations)):
        print(start_message + ' (Mock: Disabled)')
        run_test_logic(c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message, test_options,
                       slack, circle_ci, build_number, server_url, build_name)
        print('------ Test %s end ------\n' % (test_message,))

        return

    mock_run(c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name, start_message)


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


def create_result_files(failed_playbooks, skipped_integration, skipped_tests):
    with open("./Tests/failed_tests.txt", "w") as failed_tests_file:
        failed_tests_file.write('\n'.join(failed_playbooks))
    with open('./Tests/skipped_tests.txt', "w") as skipped_tests_file:
        skipped_tests_file.write('\n'.join(skipped_tests))
    with open('./Tests/skipped_integrations.txt', "w") as skipped_integrations_file:
        skipped_integrations_file.write('\n'.join(skipped_integration))


def set_integration_params(demisto_api_key, integrations, secret_params, instance_names, playbook_id):
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
                    print_error(FAILED_MATCH_INSTANCE_MSG.format(playbook_id, len(integration_params),
                                                                 integration['name'],
                                                                 '\n'.join(optional_instance_names)))
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
            integration['instance_name'] = matched_integration_params.get('instance_name', integration['name'])
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


def extract_filtered_tests():
    with open(FILTER_CONF, 'r') as filter_file:
        filtered_tests = filter_file.readlines()
        filtered_tests = [line.strip('\n') for line in filtered_tests]
        is_filter_configured = True if filtered_tests else False
        run_all = True if RUN_ALL_TESTS_FORMAT in filtered_tests else False

    return filtered_tests, is_filter_configured, run_all


def generate_demisto_api_key():
    with open("./conf_secret.json", "r") as conf_json:
        data = json.load(conf_json)
        demisto_api_key = data['temp_apikey']
    return demisto_api_key


def load_conf_files(conf_path, secret_conf_path):
    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    return conf, secret_conf


def organize_tests(tests, unmockable_integrations, skipped_integrations_conf, nightly_integrations):
    mock_tests, mockless_tests = [], []
    for test in tests:
        integrations_conf = test.get('integrations', [])

        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf, ]

        has_skipped_integration, integrations, is_nightly_integration = collect_integrations(
            integrations_conf, set(), skipped_integrations_conf, nightly_integrations)

        if not integrations or has_unmockable_integration(integrations, unmockable_integrations):
            mockless_tests.append(test)
        else:
            mock_tests.append(test)

    return mock_tests, mockless_tests


def run_test_scenario(t, c, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                      skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests, is_filter_configured,
                      filtered_tests, skipped_tests, demisto_api_key, secret_params, failed_playbooks,
                      unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server, build_name,
                      server_numeric_version, is_ami=True):
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
        print('\n------ Test {} start ------'.format(test_message))
        print('Skip test')
        print('------ Test {} end ------\n'.format(test_message))

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
        print('\n------ Test {} start ------'.format(test_message))
        print_warning('Test {} ignored due to version mismatch (test versions: {}-{})'.format(test_message,
                                                                                              test_from_version,
                                                                                              test_to_version))
        print('------ Test {} end ------\n'.format(test_message))
        return

    are_params_set = set_integration_params(demisto_api_key, integrations,
                                            secret_params, instance_names_conf, playbook_id)
    if not are_params_set:
        failed_playbooks.append(playbook_id)
        return

    test_message = update_test_msg(integrations, test_message)
    options = options_handler()
    stdout, stderr = get_docker_memory_data()
    text = 'Memory Usage: {}'.format(stdout) if not stderr else stderr
    if options.nightly and options.memCheck:
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')
        stdout, stderr = get_docker_processes_data()
        text = stdout if not stderr else stderr
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID, text, 'Content CircleCI', 'False')

    run_test(c, proxy, failed_playbooks, integrations, unmockable_integrations, playbook_id,
             succeed_playbooks, test_message, test_options, slack, circle_ci,
             build_number, server, build_name, is_ami)


def restart_demisto_service(ami, c):
    ami.check_call(['sudo', 'service', 'demisto', 'restart'])
    exit_code = 1
    for _ in range(0, SERVICE_RESTART_TIMEOUT, SERVICE_RESTART_POLLING_INTERVAL):
        sleep(SERVICE_RESTART_POLLING_INTERVAL)
        if exit_code != 0:
            exit_code = ami.call(['/usr/sbin/service', 'demisto', 'status', '--lines', '0'])
        if exit_code == 0:
            print("{}: Checking login to the server... ".format(datetime.now()))
            try:
                res = demisto_client.generic_request_func(self=c, path='/health', method='GET')
                if int(res[1]) == 200:
                    return
                else:
                    print("Failed verifying login (will retry). status: {}. text: {}".format(res.status_code, res.text))
            except Exception as ex:
                print_error("Failed verifying server start via login: {}".format(ex))

    raise Exception('Timeout waiting for demisto service to restart')


def execute_testing(server, server_ip, server_version, server_numeric_version, is_ami=True):
    print("Executing tests with the server {} - and the server ip {}".format(server, server_ip))

    options = options_handler()
    username = options.user
    password = options.password
    conf_path = options.conf
    secret_conf_path = options.secret
    is_nightly = options.nightly
    is_memory_check = options.memCheck
    slack = options.slack
    circle_ci = options.circleci
    build_number = options.buildNumber
    build_name = options.buildName

    demisto_api_key = generate_demisto_api_key()
    c = demisto_client.configure(base_url=server, api_key=demisto_api_key, verify_ssl=False)

    conf, secret_conf = load_conf_files(conf_path, secret_conf_path)

    default_test_timeout = conf.get('testTimeout', 30)

    tests = conf['tests']
    skipped_tests_conf = conf['skipped_tests']
    nightly_integrations = conf['nightly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']
    unmockable_integrations = conf['unmockable_integrations']

    secret_params = secret_conf['integrations'] if secret_conf else []

    filtered_tests, is_filter_configured, run_all_tests = extract_filtered_tests()
    if is_filter_configured and not run_all_tests:
        is_nightly = True

    if not tests or len(tests) == 0:
        print('no integrations are configured for test')
        return

    proxy = None
    if is_ami:
        ami = AMIConnection(server_ip)
        ami.clone_mock_data()
        proxy = MITMProxy(c, server_ip)

    failed_playbooks = []
    succeed_playbooks = []
    skipped_tests = set([])
    skipped_integration = set([])

    disable_all_integrations(c)

    if is_ami:
        # move all mock tests to the top of the list
        mock_tests, mockless_tests = organize_tests(tests, unmockable_integrations, skipped_integrations_conf,
                                                    nightly_integrations)
    else:  # In case of a non AMI run we don't want to use the mocking mechanism
        mockless_tests = tests
    if is_nightly and is_memory_check:
        mem_lim, err = get_docker_limit()
        send_slack_message(slack, SLACK_MEM_CHANNEL_ID,
                           'Build Number: {0}\n Server Address: {1}\nMemory Limit: {2}'.format(build_number, server,
                                                                                               mem_lim),
                           'Content CircleCI', 'False')
    # first run the mock tests to avoid mockless side effects in container
    if is_ami and mock_tests:
        proxy.configure_proxy_in_demisto(proxy.ami.docker_ip + ':' + proxy.PROXY_PORT)
        for t in mock_tests:
            run_test_scenario(t, c, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                              skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests,
                              is_filter_configured,
                              filtered_tests, skipped_tests, demisto_api_key, secret_params, failed_playbooks,
                              unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server,
                              build_name, server_numeric_version)

        print("\nRunning mock-disabled tests")
        proxy.configure_proxy_in_demisto('')
        print("Restarting demisto service")
        restart_demisto_service(ami, c)
        print("Demisto service restarted\n")

    for t in mockless_tests:
        run_test_scenario(t, c, proxy, default_test_timeout, skipped_tests_conf, nightly_integrations,
                          skipped_integrations_conf, skipped_integration, is_nightly, run_all_tests,
                          is_filter_configured,
                          filtered_tests, skipped_tests, demisto_api_key, secret_params, failed_playbooks,
                          unmockable_integrations, succeed_playbooks, slack, circle_ci, build_number, server,
                          build_name, server_numeric_version, is_ami)

    print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration, unmockable_integrations,
                       proxy, is_ami)

    create_result_files(failed_playbooks, skipped_integration, skipped_tests)

    if is_ami and build_name == 'master':
        print("Pushing new/updated mock files to mock git repo.")
        ami.upload_mock_files(build_name, build_number)

    if len(failed_playbooks):
        file_path = "./Tests/is_build_failed_{}.txt".format(server_version.replace(' ', ''))
        with open(file_path, "w") as is_build_failed_file:
            is_build_failed_file.write('Build failed')

        sys.exit(1)


def main():
    options = options_handler()
    server = options.server
    is_ami = options.isAMI
    server_version = options.serverVersion
    server_numeric_version = '0.0.0'

    if is_ami:  # Run tests in AMI configuration
        with open('./Tests/images_data.txt', 'r') as image_data_file:
            image_data = [line for line in image_data_file if line.startswith(server_version)]
            if len(image_data) != 1:
                print('Did not get one image data for server version, got {}'.format(image_data))
            else:
                server_numeric_version = re.findall('Demisto-Circle-CI-Content-[\w-]+-([\d.]+)-[\d]{5}', image_data[0])
                if server_numeric_version:
                    server_numeric_version = server_numeric_version[0]
                else:
                    server_numeric_version = '99.99.98'  # latest
                print('Server image info: {}'.format(image_data[0]))
                print('Server version: {}'.format(server_numeric_version))

        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ips = instance_file.readlines()
            instance_ips = [line.strip('\n').split(":") for line in instance_ips]

        for ami_instance_name, ami_instance_ip in instance_ips:
            if ami_instance_name == server_version:
                print_color("Starting tests for {}".format(ami_instance_name), LOG_COLORS.GREEN)
                print("Starts tests with server url - https://{}".format(ami_instance_ip))
                server = SERVER_URL.format(ami_instance_ip)
                execute_testing(server, ami_instance_ip, server_version, server_numeric_version)
                sleep(8)

    else:  # Run tests in Server build configuration
        server_numeric_version = '99.99.98'  # assume latest
        print("Using server version: {} (assuming latest for non-ami)".format(server_numeric_version))
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ips = instance_file.readlines()
            instance_ip = [line.strip('\n').split(":")[1] for line in instance_ips][0]

        execute_testing(SERVER_URL.format(instance_ip), instance_ip, server_version, server_numeric_version,
                        is_ami=False)


if __name__ == '__main__':
    main()
