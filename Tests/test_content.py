import sys
import json
import string
import random
import argparse
import requests
from time import sleep

import demisto
from slackclient import SlackClient

from test_integration import test_integration
from mock_server import MITMProxy, AMIConnection
from Tests.test_utils import print_color, print_error, print_warning, LOG_COLORS, str2bool
from Tests.scripts.constants import RUN_ALL_TESTS_FORMAT, FILTER_CONF


SERVER_URL = "https://{}"
INTEGRATIONS_CONF = "./Tests/integrations_file.txt"

FAILED_MATCH_INSTANCE_MSG = "{} Failed to run.\n There are {} instances of {}, please select one of them by using the "\
                            "instance_name argument in conf.json. The options are:\n{}"

AMI_NAMES = ["Demisto GA", "Server Master", "Demisto one before GA", "Demisto two before GA"]


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
    parser.add_argument('-d', '--serverVersion', help='Which server version to run the '
                                                      'tests on(Valid only when using AMI)')
    options = parser.parse_args()

    return options


def print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration,
                       unmocklable_integrations, proxy):
    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)
    skipped_count = len(skipped_tests)
    rerecorded_count = len(proxy.rerecorded_tests)
    empty_mocks_count = len(proxy.empty_files)
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
        print '\t (either there were no http requests or no traffic is passed through the proxy.\n' \
              '\t Investigate the playbook and the integrations.\n' \
              '\t If the integration has no http traffic, add to unmockable_integrations in conf.json)'
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
        for playbook_id, reason in unmocklable_integrations.iteritems():
            print_warning('\t - ' + playbook_id + ' - ' + reason)


def update_test_msg(integrations, test_message):
    if integrations:
        integrations_names = [integration['name'] for integration in
                              integrations]
        test_message = test_message + ' with integration(s): ' + ','.join(
            integrations_names)

    return test_message


def has_unmockable_integration(integrations, unmockable_integrations):
    return list(set(x['name'] for x in integrations).intersection(unmockable_integrations.iterkeys()))


def run_test_logic(c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message, test_options, slack,
                   circle_ci, build_number, server_url, build_name, is_mock_run=False):
    succeed, inc_id = test_integration(c, integrations, playbook_id, test_options, is_mock_run)
    if succeed:
        print 'PASS: %s succeed' % (test_message,)
        succeed_playbooks.append(playbook_id)
    else:
        print 'Failed: %s failed' % (test_message,)
        playbook_id_with_mock = playbook_id
        if not is_mock_run:
            playbook_id_with_mock += " (Mock Disabled)"
        failed_playbooks.append(playbook_id_with_mock)
        notify_failed_test(slack, circle_ci, playbook_id, build_number, inc_id, server_url, build_name)
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
        print start_message + ' (Mock: Playback)'
        proxy.start(playbook_id)
        # run test
        succeed, inc_id = test_integration(c, integrations, playbook_id, test_options, is_mock_run=True)
        # use results
        proxy.stop()
        if succeed:
            print 'PASS: %s succeed' % (test_message,)
            succeed_playbooks.append(playbook_id)
            print '------ Test %s end ------' % (test_message,)

            return

        else:
            print "Test failed with mock, recording new mock file."
            rerecord = True
    else:
        print start_message + ' (Mock: Recording)'

    # Mock recording - no mock file or playback failure.
    succeed = run_and_record(c, proxy, failed_playbooks, integrations, playbook_id, succeed_playbooks,
                             test_message, test_options, slack, circle_ci, build_number, server_url, build_name)

    if rerecord and succeed:
        proxy.rerecorded_tests.append(playbook_id)
    print '------ Test %s end ------' % (test_message,)


def run_test(c, proxy, failed_playbooks, integrations, unmockable_integrations, playbook_id, succeed_playbooks,
             test_message, test_options, slack, circle_ci, build_number, server_url, build_name):
    start_message = '------ Test %s start ------' % (test_message,)

    if not integrations or has_unmockable_integration(integrations, unmockable_integrations):
        print start_message + ' (Mock: Disabled)'
        run_test_logic(c, failed_playbooks, integrations, playbook_id, succeed_playbooks, test_message, test_options,
                       slack, circle_ci, build_number, server_url, build_name)
        print '------ Test %s end ------' % (test_message,)

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

    except Exception, e:
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
                    optional_instance_names = [optional_integration.get('instance_name') for optional_integration in
                                               integration_params]
                    print_error(FAILED_MATCH_INSTANCE_MSG.format(playbook_id, len(integration_params),
                                                                 integration['name'],
                                                                 '\n'.join(optional_instance_names)))
                    return False

            integration['params'] = matched_integration_params.get('params', {})
            integration['byoi'] = matched_integration_params.get('byoi', True)
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


def generate_demisto_api_key(c):
    demisto_api_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    apikey_json = {
        'name': 'test_apikey',
        'apikey': demisto_api_key
    }
    c.req('POST', '/apikeys', apikey_json)
    return demisto_api_key


def load_conf_files(conf_path, secret_conf_path):
    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    return conf, secret_conf


def organize_tests(tests, unmockable_integrations):
    mock_tests, mockless_tests = [], []
    for test in tests:
        if any(integration in unmockable_integrations for integration in test.get('integrations', [])):
            mockless_tests.append(test)
        else:
            mock_tests.append(test)

    # first run the mock tests to avoid mockless side effects in container
    return mock_tests + mockless_tests


def execute_testing(server, server_ip, server_version):
    options = options_handler()
    username = options.user
    password = options.password
    conf_path = options.conf
    secret_conf_path = options.secret
    is_nightly = options.nightly
    slack = options.slack
    circle_ci = options.circleci
    build_number = options.buildNumber
    build_name = options.buildName

    if not (username and password and server):
        print_error('You must provide server user & password arguments')
        sys.exit(1)

    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code != 200:
        print_error("Login has failed with status code " + str(res.status_code))
        sys.exit(1)

    demisto_api_key = generate_demisto_api_key(c)

    conf, secret_conf = load_conf_files(conf_path, secret_conf_path)

    default_test_timeout = conf.get('testTimeout', 30)

    tests = conf['tests']
    skipped_tests_conf = conf['skipped_tests']
    nightly_integrations = conf['nigthly_integrations']
    skipped_integrations_conf = conf['skipped_integrations']
    unmockable_integrations = conf['unmockable_integrations']

    secret_params = secret_conf['integrations'] if secret_conf else []

    filtered_tests, is_filter_configured, run_all_tests = extract_filtered_tests()
    if is_filter_configured and not run_all_tests:
        is_nightly = True

    if not tests or len(tests) == 0:
        print('no integrations are configured for test')
        return

    ami = AMIConnection(server_ip)
    ami.clone_mock_data()
    proxy = MITMProxy(c, server_ip)

    failed_playbooks = []
    succeed_playbooks = []
    skipped_tests = set([])
    skipped_integration = set([])

    # move all mock tests to the top of the list
    tests = organize_tests(tests, unmockable_integrations)

    for t in tests:
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
            print '------ Test %s start ------' % (test_message,)
            print 'Skip test'
            print '------ Test %s end ------' % (test_message,)

            continue

        if not run_all_tests:
            # Skip filtered test
            if is_filter_configured and playbook_id not in filtered_tests:
                continue

        # Skip bad test
        if playbook_id in skipped_tests_conf.keys():
            skipped_tests.add("{0} - reason: {1}".format(playbook_id, skipped_tests_conf[playbook_id]))
            continue

        # Skip integration
        if has_skipped_integration:
            continue

        are_params_set = set_integration_params(demisto_api_key, integrations,
                                                secret_params, instance_names_conf, playbook_id)
        if not are_params_set:
            failed_playbooks.append(playbook_id)
            continue

        test_message = update_test_msg(integrations, test_message)

        run_test(c, proxy, failed_playbooks, integrations, unmockable_integrations, playbook_id,
                 succeed_playbooks, test_message, test_options, slack, circle_ci,
                 build_number, server, build_name)

    print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration, unmockable_integrations,
                       proxy)

    create_result_files(failed_playbooks, skipped_integration, skipped_tests)

    if build_name == 'master':
        print "Pushing new/updated mock files to mock git repo."
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

    if is_ami:  # Run tests in AMI configuration
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ips = instance_file.readlines()
            instance_ips = [line.strip('\n').split(":") for line in instance_ips]

        for ami_instance_name, ami_instance_ip in instance_ips:
            if ami_instance_name == server_version and ami_instance_name != "Demisto two before GA":
                # TODO: remove the and condition once version 4.5 is out
                print_color("Starting tests for {}".format(ami_instance_name), LOG_COLORS.GREEN)
                print("Starts tests with server url - https://{}".format(ami_instance_ip))
                server = SERVER_URL.format(ami_instance_ip)
                execute_testing(server, ami_instance_ip, server_version)
                sleep(8)

    else:  # Run tests in Server build configuration
        with open('public_ip', 'rb') as f:
            public_ip = f.read().strip()

        execute_testing(server, public_ip, server_version)


if __name__ == '__main__':
    main()
