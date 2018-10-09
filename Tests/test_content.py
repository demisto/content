import os
import sys
import json
import string
import random
import argparse

import demisto
from test_integration import test_integration
from test_utils import print_color, print_error, print_warning, LOG_COLORS


FILTER_CONF = "./Tests/filter_file.txt"


def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to', required=True)
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file')
    parser.add_argument('-n', '--nightly', type=str2bool, help='Run nightly tests')
    options = parser.parse_args()

    return options


def print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration):
    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)
    skipped_count = len(skipped_tests)

    print('\nTEST RESULTS:')
    print('\t Number of playbooks tested - ' + str(succeed_count + failed_count))
    print_color('\t Number of succeeded tests - ' + str(succeed_count), LOG_COLORS.GREEN)

    if len(skipped_integration) > 0:
        print_warning('\t Number of skipped integration - ' + str(len(skipped_integration)) + ':')
        for playbook_id in skipped_integration:
            print_warning('\t - ' + playbook_id)

    if skipped_count > 0:
        print_warning('\t Number of skipped tests - ' + str(skipped_count) + ':')
        for playbook_id in skipped_tests:
            print_warning('\t - ' + playbook_id)

    if failed_count > 0:
        print_error('\t Number of failed tests - ' + str(failed_count) + ':')
        for playbook_id in failed_playbooks:
            print_error('\t - ' + playbook_id)


def main():
    options = options_handler()
    username = options.user
    password = options.password
    server = options.server
    conf_path = options.conf
    secret_conf_path = options.secret
    is_nightly = options.nightly

    if not (username and password and server):
        print_error('You must provide server user & password arguments')
        sys.exit(1)

    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code is not 200:
        print_error("Login has failed with status code " + str(res.status_code))
        sys.exit(1)

    demisto_api_key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    apikey_json = {
                    'name': 'test_apikey',
                    'apikey': demisto_api_key
                  }
    c.req('POST', '/apikeys', apikey_json)

    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    tests = conf['tests']
    skipped_tests_conf = conf['skipped_tests']
    skipped_integrations_conf = conf['skipped_integrations']

    secret_params = secret_conf['integrations'] if secret_conf else []

    with open(FILTER_CONF, 'r') as filter_file:
        filterd_tests = filter_file.readlines()
        filterd_tests = [line.strip('\n') for line in filterd_tests]
        is_filter_configured = True if filterd_tests else False

    if is_filter_configured:
        is_nightly = True

    if not tests or len(tests) is 0:
        print('no integrations are configured for test')
        return

    skipped_integration = []
    succeed_playbooks = []
    failed_playbooks = []
    skipped_tests = []
    for t in tests:
        playbook_id = t['playbookID']
        integrations_conf = t.get('integrations', [])

        nightly_test = t.get('nightly', False)
        skip_test = True if nightly_test and not is_nightly else False

        if skip_test:
            print '------ Test %s start ------' % (test_message, )
            print 'Skip test'
            print '------ Test %s end ------' % (test_message,)

            continue

        if not is_filter_configured and playbook_id in skipped_tests_conf:
            skipped_tests.append(playbook_id)
            continue

        if is_filter_configured and playbook_id not in filterd_tests:
            continue

        test_options = {
            'timeout': t['timeout'] if 'timeout' in t else conf.get('testTimeout', 30),
            'interval': conf.get('testInterval', 10)
        }

        if not isinstance(integrations_conf, list):
            integrations_conf = [integrations_conf]

        integrations = []
        has_skipped_integration = False
        for integration in integrations_conf:
            if type(integration) is dict:
                name = integration.get('name')
                if name in skipped_integrations_conf:
                    if not is_filter_configured and name not in skipped_integration:
                        skipped_integration.append(name)

                    has_skipped_integration = True
                    break

                # dict description
                integrations.append({
                    'name': integration.get('name'),
                    'byoi': integration.get('byoi',True),
                    'params': {}
                })
            else:
                if integration in skipped_integrations_conf:
                    if not is_filter_configured and integration not in skipped_integration:
                        skipped_integration.append(integration)

                    has_skipped_integration = True
                    break

                # string description
                integrations.append({
                    'name': integration,
                    'byoi': True,
                    'params': {}
                })

        if has_skipped_integration:
            continue

        for integration in integrations:
            integration_params = [item for item in secret_params if item["name"] == integration['name']]
            if integration_params:
                integration['params'] = integration_params[0].get('params', {})
            elif 'Demisto REST API' == integration['name']:
                integration['params'] = {
                                            'url': 'https://localhost',
                                            'apikey': demisto_api_key,
                                            'insecure': True,
                                        }

        test_message = 'playbook: ' + playbook_id
        if integrations:
            integrations_names = [integration['name'] for integration in integrations]
            test_message = test_message + ' with integration(s): ' + ','.join(integrations_names)

        print '------ Test %s start ------' % (test_message, )

        # run test
        succeed = test_integration(c, integrations, playbook_id, test_options)

        # use results
        if succeed:
            print 'PASS: %s succeed' % (test_message,)
            succeed_playbooks.append(playbook_id)
        else:
            print 'Failed: %s failed' % (test_message,)
            failed_playbooks.append(playbook_id)

        print '------ Test %s end ------' % (test_message,)

    print_test_summary(succeed_playbooks, failed_playbooks, skipped_tests, skipped_integration)
    os.remove(FILTER_CONF)

    with open("./Tests/failed_tests.txt", "w") as failed_tests_file:
        failed_tests_file.write('\n'.join(failed_playbooks))

    with open('./Tests/skipped_tests.txt', "w") as skipped_tests_file:
        skipped_tests_file.write('\n'.join(skipped_tests))

    with open('./Tests/skipped_integrations.txt', "w") as skipped_integrations_file:
        skipped_integrations_file.write('\n'.join(skipped_integration))

    if len(failed_playbooks):
        sys.exit(1)

if __name__ == '__main__':
    main()
