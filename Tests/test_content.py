import argparse
import demisto
from test_integration import test_integration
from test_utils import print_color, print_error, LOG_COLORS
import json
import sys


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


def print_test_summary(succeed_playbooks, failed_playbooks):
    succeed_count = len(succeed_playbooks)
    failed_count = len(failed_playbooks)

    print('\nTEST RESULTS:')
    print('\t Number of playbooks tested - ' + str(succeed_count + failed_count))
    print_color('\t Number of succeeded tests - ' + str(succeed_count), LOG_COLORS.GREEN)
    if len(failed_playbooks) > 0:
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
        exit(1)

    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code is not 200:
        print_error("Login has failed with status code " + str(res.status_code))
        exit(1)

    with open(conf_path) as data_file:
        conf = json.load(data_file)

    secret_conf = None
    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)

    tests = conf['tests']

    secret_params = secret_conf['integrations'] if secret_conf else []

    if not tests or len(tests) is 0:
        print('no integrations are configured for test')
        return

    succeed_playbooks = []
    failed_playbooks = []
    for t in tests:
        test_options = {
            'timeout': t['timeout'] if 'timeout' in t else conf.get('testTimeout', 30),
            'interval': conf.get('testInterval', 10)
        }

        playbook_id = t['playbookID']

        integration_names = t.get('integrations', None)
        if integration_names is None:
            integration_names = []
        elif not isinstance(integration_names, list):
            integration_names = [integration_names]

        integrations = [{'name': name, 'params': {}} for name in integration_names]

        for integration in integrations:
            integration_params = [item for item in secret_params if item["name"] == integration['name']]
            if integration_params:
                integration['params'] = integration_params[0].get('params', {})

        test_message = 'playbook: ' + playbook_id
        if integrations:
            test_message = test_message + ' with integration(s): ' + ','.join(integration_names)

        print '------ Test %s start ------' % (test_message, )

        nightly_test = t.get('nightly', False)

        is_byoi = t.get('byoi', True)

        skip_test = True if nightly_test and not is_nightly else False

        if skip_test:
            print 'Skip test'
        else:
            # run test
            succeed = test_integration(c, integrations, playbook_id, is_byoi, test_options)

            # use results
            if succeed:
                print 'PASS: %s succeed' % (test_message,)
                succeed_playbooks.append(playbook_id)
            else:
                print 'Failed: %s failed' % (test_message,)
                failed_playbooks.append(playbook_id)

        print '------ Test %s end ------' % (test_message,)

    print_test_summary(succeed_playbooks, failed_playbooks)
    if len(failed_playbooks):
        sys.exit(1)

if __name__ == '__main__':
    main()
