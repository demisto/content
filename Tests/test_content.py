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

    integrations = conf['integrations']

    secret_integrations = secret_conf['integrations'] if secret_conf else []

    if not integrations or len(integrations) is 0:
        print('no integrations are configured for test')
        return

    succeed_playbooks = []
    failed_playbooks = []
    for integration in integrations:
        test_options = {
            'timeout': integration['timeout'] if 'timeout' in integration else conf.get('testTimeout', 30),
            'interval': conf.get('testInterval', 10)
        }

        integration_name = integration.get(['name'], None)
        playbook_id = integration['playbookID']
        if 'params' in integration:
            integration_params = integration['params']
        else:
            # get from secret conf
            secret_integration_match = [item for item in secret_integrations if item["name"] == integration_name]
            if len(secret_integration_match) > 0:
                integration_params = secret_integration_match[0].get('params')
            else:
                integration_params = {}

        if integration_name:
            test_message = 'integration: ' + integration_name + ' with playbook: ' + playbook_id
        else:
            test_message = 'playbook: ' + playbook_id
        print '------ Test %s start ------' % (test_message, )

        nightly_test = integration.get('nightly', False)

        is_byoi = integration.get('byoi', True)

        skip_test_playbook = True if nightly_test and not is_nightly else False

        # run test
        succeed = test_integration(c, integration_name, integration_params, playbook_id,
                                   skip_test_playbook, is_byoi, test_options)

        # use results
        if succeed:
            print 'PASS: %s succeed' % (test_message, )
            succeed_playbooks.append(playbook_id)
        else:
            print 'Failed: %s failed' % (test_message,)
            failed_playbooks.append(playbook_id)

        print '------ Test %s end ------' % (test_message, )

    print_test_summary(succeed_playbooks, failed_playbooks)
    if len(failed_playbooks):
        sys.exit(1)

if __name__ == '__main__':
    main()
