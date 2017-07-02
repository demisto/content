import argparse
import demisto
from pprint import pprint
from test_integration import test_integration
from test_utils import print_color, print_error, LOG_COLORS
import json
import sys


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for batch action on incidents')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-s', '--server', help='The server URL to connect to', required=True)
    parser.add_argument('-c', '--conf', help='Path to conf file', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file')
    options = parser.parse_args()

    return options


def print_test_summary(succeed_integration, failed_integrations):
    print '\nINTEGRATIONS TEST RESULTS:'
    print_color('\t Number of succeeded tests - ' + str(len(succeed_integration)), LOG_COLORS.GREEN)
    if len(failed_integrations) > 0:
        print_error('\t Number of failed tests - ' + str(len(failed_integrations)) + ':')
        for integration_name in failed_integrations:
            print_error('\t - ' + integration_name)


def main():
    options = options_handler()
    username = options.user
    password = options.password
    server = options.server
    conf_path = options.conf
    secret_conf_path = options.secret

    if not (username and password and server):
        raise ValueError('You must provide server user & password arguments')

    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code is not 200:
        raise ValueError("Login has failed with status code " + str(res.status_code))

    with open(conf_path) as data_file:
        conf = json.load(data_file)

    if secret_conf_path:
        with open(secret_conf_path) as data_file:
            secret_conf = json.load(data_file)
            pprint(secret_conf)

    integrations = conf['integrations']

    secret_integrations = secret_conf['integrations'] if secret_conf else []

    if not integrations or len(integrations) is 0:
        print 'no integrations are configured for test'

    succeed_integrations = []
    failed_integrations = []
    for integration in integrations:
        test_options = {
            'timeout': integration['timeout'] if 'timeout' in integration else conf.get('testTimeout'),
            'interval': conf['testInterval']
        }

        integration_name = integration['name']
        playbook_id = integration['playbookID']
        if 'params' in integration:
            integration_params = integration['params']
        else:
            # get from secret conf
            print("### secret_integrations")
            print(secret_integrations)
            secret_integration_match = (item for item in secret_integrations if item["name"] == integration_name).next()
            if len(secret_integration_match) > 0:
                print("### secret_integration_match")
                print(secret_integration_match)
                integration_params = secret_integration_match.get('params')
            else:
                integration_params = {}
        print("integration_params")
        print(integration_params)
        print('------ Test integration: ' + integration_name + ' with playbook: ' + playbook_id + ' start ------')

        # run test
        succeed = test_integration(c, integration_name, integration_params, playbook_id, test_options)

        # use results
        if succeed:
            print 'PASS: Integration ' + integration_name + ' succeed'
            succeed_integrations.append(integration['name'])
        else:
            print_error('FAILED: Integration ' + integration_name + ' failed')
            failed_integrations.append(integration['name'])

        print('------ Test integration: ' + integration_name + ' end ------')

    print_test_summary(succeed_integrations, failed_integrations)
    if len(failed_integrations):
        sys.exit(1)

if __name__ == '__main__':
    main()
