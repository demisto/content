import argparse
import demisto
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
    options = parser.parse_args()

    return options


def print_test_summary(succeed_integration, failed_integrations):
    print '--- INTEGRATIONS TEST RESULTS:'
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
    conf = options.conf

    if not (username and password and server):
        raise ValueError('You must provide server user & password arguments')

    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code is not 200:
        raise ValueError("Login has failed with status code " + str(res.status_code))

    with open(conf) as data_file:
        conf = json.load(data_file)

    integrations = conf['integrations']
    if not integrations or len(integrations) is 0:
        print 'no integrations are configured for test'

    succeed_integrations = []
    failed_integrations = []
    for integration in integrations:
        test_options = {
            'timeout': integration['timeout'] if 'timeout' in integration else conf.get('testTimeout'),
            'interval': conf['testInterval']
        }
        succeed = \
            test_integration(c, integration['name'], integration['params'], integration['playbookID'], test_options)
        if succeed:
            succeed_integrations.append(integration['name'])
        else:
            failed_integrations.append(integration['name'])

    print_test_summary(succeed_integrations, failed_integrations)
    if len(failed_integrations):
        sys.exit(1)

if __name__ == '__main__':
    main()
