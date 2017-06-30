import argparse
import demisto
from test_integration import test_integration
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

    all_completed = True
    for integration in integrations:
        test_options = {
            'timeout': integration['timeout'] if 'timeout' in integration else conf.get('testTimeout'),
            'interval': conf['testInterval']
        }
        all_completed = test_integration(c, integration['name'], integration['params'], integration['playbookID'], test_options) and all_completed

    if not all_completed:
        sys.exit(1)

if __name__ == '__main__':
    main()
