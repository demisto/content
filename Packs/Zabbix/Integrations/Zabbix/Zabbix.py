import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
from pyzabbix import ZabbixAPI
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class ZabbixIntegration:
    def __init__(self):
        params = demisto.params()
        self.ZABBIX_URL = params.get('url')
        self.ZABBIX_USER = params.get('credentials').get('identifier')
        self.ZABBIX_PASSWORD = params.get('credentials').get('password')

    def execute_command(self, zapi, method, args):
        params = json.loads(args.get('params', '{}'))
        for key in args:
            if key.startswith("params_") and args[key] is not None:
                params[key.replace("params_", "")] = args[key]
        return zapi.do_request(method, params)['result']

    def login(self):
        zapi = ZabbixAPI(self.ZABBIX_URL)
        zapi.login(self.ZABBIX_USER, self.ZABBIX_PASSWORD)
        return zapi

    def logout(self, zapi):
        zapi.do_request('user.logout')

    def output_path(self, command):
        return '.'.join([w.capitalize() for w in command.split('-')[:-1]])

    def main(self):
        try:
            known_commands = ['zabbix-host-get', 'zabbix-hostgroup-get', 'zabbix-trigger-get', 'zabbix-event-get']
            command = demisto.command()
            args = demisto.args()
            if command == 'test-module':
                demisto.results('ok')
                return

            result = None
            zapi = self.login()
            if command == 'zabbix-execute-command':
                result = self.execute_command(zapi, args.get('method'), args)
            elif command in known_commands:
                result = self.execute_command(zapi, command.replace('zabbix-', '').replace('-', '.'), demisto.args())
            else:
                return_error("Unknown command " + command)

            self.logout(zapi)

            return_outputs(
                tableToMarkdown(f'{command}', result if isinstance(result, list) else [result]),
                outputs={
                    self.output_path(command): result
                },
                raw_response=result
            )

        except Exception as e:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    zabbixIntegration = ZabbixIntegration()
    zabbixIntegration.main()
