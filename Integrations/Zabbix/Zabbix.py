import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
from pyzabbix import ZabbixAPI
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class ZabbixIntegration:
    def __init__(self):
        params = demisto.params()
        self.ZABBIX_URL = params.get('url')
        self.ZABBIX_USER = params.get('credentials').get('identifier')
        self.ZABBIX_PASSWORD = params.get('credentials').get('password')

    def execute_command(self, zapi, args):
        method = args.get('method')
        params = json.loads(args.get('params', '{}'))
        return zapi.do_request(method, params)

    def login(self):
        zapi = ZabbixAPI(self.ZABBIX_URL)
        zapi.login(self.ZABBIX_USER, self.ZABBIX_PASSWORD)
        return zapi

    def logout(self, zapi):
        zapi.do_request('user.logout')

    def main(self):
        try:
            result = None
            zapi = self.login()

            if demisto.command() == 'execute_command':
                result = self.execute_command(zapi, demisto.args())

            self.logout(zapi)
            demisto.results(result)

        except Exception as e:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    zabbixIntegration = ZabbixIntegration()
    zabbixIntegration.main()
