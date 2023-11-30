import Zabbix
from pyzabbix import ZabbixAPI


class TestZabbix():

    def test_get_host(self, mocker):
        mocker.patch('demistomock.params', return_value={
            'url': 'http://localhost',
            'credentials': {
                'identifier': 'user',
                'password': 'password'
            }
        })
        zapi = ZabbixApiStub()
        spy = mocker.spy(zapi, 'do_request')
        args = {
            'method': 'host.get',
            'params': '{}'
        }

        zabbix = Zabbix.ZabbixIntegration()
        result = zabbix.execute_command(zapi, 'host.get', args)

        assert result['status'] == 'Ok'
        spy.assert_called_once_with('host.get', {})

    def test_login(self, mocker):
        mocker.patch('demistomock.params', return_value={
            'url': 'http://localhost',
            'credentials': {
                'identifier': 'user',
                'password': 'password'
            }
        })

        mocker.patch('pyzabbix.ZabbixAPI.__init__', return_value=None)
        mocker.patch('pyzabbix.ZabbixAPI.login', return_value=None)

        zabbix = Zabbix.ZabbixIntegration()
        zabbix.login()

        ZabbixAPI.__init__.assert_called_once_with('http://localhost')
        ZabbixAPI.login.assert_called_once_with('user', 'password')

    def test_logout(self, mocker):
        mocker.patch('demistomock.params', return_value={
            'url': 'http://localhost',
            'credentials': {
                'identifier': 'user',
                'password': 'password'
            }
        })
        zapi = ZabbixApiStub()
        spy = mocker.spy(zapi, 'do_request')

        zabbix = Zabbix.ZabbixIntegration()
        zabbix.logout(zapi)

        spy.assert_called_once_with('user.logout')

    def test_main_get_host(self, mocker):
        mocker.patch('demistomock.params', return_value={
            'url': 'http://localhost',
            'credentials': {
                'identifier': 'user',
                'password': 'password'
            }
        })
        mocker.patch('demistomock.args', return_value={
            'method': 'host.get'
        })
        mocker.patch('demistomock.command', return_value='zabbix-execute-command')

        zapi = ZabbixApiStub()

        mocker.patch('Zabbix.ZabbixIntegration.login', return_value=zapi)
        mocker.patch('Zabbix.ZabbixIntegration.logout')

        spy = mocker.spy(zapi, 'do_request')

        zabbix = Zabbix.ZabbixIntegration()
        zabbix.main()

        spy.assert_called_once_with('host.get', {})


class ZabbixApiStub:

    def __init__(self):
        self.apiinfo = apiinfo()

    def do_request(self, method, params=None):
        return {
            'result': {
                'status': 'Ok'
            }
        }


class apiinfo:

    def version(self):
        return {
            'result': 'Ok'
        }
