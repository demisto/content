import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ssl
from ldap3 import Server, Connection, Tls, AUTO_BIND_TLS_BEFORE_BIND, AUTO_BIND_NO_TLS, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPBindError, LDAPInvalidDnError, LDAPSocketOpenError, LDAPInvalidPortError, LDAPSocketReceiveError, LDAPStartTLSError
from ldap3.abstract.entry import Entry
from typing import List, Dict, Any, Optional

class LDAPQueryClient:
    def __init__(self, kwargs: Dict[str, Any]):
        self._host = kwargs.get('host')
        self._port = int(kwargs.get('port', 0)) if kwargs.get('port') is not None else None
        self._username = kwargs.get('credentials', {}).get('identifier', '')
        self._password = kwargs.get('credentials', {}).get('password', '')
        self._base_dn = kwargs.get('base_dn', '').strip()
        self._connection_type = kwargs.get('connection_type', 'none').lower()
        self._ssl_version = kwargs.get('ssl_version', 'None')
        self._verify = not kwargs.get('insecure', False)
        self._ldap_server = self._initialize_ldap_server()
        self._page_size = int(kwargs.get('page_size', 500))

    def _initialize_ldap_server(self) -> Server:
        if self._connection_type == 'ssl':
            tls = Tls(validate=ssl.CERT_REQUIRED if self._verify else ssl.CERT_NONE)
            server = Server(host=self._host, port=self._port, use_ssl=True, tls=tls, connect_timeout=120)
        elif self._connection_type == 'start tls':
            tls = Tls(validate=ssl.CERT_REQUIRED if self._verify else ssl.CERT_NONE)
            server = Server(host=self._host, port=self._port, use_ssl=False, tls=tls, connect_timeout=120)
        else:
            server = Server(host=self._host, port=self._port, connect_timeout=120)
        return server

    def authenticate_ldap_user(self, username: str, password: str) -> str:
        auto_bind = AUTO_BIND_TLS_BEFORE_BIND if self._connection_type == 'start tls' else AUTO_BIND_NO_TLS
        ldap_conn = Connection(server=self._ldap_server, user=username, password=password, auto_bind=auto_bind)
        if ldap_conn.bound:
            ldap_conn.unbind()
            return "Done"
        else:
            raise Exception("LDAP Authentication failed")

    def search_user_by_attribute(self, attribute: str, value: str, return_attributes: List[str] = None) -> List[Entry]:
        with Connection(self._ldap_server, self._username, self._password, auto_bind=AUTO_BIND_NO_TLS) as ldap_conn:
            search_filter = f"({attribute}={value})"
            ldap_conn.search(search_base=self._base_dn, search_filter=search_filter, attributes=return_attributes or ALL_ATTRIBUTES)
            return ldap_conn.entries

    def get_user_attributes(self, identifier: str, id_value: str, return_attribute: str = None) -> Dict[str, Any]:
        return_attributes = [return_attribute] if return_attribute else ALL_ATTRIBUTES
        entries = self.search_user_by_attribute(identifier, id_value, return_attributes)
        if entries:
            entry = entries[0]
            result = {}
            for attr in entry.entry_attributes:
                value = entry[attr].value
                if isinstance(value, bytes):
                    value = value.decode('utf-8', 'ignore')
                result[attr] = value
            if return_attribute:
                return {return_attribute: result[return_attribute]}
            else:
                return result
        else:
            raise Exception("User not found")

def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    try:
        client = LDAPQueryClient(params)

        if command == 'test-module':
            return_results("ok")
        elif command == 'ldap-query':
            cn = args.get('cn')
            uid = args.get('uid')
            attribute = args.get('attribute')
            if cn:
                result = client.get_user_attributes('cn', cn, attribute)
            elif uid:
                result = client.get_user_attributes('uid', uid, attribute)
            else:
                raise ValueError("Either 'cn' or 'uid' must be provided")
            return_results(result)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
