import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import requests

"""HELPER FUNCTIONS"""


def login_brinqa(base_url: str, username: str, password: str, verify: bool) -> str:
    # Login endpoint for token retrieval
    login_url = f"{base_url}/api/auth/login"
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/json"
    }
    payload = {"username": username, "password": password}
    response = requests.post(login_url, headers=headers, json=payload, verify=False)
    response.raise_for_status()
    data = response.json()
    api_key = data.get("token") or data.get("api_key") or data.get("access_token")
    if not api_key:
        raise DemistoException("Login failed: No token returned.")
    return api_key


class Client(BaseClient):
    def __init__(self, base_url: str, headers: dict, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

    # query hosts
    def query_hosts(self, display_name: str, limit: int = 10) -> dict:
        query = f'''
        query MyQuery {{
            hosts(filter: "displayName CONTAINS {display_name}", limit: {limit}) {{
                id complianceStatus displayName firstSeen lastUpdated
                type{{name}} riskScore profiles{{name}} riskOwner{{name}}
                environments{{name}} categories description dnsNames ipAddresses
                privateDnsName publicDnsName publicIpAddresses macAddresses
                subnets{{name}} os owners{{name emails}}
            }}
        }}
        '''
        payload = {
            "query": query,
            "variables": None,
            "operationName": "MyQuery"
        }
        response = self._http_request(method='POST', json_data=payload)
        return response

    # query vulnerabilities
    def query_vulnerabilities(self, search: str, fields: str = "description port riskScore results name displayName targets{{displayName}}", limit: int = 10) -> dict:
        if search is not None and search != "":
            search = f'''filter: "{search}", '''
            query = f'''
            query MyQuery {{
                vulnerabilities({search}limit: {limit}){{
                    {fields}
                }}
            }}
            '''
        else:
            query = f'''
            query MyQuery {{
                vulnerabilities(limit: {limit}){{
                    {fields}
                }}
            }}
            '''
        payload = {
            "query": query,
            "variables": None,
            "operationName": "MyQuery"
        }
        response = self._http_request(method='POST', json_data=payload)
        return response

    # regular request
    def query(self, table: str, search: str, fields: str = "id displayName", limit: int = 10) -> dict:
        if search is not None and search != "":
            search = f'''filter: "{search}", '''
            query = f'''
            query MyQuery {{
                {table}({search}limit: {limit}){{
                    {fields}
                }}
            }}
            '''
        else:
            query = f'''
            query MyQuery {{
                {table}(limit: {limit}){{
                    {fields}
                }}
            }}
            '''
        payload = {
            "query": query,
            "variables": None,
            "operationName": "MyQuery"
        }
        response = self._http_request(method='POST', json_data=payload)
        return response


def brinqa_query_command(client: Client, args: dict) -> CommandResults:
    table = args.get('table')
    fields = args.get('fields')
    search = args.get('search')
    limit = int(args.get('limit', 10))
    result = client.query(table, search, fields, limit)
    results = result.get('data', {}).get(table, [])
    readable_output = tableToMarkdown('Brinqa Query Results', results)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brinqa.QueryResults',
        outputs_key_field='id',
        outputs=results
    )


def brinqa_query_hosts_command(client: Client, args: dict) -> CommandResults:
    display_name = args.get('display_name')
    limit = int(args.get('limit', 10))
    result = client.query_hosts(display_name, limit)
    hosts = result.get('data', {}).get('hosts', [])
    readable_output = tableToMarkdown('Brinqa Hosts', hosts)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brinqa.Host',
        outputs_key_field='id',
        outputs=hosts
    )


def brinqa_query_vulnerabilities_command(client: Client, args: dict) -> CommandResults:
    fields = args.get('fields')
    search = args.get('search')
    limit = int(args.get('limit', 10))
    result = client.query_vulnerabilities(fields, search, limit)
    results = result.get('data', {}).get('vulnerabilities', [])
    readable_output = tableToMarkdown('Brinqa Query Results', results)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Brinqa.Vulnerabilities',
        outputs_key_field='id',
        outputs=results
    )


def test_module(client: Client) -> str:
    try:
        client.query_hosts("")
        return 'ok'
    except Exception as e:
        return f"Test failed: {str(e)}"


def main():
    params = demisto.params()
    args = demisto.args()

    base_url = params.get("url")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    credentials = params.get("credentials", {})

    username = credentials.get("identifier")
    password = credentials.get("password")
    if not username or not password:
        raise ValueError("Username or password is missing in integration parameters.")

    # Authenticate and get token
    api_key = login_brinqa(base_url, username, password, verify_certificate)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate"
    }

    graphql_url = f"{base_url}/graphql/caasm"
    client = Client(base_url=graphql_url, headers=headers, verify=verify_certificate, proxy=proxy)

    try:
        command = demisto.command()
        if command == "test-module":
            return_results(test_module(client))
        elif command == 'brinqa-query-hosts':
            return_results(brinqa_query_hosts_command(client, args))
        elif command == 'brinqa-query':
            return_results(brinqa_query_command(client, args))
        elif command == 'brinqa-query-vulnerabilities':
            return_results(brinqa_query_vulnerabilities_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
    except Exception as e:
        return_error(f"Failed to execute command. Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
