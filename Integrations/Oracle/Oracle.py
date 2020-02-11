import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''
import cx_Oracle


''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class Client:

    def __init__(self, db_server, service, username, password, privilege, db_version="18", port="1521"):
        self.db_server = db_server
        self.db_version = db_version
        self.service = service
        self.port = port
        self.username = username
        self.password = password
        self.privilege = privilege

    def connection_request(self):
        try:
            easy_connect=self.db_server+":"+self.port+"//"+self.service
            connect = cx_Oracle.connect(self.username, self.password, easy_connect)
            return connect
        except Exception as e:
            raise ValueError(f" Error while connecting to the database: \n{e}")


    def get_db_version(self):
        connection=self.connection_request()
        return connection.version


def test_module(client):
    result = client.connection_request()
    if result:
        return 'ok'
    else:
        return 'Test failed because ......'


def get_db_verion_command(client, args):
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def db_query(client, args):
    name = args.get('name')

    result = client.say_hello_http_request(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )



def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/v1/suffix')

    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'oracle-query':
            return_outputs(*db_query(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
