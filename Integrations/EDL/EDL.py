import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from flask import Flask, Response
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'EDL'
PAGE_SIZE: int = 100
APP: Flask = Flask('demisto-edl')

''' HELPER FUNCTIONS '''


def list_to_str(inp_list: list, delimiter: str = '\n') -> str:
    """
    Transforms a list to an str, with a custom delimiter between each list item
    """
    str_res = ""
    if inp_list:
        str_res = delimiter.join(map(str, inp_list))
    return str_res


def get_params_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    port: int
    try:
        if port_mapping:
            if ':' in port_mapping:
                port = int(port_mapping.split(':')[1])
            else:
                port = int(port_mapping)
        else:
            raise ValueError('Please provide a Listen Port.')
    except (ValueError, TypeError):
        raise ValueError(f'Listen Port must be an integer. {port_mapping} is not valid.')
    return port


def refresh_indicators_cache(indicator_query):
    iocs = []
    page = 0
    fetched_iocs = demisto.findIndicators(query=indicator_query, page=page, size=PAGE_SIZE).get('iocs')
    iocs.extend(fetched_iocs)
    while len(fetched_iocs) == PAGE_SIZE:
        page += 1
        fetched_iocs = demisto.findIndicators(query=indicator_query, page=page, size=PAGE_SIZE).get('iocs')
        iocs.extend(fetched_iocs)
    ctx = {}
    for ioc in iocs:
        value = ioc.get('value', '')
        if value:
            ctx[value] = ioc
    demisto.setLastRun({'last_run': date_to_timestamp(datetime.now())})
    demisto.setIntegrationContext(ctx)
    return list(ctx.values())


def get_edl_values():
    on_demand = demisto.params().get('on_demand')
    # on_demand ignores cache
    if on_demand:
        values = demisto.getIntegrationContext()
    else:
        last_run = demisto.getLastRun().get('last_run')
        indicator_query = demisto.params().get('indicators_query', '')
        if last_run:
            cache_refresh_rate = demisto.params().get('cache_refresh_rate')
            cache_time, _ = parse_date_range(cache_refresh_rate, to_timestamp=True)
            td = last_run - cache_time
            if td <= 0:  # last_run is before cache_time
                values = refresh_indicators_cache(indicator_query)
            else:
                values = demisto.getIntegrationContext()
        else:
            values = refresh_indicators_cache(indicator_query)
    return values


''' ROUTE FUNCTIONS '''
@APP.route('/', methods=['GET'])
def route_edl_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    values = list_to_str(get_edl_values())
    return Response(values, status=200, mimetype='text/plain')


''' COMMAND FUNCTIONS '''


def test_module(args):
    """
    Validates that the port is integer
    """
    params = demisto.params()
    get_params_port(params)
    cache_refresh_rate = params.get('cache_refresh_rate', '')
    if cache_refresh_rate:
        # validate $cache_refresh_rate value
        range_split = cache_refresh_rate.split(' ')
        if len(range_split) != 2:
            raise ValueError('Cache Refresh Rate must be "number date_range_unit", examples: (2 hours, 4 minutes,'
                             '6 months, 1 day, etc.)')
        if not range_split[1] in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year',
                                  'years']:
            raise ValueError('Cache Refresh Rate time unit is invalid. Must be minutes, hours, days, months or years')
        parse_date_range(cache_refresh_rate, to_timestamp=True)
    on_demand = params.get('on_demand', None)
    if not on_demand:
        # validate $indicators_query isn't empty
        query = params.get('indicators_query')
        if not query:
            raise ValueError('"Indicator Query" cannot be empty, please provide a valid query')
    return 'ok', {}, {}


def run_long_running(params):
    """
    Starts the long running thread.
    """
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')
    http_server: bool = params.get('http_flag', True)

    certificate_path = str()
    private_key_path = str()

    try:
        port = get_params_port(params)
        ssl_args = dict()

        if certificate and private_key and not http_server:  # TODO: Setup https server and http server when http_server and certificate+private_key
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(certificate, 'utf-8'))
            certificate_file.close()
            ssl_args['certfile'] = certificate_path

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(private_key, 'utf-8'))
            private_key_file.close()
            ssl_args['keyfile'] = private_key_path
            demisto.debug('Starting HTTPS Server')
        else:
            demisto.debug('Starting HTTP Server')

        server = WSGIServer(('', port), APP, **ssl_args)
        server.serve_forever()
    except Exception as e:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))


def update_edl_command(args):
    on_demand = demisto.params().get('on_demand')
    if not on_demand:
        raise DemistoException(
            '"Update EDL On Demand" is turned off. If you want to update the EDL manually please turn it on.')
    query = args.get('query')
    indicators = refresh_indicators_cache(query)
    hr = tableToMarkdown('EDL was updated successfully with the following values', indicators, ['indicators'])
    return hr, {}, {}


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'update-edl': update_edl_command
    }

    try:
        if command == 'long-running-execution':
            run_long_running(params)
        else:
            readable_output, outputs, raw_response = commands[command](demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
