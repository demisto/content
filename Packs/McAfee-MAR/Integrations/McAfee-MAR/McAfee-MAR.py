import demistomock as demisto
from CommonServerPython import *
from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.broker import Broker
from dxlmarclient import MarClient, ProjectionConstants, ConditionConstants, OperatorConstants


FILTER_OPERATORS = {
    'GreaterEqualThan': OperatorConstants.GREATER_EQUAL_THAN,
    'GreaterThan': OperatorConstants.GREATER_THAN,
    'LessEqualThan': OperatorConstants.LESS_EQUAL_THAN,
    'LessThan': OperatorConstants.LESS_THAN,
    'Equals': OperatorConstants.EQUALS,
    'Contains': OperatorConstants.CONTAINS,
    'StartWith': OperatorConstants.STARTS_WITH,
    'EndsWith': OperatorConstants.ENDS_WITH,
    'Before': OperatorConstants.BEFORE,
    'After': OperatorConstants.AFTER
}


MAR_COLLECTORS = {
    'CommandLineHistory': ['user', 'id'],  # according to docs also includes 'CommandLine'
    'CurrentFlow': ['local_ip', 'local_port', 'remote_ip', 'remote_port', 'status', 'process_id', 'user', 'user_id',
                    'proto', 'md5', 'sha1'],
    'DNSCache': ['hostname', 'ipaddress'],
    'EnvironmentVariables': ['username', 'process_id', 'name', 'value'],
    'Files': ['name', 'dir', 'full_name', 'size', 'last_write', 'md5', 'sha1', 'created_at', 'deleted_at', ],
    'HostEntries': ['hostname', 'ipaddress'],
    'HostInfo': ['hostname', 'ip_address', 'os'],
    'InstalledCertificates': ['issued_to', 'issued_by', 'expiration_date', 'purposes', 'purposes_extended',
                              'friendly_name'],
    'InstalledDrivers': ['displayname', 'description', 'last_modified_date', 'name', 'servicetype', 'startmode',
                         'state', 'path'],
    'InstalledUpdates': ['description', 'hotfix_id', 'install_date', 'installed_by'],
    'InteractiveSessions': ['userid', 'name'],
    'LocalGroups': ['groupname', 'groupdomain', 'groupdescription', 'islocal', 'sid'],
    'LoggedInUsers': ['id', 'userdomain', 'username'],
    # according to docs also includes 'flags'
    'NetworkFlow': ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'time', 'status', 'process', 'process_id', 'user',
                    'user_id', 'proto', 'direction', 'ip_class', 'seq_number', 'src_mac', 'dst_mac', 'md5', 'sha1'],
    'NetworkInterfaces': ['bssid', 'displayname', 'gwipaddress', 'gwmacaddress', 'ipaddress', 'ipprefix', 'macaddress',
                          'name', 'ssid', 'type', 'wifisecurity'],
    'NetworkSessions': ['computer', 'user', 'client', 'file', 'idletime'],
    'NetworkShares': ['name', 'description', 'path'],
    # according to docs also includes 'thread_count', 'parentId'
    'Processes': ['name', 'id', 'parentname', 'size', 'md5', 'sha1', 'cmdline', 'imagepath', 'kerneltime', 'usertime',
                  'uptime', 'user', 'user_id'],
    # according to docs also includes 'nextruntime', 'task_run', 'log_on_type'
    'ScheduledTasks': ['folder', 'taskname', 'status', 'last_run', 'username', 'schedule_on'],
    'Services': ['description', 'name', 'startuptype', 'status', 'user'],
    'Software': ['displayname', 'installdate', 'publisher', 'version'],
    'Startup': ['caption', 'command', 'description', 'name', 'user'],
    'UsbConnectedStorageDevices': ['vendor_id', 'product_id', 'serial_number', 'device_type', 'guid',
                                   'last_connection_time', 'user_name', 'last_time_used_by_user'],
    'UserProfiles': ['accountdisabled', 'domain', 'fullname', 'installdate', 'localaccount', 'lockedout',
                     'accountname', 'sid', 'passwordexpires'],
    'WinRegistry': ['keypath', 'keyvalue', 'valuedata', 'valuetype']
}

broker_ca_bundle = './brokercerts.crt'
cert_file = './cert_file.crt'
private_key = './private_key.key'
broker_urls = []  # type: List[Broker]


def create_error_entry(contents):
    return {
        'ContentsFormat': formats['text'],
        'Type': entryTypes['error'],
        'Contents': "Error - " + contents
    }


def create_entry(header, contents, table, context={}, headers=None):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': contents,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown(header, table, headers) if table else 'No result were found',
        'EntryContext': context
    }


def translate_dict(d, translator):
    res = {}
    for key, value in d.iteritems():
        new_key = translator.get(key, key)
        res[new_key] = value
    return res

# translate_list - map each lst dict by translator


def translate_list(lst, translator):
    return [translate_dict(d, translator) for d in lst]


def get_client_config():
    config = DxlClientConfig(
        broker_ca_bundle=broker_ca_bundle,
        cert_file=cert_file,
        private_key=private_key,
        brokers=[Broker.parse(url) for url in broker_urls]
    )

    config.connect_retries = 1
    config.reconnect_delay = 1
    config.reconnect_delay_max = 10

    return config


def test():
    config = get_client_config()
    demisto.info('######## config created ########')
    with DxlClient(config) as client:
        client.connect()
        demisto.info('######## client connected ########')
        client.disconnect()
        demisto.info('######## client disconnected ########')
        MarClient(client)
        demisto.info('######## client MAR client created ########')


def extract_item_output(item, capitalize):
    output = item['output']
    res = {
        'created_at': item['created_at']
    }

    # map <CollectorName>|<OutputName> to <OutputName>
    for key, value in output.iteritems():
        splited_key = key.split('|')
        if(len(splited_key) > 1):
            new_key = splited_key[1]
        else:
            new_key = splited_key[0]
        if capitalize:
            new_key = new_key.capitalize()
        res[new_key] = value or "-"
    return res


def search_result_to_table(search_result, capitalize=False):
    items = search_result['items']
    table = [extract_item_output(item, capitalize) for item in items]
    return table


def get_projection(collector, outputs):
    return {
        ProjectionConstants.NAME: collector,
        ProjectionConstants.OUTPUTS: outputs or MAR_COLLECTORS.get(collector)
    }


def search(collector, projection_collector, outputs, filter_by, filter_operator, filter_value):
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        mar_client = MarClient(client)

        if (not filter_by and not filter_operator and not filter_value):
            result_context = mar_client.search(
                projections=[{
                    ProjectionConstants.NAME: collector,
                    ProjectionConstants.OUTPUTS: outputs
                }]
            )
        else:
            if (not filter_by or not filter_operator or not filter_value):
                raise Exception('you must specify filter-by, filter-operator & filter-value (or specify none of them)')
            else:
                result_context = mar_client.search(
                    projections=[{
                        ProjectionConstants.NAME: projection_collector,
                        ProjectionConstants.OUTPUTS: outputs
                    }],
                    conditions={ConditionConstants.OR: [{
                        ConditionConstants.AND: [{
                            ConditionConstants.COND_NAME: collector,
                            ConditionConstants.COND_OUTPUT: filter_by,
                            ConditionConstants.COND_OP: FILTER_OPERATORS[filter_operator],
                            ConditionConstants.COND_VALUE: filter_value
                        }]
                    }]}
                )

        if result_context.has_results:
            return result_context.get_results()

        return None


def search_multiple(collectors, filter_collector, filter_by, filter_operator, filter_value):
    config = get_client_config()
    with DxlClient(config) as client:
        client.connect()
        mar_client = MarClient(client)
        if (not filter_collector):
            result_context = mar_client.search(
                projections=[get_projection(c, None) for c in collectors]
            )
        else:
            if (not filter_by or not filter_operator or not filter_value):
                raise Exception('you must specify filter-by,'
                                ' filter-operator & filter-value when you provide filter_collector argument')
            else:
                result_context = mar_client.search(
                    projections=[get_projection(c, None) for c in collectors],
                    conditions={ConditionConstants.OR: [{
                        ConditionConstants.AND: [{
                            ConditionConstants.COND_NAME: filter_collector,
                            ConditionConstants.COND_OUTPUT: filter_by,
                            ConditionConstants.COND_OP: FILTER_OPERATORS[filter_operator],
                            ConditionConstants.COND_VALUE: filter_value
                        }]
                    }]}
                )

        if result_context.has_results:
            return result_context.get_results()

        return None


def search_wrapper(collector, projection_collector, outputs_str, filter_by,
                   filter_operator, filter_value, capitalize=False):
    demisto.info('######## executing ' + demisto.command() + ' ########')
    try:
        if outputs_str:
            outputs = outputs_str.split(',')
        else:
            # get all outputs
            outputs = MAR_COLLECTORS.get(collector)

        result = search(collector, projection_collector, outputs, filter_by, filter_operator, filter_value)
    except Exception as ex:
        return create_error_entry(str(ex))

    if not result:
        return 'No items were found'

    table = search_result_to_table(result, capitalize)
    context = {
        'MAR.' + collector: table
    }
    demisto.info('######## ' + demisto.command() + ' command ends ########')
    return create_entry('Search Result For ' + collector, result, table, context)


def search_multiple_wrapper(collectors, filter_collector, filter_by, filter_operator, filter_value):
    try:
        result = search_multiple(collectors, filter_collector, filter_by, filter_operator, filter_value)
    except Exception as ex:
        return create_error_entry(str(ex))

    if not result:
        return 'No items were found'

    table = search_result_to_table(result)
    context = {
        'MAR.SearchMultiple': table
    }
    return create_entry('Search-Multiple Results', result, table, context)


def mar_collectors_list():
    collectors_table = [{'Name': c, 'Outputs': ', '.join(MAR_COLLECTORS[c])} for c in MAR_COLLECTORS]
    return create_entry('Collectors', collectors_table, collectors_table, {}, ['Name', 'Outputs'])


def validate_certificates_format():
    if '-----BEGIN PRIVATE KEY-----' not in demisto.params()['private_key']:  # guardrails-disable-line
        return_error(
            "The private key content seems to be incorrect as it doesn't start with -----BEGIN PRIVATE KEY-----")
    if '-----END PRIVATE KEY-----' not in demisto.params()['private_key']:
        return_error(
            "The private key content seems to be incorrect as it doesn't end with -----END PRIVATE KEY-----")
    if '-----BEGIN CERTIFICATE-----' not in demisto.params()['cert_file']:
        return_error("The client certificates content seem to be "
                     "incorrect as they don't start with '-----BEGIN CERTIFICATE-----'")
    if '-----END CERTIFICATE-----' not in demisto.params()['cert_file']:
        return_error(
            "The client certificates content seem to be incorrect as it doesn't end with -----END CERTIFICATE-----")
    if not demisto.params()['broker_ca_bundle'].lstrip(" ").startswith('-----BEGIN CERTIFICATE-----'):
        return_error(
            "The broker certificate seem to be incorrect as they don't start with '-----BEGIN CERTIFICATE-----'")
    if not demisto.params()['broker_ca_bundle'].rstrip(" ").endswith('-----END CERTIFICATE-----'):
        return_error(
            "The broker certificate seem to be incorrect as they don't end with '-----END CERTIFICATE-----'")


def main():
    with open(broker_ca_bundle, "w") as text_file:
        text_file.write(demisto.params()['broker_ca_bundle'])

    with open(cert_file, "w") as text_file:
        text_file.write(demisto.params()['cert_file'])  # lgtm [py/clear-text-storage-sensitive-data]

    with open(private_key, "w") as text_file:
        text_file.write(demisto.params()['private_key'])

    global broker_urls
    broker_urls = demisto.params()['broker_urls'].split(',')

    try:
        args = demisto.args()
        if demisto.command() == 'test-module':
            demisto.info('######## executing test command ########')
            test()
            demisto.results('ok')
            sys.exit(0)
        elif demisto.command() == 'mar-search':
            results = search_wrapper(
                args.get('collector'),
                args.get('projection-collector', args.get('collector')),
                args.get('outputs'),
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value')
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-multiple':
            results = search_multiple_wrapper(
                args.get('collectors').split(','),
                args.get('filter_collector'),
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value')
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-collectors-list':
            results = mar_collectors_list()
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-processes':
            results = search_wrapper(
                'Processes',
                'Processes',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-services':
            results = search_wrapper(
                'Services',
                'Services',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-win-registry':
            results = search_wrapper(
                'WinRegistry',
                'WinRegistry',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-files':
            results = search_wrapper(
                'Files',
                'Files',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-usb-connected-storage-devices':
            results = search_wrapper(
                'UsbConnectedStorageDevices',
                'UsbConnectedStorageDevices',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-user-profiles':
            results = search_wrapper(
                'UserProfiles',
                'UserProfiles',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-scheduled-tasks':
            results = search_wrapper(
                'ScheduledTasks',
                'ScheduledTasks',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
        elif demisto.command() == 'mar-search-host-info':
            results = search_wrapper(
                'HostInfo',
                'HostInfo',
                '',
                args.get('filter-by'),
                args.get('filter-operator'),
                args.get('filter-value'),
                True
            )
            demisto.results(results)
            sys.exit(0)
    except Exception as error:
        validate_certificates_format()
        return_error(str(error))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
