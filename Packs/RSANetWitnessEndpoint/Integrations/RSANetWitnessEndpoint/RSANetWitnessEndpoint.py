import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""

IMPORTS

"""
import math
import os

import requests
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

"""

HANDLE PROXY

"""


def set_proxies():
    if demisto.params()['proxy']:
        http = os.environ['http_proxy'] or os.environ['HTTP_PROXY']
        https = os.environ['https_proxy'] or os.environ['HTTPS_PROXY']
        proxies = {
            'http': http,
            'https': https
        }
        return proxies
    return None


"""

GLOBAL VARS

"""

SERVER_URL = demisto.params()['server']
BASE_PATH = '{}/api/v2'.format(SERVER_URL) if SERVER_URL.endswith('/') else '{}/api/v2'.format(SERVER_URL)
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
USE_SSL = not demisto.params()['insecure']
PROXIES = set_proxies()

MACHINE_DATA_EXTENDED = [
    "AgentID",
    "MachineName",
    "LocalIP",
    "RemoteIP",
    "MAC",
    "MachineStatus",
    "IIOCScore",
    "IIOCLevel0",
    "IIOCLevel1",
    "IIOCLevel2",
    "IIOCLevel3",
    "AntiVirusDisabled",
    "Comment",
    "ContainmentStatus",
    "ContainmentSupported",
    "Country",
    "DNS",
    "DomainName",
    "FirewallDisabled",
    "Gateway",
    "Group",
    "Idle",
    "InstallTime",
    "InstallationFailed",
    "LastScan",
    "LastSeen",
    "NetworkSegment",
    "OperatingSystem",
    "OrganizationUnit",
    "Platform",
    "Scanning",
    "UserName",
    "VersionInfo"
]

MACHINE_DATA = [
    'MachineName',
    'MachineGUID',
    'Online',
    'OperatingSystem',
    'LastScan',
    'IOCScore',
    'MacAddress',
    'LocalIp'
]

IOC_DATA = [
    "Description",
    "Type",
    "MachineCount",
    "ModuleCount",
    "IOCLevel",
    "Priority",
    "Active",
    "LastExecuted",
    "Alertable",
    "IOCTriggeredOnMachine"
]

MODULE_DATA = [
    'ModuleName',
    'ModuleID',
    'Description',
    'IOCScore',
    'AnalyticsScore',
    'GlobalMachineCount',
    'MD5',
    'SHA256'
]

MODULE_DATA_EXTENDED = [
    "ModuleID",
    "ModuleName",
    "FullPath",
    "FirstSeenName",
    "FirstSeenDate",
    "MD5",
    "SHA1",
    "SHA256",
    "IIOCLevel0",
    "IIOCLevel1",
    "IIOCLevel2",
    "IIOCLevel3",
    "IIOCScore",
    "Blacklisted",
    "Graylisted",
    "Whitelisted",
    "MachineCount",
    "RiskScore",
    "AVDefinitionHash",
    "AVDescription",
    "AVFirstThreat",
    "AVScanResult",
    "AccessNetwork",
    "AnalysisTime",
    "AppDataLocal",
    "AppDataRoaming",
    "AutoStartCategory",
    "Autorun",
    "BlacklistCategory",
    "BlockingStatus",
    "Desktop",
    "Downloaded",
    "DownloadedTime",
    "FakeStartAddress",
    "FileAccessDenied",
    "FileAccessTime",
    "FileCreationTime",
    "FileEncrypted",
    "FileHiddenAttributes",
    "FileModificationTime",
    "FileName",
    "FileOccurrences",
    "Floating",
    "HashLookup",
    "Hooking",
    "ImportedDLLCount",
    "ImportedDLLs",
    "LiveConnectRiskEnum",
    "LiveConnectRiskReason",
    "Loaded",
    "OriginalFileName",
    "Packed",
    "Platform",
    "RelativeFileName",
    "RelativePath",
    "RemoteFileName",
    "RemotePath",
    "Signature",
    "SignatureTimeStamp",
    "SizeInBytes",
    "Status",
    "YaraDefinitionHash",
    "YaraScanDescription",
    "YaraScanFirstThreat",
    "YaraScanresult",
    "Windows",
    "WritetoExecutable",
    "SysWOW64",
    "System32",
    "Temporary",
    "TooManyConnections",
    "User",
    "SignatureValid",
    "SignedbyMicrosoft",
    "SignatureExpired",
    "SignaturePresent",
    "RenametoExecutable",
    "ReservedName",
    "ProcessAccessDenied",
    "ProgramData",
    "ProgramFiles",
    "ReadDocument",
    "MD5Collision",
    "InstallerDirectory",
    "LikelyPacked",
    "Listen",
    "ImageHidden",
    "ImageMismatch",
    "FirewallAuthorized",
    "AutorunScheduledTask",
    "Beacon"
]

MODULE_DATA_EXTENDED_CONTEXT = [
    "ModuleID",
    "FileName",
    "FullPath",
    "MD5",
    "RiskScore",
    "SHA1",
    "SHA256",
    "IIOCScore",
    "Blacklisted",
    "Graylisted",
    "Whitelisted",
    "MachineCount",
    "IIOCLevel0",
    "IIOCLevel1",
    "IIOCLevel2",
    "IIOCLevel3",
    "FirstSeenName",
    "FirstSeenDate"
]


def is_html_response(response):
    if 'text\html' in response.headers.get('Content-Type', '').lower():
        return True
    # look for an html tag in the response text
    # if re.search("<[^>]+>", response.text):
    #     return True
    return False


def get_html_from_response(response):
    text = response.text
    open_tag = text.lower().find('<html')
    close_tag = text.lower().find('</html>')
    return text[open_tag: close_tag + len('</html>')]


def html_error_entry(html):
    return {
        'Type': entryTypes['error'],
        'Contents': html,
        'ContentsFormat': formats['html']
    }


def parse_error_response(error_response):
    # NetWitness has fixed structure for
    try:
        error = error_response.json()
        return f'Request failed with status code: ' \
               f'{error_response.status_code}\nReason: {error.ResponseStatus.ErrorCode}\n{error.ResponseStatus.Message}'
    except Exception as e:
        demisto.debug(f'{e}')
        return f'Request failed with status code: {error_response.status_code}\n{error_response.content}'


def http_request(method, url, data=None, headers={'Accept': 'application/json'}, url_params=None):
    # send http request using user settings for unsecure and proxy parameters
    # uses basic auth
    # returns the http response

    LOG(f'Attempting {method} request to {url}')
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            auth=(USERNAME, PASSWORD),
            params=url_params,
            verify=USE_SSL,
            proxies=PROXIES
        )
    except requests.exceptions.SSLError as e:
        LOG(e)
        raise ValueError('An SSL error occurred. Consider to set unsecure')

    if is_html_response(response):
        html_body = get_html_from_response(response)
        demisto.results(html_error_entry(html_body))
        raise ValueError('Caught HTML response, please verify server url.')

    if response.status_code < 200 or response.status_code >= 300:
        msg = parse_error_response(response)
        raise ValueError(msg)

    try:
        return response.json()
    except Exception as e:
        LOG(e)
        return {}


def login():
    url = f'{BASE_PATH}/auth'
    # this call will raise an exception on wrong credential
    http_request('GET', url)


def get_machines(query, limit):
    # GET /machines

    # specify additional data to be returned
    query['Properties'] = 'Online,OperatingSystem,LastScanUTCTime,IOCScore,MacAddress,LocalIp'
    # add paging to query
    query['page'] = 1
    # set per_page parameter only if 'limit' is under 50
    if limit < 50:
        query['per_page'] = limit  # int

    machines = []
    # loop on page number
    while True:
        res = http_request(
            'GET',
            '{}/machines'.format(BASE_PATH),
            url_params=query
        )
        items = res.get('Items')
        if not items:
            # no results
            break
        machines.extend(items)
        if len(machines) >= limit:
            # reached/exceeded limit
            break
        # get next page
        query['page'] = query['page'] + 1

    if len(machines) > limit:
        # results exceeded limit
        machines[limit - 1:-1] = []

    return machines


def get_machines_command():
    args = demisto.args()

    # prepare query
    query = {
        'MachineName': args.get('machineName'),  # string
        'iocscore_gte': int(args.get('iocScoreGreaterThan')) if args.get('iocScoreGreaterThan') else None,  # int
        'iocscore_lte': int(args.get('iocScoreLessThan')) if args.get('iocScoreLessThan') else None,  # int
        'IpAddress': args.get('ipAddress'),  # string
        'macAddress': args.get('macAddress'),  # string
    }
    limit = int(args.get('limit')) if args.get('limit') else math.inf
    if limit < 1:
        raise ValueError("Please input valid limit number")

    machines = get_machines(query, limit)

    context = []
    for machine in machines:
        properties = machine['Properties']
        context.append(
            {
                'MachineGUID': machine.get('Id'),
                'MachineName': machine.get('Name'),
                'Online': properties.get('Online'),
                'OperatingSystem': properties.get('OperatingSystem'),
                'LastScan': properties.get('LastScanUTCTime'),
                'IOCScore': properties.get('IOCScore'),
                'MacAddress': properties.get('MacAddress'),
                'LocalIp': properties.get('LocalIp')
            }
        )

    entry = {
        'Type': entryTypes['note'],
        'Contents': {
            "Machines": machines,
            "Machine": [],
            "IOCs": [],
            "Modules": []
        },
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('NetWitness Endpoint - Get Machines', context, MACHINE_DATA),
        'EntryContext': {
            "NetWitness.Machines(obj.MachineGUID==val.MachineGUID)": context
        }
    }

    # get additional machine data
    for id in [machine["Id"] for machine in machines]:

        if args.get('includeMachineData') == 'yes':
            machine_entry = create_machine_entry(id)

            entry["Contents"]["Machine"].append(machine_entry["Contents"])
            entry["HumanReadable"] += '\n{}'.format(machine_entry["HumanReadable"])
            entry["EntryContext"].update(machine_entry["EntryContext"])

        if args.get('includeMachineIOCs') == 'yes':
            iocs_entry = create_iocs_entry(id, 50)

            entry["Contents"]["IOCs"].extend(iocs_entry["Contents"])
            entry["HumanReadable"] += '\n{}'.format(iocs_entry["HumanReadable"])
            entry["EntryContext"].update(iocs_entry["EntryContext"])

        if args.get('includeMachineModules') == 'yes':
            modules_entry = create_modules_entry(id, {}, 30)

            entry["Contents"]["Modules"].extend(modules_entry["Contents"])
            entry["HumanReadable"] += '\n{}'.format(modules_entry["HumanReadable"])
            entry["EntryContext"].update(modules_entry["EntryContext"])

    demisto.results(entry)


def get_machine(machine_id):
    # GET /machines/{Guid}
    response = http_request(
        'GET',
        '{}/machines/{}'.format(BASE_PATH, machine_id)
    )
    return response.get('Machine')


def create_machine_entry(machine_id):
    machine = get_machine(machine_id)
    machine_name = machine.get('MachineName')

    machine_data = {k: v for k, v in machine.items() if k in MACHINE_DATA_EXTENDED}
    machine_data["MachineGUID"] = machine_id

    entry = {
        'Type': entryTypes['note'],
        'Contents': machine,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('NetWitness Endpoint - Machine {} Full Data'.format(machine_name),
                                         machine_data, MACHINE_DATA_EXTENDED),
        'EntryContext': {
            "NetWitness.Machines(obj.MachineGUID==val.MachineGUID)": machine_data
        }
    }
    return entry


def get_machine_command():
    entry = create_machine_entry(demisto.args().get('machineGUID'))
    demisto.results(entry)


def list_iocs(machine_id, limit):
    # GET /machines/{Guid}/instantiocs

    paging_params = {
        'page': 1
    }
    # set per_page parameter only if 'limit' is under 50
    if limit < 50:
        paging_params['per_page'] = limit

    iocs = []
    # loop on page number
    while True:
        res = http_request(
            'GET',
            '{}/machines/{}/instantiocs'.format(BASE_PATH, machine_id),
            url_params=paging_params
        )
        items = res.get('Iocs')
        if not items:
            # no results
            break
        iocs.extend(items)
        if len(iocs) >= limit:
            # reached/exceeded limit
            break
        # get next page
        paging_params['page'] = paging_params['page'] + 1

    if len(iocs) > limit:
        # results exceeded limit
        iocs[limit - 1:-1] = []

    return iocs


def create_iocs_entry(machine_id, limit):
    iocs = list_iocs(machine_id, limit)

    context = []
    for ioc in iocs:
        data = {k: v for k, v in ioc.items() if k in IOC_DATA}
        data['MachineGUID'] = machine_id
        context.append(data)

    entry = {
        'Type': entryTypes['note'],
        'Contents': iocs,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown("NetWitness Endpoint - Machine IOC's", context, IOC_DATA),
        'EntryContext': {
            "NetWitness.IOCS(obj.Description==val.Description)": context,
        }
    }
    return entry


def list_iocs_command():
    args = demisto.args()
    machine_id = args.get('machineGUID')
    limit = int(args.get('limit')) if args.get('limit') else math.inf

    if limit < 1:
        raise ValueError("Please input valid limit number")

    entry = create_iocs_entry(machine_id, limit)
    demisto.results(entry)


def get_machine_modules(machine_id, query, limit):
    # GET /machines/{Guid}/modules

    # specify additional data to be returned
    query['Properties'] = 'Description,IOCScore,AnalyticsScore,GlobalMachineCount,HashMD5,HashSHA256'
    # add paging to query
    query['page'] = 1
    # set per_page parameter only if 'limit' is under 50
    if limit < 50:
        query['per_page'] = limit

    modules = []
    # loop on page number
    while True:
        res = http_request(
            'GET',
            '{}/machines/{}/modules'.format(BASE_PATH, machine_id),
            url_params=query
        )
        items = res.get('Items')
        if not items:
            # no results
            break
        modules.extend(items)
        if len(modules) >= limit:
            # reached/exceeded limit
            break
        # get next page
        query['page'] = query['page'] + 1

    if len(modules) > limit:
        # results exceeded limit
        modules[limit - 1:-1] = []

    return modules


def create_modules_entry(machine_id, query, limit):
    modules = get_machine_modules(
        machine_id,
        query,
        limit
    )

    context = []
    files = []
    for module in modules:
        properties = module['Properties']
        context.append(
            {
                'ModuleID': module.get('Id'),
                'ModuleName': module.get('Name'),
                'Description': properties.get('Description'),
                'IOCScore': properties.get('IOCScore'),
                'AnalyticsScore': properties.get('AnalyticsScore'),
                'GlobalMachineCount': properties.get('GlobalMachineCount'),
                'MD5': properties.get('HashMD5'),
                'SHA256': properties.get('HashSHA256'),
                'MachineGUID': machine_id
            }
        )
        files.append(
            {
                'Name': module.get('Name'),
                'MD5': properties.get('HashMD5'),
            }
        )

    entry = {
        'Type': entryTypes['note'],
        'Contents': modules,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('NetWitness Endpoint - Get Modules', context, MODULE_DATA),
        'EntryContext': {
            "NetWitness.Modules(obj.ModuleID==val.ModuleID)": context,
            "File(obj.MD5==val.MD5)": files
        }
    }
    return entry


def get_machine_modules_command():
    args = demisto.args()

    machine_id = args.get('machineGUID')
    limit = int(args.get('limit')) if args.get('limit') else math.inf
    if limit < 1:
        raise ValueError("Please input valid limit number")
    # prepare query
    query = {
        'ModuleName': args.get('moduleName'),  # string
        'iocscore_gte': int(args.get('iocScoreGreaterThan')) if args.get('iocScoreGreaterThan') else None,  # int
        'iocscore_lte': int(args.get('iocScoreLessThan')) if args.get('iocScoreLessThan') else None  # int
    }

    entry = create_modules_entry(
        machine_id,
        query,
        limit
    )
    demisto.results(entry)


def get_machine_module(machine_guid, moudule_id):
    # GET machines/{Guid}/modules/{Id}
    response = http_request(
        'GET',
        '{}/machines/{}/modules/{}'.format(BASE_PATH, machine_guid, moudule_id),
    )
    return response.get('MachineModulePath')


def get_machine_module_command():
    args = demisto.args()
    machine_id = args.get('machineGUID')

    module = get_machine_module(
        machine_id,
        args.get('moduleID')
    )

    file = {
        'Name': module.get('Name'),
        'MD5': module.get('HashMD5'),
        'SHA1': module.get('SHA1'),
        'Path': module.get('FullPath')
    }
    readable = {k: v for k, v in module.items() if k in MODULE_DATA_EXTENDED}
    context = {k: v for k, v in module.items() if k in MODULE_DATA_EXTENDED_CONTEXT}
    context['MachineGUID'] = machine_id
    entry = {
        'Type': entryTypes['note'],
        'Contents': module,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('NetWitness Endpoint - Get Module', readable, MODULE_DATA_EXTENDED),
        'EntryContext': {
            "NetWitness.Modules(obj.ModuleID==val.ModuleID)": context,
            "File(obj.MD5==val.MD5)": file
        }
    }
    demisto.results(entry)


def blacklist_ips(ips):
    # POST /blacklist/ip
    body = {
        'Ips': ips
    }
    response = http_request(
        'POST',
        '{}/blacklist/ip'.format(BASE_PATH),
        data=body

    )
    return response.get('Ips')


def blacklist_domains(domains):
    # POST /blacklist/domain
    body = {
        'Domains': domains
    }
    response = http_request(
        'POST',
        '{}/blacklist/domain'.format(BASE_PATH),
        data=body

    )
    return response.get('Domains')


def blacklist_ips_command():
    ips = demisto.args().get('ips').split(',')

    ips_successfully_blacklisted = blacklist_ips(ips)

    ips_failed = [ip for ip in ips if ip not in ips_successfully_blacklisted]
    readable = tableToMarkdown('IPs Successfully Blacklisted', ips_successfully_blacklisted, headers=["IP"])
    if len(ips_failed) > 0:
        readable += tableToMarkdown('The following IPs could not be processed', ips_failed, headers=["IP"])

    entry = {
        'Type': entryTypes['note'],
        'Contents': ips_successfully_blacklisted,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable,
        'EntryContext': {
            "NetWitness.Blacklist.IPs": ips_successfully_blacklisted,
        }
    }
    demisto.results(entry)


def blacklist_domains_command():
    args = demisto.args()
    domains = args.get('domains').split(',')

    domains_successfully_blacklisted = blacklist_domains(domains)

    domains_failed = [domain for domain in domains if domain not in domains_successfully_blacklisted]
    readable = tableToMarkdown('Domains Successfully Blacklisted', domains_successfully_blacklisted, headers=["Domain"])
    if len(domains_failed) > 0:
        readable += tableToMarkdown('The following domains could not be processed', domains_failed, headers=["Domain"])

    entry = {
        'Type': entryTypes['note'],
        'Contents': domains_successfully_blacklisted,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': readable,
        'EntryContext': {
            "NetWitness.Blacklist.Domains": domains_successfully_blacklisted,
        }
    }
    demisto.results(entry)


"""

EXECUTION

"""


def main():
    try:

        login()
        command = demisto.command()

        if command == 'test-module':
            # validated credentials with login call
            # test permission - call get_machines
            get_machines({}, 1)
            demisto.results('ok')
        elif command == 'netwitness-get-machines':
            get_machines_command()
        elif command == 'netwitness-get-machine':
            get_machine_command()
        elif command == 'netwitness-get-machine-iocs':
            list_iocs_command()
        elif command == 'netwitness-get-machine-modules':
            get_machine_modules_command()
        elif command == 'netwitness-get-machine-module':
            get_machine_module_command()
        elif command == 'netwitness-blacklist-ips':
            blacklist_ips_command()
        elif command == 'netwitness-blacklist-domains':
            blacklist_domains_command()

    except ValueError as e:
        LOG(e)
        LOG.print_log()
        return_error(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
