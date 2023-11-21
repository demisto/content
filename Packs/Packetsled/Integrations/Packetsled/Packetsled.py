import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import struct
from urllib.parse import quote
import urllib3

urllib3.disable_warnings()

VERIFY = False


def humanReadable(title, arr):
    if len(arr) > 0:
        return tableToMarkdown(title, arr, arr[0].keys())
    return arr


def number_to_ip(n):
    if isinstance(n, str):
        return n
    try:
        return socket.inet_ntoa(struct.pack('!L', n))
    except Exception:
        return n


def ip_to_number(i):
    try:
        return struct.unpack('!L', socket.inet_aton(i))[0]
    except Exception:
        return i


proto_map = {"tcp": 10001, "udp": 10002, "dns": 10003, "dhcp": 10004, "arp": 10005, "finger": 10006, "ncp": 10007,
             "rpc": 10008, "telnet": 10009, "rlogin": 10010, "citrix": 10011, "dhcpv6": 10012, "icmp": 20001,
             "ntp": 20003, "snmp": 20004, "bgp": 20005, "ripv1": 20006, "ripv2": 20007, "ipmi": 20008, "ssh": 30001,
             "ssl": 30002, "openvpn": 30003, "teredo": 40001, "tunnel": 40002, "ciscovpn_tcp": 40003,
             "ciscovpn_udp": 40004, "syslog": 50001, "dce-rpc": 60001, "xmpp": 60002, "amqp": 60003, "emp": 60004,
             "dce-rpc-lsa": 60005, "ident": 70001, "radius": 70002, "socks": 70003, "kerberos": 70004, "ntlm": 70005,
             "login": 80001, "rdp": 80002, "vnc": 80003, "pcanywhere": 80004, "ftp": 90001, "netbios": 90002,
             "smb": 90003, "ftp-data": 90004, "irc-dcc-data": 90005, "rsync": 90006, "tftp": 90007, "dropbox": 90008,
             "bittorrent": 100001, "gnutella": 100002, "dnp3": 110001, "modbus": 110002, "gtpv1": 120001, "gps": 120002,
             "wiu": 120003, "http": 130001, "smtp": 140001, "imap": 140002, "pop3": 140004, "mapi": 140005,
             "mysql": 150001, "irc": 160001, "sip": 170001}
proto_inv_map = {v: k for k, v in proto_map.items()}
family_map = {'network_services': 1, 'network_management': 2, 'encrypted': 3, 'tunnel': 4, 'logging': 5,
              'application_service': 6, 'authentication': 7, 'remote_access': 8, 'file_transfer': 9, 'p2p': 10,
              'scada': 11, 'mobile': 12, 'web': 13, 'mail': 14, 'database': 15, 'chat': 16, 'voice': 17}
family_inv_map = {v: k for k, v in family_map.items()}


def format_flow(flow):
    if 'src_ip' in flow:
        flow['src_ip'] = number_to_ip(flow['src_ip'])
    if 'dest_ip' in flow:
        flow['dest_ip'] = number_to_ip(flow['dest_ip'])
    if 'time' in flow:
        flow['time'] = isoTime(flow['time'])
    if 'family' in flow:
        flow['family'] = list(map(lambda x: family_inv_map[x], flow['family']))
    if 'proto' in flow:
        flow['proto'] = list(map(lambda x: proto_inv_map[x], flow['proto']))
    return flow


def get_flows(result):
    data = result['data'] or []
    return list(map(lambda x: format_flow(x), data))


def validate_response(response):
    result = None
    if response.status_code == 200:
        result = response.json()
    if result and result["status"] != 1:
        raise Exception(str(result['message'] or 'an api error occurred'))
    demisto.debug(result)
    return result


def getTime(t):
    try:
        return time.mktime(time.strptime(t, '%Y-%m-%dT%H:%M:%S.%fZ'))
    except Exception:
        return t


def isoTime(epochTime):
    return datetime.fromtimestamp(epochTime).isoformat() + 'Z'


def coalesceToArray(o):
    if not isinstance(o, list):
        return [o]
    return o


def make_context(dargs, apiserver, auth_token):
    if 'probe' in dargs and 'envid' in dargs:
        sensor = {
            'probe': int(dargs['probe']),
            'envid': int(dargs['envid'])
        }
        return {
            'probes': [sensor],
            'dbs': ['probe_{envid}_{probe}'.format(**sensor)]
        }
    else:
        response = requests.get(urljoin(apiserver, '/admin/probes'),
                                params={'filterscount': 1, 'filtercondition0': 'NOT_EQUAL',  # type: ignore[arg-type]
                                        'filterdatafield0': 'deleted', 'filtervalue0': 1},
                                headers={'cache-control': 'no-cache', 'x-api-access-token': auth_token}, verify=VERIFY)
        result = validate_response(response)
        return {
            'probes': result['rows'],
            'dbs': list(map(lambda x: 'probe_{envid}_{probe}'.format(**x), result['rows']))
        }


def make_timerange(dargs):
    if 'stop_time' in dargs:
        tnow = getTime(dargs['stop_time'])
    else:
        tnow = time.mktime(datetime.now().timetuple())

    if 'start_time' in dargs:
        tmin = getTime(dargs['start_time'])
    else:
        lastRun = demisto.getLastRun() and demisto.getLastRun()["time"]
        if len(lastRun) != 0:
            tmin = getTime(lastRun)
        else:
            tmin = tnow - 1 * 60 * 60

    return tmin, tnow


def make_query(dargs):
    tmin, tnow = make_timerange(dargs)

    search = {'time': {'=': {'scalars': [], 'ranges': [{'v1': tmin, 'v2': tnow}]}}}

    if 'entity' in dargs:
        entity = coalesceToArray(dargs['entity'])
        search['ip'] = {
            '=': {
                'scalars': list(map(lambda x: {'v1': ip_to_number(x)}, entity)),
                'ranges': []
            }
        }

    if 'protocol' in dargs:
        protocol = coalesceToArray(dargs['protocol'])
        search['proto'] = {
            '=': {
                'scalars': list(map(lambda x: {'v1': proto_map[x]}, protocol)),
                'ranges': []
            }
        }

    if 'family' in dargs:
        family = coalesceToArray(dargs['family'])
        search['family'] = {
            '=': {
                'scalars': list(map(lambda x: {'v1': family_map[x]}, family)),
                'ranges': []
            }
        }

    if 'geo' in dargs:
        geo = coalesceToArray(dargs['geo'])
        search['geo'] = {
            '=': {
                'scalars': list(map(lambda x: {'v1': x}, geo)),
                'ranges': []
            }
        }

    if 'port' in dargs:
        port = coalesceToArray(dargs['port'])
        search['port'] = {
            '=': {
                'scalars': list(map(lambda x: {'v1': x}, port)),
                'ranges': []
            }
        }

    return search


def main():
    auth_token = ''
    apiserver = demisto.params()['ApiServer']
    username = demisto.params()['credentials']['identifier']
    password = demisto.params()['credentials']['password']

    response = requests.post(urljoin(apiserver, '/api/login'), data={'email': username, 'password': password},
                             headers={'cache-control': 'no-cache'}, verify=VERIFY)

    if response.status_code == 200:
        result = response.json()
        if result["status"] == 1:
            auth_token = result["token"]

    if not auth_token:
        raise ValueError('Authorization failed')

    if demisto.command() == 'test-module':
        demisto.results('ok')
        sys.exit(0)

    elif demisto.command() == 'packetsled-sensors':
        response = requests.get(urljoin(apiserver, '/admin/probes'),
                                params={'filterscount': 1, 'filtercondition0': 'NOT_EQUAL',
                                        'filterdatafield0': 'deleted', 'filtervalue0': 1},  # type: ignore[arg-type]
                                headers={'cache-control': 'no-cache', 'x-api-access-token': auth_token}, verify=VERIFY)

        result = response.json()
        demisto.results({
            'HumanReadable': humanReadable('Sensors', result['rows']),
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'packetsled-sensors': result['rows']},
            'EntryContext': {
                'Packetsled.Sensors': result['rows']
            }
        })

    elif demisto.command() == "fetch-incidents" or demisto.command() == 'packetsled-get-incidents':
        now = datetime.utcnow().isoformat()[:-3] + "Z"
        dargs = demisto.args()
        tmin, tnow = make_timerange(dargs)
        sensorContext = make_context(dargs, apiserver, auth_token)

        severity = 5
        if 'severity' in dargs:
            severity = int(dargs['severity'])

        search = {'severity': {'$gte': severity}, 'time': {'$lte': tnow, '$gte': tmin}}

        incidents: list = []
        for sensor in sensorContext['probes']:
            incidentContext = {'probes': [sensor], 'dbs': ['probe_{envid}_{probe}'.format(**sensor)]}

            # query for incidents
            flows_query = {
                "limit": 50000,
                "pivot": {
                    "attribute": "src_ip",
                    "fields": ["log"],
                    "dimensions": ["src_ip", "log"]
                },
                "query": {
                    "time": {
                        "=": {
                            "scalars": [],
                            "ranges": [{
                                "lhs": "time",
                                "v1": tmin,
                                "v2": tnow
                            }]
                        }
                    },
                    "log": {
                        "=": {
                            "scalars": [{
                                "i": 7,
                                "t": "a",
                                "v1": "intel"
                            }, {
                                "i": 9,
                                "t": "a",
                                "v1": "notice"
                            }, {
                                "i": 11,
                                "t": "a",
                                "v1": "psfile_analytics"
                            }],
                            "ranges": []
                        }
                    }
                },
                "search_text": "log = [intel notice psfile_analytics ] cluster src_ip on [log]"
            }

            response = requests.post(urljoin(apiserver, '/flows/flows'),
                                     data=json.dumps({'context': incidentContext, 'search': flows_query}),
                                     headers={'content-type': 'application/json', 'cache-control': 'no-cache',
                                              'x-api-access-token': auth_token}, verify=VERIFY)

            # validate the response
            result = validate_response(response)
            entitys = list(map(lambda x: number_to_ip(x['name']), result['data'] or []))

            flows_query = {"limit": 50000,
                           "pivot": {"attribute": "dest_ip", "fields": ["log"], "dimensions": ["dest_ip", "log"]},
                           "query": {"time": {"=": {"scalars": [], "ranges": [{"lhs": "time", "v1": tmin, "v2": tnow}]}},
                                     "log": {
                                         "=": {
                                             "scalars": [{
                                                 "i": 7,
                                                 "t": "a",
                                                 "v1": "intel"
                                             }, {
                                                 "i": 9,
                                                 "t": "a",
                                                 "v1": "notice"
                                             }, {
                                                 "i": 11,
                                                 "t": "a",
                                                 "v1": "psfile_analytics"
                                             }], "ranges": []}}},
                           "search_text": "log = [intel notice psfile_analytics ] cluster dest_ip on [log]"}

            response = requests.post(urljoin(apiserver, '/flows/flows'),
                                     data=json.dumps({'context': incidentContext, 'search': flows_query}),
                                     headers={'content-type': 'application/json', 'cache-control': 'no-cache',
                                              'x-api-access-token': auth_token}, verify=VERIFY)

            # validate the response
            result = validate_response(response)
            entitys += list(map(lambda x: number_to_ip(x['name']), result['data'] or []))
            entitys = list(set(entitys))

        if demisto.command() == "fetch-incidents":
            incidents += list(map(lambda x: {
                'id': x + '-' + str(tmin) + '-' + str(tnow),
                'name': 'SOURCE: Packetsled SENSOR: ' + sensor['label'] + ' ENTITY: ' + x,
                'labels': [{'Provider': 'packetsled'}, {'Sensor': sensor['label']}, {'Entity': x}],
                'rawJSON': json.dumps({
                    'id': x + '-' + str(tmin) + '-' + str(tnow),
                    'log': ['intel', 'notice', 'psfile_analytics'],
                    'entity': x,
                    'start_time': tmin,
                    'stop_time': tnow,
                    'envid': sensor['envid'],
                    'probe': sensor['probe']
                })
            }, entitys))
            demisto.incidents(incidents)
        else:
            incidents += list(map(lambda x: {
                'id': x + '-' + str(tmin) + '-' + str(tnow),
                'log': ['intel', 'notice', 'psfile_analytics'],
                'entity': x,
                'start_time': tmin,
                'stop_time': tnow,
                'envid': sensor['envid'],
                'probe': sensor['probe']
            }, entitys))
            demisto.results({
                'HumanReadable': humanReadable('Incidents', incidents),
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': {
                    'packetsled-incidents': incidents
                },
                'EntryContext': {
                    'Packetsled.Incidents': incidents
                }
            })
        demisto.setLastRun({"time": now})

    elif demisto.command() == 'packetsled-get-flows':
        dargs = demisto.args()

        limit = 5000
        if 'limit' in dargs:
            limit = dargs['limit']
        search = make_query(dargs)
        sensorContext = make_context(dargs, apiserver, auth_token)

        # query for flows
        response = requests.post(urljoin(apiserver, '/flows/flows'),
                                 data=json.dumps({'context': sensorContext, 'search': {'query': search, 'limit': limit}}),
                                 headers={'content-type': 'application/json', 'cache-control': 'no-cache',
                                          'x-api-access-token': auth_token}, verify=VERIFY)

        # validate the response
        result = validate_response(response)
        flows = get_flows(result)
        demisto.results({
            'HumanReadable': humanReadable('Flows', flows),
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'packetsled-get-flows': flows
            },
            'EntryContext': {
                'Packetsled.Flows': flows
            }
        })
    elif demisto.command() == 'packetsled-get-events':
        dargs = demisto.args()
        sensorContext = make_context(dargs, apiserver, auth_token)

        # prepare a time range query on host
        uid = dargs['uid']

        # times are expressed in UNIX epoch seconds
        # search for any times greater than NOW minus 1 hours
        search = {'uid': uid}

        # query for flows
        response = requests.post(urljoin(apiserver, '/flows/events'),
                                 data=json.dumps({'context': sensorContext, 'search': search}),
                                 headers={'content-type': 'application/json', 'cache-control': 'no-cache',
                                          'x-api-access-token': auth_token}, verify=VERIFY)

        # validate the response
        result = validate_response(response)
        demisto.results({'HumanReadable': humanReadable('Events', result['data']), 'Type': entryTypes['note'],
                         'ContentsFormat': formats['json'], 'Contents': {'packetsled-get-events': result['data']},
                         'EntryContext': {'packetsled.events': result['data']}
                         })
    elif demisto.command() == 'packetsled-get-files':
        dargs = demisto.args()

        limit = 5000
        if 'limit' in dargs:
            limit = dargs['limit']

        search = make_query(dargs)
        sensorContext = make_context(dargs, apiserver, auth_token)
        search["@attribute"] = {'=': {'scalars': [{'v1': 'extracted'}], 'ranges': []}}

        # query for flows
        response = requests.post(urljoin(apiserver, '/flows/flows'),
                                 data=json.dumps({'context': sensorContext, 'search': {'query': search, 'limit': limit}}),
                                 headers={'content-type': 'application/json', 'cache-control': 'no-cache',
                                          'x-api-access-token': auth_token}, verify=VERIFY)

        # validate the response
        result = validate_response(response)
        # iterate over the returned flows, looking for extracted files
        for flow in result["data"]:
            if 'extracted' in flow:
                for file in flow["extracted"]:

                    # download the extracted file
                    response = requests.get(
                        urljoin(apiserver, ('/download/file_extraction/{probe}/' + file).format(**flow)),
                        headers={
                            'cache-control': 'no-cache',
                            'x-api-access-token': auth_token
                        },
                        verify=VERIFY)

                    # the download will return 404 if the file has been purged
                    if response.status_code == 200:
                        demisto.results(fileResult(file.replace('/', '_'), response.content))

    elif demisto.command() == 'packetsled-get-pcaps':
        dargs = demisto.args()
        tmin, tnow = make_timerange(dargs)
        sensorContext = make_context(dargs, apiserver, auth_token)

        query = "before " + isoTime(tnow) + " and after " + isoTime(tmin)

        if 'entity' in dargs:
            entity = coalesceToArray(dargs['entity'])
            if len(entity) > 1:
                query = query + " and (" + " or ".join(list(map(lambda x: "host " + x, entity))) + ")"
            else:
                query = query + " and host " + entity[0]

        if 'protocol' in dargs:
            protocol = coalesceToArray(dargs['protocol'])
            if len(protocol) > 1:
                query = query + " and (" + " or ".join(list(map(lambda x: x, protocol))) + ")"
            else:
                query = query + " and " + protocol[0]

        if 'port' in dargs:
            port = coalesceToArray(dargs['port'])
            if len(port) > 1:
                query = query + " and (" + " or ".join(list(map(lambda x: "port " + x, port))) + ")"
            else:
                query = query + " and port " + port[0]

        for sensor in sensorContext['probes']:
            route = "?rule=" + quote(query)
            if 'limitbytes' in dargs:
                route = route + "&limitbytes=" + dargs['limitbytes']

            if 'limitpkts' in dargs:
                route = route + "&limitpkts=" + dargs['limitpkts']

            # download the extracted file
            response = requests.get(urljoin(apiserver, ('/download/ndr/{probe}/' + route).format(**sensor)),
                                    headers={'cache-control': 'no-cache', 'x-api-access-token': auth_token}, verify=VERIFY)

            # the download will return 404 if the file has been purged
            if response.status_code == 200:
                demisto.results(fileResult(query, response.content))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
