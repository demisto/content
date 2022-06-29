var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server;
var insecure = params.insecure;

var sendRequest = function(url, queryName) {
    var res = http(
            server + '/' + url,
            {
                Method: 'GET',
                Username: username,
                Password: password,
                UseAuthDigest: true,
            },
            insecure
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + queryName + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res;
}

var pcap_command = 'moloch_sessions_pcap';
var unique_command = 'moloch_unique_json';

// Fields to get from the db while sending moloch_sessions_json requests
var other_fields = "ipProtocol";
var http_fields = "http.statuscode,http.method";
var src_fields = "srcPackets,srcBytes,srcDataBytes";
var dst_fields = "dstPackets,dstBytes,dstDataBytes";
var fields_to_req = "&fields={0},{1},{2},{3}&expression=http.statuscode==EXISTS!".format(http_fields, src_fields, dst_fields,other_fields);

var urlDict = {
    'moloch_connections_json': 'connections.json',
    'moloch_connections_csv': 'connections.csv',
    'moloch_files_json': 'file/list',
    'moloch_sessions_json': 'sessions.json',
    'moloch_sessions_csv': 'sessions.csv',
    'moloch_sessions_pcap': 'sessions.pcap',
    'moloch_spigraph_json': 'spigraph.json',
    'moloch_spiview_json': 'spiview.json',
    'moloch_unique_json': 'unique.txt'
}

var prToName = {
    1: 'icmp',
    6: 'tcp',
    17: 'udp',
    47: 'gre',
    58: 'icmpv6'
}

var jsonResponses = ['moloch_connections_json', 'moloch_files_json', 'moloch_sessions_json', 'moloch_spigraph_json', 'moloch_spiview_json'];
var csvResponses = ['moloch_connections_csv', 'moloch_sessions_csv'];
var pcapResponses = ['moloch_sessions_pcap'];

var parseSessions = function(response) {
    var outputs = [];
    var contexts = [];
    for (var i = 0, objects = response.data; i < objects.length; i++) {
        var output = {};

        output['ID'] = objects[i].id;
        output['Index'] = objects[i].index;
        output['Protocol'] = objects[i].ipProtocol in prToName ? prToName[objects[i].ipProtocol] : objects[i].ipProtocol;
        output['Start Time'] = args.startTime;
        output['End Time'] = args.stopTime;

        output['Source IP'] = objects[i].srcIp;
        output['Source Port'] = objects[i].srcPort;
        output['Source Packets'] = objects[i].srcPackets;
        output['Source Bytes'] = objects[i].srcBytes;
        output['Source Databytes'] = objects[i].srcDataBytes;

        output['Destination IP'] = objects[i].dstIp;
        output['Destination Port'] = objects[i].dstPort;
        output['Destination Packets'] = objects[i].dstPackets;
        output['Destination Bytes'] = objects[i].dstBytes;
        output['Destination Databytes'] = objects[i].dstDataBytes;

        output['HTTP method'] = objects[i].http.method;
        output['HTTP Status code'] = objects[i].http.statuscode;

        outputs.push(output);
        contexts.push(convertKeysToPascalCase(output));
    }

    entry = {
        Type: entryTypes.note,
        Contents: null,
        ContentsFormat: formats.json,
        EntryContext: {'Moloch.Sessions': contexts},
        HumanReadable: tableToMarkdown('Moloch Sessions Search', outputs)
    };
    return entry;
}

switch (command) {
    case 'test-module':
        if (sendRequest(urlDict['moloch_connections_json'], 'Test').Body) {
            return 'ok';
        }

        return 'not cool';

    default:
        var currentTime = new Date();

        if (!args.date && command != pcap_command && command != unique_command) {
            args.date = -1;
        }

        url = urlDict[command] + encodeToURLQuery(args);

        var res = sendRequest(url, urlDict[command]);
        if (!res || !res.Body) {
            return 'No data was found in Moloch';
        }

        if (command == unique_command) {
            return res.Body;
        } else if (jsonResponses.indexOf(command) !== -1) {
            if (command == 'moloch_sessions_json') {
                return parseSessions(JSON.parse(res.Body));
            } else {
                return JSON.parse(res.Body);
            }
        } else if (csvResponses.indexOf(command) !== -1) {
            return {Type: 9, FileID: saveFile(res.Bytes), File: command + encodeToURLQuery(args).substr(1) + '_at_' + currentTime.getTime() + '.csv',  Contents: 'we must have contents for an entry'};
        } else if (pcapResponses.indexOf(command) !== -1) {
            return {Type: 9, FileID: saveFile(res.Bytes), File: command + encodeToURLQuery(args).substr(1) + '_at_' + currentTime.getTime() + '.pcap',  Contents: 'we must have contents for an entry'};
        }

        return res;
}
